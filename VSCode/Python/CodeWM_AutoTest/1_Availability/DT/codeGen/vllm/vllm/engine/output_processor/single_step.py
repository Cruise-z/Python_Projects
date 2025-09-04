# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from typing import List

from vllm.config import SchedulerConfig
from vllm.core.scheduler import Scheduler
from vllm.engine.output_processor.interfaces import (
    SequenceGroupOutputProcessor)
from vllm.engine.output_processor.stop_checker import StopChecker
from vllm.logger import init_logger
from vllm.sequence import (CompletionSequenceGroupOutput, SequenceGroup,
                           SequenceGroupOutput, Sequence)
from vllm.transformers_utils.detokenizer import Detokenizer
from vllm.utils import Counter

logger = init_logger(__name__)


def single_step_process_prompt_logprob(
        sg_output_proc: SequenceGroupOutputProcessor, seq_group: SequenceGroup,
        output: CompletionSequenceGroupOutput) -> None:
    """Process prompt logprobs associated with the
    [`SequenceGroupOutput`][vllm.sequence.SequenceGroupOutput] for a given step.

    Do nothing if the output has no prompt logprobs.

    Account for the fact that transformers do not compute first-token logprobs.
    
    Args:
      sg_output_proc:
          [`SequenceGroupOutputProcessor`][vllm.engine.output_processor.interfaces.SequenceGroupOutputProcessor]
          instance
      seq_group: the output is associated with this
          [`SequenceGroup`][vllm.sequence.SequenceGroup]
      output: the [`SequenceGroupOutput`][vllm.sequence.SequenceGroupOutput]
          for a single scheduler step
    """
    prompt_logprobs = output.prompt_logprobs

    # If this is the first (or only) "chunk" of the prefill, we need
    # to prepend None to the list of prompt logprobs. The reason for this
    # is that for N prompt tokens, the Sampler will generate N-1 total
    # prompt logprobs during prefill since the token at idx 0 will not
    # have a logprob associated with it.
    if prompt_logprobs is not None:
        if not seq_group.prompt_logprobs:
            prompt_logprobs = [None] + prompt_logprobs
            seq_group.prompt_logprobs = []

        assert hasattr(sg_output_proc, 'detokenizer')
        if (seq_group.sampling_params.detokenize
                and sg_output_proc.detokenizer):
            sg_output_proc.detokenizer.decode_prompt_logprobs_inplace(
                seq_group,
                prompt_logprobs,
                position_offset=len(seq_group.prompt_logprobs))

        seq_group.prompt_logprobs.extend(prompt_logprobs)


class SingleStepOutputProcessor(SequenceGroupOutputProcessor):
    """SequenceGroupOutputProcessor which handles "output processing" logic,
    which happens after the model returns generated token ids and before
    scheduling of the next batch. Output processing logic includes
    detokenization, and determining if a sequence is finished (e.g. via max len
    or eos token).

    The SingleStepOutputProcessor is specialized to the case where the model
    emits at most a single token per invocation, which precludes configurations
    such as speculative decoding or multi-step decoding. This enables beam
    search sampling, which requires forking/finishing/freeing sequences in a way
    that is currently difficult to schedule multiple steps ahead of time.
    """

    def __init__(self, scheduler_config: SchedulerConfig,
                 detokenizer: Detokenizer, scheduler: List[Scheduler],
                 seq_counter: Counter, stop_checker: StopChecker):
        self.scheduler_config = scheduler_config
        self.detokenizer = detokenizer
        self.scheduler = scheduler
        self.seq_counter = seq_counter
        self.stop_checker = stop_checker
    
    #TODO: <expose tokenizer>
    # --- NEW: expose tokenizer special ids to extra_args for downstream processors ---
    def _maybe_attach_special_token_ids(self, seq_group: SequenceGroup) -> None:
        sp = getattr(seq_group, "sampling_params", None)
        if sp is None:
            return
        extra = getattr(sp, "extra_args", None) or {}
        if "special_token_ids" in extra:
            return
        special_ids = []
        tok = getattr(self.detokenizer, "tokenizer", None)
        if tok is not None:
            # HF tokenizer usually has .all_special_ids
            try:
                ids = getattr(tok, "all_special_ids", None)
                if ids:
                    special_ids = list(map(int, ids))
            except Exception:
                pass
        # write once; if拿不到就写空列表也没关系
        extra["special_token_ids"] = special_ids
        sp.extra_args = extra
    #TODO: </expose tokenizer>
        
    #TODO: <dual channel Gen(base vs. wm)>
    def _maybe_setup_wm_for_n(self, seq_group: SequenceGroup) -> None:
        """
        当用户在 SamplingParams.extra_args 里开启 wm_compare 且使用 n>=2 时，
        不手动 fork，由调度/采样产生多路。这里仅负责：
          1) 把第一条路标成 'base'，第二条路标成 'wm'（按 seq_group.seqs 当前顺序）
          2) 同步写入 extra_args：wm_branch_seq_ids / seq_ids / wm_mask
             - 第1步结束后（即下一解码步开始前）把 wm_mask 设为仅第二路 True
        """
        sp = getattr(seq_group, "sampling_params", None)
        if sp is None:
            return
        extra = getattr(sp, "extra_args", None) or {}
        if not bool(extra.get("wm_compare", False)):
            return

        # 当前活跃序列的顺序
        seqs = list(getattr(seq_group, "seqs", []) or [])
        if not seqs:
            return

        # 若尚未打过标签，且至少有两路，则按顺序 0->base, 1->wm 标注
        if not extra.get("_wm_labeled", False) and len(seqs) >= 2:
            for i, s in enumerate(seqs):
                setattr(s, "_wm_branch", "wm" if i == 1 else "base")
            branch_map = {str(s.seq_id): getattr(s, "_wm_branch", None)
                          for s in seqs[:2]}
            extra["wm_branch_seq_ids"] = branch_map
            extra["_wm_labeled"] = True

        # 每步都写入当前顺序，便于处理器对齐 B 维
        extra["seq_ids"] = [int(s.seq_id) for s in seqs]

        # 构造下一步使用的 wm_mask：
        # - 第1个解码步前在 prefill 已经把 extra['wm']=False（全透传）
        # - 从此处开始（走完第1步后）切换到仅 'wm' 分支为 True 的掩码
        if extra.get("_wm_labeled", False):
            wm_mask = [getattr(s, "_wm_branch", None) == "wm" for s in seqs]
        else:
            # 尚未形成两路时，保持全 False（等形成两路后再打开）
            wm_mask = [False for _ in seqs]
        extra["wm_mask"] = wm_mask
        # 用过一次全局 'wm' 之后就去掉，避免覆盖逐步掩码
        if "wm" in extra:
            extra.pop("wm", None)
        sp.extra_args = extra
        
    #TODO: </dual channel Gen(base vs. wm)>

    def process_outputs(self, sequence_group: SequenceGroup,
                        outputs: List[SequenceGroupOutput],
                        is_async: bool) -> None:
        """Append all new tokens to sequences in the sequence group. Fork any
        surviving beam candidates; free any unsurviving ones.

        Invokes detokenizer to detokenize new tokens, and also marks sequences
        as finished if they meet stop conditions.
        
        is_async - Indicates whether this postprocessor runs in 
            parallel with the GPU forward pass and is processing 
            tokens from the previous step. If this is true, then
            no tokens need to be appended since it is already done
            externally (before the next schedule() call)
        """
        assert (len(outputs) == 1
                ), f"{type(self)} does not support multiple outputs per step"
        return self._process_sequence_group_outputs(sequence_group, outputs[0],
                                                    is_async)

    def process_prompt_logprob(self, seq_group: SequenceGroup,
                               outputs: List[SequenceGroupOutput]) -> None:
        """
        保持原有 prompt logprobs 处理；另外在 prefill 阶段：
          - 若启用 wm_compare，则把 extra_args['wm']=False，
            保证“第1个解码步不加水印”（第二步开始再由 wm_mask 生效）。
        """
        assert len(outputs) == 1, "Single step should only have 1 output."
        output = outputs[0]
        assert isinstance(output, CompletionSequenceGroupOutput)
        single_step_process_prompt_logprob(self, seq_group, output)

        # prefill 阶段：设置首步全透传
        sp = getattr(seq_group, "sampling_params", None)
        if sp is None:
            return
        extra = getattr(sp, "extra_args", None) or {}
        if bool(extra.get("wm_compare", False)):
            # 第1个解码步前全部不加水印（方案A的“先走一步再分路”的模拟）
            extra["wm"] = False
            sp.extra_args = extra

    def _process_sequence_group_outputs(self, seq_group: SequenceGroup,
                                        outputs: SequenceGroupOutput,
                                        is_async: bool) -> None:
        
        # Ensure special_token_ids is available to logits processors
        self._maybe_attach_special_token_ids(seq_group)
        sampling_params = seq_group.sampling_params

        
        #TODO: <fix logic>
        # === 逐样本处理：n>=2 时两路都要追加/解码/检查 ===
        samples = list(getattr(outputs, "samples", []) or [])
        seqs_dict = getattr(seq_group, "seqs_dict", {}) or {}
        seqs_by_order = list(getattr(seq_group, "seqs", []) or [])

        for i, sample in enumerate(samples):
            # 找到对应的 Sequence：优先用 sample.seq_id → seqs_dict
            seq = None
            sid = getattr(sample, "seq_id", None)
            if sid is not None and sid in seqs_dict:
                seq = seqs_dict[sid]
            elif i < len(seqs_by_order):
                seq = seqs_by_order[i]
            else:
                # 无法对齐就跳过该样本（极端容错）
                continue

            if not is_async:
                seq.append_token_id(sample.output_token,
                                    sample.logprobs,
                                    sample.output_embed)

            if sampling_params.detokenize and self.detokenizer:
                new_char_count = self.detokenizer.decode_sequence_inplace(
                    seq, sampling_params)
            else:
                new_char_count = 0
            self.stop_checker.maybe_stop_sequence(
                seq,
                new_char_count,
                sampling_params,
                lora_req=seq_group.lora_request,
            )
        
        # 释放所有已完成的序列，避免残留（并行/beam 下尤为重要）
        get_finished = getattr(seq_group, "get_finished_seqs", None)
        if callable(get_finished):
            finished = get_finished()
        else:
            # fallback：没有该方法时手动筛选
            finished = [s for s in getattr(seq_group, "seqs", []) if s.is_finished()]
        for s in finished:
            for sch in self.scheduler:
                sch.free_seq(s)
        # 刷新/建立并行两路的标注与掩码（供下一步采样时使用）
        self._maybe_setup_wm_for_n(seq_group)
        #TODO: </fix logic>
