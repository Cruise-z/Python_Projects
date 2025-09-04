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
        
    #TODO: <dual channel fork(base vs. wm)>
    def _maybe_fork_wm_branch(self, seq_group: SequenceGroup,
                              parent: Sequence) -> None:
        """
        If enabled via sampling_params.extra_args['wm_compare'], fork a child
        sequence that shares KV with `parent`, and mark branches:
          parent._wm_branch = "base"
          child._wm_branch  = "wm"
        Also persist a seq_id -> branch mapping into
          sampling_params.extra_args['wm_branch_seq_ids'] = {id: "base"/"wm"}
        so a custom logits processor can selectively apply only to the 'wm'
        branch at sampling time.
        """
        sp = getattr(seq_group, "sampling_params", None)
        if sp is None:
            return
        extra = getattr(sp, "extra_args", None) or {}
        wm_compare = bool(extra.get("wm_compare", False))

        # Only fork once per SequenceGroup.
        if (not wm_compare) or getattr(seq_group, "_wm_dual_forked", False):
            return

        # Allocate a new seq_id and fork the sequence (COW, shared KV).
        try:
            new_seq_id = next(self.seq_counter)
        except TypeError:
            # Fallback if Counter is callable rather than iterator-like.
            new_seq_id = self.seq_counter()
        child = parent.fork(new_seq_id)

        # Tag branches (lightweight Python attributes are fine here).
        setattr(parent, "_wm_branch", "base")
        setattr(child, "_wm_branch", "wm")

        # Register child into the SequenceGroup.
        seq_group.seqs.append(child)
        seq_group.seqs_dict[child.seq_id] = child
        seq_group.is_single_seq = False

        # Inform all schedulers so BlockManager can COW/fork the KV.
        for sch in self.scheduler:
            # Modern schedulers expose fork(parent, child).
            # (core.interfaces defines this hook)
            sch.fork(parent, child)

        # Persist mapping into extra_args for downstream processors.
        branch_map = extra.get("wm_branch_seq_ids", {})
        branch_map[str(parent.seq_id)] = "base"
        branch_map[str(child.seq_id)] = "wm"
        extra["wm_branch_seq_ids"] = branch_map
        sp.extra_args = extra
        
        # === NEW(1): optional per-sequence flag for debugging ===
        setattr(parent, "_wm_enabled", False)
        setattr(child, "_wm_enabled", True)

        # === NEW(2): build boolean mask aligned with current seq order ===
        # Note: child has been appended to seq_group.seqs above.
        wm_mask = [getattr(s, "_wm_branch", None) == "wm" for s in seq_group.seqs]
        extra["wm_mask"] = wm_mask
        # === NEW(3): expose current seq_ids order for robust per-row mapping ===
        # 方便处理器用 wm_branch_seq_ids + seq_ids 自行构造掩码，避免 B 尺寸假设。
        extra["seq_ids"] = [int(s.seq_id) for s in seq_group.seqs]
        # re-assign after updating extra_args
        sp.extra_args = extra

        # Guard: don't fork again.
        setattr(seq_group, "_wm_dual_forked", True)
        
    #TODO: </dual channel fork(base vs. wm)>

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
        """Process prompt logprobs associated with one step of a single-step-
        scheduled computation.
        
        Args:
          seq_group: the output is associated with this
              [`SequenceGroup`][vllm.sequence.SequenceGroup]
          outputs: the
              [`SequenceGroupOutput`][vllm.sequence.SequenceGroupOutput]
              for a single scheduler step
        """
        assert len(outputs) == 1, "Single step should only have 1 output."
        output = outputs[0]
        assert isinstance(output, CompletionSequenceGroupOutput)
        single_step_process_prompt_logprob(self, seq_group, output)

    def _process_sequence_group_outputs(self, seq_group: SequenceGroup,
                                        outputs: SequenceGroupOutput,
                                        is_async: bool) -> None:
        
        # Ensure special_token_ids is available to logits processors
        self._maybe_attach_special_token_ids(seq_group)
        sampling_params = seq_group.sampling_params

        sample = outputs.samples[0]
        seq = seq_group.first_seq
        
        #TODO: <fix logic>
        # 如果是异步 postprocessor，第一步 token 已在外部 append 完成，
        # 也需要在这里判断一次并触发 fork，保证双路并行正常生效。
        if is_async:
            try:
                if seq.get_output_len() == 1:
                    self._maybe_fork_wm_branch(seq_group, seq)
            except AttributeError:
                pass  # 极端老接口上没有 get_output_len，可忽略
        # if not is_async:
        #     seq.append_token_id(sample.output_token, sample.logprobs,
        #                         sample.output_embed)
        if not is_async:
            # Append the sampled token to the first (active) sequence.
            seq.append_token_id(sample.output_token, sample.logprobs,
                                sample.output_embed)
            # ---- NEW: fork dual-route after the *first* decode step ----
            # Only do this when user requests 'wm_compare' and after we've
            # appended the first decode token so parent/child share KV.
            # (KV created during prefill and extended by this token)
            if seq.get_output_len() == 1:
                self._maybe_fork_wm_branch(seq_group, seq)
        #TODO: </fix logic>
        
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
        
        #TODO: <fix logic>
        # if seq.is_finished():
        #     for scheduler in self.scheduler:
        #         scheduler.free_seq(seq)
        
        # --- CHANGED: free *all* finished sequences in the group to avoid
        # orphaned children (when dual-route or beam leaves extras around).
        get_finished = getattr(seq_group, "get_finished_seqs", None)
        if callable(get_finished):
            finished = get_finished()
        else:
            # fallback：没有该方法时手动筛选
            finished = [s for s in getattr(seq_group, "seqs", []) if s.is_finished()]
        for s in finished:
            for sch in self.scheduler:
                sch.free_seq(s)
        # --- NEW: refresh wm_mask to match current active sequences ---
        extra = getattr(seq_group.sampling_params, "extra_args", None)
        if isinstance(extra, dict) and "wm_branch_seq_ids" in extra:
            extra["wm_mask"] = [getattr(s, "_wm_branch", None) == "wm"
                                for s in seq_group.seqs]
            # 同步刷新当前顺序的 seq_ids，保持与本步 logits 行顺序一致
            try:
                extra["seq_ids"] = [int(s.seq_id) for s in seq_group.seqs]
            except Exception:
                pass
            seq_group.sampling_params.extra_args = extra
        #TODO: </fix logic>
