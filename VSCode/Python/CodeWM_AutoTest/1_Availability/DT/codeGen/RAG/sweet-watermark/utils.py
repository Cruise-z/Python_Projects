# -*- coding: utf-8 -*-
# pip install transformers accelerate torch
from __future__ import annotations
from typing import Callable, List, Dict, Optional, Protocol, Any
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from transformers.generation.logits_process import LogitsProcessor, LogitsProcessorList

########################################################
# 1) Retriever 接口 & 适配器
########################################################

class RetrievalHit(Dict[str, Any]):
    """
    约定字段（至少要有 reference）。你也可扩展更多元数据。
      - reference: str      # 召回的参考代码文本
      - score: float        # 可选，召回分
      - task_id / task_name / prompt / prefix ... 任选
    """
    pass

class Retriever(Protocol):
    def retrieve(self, query: str, top_k: int = 1) -> List[RetrievalHit]: ...

class FunctionRetriever:
    """
    用你的已有函数适配为 Retriever：
    你的函数签名形如: fn(query_text: str, top_k: int) -> List[Dict]
    返回的 Dict 里必须包含 'reference'.
    """
    def __init__(self, fn: Callable[[str, int], List[Dict]]):
        self.fn = fn
    def retrieve(self, query: str, top_k: int = 1) -> List[RetrievalHit]:
        hits = self.fn(query, top_k)
        if not hits:
            return []
        if "reference" not in hits[0]:
            raise ValueError("retriever 返回结果缺少 'reference' 字段")
        return hits  # type: ignore


########################################################
# 2) SoftConstraint 处理器（可与水印 Processor 叠加）
########################################################

# class ReferenceMarginEnforcer(LogitsProcessor):
#     """
#     自适应软约束：
#       每步对参考下一 token 增加“最小必要偏置”使其成为 argmax（不屏蔽其它 token）。
#       finish_with_eos=True: 复制完后一键强制 EOS。
#     适合与 Watermark Processor 串联（把它放在链的末端兜底，保证一致性）。
#     """
#     def __init__(
#         self,
#         ref_ids: List[int],
#         start_len: int,
#         eos_token_id: int,
#         margin: float = 2.0,
#         finish_with_eos: bool = True,
#         max_bias: float = 50.0,
#     ):
#         self.ref_ids = [int(t) for t in ref_ids]
#         self.start_len = int(start_len)
#         self.eos_token_id = int(eos_token_id)
#         self.margin = float(margin)
#         self.finish_with_eos = bool(finish_with_eos)
#         self.max_bias = float(max_bias)

#     def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
#         step = input_ids.shape[-1] - self.start_len
#         if step < len(self.ref_ids):
#             tgt = self.ref_ids[step]
#             tgt_score = scores[:, tgt:tgt+1]
#             tmp = scores.clone()
#             tmp[:, tgt] = float("-inf")
#             max_others = tmp.max(dim=-1, keepdim=True).values
#             need = torch.clamp(max_others - tgt_score + self.margin, min=0.0, max=self.max_bias)
#             scores[:, tgt] += need.squeeze(-1)
#         elif self.finish_with_eos:
#             scores[:] = float("-inf")
#             scores[:, self.eos_token_id] = 0.0
#         return scores

# class ReferenceMarginEnforcer(LogitsProcessor):
#     """
#     自适应软约束：通过渐进性约束和动态参考调整，确保生成的代码尽可能接近参考代码。
#     同时，通过 logit 平滑（temperature scaling）和多样性增强（beam search、top-k）模拟真实推理过程。
#     """
#     def __init__(
#         self,
#         ref_ids: List[int],
#         start_len: int,
#         eos_token_id: int,
#         max_margin: float = 2.0,
#         min_margin: float = 2.0,
#         decay_rate: float = 0.95,
#         temperature: float = 0.3,
#         max_bias: float = 50.0,
#         window_size: int = 100,
#         finish_with_eos: bool = True,
#     ):
#         """
#         初始化 ReferenceMarginEnforcer，接受软约束和其他参数:
#         参数：
#         - ref_ids: 参考代码的 token IDs。
#         - start_len: 输入部分的 token 长度。
#         - eos_token_id: EOS token 的 ID。
#         - max_margin: 最大 margin，用于控制参考的偏置强度。
#         - min_margin: 最小 margin，防止 margin 过小。
#         - decay_rate: margin 随着步骤递减的速率。
#         - temperature: 控制 logits 的平滑程度。
#         - max_bias: 最大偏置，防止过大偏置。
#         - finish_with_eos: 是否在生成结束后强制使用 EOS。
#         - window_size: 动态参考窗口大小，控制参考序列的更新频率。
#         """
#         self.ref_ids = ref_ids
#         self.start_len = start_len
#         self.eos_token_id = eos_token_id
#         self.max_margin = max_margin
#         self.min_margin = min_margin
#         self.decay_rate = decay_rate
#         self.temperature = temperature
#         self.max_bias = max_bias
#         self.window_size = window_size
#         self.finish_with_eos = finish_with_eos

#     def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
#         step = input_ids.shape[-1] - self.start_len

#         # 动态计算 margin：随着生成过程递减
#         margin = max(self.min_margin, self.max_margin * (self.decay_rate ** step))

#         # 计算参考 token 的得分（目标是让参考 token 成为 argmax）
#         if step < len(self.ref_ids):
#             tgt = self.ref_ids[step]
#             tgt_score = scores[:, tgt:tgt+1]

#             # 计算其他 token 的最大分数
#             tmp = scores.clone()
#             tmp[:, tgt] = float("-inf")
#             max_others = tmp.max(dim=-1, keepdim=True).values
#             need = torch.clamp(max_others - tgt_score + margin, min=0.0, max=self.max_bias)
#             scores[:, tgt] += need.squeeze(-1)

#         # 动态参考调整：允许参考序列在生成过程中更新
#         reference_window = self.ref_ids[max(0, step - self.window_size):step]
#         for ref_token in reference_window:
#             scores[:, ref_token] += 1.0  # 增加参考 token 的得分

#         # 如果生成完参考内容，强制 EOS 结束
#         if step >= len(self.ref_ids) and self.finish_with_eos:
#             scores[:] = float("-inf")
#             scores[:, self.eos_token_id] = 0.0

#         # 平滑 logits 分布：通过 temperature 缩放 logits（增加多样性）
#         scores = scores / self.temperature

#         return scores

class HybridKLProjectionEnforcer(LogitsProcessor):
    """
    同时支持 'margin' 与 'prob' 约束，并通过 λ∈[0,1] 平滑过渡：
      - λ=0: 仅边际约束 s_t' - max_{j≠t} s_j' ≥ γ（硬复制更稳）
      - λ=1: 仅概率约束 q_t(δ) = α（KL最小抬升使概率达到目标）
      - 0<λ<1: 同时满足 弱化的边际 γ_λ 与 强化的概率 α_λ
    可选 ensure_copy=True 以极小安全边际兜底，保证贪心解码严格复制。
    """
    def __init__(
        self,
        ref_ids: List[int],
        start_len: int,
        eos_token_id: int,
        # 目标参数
        gamma: float = 2.5,       # 纯margin时的目标logit边际
        alpha: float = 0.5,       # 纯prob时的目标概率
        # 混合与调度:
        # λ=0: 完全logit复制；λ=1: 完全prob强化
        lambda_start: float = 0.0,
        lambda_end: float = 1.0,
        schedule: str = "linear",   # "constant" | "linear"（按步数从 start→end）
        # 数值与安全
        max_bias: float = 50.0,
        eps: float = 1e-12,
        compute_in_fp32: bool = False,
        finish_with_eos: bool = True,
        ensure_copy: bool = False,      # 兜底保证复制
        gamma_safe: float = 1e-6,       # 兜底的极小边际
    ):
        self.ref_ids = [int(t) for t in ref_ids]
        self.start_len = int(start_len)
        self.eos_token_id = int(eos_token_id)
        # 目标
        self.gamma = float(gamma)
        self.alpha = float(alpha)
        # 混合调度
        self.lambda_start = float(lambda_start)
        self.lambda_end = float(lambda_end)
        assert 0.0 <= self.lambda_start <= 1.0 and 0.0 <= self.lambda_end <= 1.0
        assert schedule in ("constant", "linear")
        self.schedule = schedule
        # 数值
        self.max_bias = float(max_bias)
        self.eps = float(eps)
        self.compute_in_fp32 = bool(compute_in_fp32)
        self.finish_with_eos = bool(finish_with_eos)
        # 兜底复制
        self.ensure_copy = bool(ensure_copy)
        self.gamma_safe = float(gamma_safe)

    def _lambda_at(self, step: int, total_steps: int) -> float:
        if self.schedule == "constant" or total_steps <= 1:
            return self.lambda_end  # 恒定
        # 线性从 start -> end
        ratio = step / (total_steps - 1)
        return self.lambda_start + (self.lambda_end - self.lambda_start) * ratio

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
        step = input_ids.shape[-1] - self.start_len
        L = len(self.ref_ids)

        if step < L:
            t = self.ref_ids[step]
            # 1) 当前步的混合系数 λ
            lam = self._lambda_at(step, L)  # in [0,1]

            # 2) 边际目标弱化：γ_λ = (1-λ)*γ
            gamma_eff = (1.0 - lam) * self.gamma

            # 3) 概率目标强化：α_λ = (1-λ)*p_t + λ*α
            #    先计算当前 p_t（建议在FP32下做logsumexp）
            scores = torch.clamp(scores, min=-1e5, max=1e5)
            if self.compute_in_fp32 and scores.dtype != torch.float32:
                scores_f = scores.float()
            else:
                scores_f = scores
            logZ = torch.logsumexp(scores_f, dim=-1, keepdim=True)  # Bx1
            log_p_t = scores_f[:, t:t+1] - logZ                     # Bx1
            p_t = log_p_t.exp().clamp(self.eps, 1.0 - self.eps)     # Bx1
            alpha_eff = ((1.0 - lam) * p_t) + (lam * self.alpha)
            alpha_eff = alpha_eff.clamp(self.eps, 1.0 - self.eps)   # Bx1

            # 4) 计算两种约束的最小抬升量
            #   margin: δ_m = max(0, γ_λ - (s_t - m))
            tmp = scores.clone()
            tmp[:, t] = float("-inf")
            max_others = tmp.max(dim=-1, keepdim=True).values  # Bx1
            delta_m = (max_others - scores[:, t:t+1] + gamma_eff).clamp_min(0.0)

            #   prob: δ_p = log( α_eff(1-p) / (p(1-α_eff)) ), 若为负则置0
            delta_p = torch.log(alpha_eff * (1.0 - p_t) / (p_t * (1.0 - alpha_eff)))
            delta_p = delta_p.clamp_min(0.0)

            # 5) 同时满足两者 => 取最大；并裁剪 max_bias
            need = torch.maximum(delta_m, delta_p).clamp_max(self.max_bias)

            # 6) 可选兜底：确保贪心复制（极小的硬边际）
            if self.ensure_copy:
                delta_safe = (max_others - scores[:, t:t+1] + self.gamma_safe).clamp_min(0.0)
                need = torch.maximum(need, delta_safe)

            scores[:, t] += need.squeeze(-1)

        elif self.finish_with_eos:
            scores[:] = float("-inf")
            scores[:, self.eos_token_id] = 0.0

        return scores

# class HybridKLProjectionEnforcer(LogitsProcessor):
#     """
#     同时支持 'margin' 与 'prob' 约束，并通过 λ∈[0,1] 平滑过渡：
#       - λ=0: 仅边际约束 s_t' - max_{j≠t} s_j' ≥ γ（硬复制更稳）
#       - λ=1: 仅概率约束 q_t(δ) > max(p_others)（目标概率略大于其它 token）
#       - 0<λ<1: 同时满足 弱化的边际 γ_λ 与 强化的概率 α_λ
#     可选 ensure_copy=True 以极小安全边际兜底，保证贪心解码严格复制。
#     """
#     def __init__(
#         self,
#         ref_ids: List[int],
#         start_len: int,
#         eos_token_id: int,
#         # 目标参数
#         gamma: float = 2.0,       # 纯margin时的目标logit边际
#         # 修改：使用增量来确保目标token的概率比当前最大概率多出一定的增量
#         alpha: float = 0.1,  # 增量：目标token概率比最大概率多出的值
#         # 混合与调度:
#         lambda_start: float = 0.0,
#         lambda_end: float = 1.0,
#         schedule: str = "linear",   # "constant" | "linear"（按步数从 start→end）
#         # 数值与安全
#         max_bias: float = 50.0,
#         eps: float = 1e-12,
#         compute_in_fp32: bool = False,
#         finish_with_eos: bool = True,
#         ensure_copy: bool = False,      # 兜底保证复制
#         gamma_safe: float = 1e-6,       # 兜底的极小边际
#     ):
#         self.ref_ids = [int(t) for t in ref_ids]
#         self.start_len = int(start_len)
#         self.eos_token_id = int(eos_token_id)
#         # 目标
#         self.gamma = float(gamma)
#         self.alpha = float(alpha)
#         # 混合调度
#         self.lambda_start = float(lambda_start)
#         self.lambda_end = float(lambda_end)
#         assert 0.0 <= self.lambda_start <= 1.0 and 0.0 <= self.lambda_end <= 1.0
#         assert schedule in ("constant", "linear")
#         self.schedule = schedule
#         # 数值
#         self.max_bias = float(max_bias)
#         self.eps = float(eps)
#         self.compute_in_fp32 = bool(compute_in_fp32)
#         self.finish_with_eos = bool(finish_with_eos)
#         # 兜底复制
#         self.ensure_copy = bool(ensure_copy)
#         self.gamma_safe = float(gamma_safe)

#     def _lambda_at(self, step: int, total_steps: int) -> float:
#         if self.schedule == "constant" or total_steps <= 1:
#             return self.lambda_end  # 恒定
#         # 线性从 start -> end
#         ratio = step / (total_steps - 1)
#         return self.lambda_start + (self.lambda_end - self.lambda_start) * ratio

#     def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
#         step = input_ids.shape[-1] - self.start_len
#         L = len(self.ref_ids)

#         if step < L:
#             t = self.ref_ids[step]
#             # 1) 当前步的混合系数 λ
#             lam = self._lambda_at(step, L)  # in [0,1]

#             # 2) 边际目标弱化：γ_λ = (1-λ)*γ
#             gamma_eff = (1.0 - lam) * self.gamma

#             # 3) 概率目标：目标 token 的概率比当前最大概率多出的增量
#             if self.compute_in_fp32 and scores.dtype != torch.float32:
#                 scores_f = scores.float()
#             else:
#                 scores_f = scores

#             logZ = torch.logsumexp(scores_f, dim=-1, keepdim=True)  # Bx1
#             raw_probs = torch.softmax(scores_f, dim=-1)  # BxV
#             max_other_probs, _ = raw_probs.max(dim=-1, keepdim=True)  # Bx1: 最大概率

#             # 目标token概率略高于当前最大概率
#             target_prob = max_other_probs + self.alpha
#             target_prob = target_prob.clamp(self.eps, 1.0 - self.eps)  # 保证不超出[0, 1]

#             # 计算目标token的logit需要增加的偏移量
#             log_target_prob = target_prob.log()
#             delta_p = log_target_prob - scores_f[:, t:t+1]

#             # 4) 计算边际约束：δ_m = max(0, γ_λ - (s_t - m))
#             tmp = scores.clone()
#             tmp[:, t] = float("-inf")
#             max_others = tmp.max(dim=-1, keepdim=True).values  # Bx1
#             delta_m = (max_others - scores[:, t:t+1] + gamma_eff).clamp_min(0.0)

#             # 5) 同时满足两者 => 取最大；并裁剪 max_bias
#             need = torch.maximum(delta_m, delta_p).clamp_max(self.max_bias)

#             # 6) 可选兜底：确保贪心复制（极小的硬边际）
#             if self.ensure_copy:
#                 delta_safe = (max_others - scores[:, t:t+1] + self.gamma_safe).clamp_min(0.0)
#                 need = torch.maximum(need, delta_safe)

#             scores[:, t] += need.squeeze(-1)

#         elif self.finish_with_eos:
#             scores[:] = float("-inf")
#             scores[:, self.eos_token_id] = 0.0

#         return scores


class ReferenceBias(LogitsProcessor):
    """
    固定偏置软约束：对参考下一 token 加 +bias，不屏蔽其它 token。
    bias=12~20 常能达到 99%+ 一致；比 Margin 版更简单。
    """
    def __init__(self, ref_ids, start_len, eos_token_id, bias=12.0, finish_with_eos=True):
        self.ref_ids = [int(t) for t in ref_ids]
        self.start_len = int(start_len)
        self.eos_token_id = int(eos_token_id)
        self.bias = float(bias)
        self.finish_with_eos = bool(finish_with_eos)
    def __call__(self, input_ids, scores):
        step = input_ids.shape[-1] - self.start_len
        if step < len(self.ref_ids):
            scores[:, self.ref_ids[step]] += self.bias
        elif self.finish_with_eos:
            scores[:] = float("-inf")
            scores[:, self.eos_token_id] = 0.0
        return scores

class HardClampToReference(LogitsProcessor):
    """
    硬夹紧（可选）：每步只允许参考下一 token；复制完只允许 eos。
    用于 100% 一致的极端情形；与 Watermark 同用时建议把它放到处理器链的“最后”。
    """
    def __init__(self, ref_ids, start_len, eos_token_id):
        self.ref_ids = [int(t) for t in ref_ids]
        self.start_len = int(start_len)
        self.eos_token_id = int(eos_token_id)
    def __call__(self, input_ids, scores):
        step = input_ids.shape[-1] - self.start_len
        scores[:] = float("-inf")
        if step < len(self.ref_ids):
            scores[:, self.ref_ids[step]] = 0.0
        else:
            scores[:, self.eos_token_id] = 0.0
        return scores


########################################################
# 3) HuggingFace 模型引擎（通用，可换任意 CausalLM）
########################################################

class HFModelEngine:
    """
    统一封装 HuggingFace CausalLM：
      - 自动处理 pad_token / attention_mask
      - 单卡最稳（device_map=None）；分片 (device_map="auto") 时自动把输入放到嵌入层设备
      - 提供带 logits_processor 的确定性 generate 接口
    """
    def __init__(
        self,
        model_name: str,
        device: Optional[str] = None,
        fp16: bool = True,
        device_map: Optional[str] = None,   # None: 单卡; "auto": 分片
        revision: Optional[str] = None,
        trust_remote_code: bool = True,
        use_auth_token: bool = True,
        max_context: int = 8192,
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name, 
            revision=revision,
            trust_remote_code=trust_remote_code,
            use_auth_token=use_auth_token,
            truncation_side="left",
            padding_side="right",
        )
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        torch_dtype = torch.float16 if (fp16 and device == "cuda") else torch.float32

        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch_dtype,
            device_map=device_map,              # 建议先用 None
            trust_remote_code=trust_remote_code,
        )
        # 输入目标设备
        if hasattr(self.model, "hf_device_map") and device_map == "auto":
            wte_dev = self.model.hf_device_map.get("transformer.wte")
            self.input_device = torch.device(wte_dev if wte_dev is not None else list(self.model.hf_device_map.values())[0])
        else:
            self.model.to(device)
            self.input_device = next(self.model.parameters()).device

        self.max_context = max_context

    def tokenize_to_device(self, text: str):
        tok = self.tokenizer(text, return_tensors="pt", add_special_tokens=True)
        input_ids = tok["input_ids"].to(self.input_device)
        attention_mask = tok.get("attention_mask", torch.ones_like(input_ids)).to(self.input_device)
        return input_ids, attention_mask

    def ids_from_text(self, text: str) -> List[int]:
        return self.tokenizer(text, add_special_tokens=False, return_tensors="pt").input_ids[0].tolist()

    def generate_with_processors(
        self,
        input_ids: torch.LongTensor,
        attention_mask: torch.LongTensor,
        processors: LogitsProcessorList,
        max_new_tokens: int,
        eos_token_id: Optional[int] = None,
        pad_token_id: Optional[int] = None,
    ) -> torch.LongTensor:
        if eos_token_id is None:
            eos_token_id = self.tokenizer.eos_token_id
        if pad_token_id is None:
            pad_token_id = self.tokenizer.pad_token_id

        out = self.model.generate(
            input_ids=input_ids,
            attention_mask=attention_mask,
            max_new_tokens=max_new_tokens,  # 生成的最大 token 数量
            do_sample=True,                 # 启用采样
            temperature=0.2,                # 设置温度
            top_p=0.95,                     # 使用 top_p (nucleus sampling)
            num_beams=1,                    # 使用贪心解码
            use_cache=True,                 # 使用缓存
            eos_token_id=eos_token_id,      # 结束 token id
            pad_token_id=pad_token_id,      # 填充 token id
            logits_processor=processors     # 添加 logits processor 进行约束
        )
        return out


########################################################
# 4) RAG 编排：检索 + 软约束/硬夹紧 + （可选）水印
########################################################

class RagConstrainedGenerator:
    """
    编排器：给定 retriever + HF 模型引擎
      1) 使用 retriever(query) 召回 reference
      2) 构造软约束/硬夹紧 LogitsProcessor（可叠加 watermark_processor）
      3) 调用 HF 引擎 generate
    """
    def __init__(self, engine: HFModelEngine, retriever: Retriever):
        self.engine = engine
        self.retriever = retriever

    def _check_context(self, start_len: int, ref_len: int):
        total = start_len + ref_len + 1  # +1 for EOS
        if total > self.engine.max_context:
            raise ValueError(f"上下文超限: input({start_len}) + gen({ref_len}+1) = {total} > {self.engine.max_context}")

    def generate(
        self,
        prompt: str,
        prefix: str,
        top_k: int = 1,
        constraint: str = "adaptive",    # 'adaptive' | 'fixed' | 'hard'
        gamma: float = 2.5,
        alpha: float = 0.1,
        lambda_start: float = 0.0,
        lambda_end: float = 1.0,
        schedule: str = "linear",   # "constant" | "linear"
        max_bias: float = 50.0,
        eps: float = 1e-12,
        compute_in_fp32: bool = False,
        finish_with_eos: bool = True,
        ensure_copy: bool = False,
        gamma_safe: float = 1e-6,
        fixed_bias: float = 12.0,
        watermark_processor: Optional[LogitsProcessor] = None,
        system_prompt: str = "Output exactly the following code. Begin now.\n",
    ) -> Dict[str, Any]:
        # 1) RAG 检索
        hits = self.retriever.retrieve((prompt or "") + "\n" + (prefix or ""), top_k=top_k)
        if not hits:
            raise RuntimeError("RAG 未检索到参考代码。")
        best = hits[0]
        ref_text = best["reference"]

        # 2) 准备输入
        input_ids, attention_mask = self.engine.tokenize_to_device(system_prompt)
        start_len = input_ids.shape[-1]
        ref_ids = self.engine.ids_from_text(ref_text)
        self._check_context(start_len, len(ref_ids))

        # 3) 处理器链（顺序：约束 → 水印）
        processors = LogitsProcessorList()

        # 根据 constraint 类型选择不同的约束策略
        if constraint == "adaptive":
            processors.append(HybridKLProjectionEnforcer(
                ref_ids=ref_ids,
                start_len=start_len,
                eos_token_id=self.engine.tokenizer.eos_token_id,
                gamma=gamma,
                alpha=alpha,
                lambda_start=lambda_start,
                lambda_end=lambda_end,
                schedule=schedule,
                max_bias=max_bias,
                eps=eps,
                compute_in_fp32=compute_in_fp32,
                finish_with_eos=finish_with_eos,
                ensure_copy=ensure_copy,
                gamma_safe=gamma_safe,
            ))
        elif constraint == "fixed":
            processors.append(ReferenceBias(
                ref_ids=ref_ids,
                start_len=start_len,
                eos_token_id=self.engine.tokenizer.eos_token_id,
                bias=fixed_bias,
                finish_with_eos=finish_with_eos
            ))
        elif constraint == "hard":
            processors.append(HardClampToReference(
                ref_ids=ref_ids,
                start_len=start_len,
                eos_token_id=self.engine.tokenizer.eos_token_id
            ))
        else:
            raise ValueError("constraint 需为 'adaptive' | 'fixed' | 'hard'")
        
        if watermark_processor is not None:
            processors.append(watermark_processor)

        # 4) 解码过程：传递处理器链和生成参数
        out = self.engine.generate_with_processors(
            input_ids=input_ids,
            attention_mask=attention_mask,
            processors=processors,
            max_new_tokens=len(ref_ids) + 1
        )
        gen_ids = out[0][start_len:]
        text = self.engine.tokenizer.decode(gen_ids, skip_special_tokens=True)

        exact_match = (text == ref_text) or text.endswith(ref_text)
        return {
            # "text": ref_text if not exact_match else text,  # 保险回落
            "text": text,
            "exact_match": bool(exact_match),
            "ref_len_tokens": len(ref_ids),
            "route": f"rag+{constraint}",
            "rag_meta": best
        }
