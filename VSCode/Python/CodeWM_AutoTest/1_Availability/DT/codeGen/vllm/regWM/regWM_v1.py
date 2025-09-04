# regWM/regWM_v1.py  (或你的实际路径)
from typing import Any, Dict, List, Optional, Union
import importlib, inspect, torch, json
from vllm.v1.sample.logits_processor.interface import LogitsProcessor

# 你原有的工具函数保持不变：_load_obj/_merge_kwargs/_call_with_known_kwargs/_derive_wm_mask
# ---------------- 省略：这些函数沿用你现有实现 ----------------

def _maybe_json(obj):
    """
    若 obj 是 JSON 字符串，则尝试 json.loads；否则原样返回。
    兼容 bytes/bytearray。
    """
    if isinstance(obj, (bytes, bytearray)):
        try:
            obj = obj.decode("utf-8", "ignore")
        except Exception:
            return obj
    if isinstance(obj, str):
        try:
            return json.loads(obj)
        except Exception:
            return obj
    return obj

class DualRouteWatermarkProcessor(LogitsProcessor):
    """
    V1 版自定义处理器：
    - 构造函数签名必须为 __init__(vllm_config, device, is_pin_memory, **kwargs)
    - 外部子处理器实现 & 参数不再走 CLI，而是从每次请求的 extra_args 里拿：
        extra_args = {
          "wm": true/false 或 "wm_mask": [...],
          "special_token_ids": [...],           # 可选
          "dualroute": {                        # 建议包一层命名空间
            "apply_order": "wllm" | "sweet",
            "exclude_special": true/false,
            "shared_kwargs": {...},             # 可选，给两路公共参数
            "wllm_impl":  "regWM.libWM.watermark:WatermarkLogitsProcessor",
            "wllm_kwargs":{...},
            "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
            "sweet_kwargs":{...}
          }
        }
    """

    def __init__(self,
                 vllm_config,                 # ★ V1 必须
                 device: torch.device,        # ★ V1 必须
                 is_pin_memory: bool,         # ★ V1 必须
                 **kwargs):
        
        # ✅ V1 要求子类自管这三个参数，别调用 super().__init__
        self.vllm_config = vllm_config
        self.device = device
        self.is_pin_memory = is_pin_memory

        # 运行期会用到
        self.shared_kwargs: Dict[str, Any] = {}
        self.apply_order: str = "sweet"
        self.exclude_special: bool = True

        # 子处理器实例 / 延迟构造占位
        self.wllm = None
        self.sweet = None
        self._defer_wllm = None   # (qualname, kwargs)
        self._defer_sweet = None

        self._vocab_ids: Optional[List[int]] = None  # 首次拿到 logits 时构造
        # v1 的 sampler 调用 processor.apply(logits)，上下文通过 update_state 注入
        self._prev_tokens: Optional[torch.Tensor] = None
        self._prompt_tokens: Optional[torch.Tensor] = None
        self._extra_args: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None

    # --------- 从 extra_args 读取配置（仅在首次或尚未配置时） ---------
    def _ingest_config_from_extra(self, extra_args):
        # 允许 extra_args/dualroute/kwargs 写成 JSON 字符串
        extra_args = _maybe_json(extra_args)
        cfg = None
        if isinstance(extra_args, dict):
            cand = _maybe_json(extra_args.get("dualroute", extra_args))
            if isinstance(cand, dict):
                cfg = cand
        elif isinstance(extra_args, list):
            for d in extra_args:
                d = _maybe_json(d)
                if isinstance(d, dict) and ("dualroute" in d or "wllm_impl" in d or "sweet_impl" in d):
                    cand = _maybe_json(d.get("dualroute", d))
                    if isinstance(cand, dict):
                        cfg = cand
                        break
        
        if not isinstance(cfg, dict):
            return

        # 行为配置
        if "apply_order" in cfg:
            if cfg["apply_order"] in ("wllm", "sweet"):
                self.apply_order = cfg["apply_order"]
        if "exclude_special" in cfg:
            self.exclude_special = bool(cfg["exclude_special"])
        if "shared_kwargs" in cfg:
            sk = _maybe_json(cfg.get("shared_kwargs"))
            if isinstance(sk, dict):
                self.shared_kwargs.update(sk)

        # 延迟实例化的实现与参数
        if self.wllm is None and self._defer_wllm is None and "wllm_impl" in cfg:
            self._defer_wllm = (
                cfg["wllm_impl"],
                _maybe_json(cfg.get("wllm_kwargs")) or {}
            )
        if self.sweet is None and self._defer_sweet is None and "sweet_impl" in cfg:
            self._defer_sweet = (
                cfg["sweet_impl"],
                _maybe_json(cfg.get("sweet_kwargs")) or {}
            )

    # --------- 你原来的 vocab / special-token 处理保持不变 ---------
    def _build_vocab_from_logits(self, logits: torch.Tensor, extra_args) -> List[int]:
        V = int(logits.size(1))
        vocab = list(range(V))
        if not self.exclude_special:
            return vocab
        # 支持 special_token_ids 为 JSON 字符串 或 list
        special: List[int] = []
        extra_args = _maybe_json(extra_args)
        if isinstance(extra_args, dict):
            ids = _maybe_json(extra_args.get("special_token_ids", []))
            if isinstance(ids, (list, tuple)):
                special = [int(x) for x in ids]
        elif isinstance(extra_args, list):
            for d in extra_args:
                d = _maybe_json(d)
                if isinstance(d, dict) and "special_token_ids" in d:
                    ids = _maybe_json(d.get("special_token_ids"))
                    if isinstance(ids, (list, tuple)):
                        special.extend(int(x) for x in ids)
            if special:
                special = sorted(set(special))
        if special:
            banned = set(special)
            vocab = [i for i in vocab if i not in banned]
        return vocab

    def _maybe_deferred_init(self, logits: torch.Tensor, extra_args):
        # 先尝试从请求里拿配置
        self._ingest_config_from_extra(_maybe_json(extra_args))

        # 若仍未配置任何一路，就当 no-op 处理器使用
        if (self.wllm is None and self._defer_wllm is None and
            self.sweet is None and self._defer_sweet is None):
            return

        # 第一次看到 logits 时构造 vocab
        if self._vocab_ids is None:
            self._vocab_ids = self._build_vocab_from_logits(logits, extra_args)

        # 延迟实例化子处理器
        def _load_obj(qualname: str):
            if ":" in qualname:
                mod, name = qualname.split(":", 1)
            else:
                mod, name = qualname.rsplit(".", 1)
            module = importlib.import_module(mod)
            return getattr(module, name)

        def _merge_kwargs(base, extra):
            out = {}
            if base: out.update(base)
            if extra: out.update(extra)
            return out

        def _call_with_known_kwargs(fn, **kwargs):
            sig = inspect.signature(fn)
            accepted = {k: v for k, v in kwargs.items() if k in sig.parameters}
            return fn(**accepted)

        if self._defer_wllm is not None and self.wllm is None:
            qual, kwargs = self._defer_wllm
            Cls = _load_obj(qual)
            merged = _merge_kwargs(self.shared_kwargs, kwargs)
            merged.setdefault("vocab", self._vocab_ids)
            self.wllm = _call_with_known_kwargs(Cls, **merged)
            self._defer_wllm = None

        if self._defer_sweet is not None and self.sweet is None:
            qual, kwargs = self._defer_sweet
            Cls = _load_obj(qual)
            merged = _merge_kwargs(self.shared_kwargs, kwargs)
            merged.setdefault("vocab", self._vocab_ids)
            self.sweet = _call_with_known_kwargs(Cls, **merged)
            self._defer_sweet = None

    def _apply_chain(self, prev_row: torch.Tensor, logits_row: torch.Tensor) -> torch.Tensor:
        out = logits_row
        if self.apply_order == "wllm":
            if self.wllm is not None:
                out = self.wllm(prev_row, out)
        elif self.apply_order == "sweet":
            if self.sweet is not None:
                out = self.sweet(prev_row, out)
        else:
            return out
        return out

    # === vLLM V1 必需的 3 个接口 ===
    def update_state(self, state) -> None:
        """由 vLLM 在每步采样前调用，注入上下文。"""
        def _get(field, default=None):
            if isinstance(state, dict):
                return state.get(field, default)
            return getattr(state, field, default)
        self._prev_tokens = _get("prev_tokens")
        self._prompt_tokens = _get("prompt_tokens")
        # 这里也做一次 JSON 解析，保证 self._extra_args 始终为 Python 对象
        self._extra_args = _maybe_json(_get("extra_args"))

    @torch.inference_mode()
    def apply(self, logits: torch.Tensor) -> torch.Tensor:
        """vLLM sampler 只会传入 logits；其他上下文经 update_state 提前注入。"""
        # 先完成延迟配置/实例化
        self._maybe_deferred_init(logits, _maybe_json(self._extra_args))
        # 没有任何一路 => no-op
        if self.wllm is None and self.sweet is None:
            return logits
        # 没 prev_tokens 或形状异常 => 透传
        if self._prev_tokens is None or self._prev_tokens.size(0) != logits.size(0):
            return logits
        B = logits.size(0)
        # 计算掩码前再保守解析一次（兼容极端场景）
        wm_mask = _derive_wm_mask(_maybe_json(self._extra_args), B, logits.device)
        if not wm_mask.any():
            return logits
        idx = torch.nonzero(wm_mask, as_tuple=False).squeeze(-1).tolist()
        for i in idx:
            new_row = self._apply_chain(self._prev_tokens[i], logits[i])
            if new_row is not logits[i]:
                logits[i].copy_(new_row)
        return logits
    
    def is_argmax_invariant(self) -> bool:
        return False  # 会影响分布/argmax

    # 兼容 __call__（vLLM 不会用到，但便于单元测试）
    def __call__(self, logits: torch.Tensor):
        return self.apply(logits)
