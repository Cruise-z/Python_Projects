# server.py
# pip install "transformers>=4.41" fastapi uvicorn pydantic torch accelerate
import time
import asyncio
from typing import Any, Dict, List, Optional, Union, Callable
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, PrivateAttr
import torch
import copy
import json
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from transformers import (
    AutoModelForCausalLM, AutoTokenizer,
    LogitsProcessorList, TopPLogitsWarper, TopKLogitsWarper, TemperatureLogitsWarper,
    LogitsProcessor
)
from transformers.generation.stopping_criteria import (
    StoppingCriteriaList, MaxLengthCriteria
)

# ================= 配置项(是否开启采样/双路同配置) =================
import os
# SERVER_DO_SAMPLE: "1"/"true" 开启采样；"0"/"false" 走贪心。默认开启。
def _as_bool(x: str) -> bool:
    return str(x).strip().lower() not in ("0", "false", "no", "off", "")
SERVER_DO_SAMPLE = _as_bool(os.getenv("SERVER_DO_SAMPLE", "1"))
# SAMPLING_MODE: "lenient_openai" | "map_to_greedy" | "strict"
# 详见 normalize_sampling_args() 说明。默认 "lenient_openai"。
def _as_mode(x: str) -> str:
    """把字符串归一化到 {'lenient_openai','map_to_greedy','strict'} 三者之一。"""
    s = str(x or "").strip().lower().replace("-", "_")
    if s in ("lenient_openai", "lenient", "openai", "lo"):
        return "lenient_openai"
    if s in ("map_to_greedy", "map2greedy", "to_greedy", "greedy_map", "mg"):
        return "map_to_greedy"
    if s in ("strict", "error", "raise", "s"):
        return "strict"
    # 不认识就回退到宽松模式
    return "lenient_openai"
SAMPLING_MODE = _as_mode(os.getenv("SAMPLING_MODE", "lenient_openai"))

# 是否强制在并行模式下提供 external_processor_names（避免“两路同配置”的误用）
REQUIRE_EXTERNAL_IN_PARALLEL = _as_bool(os.getenv("REQUIRE_EXTERNAL_IN_PARALLEL", "0"))

# ====== 原始请求体打印控制（默认关闭，按需开启）======
# LOG_REQ_BODY=1 开启打印；LOG_REQ_BODY_BYTES 控制最多打印多少原始字节
LOG_REQ_BODY = _as_bool(os.getenv("LOG_REQ_BODY", "0"))
LOG_REQ_BODY_BYTES = int(os.getenv("LOG_REQ_BODY_BYTES", "4096"))

# ================= 模型加载（默认不启用任何内置水印） =================
MODEL_ID = "Qwen/Qwen2.5-Coder-32B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID, torch_dtype=torch.bfloat16, device_map="cuda"
)
model.eval()
# === 生成前的 tokenizer/model 配置兜底：避免 pad 缺失导致的警告或越界 ===
try:
    if tokenizer.pad_token_id is None and tokenizer.eos_token_id is not None:
        tokenizer.pad_token_id = tokenizer.eos_token_id
    if getattr(model, "config", None) is not None:
        cfg = model.config
        if getattr(cfg, "pad_token_id", None) is None and tokenizer.pad_token_id is not None:
            cfg.pad_token_id = tokenizer.pad_token_id
        if getattr(cfg, "eos_token_id", None) is None and tokenizer.eos_token_id is not None:
            cfg.eos_token_id = tokenizer.eos_token_id
except Exception:
    # 兜底不应影响主流程，静默即可
    pass

# 供你的处理器构造使用的词表（与本服务 tokenizer 完全一致）
vocab_ids: List[int] = list(tokenizer.get_vocab().values())

# ================= 处理器注册表 & 注册函数 =================
# 你可以按自己的喜好把“HF内置水印/你自定义的水印”注册到任意一侧
# 注册**工厂函数**，在请求解析阶段再实例化，避免跨请求共享可变状态
ProcessorFactory = Callable[[], LogitsProcessorList]
INTERNAL_PROCESSORS: Dict[str, ProcessorFactory] = {}
EXTERNAL_PROCESSORS: Dict[str, ProcessorFactory] = {} # 保留类型与 API，但解析时将不再使用

# ===== 纯 builder 化：外置处理器通过可参数化 builder 动态实例化 =====
ParametricBuilder = Callable[..., Any]
EXTERNAL_BUILDERS: Dict[str, ParametricBuilder] = {}

def register_external_builder(name: str, builder: ParametricBuilder) -> None:
    """
    注册可参数化的外置处理器 builder。请求端可通过 external_processor_params[name]
    传参；这里会强制覆盖 vocab=vocab_ids，忽略来路 vocab。
    """
    if not callable(builder):
        raise TypeError(f"external builder for '{name}' must be callable")
    EXTERNAL_BUILDERS[name] = builder

def _ensure_lp_list(p) -> LogitsProcessorList:
    """
    将对象规范化为 LogitsProcessorList，并做强类型校验：
      - 禁止 None
      - 允许：单个 LogitsProcessor、LogitsProcessorList、list/tuple[LogitsProcessor]
    """
    if p is None:
        raise TypeError("LogitsProcessor is None (expected LogitsProcessor or LogitsProcessorList).")
    if isinstance(p, LogitsProcessorList):
        for it in p:
            if not isinstance(it, LogitsProcessor):
                raise TypeError(f"Invalid item in LogitsProcessorList: {type(it)}")
        return p
    if isinstance(p, LogitsProcessor):
        return LogitsProcessorList([p])
    if isinstance(p, (list, tuple)):
        if not all(isinstance(it, LogitsProcessor) for it in p):
            bad = [type(it) for it in p if not isinstance(it, LogitsProcessor)]
            raise TypeError(f"Invalid items in processor list: {bad}")
        return LogitsProcessorList(list(p))
    raise TypeError(f"Expected LogitsProcessor/LogitsProcessorList/list[LogitsProcessor], got {type(p)}")

def _as_factory(factory_or_obj: Any) -> ProcessorFactory:
    """
    统一转为“无参工厂函数”：
      1) 若是处理器实例（即使可调用，也当实例对待）→ 每次返回克隆；
      2) 否则若是可调用的 0 参工厂 → 调用并做强校验；
    """
    # ✅ 优先处理实例（LogitsProcessor / LogitsProcessorList / list/tuple[LogitsProcessor]）
    if isinstance(factory_or_obj, (LogitsProcessor, LogitsProcessorList, list, tuple)):
        inst_lp = _ensure_lp_list(factory_or_obj)
        def _factory_from_instance() -> LogitsProcessorList:
            return _clone_lp_list(inst_lp)
        return _factory_from_instance
    # ✅ 其次才把“可调用对象”视作 0 参工厂
    if callable(factory_or_obj):
        def _factory_from_callable() -> LogitsProcessorList:
            prod = factory_or_obj()
            return _ensure_lp_list(prod)
        return _factory_from_callable
    raise TypeError(
        f"register_* expects a LogitsProcessor/LogitsProcessorList/list[LogitsProcessor] "
        f"or a zero-arg factory that returns one, got {type(factory_or_obj)}"
    )

def register_internal(name: str, factory_or_obj: Any) -> None:
    """注册到“内置处理器列表”命名空间（以工厂的形式存储）。"""
    INTERNAL_PROCESSORS[name] = _as_factory(factory_or_obj)

def register_external(name: str, factory_or_obj: Any) -> None:
    """
    兼容函数：保留以防老代码调用，但解析阶段不再使用 EXTERNAL_PROCESSORS。
    如继续调用，本函数只做注册，不参与生成路径。
    """
    EXTERNAL_PROCESSORS[name] = _as_factory(factory_or_obj)

def _clone_lp_list(lp: LogitsProcessorList) -> LogitsProcessorList:
    """
    为每次请求克隆一份处理器实例，避免跨请求/双路共享内部状态导致串扰。
    deepcopy 失败则回退到原对象（尽量不阻断）。
    """
    new = []
    for p in lp:
        try:
            new.append(copy.deepcopy(p))
        except Exception:
            new.append(p)
    return LogitsProcessorList(new)

def _resolve_lp_list(
    internal_names: Optional[List[str]],
    external_names: Optional[List[str]],
    mode: str,  # "internal_only" | "internal_plus_external" | "any"
    *,
    external_params: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[LogitsProcessorList]:
    """按名称把多个处理器拼成一个 LogitsProcessorList，保持你传入的顺序。
       约定：并行模式下内置先于外置；单路模式下也遵循“先内置、后外置”的顺序。
    """
    chain: List[Any] = []

    if internal_names:
        for n in internal_names:
            if n not in INTERNAL_PROCESSORS:
                raise HTTPException(status_code=400, detail=f"Unknown internal processor: {n}")
            # 实例化工厂 -> 得到当次请求的独立处理器链
            try:
                lp = INTERNAL_PROCESSORS[n]()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Internal processor '{n}' factory error: {e}") from e
            # 逐项强类型校验
            for it in lp:
                if not isinstance(it, LogitsProcessor):
                    raise HTTPException(status_code=400, detail=f"Internal processor '{n}' produced invalid item: {type(it)}")
            chain.extend(lp)

    if mode != "internal_only" and external_names:
        for n in external_names:
            if n not in EXTERNAL_BUILDERS:
                # 纯 builder 化：未注册 builder 直接报错
                raise HTTPException(status_code=400, detail=f"Unknown external builder: {n}")
            # 从请求取参数并强制覆盖 vocab
            cfg = dict((external_params or {}).get(n) or {})
            cfg.pop("vocab", None)
            try:
                obj = EXTERNAL_BUILDERS[n](vocab=vocab_ids, **cfg)
                lp = _ensure_lp_list(obj)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"External builder '{n}' error: {e}") from e
            for it in lp:
                if not isinstance(it, LogitsProcessor):
                    raise HTTPException(status_code=400, detail=f"External builder '{n}' produced invalid item: {type(it)}")
            chain.extend(lp)

    if not chain:
        return None
    return LogitsProcessorList(chain)

# ===== 在此处插入：自动加载 uiAPI（可选）=====
try:
    import importlib, sys, os
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    importlib.import_module("regWM")  # 其中应在顶层调用 register_xxx 完成注册
    print("[server] processors loaded ->",
          "internal:", list(INTERNAL_PROCESSORS.keys()),
          "external_builders:", list(EXTERNAL_BUILDERS.keys()))
except Exception as e:
    print(f"[server] regWM not loaded: {e}")

# ================== OpenAI 兼容请求/响应模型 ==================
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: Optional[str] = MODEL_ID
    messages: List[Message]
    temperature: Optional[float] = 0.7
    top_p: Optional[float] = 0.95
    max_tokens: Optional[int] = 512
    stream: Optional[bool] = False  # 本示例不做流式
    # 可选：固定本次请求的随机种子（保证跨运行复现），不传也可耦合
    rng_seed: Optional[int] = None

    # 你关心的接口（都为“列表”）——名字需先在注册表里注册好
    internal_processor_names: Optional[List[str]] = None
    external_processor_names: Optional[List[str]] = None

    # 并行开关：True 时返回两路结果（仅内置）与（内置+外置）
    parallel: Optional[bool] = False
    # 仅对 external 生效：按名称传 builder 参数
    external_processor_params: Optional[Dict[str, Dict[str, Any]]] = None
    
    # —— 隐藏开关：不出现在 schema，客户端也传不进来 —— #
    _do_sample: bool = PrivateAttr(default=SERVER_DO_SAMPLE)

# 归一处理传入参数
def normalize_sampling_args(do_sample: bool,
                            temperature: Optional[float],
                            top_p: Optional[float],
                            mode: str = SAMPLING_MODE):
    """
    mode:
      - "lenient_openai": do_sample=True 且 temp<=0 → temp=1e-4；do_sample=False → temp=1.0, top_p=1.0
      - "map_to_greedy":  do_sample=True 且 temp<=0 → do_sample=False（转贪心）
      - "strict":         do_sample=True 且 temp<=0 → raise ValueError
    """
    if not do_sample:
        return False, 1.0, 1.0

    t = 1.0 if temperature is None else float(temperature)
    p = 1.0 if top_p is None else float(top_p)

    if t <= 0:
        if mode == "lenient_openai":
            t = 1e-4
        elif mode == "map_to_greedy":
            return False, 1.0, 1.0
        else:  # "strict"
            raise ValueError("temperature must be > 0 when do_sample=True")

    # 约束 top_p ∈ (0,1]
    if not (0 < p <= 1.0):
        p = 1.0

    return True, t, p

app = FastAPI()

# ====== 简单请求体大小日志中间件（仅在特定路由启用）======
logger = logging.getLogger("server")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

class LogReqSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 需要统计的路径可按需增减
        if request.url.path in ("/v1/chat/completions", "/dbg/echo-len"):
            try:
                body = await request.body()          # Starlette 会缓存，后续可重复读取
                size = len(body or b"")
                cl = request.headers.get("content-length")
                # 尝试解析 parallel 字段，便于并行压测时定位
                parallel = None
                try:
                    data = json.loads(body.decode("utf-8"))
                    parallel = data.get("parallel", None)
                except Exception:
                    pass
                logger.info("[recv] bytes=%s content-length=%s path=%s parallel=%s",
                            size, cl, request.url.path, parallel)
                # 可选：打印请求体内容（受限于 LOG_REQ_BODY / LOG_REQ_BODY_BYTES）
                if LOG_REQ_BODY:
                    preview = body[:LOG_REQ_BODY_BYTES]
                    # 优先尝试 JSON pretty-print；失败则按文本打印
                    printed = None
                    try:
                        parsed = json.loads(preview.decode("utf-8", "replace"))
                        printed = json.dumps(parsed, ensure_ascii=False, indent=2)
                    except Exception:
                        printed = preview.decode("utf-8", "replace")
                    # 标注预览与总大小，避免误解为完整 body
                    logger.info(
                        "[recv] body_preview(%d/%dB): %s",
                        len(preview), size, printed
                    )
            except Exception as e:
                logger.warning("[recv] failed to read body: %r", e)
        return await call_next(request)

app.add_middleware(LogReqSizeMiddleware)

@app.get("/v1/_processors")
def list_processors():
    """调试端点：查看当前已注册的处理器名称。"""
    return {
        "internal": list(INTERNAL_PROCESSORS.keys()),
        "external": list(EXTERNAL_PROCESSORS.keys()),     # 保留兼容展示
        "external_builders": list(EXTERNAL_BUILDERS.keys())
    }
    
@app.get("/v1/models")
def list_models():
    """OpenAI 兼容：列出单个可用模型。"""
    return {"object": "list", "data": [{"id": MODEL_ID, "object": "model"}]}

# ====== 调试端点：返回请求体长度 ======
@app.post("/dbg/echo-len")
async def dbg_echo_len(request: Request):
    try:
        body = await request.body()
        cl = request.headers.get("content-length")
        return {"len": len(body or b""), "content_length": cl}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"echo_len_error: {e}")

def _model_ctx_limit() -> Optional[int]:
    """
    推断模型支持的最大上下文长度（tokens）。不同模型/配置字段命名不同，这里做兼容兜底，
    若存在 rope_scaling（如 Llama/Qwen 的扩展）则按 factor 估算有效上限。
    返回 None 表示无法可靠推断。
    """
    cfg = getattr(model, "config", None)
    if cfg is None:
        return None
    base = None
    for name in ("max_position_embeddings", "max_seq_len", "max_sequence_length", "n_positions", "seq_length"):
        v = getattr(cfg, name, None)
        if isinstance(v, int) and v > 0:
            base = int(v)
            break
    if base is None:
        v = getattr(cfg, "max_length", None)
        base = int(v) if isinstance(v, int) and v > 0 else None
    if base is None:
        return None
    # rope_scaling 推断（若存在）
    try:
        rs = getattr(cfg, "rope_scaling", None)
        if isinstance(rs, dict):
            factor = rs.get("factor") or rs.get("rope_factor")
            if factor:
                base = int(base * float(factor))
    except Exception:
        pass
    return base

def _cap_max_new_tokens(prompt_len: int, want_new: Optional[int]) -> int:
    ctx = _model_ctx_limit()
    safe = int(want_new or 0)
    return max(0, min(safe, (ctx - prompt_len) if isinstance(ctx, int) else safe))

@app.get("/healthz")
def healthz():
    """简单健康检查：可用于 LB 探活。"""
    return {"status": "ok", "model": MODEL_ID}

def _is_cache_obj(pkv) -> bool:
    """
    判断是否为 transformers 新式 Cache 对象（例如 StaticCache/DynamicCache）。
    这类对象通常具备 get_seq_length()/get_max_capacity 等方法。
    """
    if pkv is None:
        return False
    cls_name = pkv.__class__.__name__.lower()
    return hasattr(pkv, "get_seq_length") or cls_name.endswith("cache")
    
def _prefill_and_expand_kv(input_ids: torch.Tensor,
                           attn: torch.Tensor,
                           times: int = 2):
    """
    先做一次 batch=1 的 prefill，尝试把 past_key_values 沿 batch 维复制为多路；
    如果复制失败（例如遇到新式 Cache 抽象或非张量结构），
    则回退到 batch=times 的 prefill（多算一次 prompt，但确保兼容性）。
    返回：(pkv_batched, last_logits_batched[times, vocab], used_fallback: bool)
    """
    prefill = model(input_ids=input_ids, attention_mask=attn, use_cache=True)
    pkv = prefill.past_key_values
    last_logits_1 = prefill.logits[:, -1, :]  # [1, vocab]
    # 新式 Cache：不要复制，直接回退到 batch=times 的 prefill（稳定且与模型期望一致）
    if _is_cache_obj(pkv):
        ids2 = input_ids.repeat(times, 1).contiguous()
        attn2 = attn.repeat(times, 1).contiguous()
        prefill2 = model(input_ids=ids2, attention_mask=attn2, use_cache=True)
        pkv2 = prefill2.past_key_values
        last_logits_batched = prefill2.logits[:, -1, :]  # [times, vocab]
        return pkv2, last_logits_batched, True

    # 旧式 tuple/list：尝试复制 KV 的 batch 维
    try:
        pkv_batched = _repeat_pkv(pkv, times=times)
        last_logits_batched = last_logits_1.repeat(times, 1)
        return pkv_batched, last_logits_batched, False
    except Exception:
        # 最终兜底：直接做 batch=times 的 prefill
        pass

    # 兜底
    ids2 = input_ids.repeat(times, 1).contiguous()
    attn2 = attn.repeat(times, 1).contiguous()
    prefill2 = model(input_ids=ids2, attention_mask=attn2, use_cache=True)
    pkv2 = prefill2.past_key_values
    last_logits_batched = prefill2.logits[:, -1, :]  # [times, vocab]
    return pkv2, last_logits_batched, True

def _repeat_pkv(pkv, times: int = 2):
    """
    将单路 past_key_values 沿 batch 维复制为多路。
    兼容大多数 HF 模型的 pkv 结构：tuple[layer] -> tuple[tensor...]
    """
    if pkv is None:
        return None
    # 仅允许对旧式 tuple/list 结构复制；新式 Cache 直接抛错，触发回退逻辑
    if not isinstance(pkv, (tuple, list)):
        raise TypeError(f"repeat_pkv expects legacy tuple/list, got {type(pkv)}")
    rep_layers = []
    # 某些实现返回 list；统一按可迭代层处理
    for layer in pkv:  # type: ignore[assignment]
        if not isinstance(layer, (tuple, list)):
            raise TypeError("unexpected PKV layer type; expected tuple/list of tensors")
        rep_tensors = []
        for t in layer:
            rep_tensors.append(torch.repeat_interleave(t, repeats=times, dim=0) if torch.is_tensor(t) else t)
        rep_layers.append(tuple(rep_tensors))
    return tuple(rep_layers)

def _prep_inputs(messages: List[Dict[str, str]]) -> Dict[str, torch.Tensor]:
    chat_text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    return tokenizer([chat_text], return_tensors="pt").to(model.device)

def _safe_get_logits_processor(gen_cfg, prompt_len: int) -> LogitsProcessorList:
    """
    兼容获取 HF 的 logits_processor；若模型无对应私有方法则回退为空列表。
    """
    try:
        return model._get_logits_processor(
            generation_config=gen_cfg,
            input_ids_seq_length=prompt_len,
            encoder_input_ids=None,
            prefix_allowed_tokens_fn=None,
            logits_processor=None,
        )
    except Exception:
        return LogitsProcessorList([])

def _safe_get_logits_warper(gen_cfg) -> LogitsProcessorList:
    """
    兼容获取 HF 的 warpers；若模型无对应私有方法则根据 temperature / top_p 手动构建。
    """
    try:
        return model._get_logits_warper(gen_cfg)
    except Exception:
        warpers = LogitsProcessorList([])
        if getattr(gen_cfg, "do_sample", False):
            # temperature
            temp = float(getattr(gen_cfg, "temperature", 1.0) or 1.0)
            if abs(temp - 1.0) > 1e-6:
                warpers.append(TemperatureLogitsWarper(temp))
            # top_p
            tp = float(getattr(gen_cfg, "top_p", 1.0) or 1.0)
            if 0.0 < tp < 1.0:
                warpers.append(TopPLogitsWarper(tp))
            # 如需支持 top_k，可在此按需追加 TopKLogitsWarper
        return warpers

def _safe_get_stopping_criteria(gen_cfg) -> StoppingCriteriaList:
    """
    兼容获取 HF 的 stopping_criteria；若模型无对应私有方法则返回空列表。
    """
    try:
        return model._get_stopping_criteria(gen_cfg, None)
    except Exception:
        return StoppingCriteriaList([])
    
def _stopping_met(stopping_criteria: StoppingCriteriaList,
                  input_ids: torch.Tensor,
                  scores: Optional[torch.Tensor] = None) -> bool:
    """
    统一把 StoppingCriteriaList 的返回结果转为 bool。
    - 标准实现返回 bool；
    - 若某些自定义 criterion 返回 shape=[B] 的 BoolTensor，则归并 any()；
    - 其它可布尔化对象用 bool()。
    出错时安全地视为未触发停止。
    """
    try:
        out = stopping_criteria(input_ids, scores)
        if isinstance(out, bool):
            return out
        if torch.is_tensor(out):
            # 兼容形状既可能是 0-d 也可能是 1-d（batch 维）
            return bool(out.any().item())
        return bool(out)
    except Exception:
        return False

@torch.inference_mode()
def _build_hf_components(
    prompt_len: int,
    do_sample: bool,
    temperature: Optional[float],
    top_p: Optional[float],
    max_new_tokens: int,
) -> tuple:
    """
    复用 HF 生成子模块：根据归一化后的 sampling 配置构造
    - hf_logits_processor：HF 自带的处理器（如 no_repeat_ngram/repetition_penalty/…）
    - hf_warpers：HF 自带的 warpers（temperature/top_p/top_k/…）
    - stopping_criteria：HF 停止准则（补齐 MaxLengthCriteria(prompt_len+max_new_tokens)）
    """
    # clone 一份，避免污染全局 config
    gen_cfg = copy.deepcopy(model.generation_config)
    gen_cfg.do_sample = bool(do_sample)
    if temperature is not None:
        gen_cfg.temperature = float(temperature)
    if top_p is not None:
        gen_cfg.top_p = float(top_p)
    # 让 stopping criteria 能拿到 max_length 语义（以 max_new_tokens 推导）
    # 注：HF 内部通常把 max_new_tokens 与当前长度合成 max_length；此处显式补齐。
    max_len = int(prompt_len + max_new_tokens) if max_new_tokens and max_new_tokens > 0 else int(prompt_len)

    # 注意：HF 的私有方法在部分模型上可能不存在，这里做安全回退
    hf_lp = _safe_get_logits_processor(gen_cfg, prompt_len)
    hf_warpers = _safe_get_logits_warper(gen_cfg)
    stopping_criteria = _safe_get_stopping_criteria(gen_cfg)
    # 若未包含 MaxLengthCriteria，则补齐一条（以 prompt_len+max_new_tokens 为上限）
    has_maxlen = any(isinstance(c, MaxLengthCriteria) for c in stopping_criteria)
    if not has_maxlen:
        stopping_criteria.append(MaxLengthCriteria(max_length=max_len))
    return gen_cfg, hf_lp, hf_warpers, stopping_criteria

@torch.inference_mode()
def _gen_internal_like_parallel(
    inputs: Dict[str, torch.Tensor],
    lp_internal: Optional[LogitsProcessorList],
    temperature: float,
    top_p: float,
    max_new_tokens: int,
    do_sample: bool = SERVER_DO_SAMPLE,
    rng_seed: Optional[int] = None,
) -> tuple[str, int, int, int]:
    """
    单路生成但**完全对齐**并行里的“internal-only”分路：
      - 共享相同的 HF 子模块（hf_logits_processor + hf_warpers）
      - 步进/终止与并行相同（增量一步一步 forward）
      - 采样使用与并行一致的 U(0,1) CDF 取样（通过“自耦合”）
    """
    device = next(model.parameters()).device
    input_ids = inputs["input_ids"].to(device)  # [1, L]
    attn = inputs.get("attention_mask", None)
    if attn is None:
        attn = torch.ones_like(input_ids, dtype=torch.long, device=device)
    else:
        attn = attn.to(device)

    prompt_len = int(input_ids.shape[1])
    try:
        want = int(max_new_tokens or 0)
    except Exception:
        want = 0
    max_new_tokens = _cap_max_new_tokens(prompt_len, want)
    if max_new_tokens <= 0:
        return "", prompt_len, 0, prompt_len

    # 归一化采样参数，并据此构造 HF 子模块
    do_sample, temperature, top_p = normalize_sampling_args(do_sample, temperature, top_p)
    _, hf_lp, hf_warpers, stopping_criteria = _build_hf_components(
        prompt_len, do_sample, temperature, top_p, max_new_tokens
    )
    lp0_full = LogitsProcessorList(list(hf_lp) + list(lp_internal or []))

    # 共享随机源（与并行一致的种子推导）
    gen = None
    if do_sample:
        gen = torch.Generator(device=device)
        seed = int(torch.sum(input_ids).item() % (2**31 - 1)) if rng_seed is None else int(rng_seed)
        gen.manual_seed(seed)

    # 预填充
    pkv, last_logits_b1, _ = _prefill_and_expand_kv(input_ids, attn, times=1)
    cur_ids = input_ids.clone()
    cur_attn = attn.clone()

    # 终止 token
    eos_token_id = model.generation_config.eos_token_id
    eos_ids: List[int] = []
    if isinstance(eos_token_id, int) and eos_token_id >= 0:
        eos_ids = [eos_token_id]
    elif isinstance(eos_token_id, (list, tuple)):
        eos_ids = [int(x) for x in eos_token_id if x is not None]

    finished = False
    comp_tok = 0

    def _apply(proc: Optional[LogitsProcessorList], ids_ctx: torch.Tensor, scores: torch.Tensor) -> torch.Tensor:
        if proc is not None:
            scores = proc(ids_ctx, scores)
        return scores

    # 首步：利用 prefill 的最后时刻 logits
    scores0 = _apply(lp0_full, cur_ids, last_logits_b1)  # [1,V]
    if do_sample and len(hf_warpers):
        scores0 = hf_warpers(cur_ids, scores0)
    # 自耦合采样（保证与并行 internal-only 完全一致的取样分布/数值路径）
    tok0, _ = _coupled_pick_from_scores(scores0, scores0, do_sample, generator=gen)
    comp_tok += 1
    if eos_ids and int(tok0.item()) in eos_ids:
        finished = True
    cur_ids = torch.cat([cur_ids, tok0], dim=1)
    cur_attn = torch.cat([cur_attn, torch.ones((1,1), dtype=cur_attn.dtype, device=device)], dim=1)
    # HF 停止准则（长度等）检查
    if stopping_criteria(cur_ids, None):
        finished = True

    steps = 1
    while steps < max_new_tokens:
        if finished:
            break
        step_in = cur_ids[:, -1:].contiguous()
        outputs = model(
            input_ids=step_in,
            attention_mask=cur_attn,
            past_key_values=pkv,
            use_cache=True
        )
        pkv = outputs.past_key_values
        logits = outputs.logits[:, -1, :]  # [1,V]
        scores0 = _apply(lp0_full, cur_ids, logits)
        if do_sample and len(hf_warpers):
            scores0 = hf_warpers(cur_ids, scores0)
        tok0, _ = _coupled_pick_from_scores(scores0, scores0, do_sample, generator=gen)
        comp_tok += 1
        if eos_ids and int(tok0.item()) in eos_ids:
            finished = True
        cur_ids = torch.cat([cur_ids, tok0], dim=1)
        cur_attn = torch.cat([cur_attn, torch.ones((1,1), dtype=cur_attn.dtype, device=device)], dim=1)
        # HF 停止准则（长度等）检查
        if stopping_criteria(cur_ids, None):
            finished = True
        steps += 1

    text = tokenizer.batch_decode(cur_ids[:, prompt_len:], skip_special_tokens=True)[0]
    prompt_tok = int(inputs["input_ids"].shape[1])
    total_tok = prompt_tok + comp_tok
    return text, prompt_tok, comp_tok, total_tok

@torch.inference_mode()
def _coupled_pick_from_scores(
    scores0: torch.Tensor, scores1: torch.Tensor, do_sample: bool, *,
    generator: Optional[torch.Generator] = None
) -> tuple[torch.Tensor, torch.Tensor]:
    """
    使用“共享随机数”的耦合采样：
      - do_sample=False ：两路均 argmax（完全一致的确定性规则）
      - do_sample=True  ：采一个共同的 u~U(0,1)，
                          分别在各自的概率分布 CDF 上用同一个 u 取样
    输入形状：scoresX [1, vocab]，返回 token id 形状均为 [1,1]
    """
    if not do_sample:
        tok0 = scores0.argmax(dim=-1, keepdim=True)
        tok1 = scores1.argmax(dim=-1, keepdim=True)
        return tok0, tok1
    # softmax -> 概率；注意 float32 计算稳定性
    p0 = torch.softmax(scores0, dim=-1).to(torch.float32)  # [1,V]
    p1 = torch.softmax(scores1, dim=-1).to(torch.float32)  # [1,V]
    # 共享随机数 u
    if generator is None:
        u = torch.rand((), device=scores0.device)
    else:
        u = torch.rand((), device=scores0.device, generator=generator)
    # 数值安全：防止极端情况下 u==1 命中越界
    eps = torch.finfo(p0.dtype).eps
    u = torch.clamp(u, eps, 1 - eps)
    # CDF 搜索
    cdf0 = p0.cumsum(dim=-1).squeeze(0)  # [V]
    cdf1 = p1.cumsum(dim=-1).squeeze(0)  # [V]
    # 边界保护：极端数值下 cdf 末尾可能 < 1，searchsorted 可能返回 V
    i0 = torch.searchsorted(cdf0, u).clamp(max=cdf0.numel() - 1).long().item()
    i1 = torch.searchsorted(cdf1, u).clamp(max=cdf1.numel() - 1).long().item()
    return (torch.tensor([[i0]], device=scores0.device, dtype=torch.long),
            torch.tensor([[i1]], device=scores1.device, dtype=torch.long))

@torch.inference_mode()
def _dual_sync_generate_internal_base(
    inputs: Dict[str, torch.Tensor],
    lp_internal: Optional[LogitsProcessorList],   # 仅“内置”链
    lp_external: Optional[LogitsProcessorList],   # 仅“外置”链（可 None）
    temperature: float,
    top_p: float,
    max_new_tokens: int,
    eos_token_id: Optional[Union[int, List[int]]] = None,
    min_new_tokens: int = 0,
    do_sample: bool = SERVER_DO_SAMPLE,           # 新增，默认用全局
    rng_seed: Optional[int] = None,
) -> tuple[str, str, int, int, int, List[bool]]:
    """
    同步分叉并行（以内置处理后的分布作为基准），并避免对 prompt 的重复前向：
    - 每步只做一次前向，得到 logits；
    - scores_internal = 内置处理器链(logits) 作为“基准分布”；
      * internal_only 分支：在 scores_internal 上采样；
      * internal_plus_external 分支：在 scores_internal.clone() 上再应用“外置链”后采样。
    - 两路各自推进各自序列（batch=2，共享 KV cache）。
    返回：(text_internal_only, text_internal_plus_external, prompt_tok, completion_tok_sum, total_tok, finished[List[bool]])
    """
    device = next(model.parameters()).device
    input_ids = inputs["input_ids"].to(device)  # [1, L]
    attn = inputs.get("attention_mask", None)
    if attn is None:
        attn = torch.ones_like(input_ids, dtype=torch.long, device=device)
    else:
        attn = attn.to(device)
        
    # === 在进入生成循环前，根据模型上下文上限裁剪 max_new_tokens，避免越界 ===
    prompt_len = int(input_ids.shape[1])
    try:
        want = int(max_new_tokens or 0)
    except Exception:
        want = 0
    max_new_tokens = _cap_max_new_tokens(prompt_len, want)
    if max_new_tokens <= 0:
        return "", "", prompt_len, 0, prompt_len, [False, False]

    # ====== 预填充阶段（prefill）：优先尝试 KV 复制，失败则回退到 batch=2 prefill ======
    pkv, last_logits_b2, _used_fallback = _prefill_and_expand_kv(input_ids, attn, times=2)

    # 两路各自保持独立序列，但首步避免重复跑 prompt
    cur_ids = input_ids.repeat(2, 1).contiguous()   # [2, L]
    cur_attn = attn.repeat(2, 1).contiguous()       # [2, L]

    # 归一化采样参数 + 复用 HF 子模块
    do_sample, temperature, top_p = normalize_sampling_args(do_sample, temperature, top_p)
    _, hf_lp, hf_warpers, stopping_criteria = _build_hf_components(
        prompt_len, do_sample, temperature, top_p, max_new_tokens
    )
    # 拼接两路的处理器链：
    # 路0（internal-only）：HF 内置 + 你的内置
    lp0_full = LogitsProcessorList(list(hf_lp) + list(lp_internal or []))
    # 路1（internal+external）：在 lp0_full 基础上 + 你的外置
    lp1_full = LogitsProcessorList(list(lp0_full) + list(lp_external or []))

    # 共享随机数发生器（仅用于“耦合采样”）
    gen = None
    if do_sample:
        gen = torch.Generator(device=device)
        if rng_seed is None:
            # 默认：基于输入构造一个稳定种子（同一 prompt 可复现）
            # 注意：不泄露用户内容，仅用 token id 做简单 hash
            seed = int(torch.sum(input_ids).item() % (2**31 - 1))
        else:
            seed = int(rng_seed)
        gen.manual_seed(seed)
    
    # 终止 token
    if eos_token_id is None:
        eos_token_id = model.generation_config.eos_token_id
    eos_ids: List[int] = []
    if isinstance(eos_token_id, int) and eos_token_id >= 0:
        eos_ids = [eos_token_id]
    elif isinstance(eos_token_id, (list, tuple)):
        eos_ids = [int(x) for x in eos_token_id if x is not None]

    finished = [False, False]
    # 每路精确的“有效生成 token 计数”（不含对齐复制）
    comp_tok_each = [0, 0]
    new_steps = 0  # 步数（两路对齐的步数）

    def _apply(proc: Optional[LogitsProcessorList], ids_ctx: torch.Tensor, scores: torch.Tensor) -> torch.Tensor:
        # ids_ctx: [1, seq], scores: [1, vocab]
        if proc is not None:
            scores = proc(ids_ctx, scores)
        return scores

    # ====== 首步生成（就地对照：内置 vs. 内置+外置；耦合采样）=====
    logits_b2 = last_logits_b2  # [2, vocab]
    base0 = _apply(lp0_full, cur_ids[0:1, :], logits_b2[0:1, :])  # [1, vocab]
    base1 = _apply(lp1_full, cur_ids[1:2, :], logits_b2[1:2, :])  # [1, vocab]
    # 路0：internal_only
    scores0 = base0.clone()
    # 路1：internal_plus_external
    scores1 = base1.clone()
    # 统一 warper（复用 HF warpers）
    if do_sample and len(hf_warpers):
        scores0 = hf_warpers(cur_ids[0:1, :], scores0)
        scores1 = hf_warpers(cur_ids[1:2, :], scores1)
    # ——耦合采样（共享同一个 u）——
    tok0, tok1 = _coupled_pick_from_scores(scores0, scores1, do_sample, generator=gen)
    # 计数与终止
    comp_tok_each[0] += (not finished[0])
    comp_tok_each[1] += (not finished[1])
    if eos_ids and int(tok0.item()) in eos_ids:
        finished[0] = True
    if eos_ids and int(tok1.item()) in eos_ids:
        finished[1] = True

    # 拼接与对齐
    next_ids = torch.cat([tok0, tok1], dim=0)  # [2,1]
    cur_ids = torch.cat([cur_ids, next_ids], dim=1)
    cur_attn = torch.cat([cur_attn, torch.ones((2, 1), dtype=cur_attn.dtype, device=device)], dim=1)
    new_steps = 1
    # HF 停止准则（长度等）检查
    if stopping_criteria(cur_ids, None):
        # 若长度到上限则直接退出；finish_reason 将在返回时按 finished[] 与长度判断设置
        texts = tokenizer.batch_decode(cur_ids[:, prompt_len:], skip_special_tokens=True)
        prompt_tok = int(inputs["input_ids"].shape[1])
        comp_tok_sum = int(comp_tok_each[0] + comp_tok_each[1])
        total_tok = prompt_tok + comp_tok_sum
        return texts[0], texts[1], prompt_tok, comp_tok_sum, total_tok, finished

    # ====== 后续增量解码：每步仅以最新 token 做一次 batch=2 前向 ======
    while new_steps < max_new_tokens:
        # 终止判定（满足 min_new_tokens 后两路均结束才退出）
        if all(finished) and new_steps >= min_new_tokens:
            break

        step_in = cur_ids[:, -1:].contiguous()  # [2,1]
        outputs = model(
            input_ids=step_in,
            attention_mask=cur_attn,
            past_key_values=pkv,
            use_cache=True
        )
        pkv = outputs.past_key_values
        logits = outputs.logits[:, -1, :]   # [2, vocab]

        # 对“每一路各自的上下文”计算这一时刻的“内置基准分布”
        base0 = _apply(lp0_full, cur_ids[0:1, :], logits[0:1, :])   # [1, vocab]
        base1 = _apply(lp1_full, cur_ids[1:2, :], logits[1:2, :])   # [1, vocab]

        active0 = not finished[0]
        active1 = not finished[1]

        scores0 = None
        scores1 = None
        if active0:
            scores0 = base0.clone()
            if do_sample and len(hf_warpers):
                scores0 = hf_warpers(cur_ids[0:1, :], scores0)
        if active1:
            scores1 = base1.clone()
            if do_sample and len(hf_warpers):
                scores1 = hf_warpers(cur_ids[1:2, :], scores1)

        # 统一决策：四种情形
        if active0 and active1:
            tok0, tok1 = _coupled_pick_from_scores(scores0, scores1, do_sample, generator=gen)
        elif active0 and (not active1):
            # 仅路0继续：用“自耦合”取样，路1冻结
            tok0, _ = _coupled_pick_from_scores(scores0, scores0, do_sample, generator=gen)
            tok1 = cur_ids[1:2, -1:].clone()
        elif (not active0) and active1:
            # 仅路1继续：用“自耦合”取样，路0冻结
            tok1, _ = _coupled_pick_from_scores(scores1, scores1, do_sample, generator=gen)
            tok0 = cur_ids[0:1, -1:].clone()
        else:
            # 两路都已结束：保持最后一个 token（用于对齐拼接）
            tok0 = cur_ids[0:1, -1:].clone()
            tok1 = cur_ids[1:2, -1:].clone()

        # 记录有效生成 token 与终止
        if active0:
            comp_tok_each[0] += 1
            if eos_ids and int(tok0.item()) in eos_ids:
                finished[0] = True
        if active1:
            comp_tok_each[1] += 1
            if eos_ids and int(tok1.item()) in eos_ids:
                finished[1] = True

        # 拼接
        next_ids = torch.cat([tok0, tok1], dim=0)  # [2,1]
        cur_ids = torch.cat([cur_ids, next_ids], dim=1)
        cur_attn = torch.cat([cur_attn, torch.ones((2,1), dtype=cur_attn.dtype, device=device)], dim=1)

        new_steps += 1
        # HF 停止准则（长度等）检查
        if stopping_criteria(cur_ids, None):
            break


    texts = tokenizer.batch_decode(cur_ids[:, prompt_len:], skip_special_tokens=True)
    # 计算token数
    prompt_tok = int(inputs["input_ids"].shape[1])
    comp_tok_sum = int(comp_tok_each[0] + comp_tok_each[1])  # 并行两路各自有效 completion token 的“和”
    total_tok = prompt_tok + comp_tok_sum
    
    return texts[0], texts[1], prompt_tok, comp_tok_sum, total_tok, finished

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest) -> Dict[str, Any]:
    print(f"[recv] at {time.time():.3f} messages={len(req.messages)} parallel={req.parallel}")
    import sys; sys.stdout.flush()
    # 基本校验：messages 不可为空
    if not req.messages:
        raise HTTPException(status_code=422, detail="messages must not be empty")
    msgs = [m.model_dump() for m in req.messages]
    inputs = _prep_inputs(msgs)
    # 额外校验：prompt 不应超过上下文上限（超过直接 400）
    try:
        prompt_len = int(inputs["input_ids"].shape[1])
    except Exception:
        prompt_len = 0
    ctx_lim = _model_ctx_limit()
    if isinstance(ctx_lim, int) and prompt_len > ctx_lim:
        raise HTTPException(status_code=400, detail=f"prompt_too_long: {prompt_len}>{ctx_lim}")

    # 并行：两路（仅内置）与（内置+外置）
    if req.parallel:
        # 可选校验：并行时是否必须提供 external 链（通过环境变量控制）
        if REQUIRE_EXTERNAL_IN_PARALLEL and not req.external_processor_names:
            raise HTTPException(status_code=400, detail="parallel=True 需要提供 external_processor_names 列表（可通过环境变量 REQUIRE_EXTERNAL_IN_PARALLEL=0 关闭此限制）")

        # 组装“仅内置链”（作为基准）与“仅外置链”（追加在基准之上）
        lp_internal = _resolve_lp_list(
            internal_names=req.internal_processor_names,
            external_names=None,
            mode="internal_only"
        )
        lp_external = _resolve_lp_list(   # 只拿“外置”链；允许 None
            internal_names=None,
            external_names=req.external_processor_names,
            mode="any",
            external_params=req.external_processor_params
        )

        try:
            # 放入线程池避免阻塞事件循环；并显式处理 CUDA OOM
            text_internal, text_both, prompt_tok, comp_tok_sum, total_tok, finished = await asyncio.to_thread(
                _dual_sync_generate_internal_base,
                inputs,
                lp_internal,
                lp_external,
                req.temperature,
                req.top_p,
                req.max_tokens,
                model.generation_config.eos_token_id,
                0,
                do_sample=req._do_sample,
                rng_seed=req.rng_seed,
            )
        except torch.cuda.OutOfMemoryError as e:
            try:
                torch.cuda.empty_cache()
            except Exception:
                pass
            raise HTTPException(status_code=503, detail="generation_error: cuda_oom") from e
        except Exception as e:
            # 统一转换为 500，避免栈追踪暴露
            raise HTTPException(status_code=500, detail=f"generation_error: {e.__class__.__name__}: {e}") from e
        
        # 逐路精确设置 finish_reason：到达 EOS => "stop"；达到长度上限 => "length"
        fr_internal = "stop" if finished[0] else "length"
        fr_both = "stop" if finished[1] else "length"

        return {
            "id": f"chatcmpl-{int(time.time()*1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text_internal},
                    "finish_reason": fr_internal,
                    "variant": "internal_only"
                },
                {
                    "index": 1,
                    "message": {"role": "assistant", "content": text_both},
                    "finish_reason": fr_both,
                    "variant": "internal_plus_external"
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tok,
                "completion_tokens": comp_tok_sum,
                "total_tokens": total_tok
            }
        }

    # 非并行：按你给的列表统一拼接（可只内置、只外置、或内外兼容）
    # 为了保证“单路 == 并行 internal-only 路径”，这里仅拼接 **你的内置链**，并复用 HF 子模块，
    # 不直接调用 model.generate。
    lp_internal_only = _resolve_lp_list(
        internal_names=req.internal_processor_names,
        external_names=None,
        mode="internal_only",
    )
    try:
        text, prompt_tok, comp_tok, total_tok = await asyncio.to_thread(
            _gen_internal_like_parallel,
            inputs,
            lp_internal_only,
            req.temperature,
            req.top_p,
            req.max_tokens,
            do_sample=req._do_sample,
            rng_seed=req.rng_seed,
        )
    except torch.cuda.OutOfMemoryError as e:
        try:
            torch.cuda.empty_cache()
        except Exception:
            pass
        raise HTTPException(status_code=503, detail="generation_error: cuda_oom") from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"generation_error: {e.__class__.__name__}: {e}") from e
    # 更准确的 finish_reason：与裁剪后的 max_new_tokens 比较
    try:
        prompt_len = int(inputs["input_ids"].shape[1])
        want = int(req.max_tokens or 0)
    except Exception:
        prompt_len, want = int(inputs["input_ids"].shape[1]), 0
    capped = _cap_max_new_tokens(prompt_len, want)
    # comp_tok == capped → 达到长度上限，否则视为正常停止
    fr = "length" if capped > 0 and comp_tok >= capped else "stop"
    return {
        "id": f"chatcmpl-{int(time.time()*1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": fr}
        ],
        "usage": {
            "prompt_tokens": prompt_tok,
            "completion_tokens": comp_tok,
            "total_tokens": total_tok
        }
    }

# 启动(开启采样): `uvicorn server:app --host 0.0.0.0 --port 8000`
# 启动(关闭采样): `SERVER_DO_SAMPLE=0 uvicorn server:app --host 0.0.0.0 --port 8000`
# 前置可选参数：
##SAMPLING_MODE=lenient_openai | map_to_greedy | strict
# 详见 normalize_sampling_args() 说明。默认 lenient_openai。
# 注意：如果你用的是“strict”模式，
# 那么请求体里传入 temperature<=0 时会报错。  
##SERVER_DO_SAMPLE=0 | 1 | false | true
# 该参数决定默认的采样模式，默认开启采样（true）。
# 你也可以在请求体里针对每次请求单独指定是否采样。