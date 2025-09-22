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
    LogitsProcessorList,
    LogitsProcessor
)
from transformers.generation.stopping_criteria import (
    StoppingCriteriaList, MaxLengthCriteria
)
import threading

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

# 并行返回 usage 统计口径：1=每个 choice 单独统计（默认）；0=旧口径（合并统计）
USAGE_PER_CHOICE = _as_bool(os.getenv("USAGE_PER_CHOICE", "1"))

# 在不支持 `generator=` 的模型上启用回退；默认启用
ALLOW_GENERATOR_FALLBACK = _as_bool(os.getenv("ALLOW_GENERATOR_FALLBACK", "1"))

# RNG 种子策略（与上传文档建议保持一致）：默认不为未传 seed 派生种子，行为与 HF 一致；
# 如需兼容旧行为，可设 RNG_SEED_FALLBACK=derived
RNG_SEED_FALLBACK = os.getenv("RNG_SEED_FALLBACK", "none").strip().lower()

# （可选）极致确定性：设置 DETERMINISTIC=1 开启；会牺牲性能
if _as_bool(os.getenv("DETERMINISTIC", "0")):
    try:
        torch.use_deterministic_algorithms(True)
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":16:8")
        import torch.backends.cudnn as _cudnn
        _cudnn.benchmark = False
        _cudnn.deterministic = True
    except Exception as _e:
        print(f"[server] DETERMINISTIC setup failed: {_e}")

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
# 覆盖到外置 builder 的 vocab 参数：保证是 0..N-1 的连续 id
# 使用连续 id 列表，避免 dict.values() 顺序不定导致 builder 误用
vocab_ids: List[int] = list(range(len(tokenizer)))

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

_GLOBAL_RNG_LOCK = threading.Lock()

def _pick_seed(rng_seed: Optional[int], input_ids: torch.LongTensor) -> Optional[int]:
    """
    选择用于本次采样的种子：
      - 传入 rng_seed → 直接使用；
      - 否则按 RNG_SEED_FALLBACK：
          * 'derived' → 从 prompt 求和派生一个稳定 seed；
          * 其它 → 返回 None（与 HF 默认一致，不传 generator）
    """
    if rng_seed is not None:
        return int(rng_seed)
    if RNG_SEED_FALLBACK == "derived":
        return int(torch.sum(input_ids).item() % (2**31 - 1))
    return None

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

def _prep_inputs(messages: List[Dict[str, str]]) -> Dict[str, torch.Tensor]:
    chat_text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    return tokenizer([chat_text], return_tensors="pt")

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

def _safe_get_stopping_criteria(gen_cfg) -> StoppingCriteriaList:
    """
    兼容获取 HF 的 stopping_criteria；若模型无对应私有方法则返回空列表。
    """
    try:
        return model._get_stopping_criteria(gen_cfg, None)
    except Exception:
        return StoppingCriteriaList([])

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
    stopping_criteria = _safe_get_stopping_criteria(gen_cfg)
    # 若未包含 MaxLengthCriteria，则补齐一条（以 prompt_len+max_new_tokens 为上限）
    has_maxlen = any(isinstance(c, MaxLengthCriteria) for c in stopping_criteria)
    if not has_maxlen:
        stopping_criteria.append(MaxLengthCriteria(max_length=max_len))
    return gen_cfg, hf_lp, None, stopping_criteria  # warpers 由 HF 基于 kwargs 内部构建

def _count_new_and_reason(seqs: torch.LongTensor,
                          prompt_len: int,
                          capped: int,
                          eos_ids: List[int],
                          pad_id: Optional[int]) -> tuple[List[int], List[str]]:
    """
    逐样本统计生成长度与 finish_reason（'stop' | 'length'）
    - 'length': 达到 capped 上限
    - 'stop'  : 未达上限但已生成 EOS（或其它停止条件被 HF 提前触发）
    """
    B, T = seqs.shape
    new_lens, reasons = [], []
    for b in range(B):
        new_part = seqs[b, prompt_len:]
        # —— 优先以“首个 EOS 的位置（含 EOS）”为准，避免 pad==eos 少算 1 —— #
        new_len = None
        if eos_ids:  # 仅在确实有 EOS 定义时才做 isin 搜索
            eos_tensor = torch.tensor(eos_ids, device=new_part.device, dtype=new_part.dtype)
            # torch.isin: [T] vs [K] -> [T]
            eos_mask = torch.isin(new_part, eos_tensor)
            idx = torch.nonzero(eos_mask, as_tuple=False)
            if idx.numel() > 0:
                first_eos_pos = int(idx[0].item())  # 0-based
                new_len = first_eos_pos + 1         # 含 EOS
        if new_len is None:
            # 没遇到 EOS，退回“非 pad 计数”或全长
            if pad_id is not None:
                new_len = int((new_part != pad_id).sum().item())
            else:
                new_len = int(new_part.numel())
        # 判定 finish_reason
        if capped > 0 and new_len >= capped:
            reason = "length"
        else:
           reason = "stop"
        # 若未到上限，进一步看是否包含 EOS（仅用于信息判断，不改变结果）
        if reason != "length" and eos_ids:
            # 若确实含有 EOS，保持 'stop'；否则依然 'stop'（可能被其它准则截断）
            pass
        new_lens.append(new_len)
        reasons.append(reason)
    return new_lens, reasons

@torch.inference_mode()
def _hf_generate_single(inputs: Dict[str, torch.Tensor],
                        lp_internal: Optional[LogitsProcessorList],
                        temperature: float,
                        top_p: float,
                        max_new_tokens: int,
                        do_sample: bool,
                        rng_seed: Optional[int]) -> tuple[str, int, int, int, str]:
    device = next(model.parameters()).device
    input_ids = inputs["input_ids"].to(device)
    attn = inputs.get("attention_mask", None)
    if attn is None:
        attn = torch.ones_like(input_ids, dtype=torch.long, device=device)
    else:
        attn = attn.to(device=device, dtype=torch.long)
    prompt_len = int(input_ids.shape[1])
    capped = _cap_max_new_tokens(prompt_len, int(max_new_tokens or 0))
    if capped <= 0:
        # 若用户请求了正数但被上限裁剪为0，更符合语义的是返回 "length"
        reason = "length" if int(max_new_tokens or 0) > 0 else "stop"
        return "", prompt_len, 0, prompt_len, reason
    do_sample, temperature, top_p = normalize_sampling_args(do_sample, temperature, top_p)
    _, hf_lp, _, stopping_criteria = _build_hf_components(prompt_len, do_sample, temperature, top_p, capped)
    final_lp = LogitsProcessorList(list(hf_lp) + list(lp_internal or []))
    # 为本次调用创建“私有”随机数发生器；AB 两路用同一个 seed 即可复现且互不干扰
    # 优先尝试“私有 generator”路径；若目标模型不支持，则回退到全局 RNG + 互斥锁
    seed_to_use = _pick_seed(rng_seed, input_ids) if do_sample else None
    gen = None
    if do_sample and seed_to_use is not None:
        gen = torch.Generator(device=input_ids.device)
        gen.manual_seed(seed_to_use)

    def _call_generate_with(gen_arg):
        return model.generate(
            input_ids=input_ids,
            attention_mask=attn,
            do_sample=do_sample,
            temperature=temperature,
            top_p=top_p,
            max_new_tokens=capped,
            logits_processor=final_lp,
            stopping_criteria=stopping_criteria,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=model.generation_config.eos_token_id,
            generator=gen_arg,
            return_dict_in_generate=True,
        )

    try:
        out = _call_generate_with(gen)
    except Exception as e:
        msg = str(e)
        # 仅当确认为“generator 未被模型接受”且允许回退时，启用安全回退
        need_fallback = (
            ALLOW_GENERATOR_FALLBACK
            and do_sample
            and seed_to_use is not None
            # 更严格：必须同时包含两个核心提示词
            and ("not used by the model" in msg)
            and ("generator" in msg)
        )
        if not need_fallback:
            raise
        print("[server] generator not accepted by model; falling back to global RNG seeding")
        # 回退：全局 RNG 受互斥锁保护，避免并行线程互相干扰
        with _GLOBAL_RNG_LOCK:
            try:
                torch.manual_seed(seed_to_use)
                if torch.cuda.is_available():
                    torch.cuda.manual_seed_all(seed_to_use)
            except Exception:
                pass
            out = _call_generate_with(None)
    
    seqs = out.sequences  # [1, L+new]
    eos = model.generation_config.eos_token_id
    eos_ids = [eos] if isinstance(eos, int) else [int(x) for x in (eos or [])]
    new_lens, reasons = _count_new_and_reason(seqs, prompt_len, capped, eos_ids, tokenizer.pad_token_id)
    text = tokenizer.batch_decode(seqs[:, prompt_len:], skip_special_tokens=True)[0]
    comp = new_lens[0]
    total = prompt_len + comp
    return text, prompt_len, comp, total, reasons[0]

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

        # 组装两套“仅内置链”（相互独立的克隆）与一套“外置链”（可为空）
        lp_internal_for_internal = _resolve_lp_list(
            internal_names=req.internal_processor_names,
            external_names=None,
            mode="internal_only"
        )
        lp_internal_for_both = _resolve_lp_list(
            internal_names=req.internal_processor_names,
            external_names=None,
            mode="internal_only"
        )
        lp_external = _resolve_lp_list(
            internal_names=None,
            external_names=req.external_processor_names,
            mode="any",
            external_params=req.external_processor_params
        )

        # 合成“内置+外置”的处理器链（保持顺序：先内置，后外置）
        if lp_internal_for_both is None and lp_external is None:
            lp_both = None
        elif lp_internal_for_both is None:
            lp_both = lp_external
        elif lp_external is None:
            lp_both = lp_internal_for_both
        else:
            lp_both = LogitsProcessorList(list(lp_internal_for_both) + list(lp_external))

        # 用“同一个 seed”分别做两次独立 generate，确保差异只来自外置处理器
        try:
            text_internal, prompt_tok_0, comp_tok_0, total_tok_0, fr_internal = await asyncio.to_thread(
                _hf_generate_single,
                inputs,
                lp_internal_for_internal,
                req.temperature,
                req.top_p,
                req.max_tokens,
                req._do_sample,
                req.rng_seed,
            )
            text_both, prompt_tok_1, comp_tok_1, total_tok_1, fr_both = await asyncio.to_thread(
                _hf_generate_single,
                inputs,
                lp_both,
                req.temperature,
                req.top_p,
                req.max_tokens,
                req._do_sample,
                req.rng_seed,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad_sampling_args: {e}") from e
        except torch.cuda.OutOfMemoryError as e:
            try:
                torch.cuda.empty_cache()
            except Exception:
                pass
            raise HTTPException(status_code=503, detail="generation_error: cuda_oom") from e
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"generation_error: {e.__class__.__name__}: {e}") from e

        if USAGE_PER_CHOICE:
            # 新口径：每个 choice 自带 usage；并行模式下不再返回顶层 usage
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
                        "variant": "internal_only",
                        "usage": {
                            "prompt_tokens": int(prompt_tok_0),
                            "completion_tokens": int(comp_tok_0),
                            "total_tokens": int(total_tok_0),
                        },
                    },
                    {
                        "index": 1,
                        "message": {"role": "assistant", "content": text_both},
                        "finish_reason": fr_both,
                        "variant": "internal_plus_external",
                        "usage": {
                            "prompt_tokens": int(prompt_tok_1),
                            "completion_tokens": int(comp_tok_1),
                            "total_tokens": int(total_tok_1),
                        },
                    },
                ],
            }
        else:
            # 旧口径：合并统计（与之前行为完全一致）
            prompt_tok = int(prompt_tok_0)
            comp_tok_sum = int(comp_tok_0 + comp_tok_1)
            total_tok = int(prompt_tok + comp_tok_sum)
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

    # 非并行：使用纯 generate（batch=1），仅拼接 **你的内置链**（与并行 internal-only 对齐）
    lp_internal_only = _resolve_lp_list(
        internal_names=req.internal_processor_names,
        external_names=None,
        mode="internal_only",
    )
    try:
        text, prompt_tok, comp_tok, total_tok, fr = await asyncio.to_thread(
            _hf_generate_single,
            inputs,
            lp_internal_only,
            req.temperature,
            req.top_p,
            req.max_tokens,
            req._do_sample,
            req.rng_seed,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"bad_sampling_args: {e}") from e
    except torch.cuda.OutOfMemoryError as e:
        try:
            torch.cuda.empty_cache()
        except Exception:
            pass
        raise HTTPException(status_code=503, detail="generation_error: cuda_oom") from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"generation_error: {e.__class__.__name__}: {e}") from e
    # fr 已在 _hf_generate_single 内部给出
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