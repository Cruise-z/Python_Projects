# server.py
# pip install "transformers>=4.41" fastapi uvicorn pydantic torch accelerate
import time
import asyncio
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, PrivateAttr
import torch
import copy
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, LogitsProcessorList, TopPLogitsWarper, TemperatureLogitsWarper
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

# ================= 模型加载（默认不启用任何内置水印） =================
MODEL_ID = "Qwen/Qwen2.5-Coder-32B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID, torch_dtype=torch.bfloat16, device_map="cuda"
)
model.eval()

# 供你的处理器构造使用的词表（与本服务 tokenizer 完全一致）
vocab_ids: List[int] = list(tokenizer.get_vocab().values())

# ================= 处理器注册表 & 注册函数 =================
# 你可以按自己的喜好把“HF内置水印/你自定义的水印”注册到任意一侧
INTERNAL_PROCESSORS: Dict[str, LogitsProcessorList] = {}
EXTERNAL_PROCESSORS: Dict[str, LogitsProcessorList] = {}

def _ensure_lp_list(p) -> LogitsProcessorList:
    if isinstance(p, LogitsProcessorList):
        return p
    return LogitsProcessorList([p])

def register_internal(name: str, processor_obj: Any) -> None:
    """注册到“内置处理器列表”命名空间。"""
    INTERNAL_PROCESSORS[name] = _ensure_lp_list(processor_obj)

def register_external(name: str, processor_obj: Any) -> None:
    """注册到“外置处理器列表”命名空间。"""
    EXTERNAL_PROCESSORS[name] = _ensure_lp_list(processor_obj)

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
) -> Optional[LogitsProcessorList]:
    """按名称把多个处理器拼成一个 LogitsProcessorList，保持你传入的顺序。
       约定：并行模式下内置先于外置；单路模式下也遵循“先内置、后外置”的顺序。
    """
    chain: List[Any] = []

    if internal_names:
        for n in internal_names:
            if n not in INTERNAL_PROCESSORS:
                raise HTTPException(status_code=400, detail=f"Unknown internal processor: {n}")
            chain.extend(_clone_lp_list(INTERNAL_PROCESSORS[n]))

    if mode != "internal_only" and external_names:
        for n in external_names:
            if n not in EXTERNAL_PROCESSORS:
                raise HTTPException(status_code=400, detail=f"Unknown external processor: {n}")
            chain.extend(_clone_lp_list(EXTERNAL_PROCESSORS[n]))

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
          "external:", list(EXTERNAL_PROCESSORS.keys()))
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

    # 你关心的接口（都为“列表”）——名字需先在注册表里注册好
    internal_processor_names: Optional[List[str]] = None
    external_processor_names: Optional[List[str]] = None

    # 并行开关：True 时返回两路结果（仅内置）与（内置+外置）
    parallel: Optional[bool] = False
    
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

@app.get("/v1/_processors")
def list_processors():
    """调试端点：查看当前已注册的处理器名称。"""
    return {
        "internal": list(INTERNAL_PROCESSORS.keys()),
        "external": list(EXTERNAL_PROCESSORS.keys())
    }
    
def _is_cache_obj(pkv) -> bool:
    """
    判断是否为 transformers 新式 Cache 对象（例如 StaticCache/DynamicCache）。
    这类对象通常具备 get_seq_length()/get_max_capacity 等方法。
    """
    return hasattr(pkv, "get_seq_length") or pkv.__class__.__name__.lower().endswith("cache")
    
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

def _decode(outputs: torch.Tensor, prompt_len: int) -> str:
    return tokenizer.batch_decode(outputs[:, prompt_len:], skip_special_tokens=True)[0]

@torch.inference_mode()
def _gen_once(
    inputs: Dict[str, torch.Tensor],  
    temperature: float,
    top_p: float,
    max_tokens: int,
    logits_processor: Optional[LogitsProcessorList],
    do_sample: Optional[bool] = None,
) -> tuple[str, int, int, int]:
    _do_sample = SERVER_DO_SAMPLE if do_sample is None else bool(do_sample)
    # 归一化采样参数
    _do_sample, temperature, top_p = normalize_sampling_args(_do_sample, temperature, top_p)

    gen_kwargs = dict(
        do_sample=_do_sample,
        temperature=temperature,
        top_p=top_p,
        max_new_tokens=max_tokens,
        logits_processor=logits_processor,
    )

    out = model.generate(**inputs, **gen_kwargs)
    # 计算token数
    prompt_tok = int(inputs["input_ids"].shape[1])
    comp_tok = int(out.shape[1] - prompt_tok)
    total_tok = prompt_tok + comp_tok
    
    return _decode(out, inputs["input_ids"].shape[1]), prompt_tok, comp_tok, total_tok

@torch.inference_mode()
def _sample_from_scores(scores: torch.Tensor, do_sample: bool) -> torch.Tensor:
    """
    统一的安全采样：softmax 后转换为 float32，再 multinomial。
    在 do_sample=False 时走贪心。
    返回形状 [1,1] 的 token id。
    """
    if do_sample:
        probs = torch.softmax(scores, dim=-1).to(torch.float32)
        return torch.multinomial(probs, num_samples=1)
    return scores.argmax(dim=-1, keepdim=True)

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
) -> tuple[str, str, int, int, int]:
    """
    同步分叉并行（以内置处理后的分布作为基准），并避免对 prompt 的重复前向：
    - 每步只做一次前向，得到 logits；
    - scores_internal = 内置处理器链(logits) 作为“基准分布”；
      * internal_only 分支：在 scores_internal 上采样；
      * internal_plus_external 分支：在 scores_internal.clone() 上再应用“外置链”后采样。
    - 两路各自推进各自序列（batch=2，共享 KV cache）。
    返回：(text_internal_only, text_internal_plus_external, prompt_tok, completion_tok_sum, total_tok)
    """
    device = next(model.parameters()).device
    input_ids = inputs["input_ids"].to(device)  # [1, L]
    attn = inputs.get("attention_mask", None)
    if attn is None:
        attn = torch.ones_like(input_ids, dtype=torch.long, device=device)
    else:
        attn = attn.to(device)

    # ====== 早退：不生成任何新 token 的情况 ======
    if max_new_tokens <= 0:
        prompt_tok = int(input_ids.shape[1])
        return "", "", prompt_tok, 0, prompt_tok

    # ====== 预填充阶段（prefill）：优先尝试 KV 复制，失败则回退到 batch=2 prefill ======
    pkv, last_logits_b2, _used_fallback = _prefill_and_expand_kv(input_ids, attn, times=2)

    # 两路各自保持独立序列，但首步避免重复跑 prompt
    cur_ids = input_ids.repeat(2, 1).contiguous()   # [2, L]
    cur_attn = attn.repeat(2, 1).contiguous()       # [2, L]
    prompt_len = input_ids.shape[1]

    # 归一化采样参数
    do_sample, temperature, top_p = normalize_sampling_args(do_sample, temperature, top_p)
    # ====== 采样 warpers（温度 / top-p）=====
    warpers = LogitsProcessorList([])
    if do_sample:
        if temperature and abs(temperature - 1.0) > 1e-6:
            warpers.append(TemperatureLogitsWarper(temperature))
        if top_p and top_p < 1.0:
            warpers.append(TopPLogitsWarper(top_p))

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

    # ====== 首步生成：利用预填充得到的最后时刻 logits，避免重复跑 prompt ======
    logits_b2 = last_logits_b2  # [2, vocab]（两路首步上下文相同/或回退路径下的真实 batch=2 logits）
    base0 = _apply(lp_internal, cur_ids[0:1, :], logits_b2[0:1, :])  # [1, vocab]
    base1 = _apply(lp_internal, cur_ids[1:2, :], logits_b2[1:2, :])  # [1, vocab]

    # 路0：internal_only
    scores0 = base0.clone()
    if do_sample and len(warpers):
        scores0 = warpers(cur_ids[0:1, :], scores0)
    tok0 = _sample_from_scores(scores0, do_sample)
    if not finished[0]:
        comp_tok_each[0] += 1
    if eos_ids and int(tok0.item()) in eos_ids:
        finished[0] = True

    # 路1：internal_plus_external
    scores1 = base1.clone()
    if lp_external is not None:
        scores1 = _apply(lp_external, cur_ids[1:2, :], scores1)
    if do_sample and len(warpers):
        scores1 = warpers(cur_ids[1:2, :], scores1)
    tok1 = _sample_from_scores(scores1, do_sample)
    if not finished[1]:
        comp_tok_each[1] += 1
    if eos_ids and int(tok1.item()) in eos_ids:
        finished[1] = True

    # 拼接与对齐
    next_ids = torch.cat([tok0, tok1], dim=0)  # [2,1]
    cur_ids = torch.cat([cur_ids, next_ids], dim=1)
    cur_attn = torch.cat([cur_attn, torch.ones((2, 1), dtype=cur_attn.dtype, device=device)], dim=1)
    new_steps = 1

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
        base0 = _apply(lp_internal, cur_ids[0:1, :], logits[0:1, :])   # [1, vocab]
        base1 = _apply(lp_internal, cur_ids[1:2, :], logits[1:2, :])   # [1, vocab]

        # 在同一“基准分布”上，分别得到两路的最终分布
        # 路0（internal_only）：直接在 base_scores 上做 warper + 采样
        if finished[0]:
            tok0 = cur_ids[0:1, -1:].clone()  # 冻结，保持 [1,1]
        else:
            scores0 = base0.clone()
            if do_sample and len(warpers):
                scores0 = warpers(cur_ids[0:1, :], scores0)
            tok0 = _sample_from_scores(scores0, do_sample)  # [1,1]
            # 记录有效生成 token
            comp_tok_each[0] += 1
            # 采样/贪心后立刻判 EOS（不看 min_new_tokens）
            if eos_ids and int(tok0.item()) in eos_ids:
                finished[0] = True

        # 路1（internal_plus_external）：对“基准分布”再施加“外置链”，再 warper + 采样
        if finished[1]:
            tok1 = cur_ids[1:2, -1:].clone()  # 保持 [1,1]，与 tok0 对齐
        else:
            # 以“内置基准分布” base1 为起点
            scores1 = base1.clone()
            if lp_external is not None:
                scores1 = _apply(lp_external, cur_ids[1:2, :], scores1)
            if do_sample and len(warpers):
                scores1 = warpers(cur_ids[1:2, :], scores1)
            tok1 = _sample_from_scores(scores1, do_sample)  # [1,1]
            # 记录有效生成 token
            comp_tok_each[1] += 1
            # 采样/贪心后立刻判 EOS（不看 min_new_tokens）
            if eos_ids and int(tok1.item()) in eos_ids:
                finished[1] = True

        # 拼接
        next_ids = torch.cat([tok0, tok1], dim=0)  # [2,1]
        cur_ids = torch.cat([cur_ids, next_ids], dim=1)
        cur_attn = torch.cat([cur_attn, torch.ones((2,1), dtype=cur_attn.dtype, device=device)], dim=1)

        new_steps += 1

    texts = tokenizer.batch_decode(cur_ids[:, prompt_len:], skip_special_tokens=True)
    # 计算token数
    prompt_tok = int(inputs["input_ids"].shape[1])
    comp_tok_sum = int(comp_tok_each[0] + comp_tok_each[1])  # 仅计有效生成，不含对齐
    total_tok = prompt_tok + comp_tok_sum
    
    return texts[0], texts[1], prompt_tok, comp_tok_sum, total_tok

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest) -> Dict[str, Any]:
    msgs = [m.model_dump() for m in req.messages]
    inputs = _prep_inputs(msgs)

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
            mode="any"
        )

        # 可按需自定义 eos/min_new_tokens；这里用默认
        text_internal, text_both, prompt_tok, comp_tok_sum, total_tok = _dual_sync_generate_internal_base(
            inputs=inputs,
            lp_internal=lp_internal,
            lp_external=lp_external,
            do_sample=req._do_sample,
            temperature=req.temperature,
            top_p=req.top_p,
            max_new_tokens=req.max_tokens,
            eos_token_id=model.generation_config.eos_token_id,
            min_new_tokens=0
        )

        return {
            "id": f"chatcmpl-{int(time.time()*1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text_internal},
                    "finish_reason": "stop",
                    "variant": "internal_only"
                },
                {
                    "index": 1,
                    "message": {"role": "assistant", "content": text_both},
                    "finish_reason": "stop",
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
    lp_any = _resolve_lp_list(
        internal_names=req.internal_processor_names,
        external_names=req.external_processor_names,
        mode="any"
    )
    text, prompt_tok, comp_tok, total_tok = await asyncio.to_thread(
        _gen_once, inputs, req.temperature, req.top_p, req.max_tokens, lp_any, do_sample=req._do_sample
    )
    return {
        "id": f"chatcmpl-{int(time.time()*1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
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