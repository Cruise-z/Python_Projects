# server.py
# pip install "transformers>=4.41" fastapi uvicorn pydantic torch accelerate
import time
import asyncio
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, PrivateAttr
import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, LogitsProcessorList, TopPLogitsWarper, TemperatureLogitsWarper
)

# ================= 配置项(是否开启采样) =================
import os
# SERVER_DO_SAMPLE: "1"/"true" 开启采样；"0"/"false" 走贪心。默认开启。
def _as_bool(x: str) -> bool:
    return str(x).strip().lower() not in ("0", "false", "no", "off", "")

SERVER_DO_SAMPLE = _as_bool(os.getenv("SERVER_DO_SAMPLE", "1"))

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
            chain.extend(INTERNAL_PROCESSORS[n])

    if mode != "internal_only" and external_names:
        for n in external_names:
            if n not in EXTERNAL_PROCESSORS:
                raise HTTPException(status_code=400, detail=f"Unknown external processor: {n}")
            chain.extend(EXTERNAL_PROCESSORS[n])

    if not chain:
        return None
    return LogitsProcessorList(chain)

# ===== 在此处插入：自动加载 uiAPI（可选）=====
try:
    import importlib, sys, os
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    importlib.import_module("uiAPI")  # 其中应在顶层调用 register_xxx 完成注册
    print("[server] processors loaded ->",
          "internal:", list(INTERNAL_PROCESSORS.keys()),
          "external:", list(EXTERNAL_PROCESSORS.keys()))
except Exception as e:
    print(f"[server] uiAPI not loaded: {e}")

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

app = FastAPI()

@app.get("/v1/_processors")
def list_processors():
    """调试端点：查看当前已注册的处理器名称。"""
    return {
        "internal": list(INTERNAL_PROCESSORS.keys()),
        "external": list(EXTERNAL_PROCESSORS.keys())
    }

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
) -> str:
    _do_sample = SERVER_DO_SAMPLE if do_sample is None else bool(do_sample)
    # 不采样时，忽略采样相关参数，保持纯贪心行为
    gen_kwargs = dict(
        do_sample=_do_sample,
        max_new_tokens=max_tokens,
        logits_processor=logits_processor,
    )
    if _do_sample:
        gen_kwargs.update(temperature=temperature, top_p=top_p)

    out = model.generate(**inputs, **gen_kwargs)
    return _decode(out, inputs["input_ids"].shape[1])

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
) -> tuple[str, str]:
    """
    同步分叉并行（以内置处理后的分布作为基准）：
    - 每步只做一次前向，得到 logits；
    - scores_internal = 内置处理器链(logits) 作为“基准分布”；
      * internal_only 分支：在 scores_internal 上采样；
      * internal_plus_external 分支：在 scores_internal.clone() 上再应用“外置链”后采样。
    - 两路各自推进各自序列（batch=2，共享 KV cache）。
    返回：(text_internal_only, text_internal_plus_external)
    """
    device = next(model.parameters()).device
    input_ids = inputs["input_ids"].to(device)  # [1, L]
    attn = inputs.get("attention_mask", None)
    if attn is None:
        attn = torch.ones_like(input_ids, dtype=torch.long, device=device)
    else:
        attn = attn.to(device)

    # batch=2：两路共享前向，但各自保持独立序列
    cur_ids = input_ids.repeat(2, 1).contiguous()   # [2, L]
    cur_attn = attn.repeat(2, 1).contiguous()      # [2, L]
    prompt_len = input_ids.shape[1]

    # 采样 warpers（温度 / top-p）
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
    pkv = None
    new_tokens = 0

    def _apply(proc: Optional[LogitsProcessorList], ids_ctx: torch.Tensor, scores: torch.Tensor) -> torch.Tensor:
        # ids_ctx: [1, seq], scores: [1, vocab]
        if proc is not None:
            scores = proc(ids_ctx, scores)
        return scores

    while new_tokens < max_new_tokens:
        if pkv is None:
            outputs = model(input_ids=cur_ids, attention_mask=cur_attn, use_cache=True)
        else:
            step_in = cur_ids[:, -1:].contiguous()  # [2,1]
            outputs = model(input_ids=step_in, attention_mask=cur_attn, past_key_values=pkv, use_cache=True)
        pkv = outputs.past_key_values
        logits = outputs.logits[:, -1, :]   # [2, vocab]

        # 对“每一路各自的上下文”计算这一时刻的“内置基准分布”
        # 注意：即使两路上下文已不同，也各自先做“内置处理”，保证“基准”是“该路当前上下文 + 内置链”的结果
        base0 = _apply(lp_internal, cur_ids[0:1, :], logits[0:1, :])   # [1, vocab]
        base1 = _apply(lp_internal, cur_ids[1:1+1, :], logits[1:1+1, :])   # [1, vocab]

        # 在同一“基准分布”上，分别得到两路的最终分布
        # 路0（internal_only）：直接在 base_scores 上做 warper + 采样
        if finished[0]:
            tok0 = cur_ids[0:1, -1:].clone()  # 冻结，保持 [1,1]
        else:
            scores0 = base0.clone()
            if do_sample and len(warpers):
                scores0 = warpers(cur_ids[0:1, :], scores0)
            tok0 = (
                torch.multinomial(torch.softmax(scores0, dim=-1), num_samples=1)
                if do_sample else
                scores0.argmax(dim=-1, keepdim=True)
            )  # 形状 [1,1]
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
            tok1 = (
                torch.multinomial(torch.softmax(scores1, dim=-1), num_samples=1)
                if do_sample else
                scores1.argmax(dim=-1, keepdim=True)
            )
            # 采样/贪心后立刻判 EOS（不看 min_new_tokens）
            if eos_ids and int(tok1.item()) in eos_ids:
                finished[1] = True

        # 拼接
        next_ids = torch.cat([tok0, tok1], dim=0)  # [2,1]
        cur_ids = torch.cat([cur_ids, next_ids], dim=1)
        cur_attn = torch.cat([cur_attn, torch.ones((2,1), dtype=cur_attn.dtype, device=device)], dim=1)

        # 终止判定
        if eos_ids:
            if not finished[0] and int(tok0.item()) in eos_ids and new_tokens >= min_new_tokens:
                finished[0] = True
            if not finished[1] and int(tok1.item()) in eos_ids and new_tokens >= min_new_tokens:
                finished[1] = True

        new_tokens += 1
        if all(finished) and new_tokens >= min_new_tokens:
            break

    texts = tokenizer.batch_decode(cur_ids[:, prompt_len:], skip_special_tokens=True)
    return texts[0], texts[1]

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest) -> Dict[str, Any]:
    msgs = [m.model_dump() for m in req.messages]
    inputs = _prep_inputs(msgs)

    # 并行：两路（仅内置）与（内置+外置）
    if req.parallel:
        # 你这版逻辑以“内置分布”为基准，因此并行时必须提供 external_processor_names
        # if not req.external_processor_names:
        #     raise HTTPException(status_code=400, detail="parallel=True 需要提供 external_processor_names 列表")

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
        text_internal, text_both = _dual_sync_generate_internal_base(
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
                "prompt_tokens": int(inputs["input_ids"].numel()),
                "completion_tokens": None,
                "total_tokens": None
            }
        }

    # 非并行：按你给的列表统一拼接（可只内置、只外置、或内外兼容）
    lp_any = _resolve_lp_list(
        internal_names=req.internal_processor_names,
        external_names=req.external_processor_names,
        mode="any"
    )
    text = await asyncio.to_thread(
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
            "prompt_tokens": int(inputs["input_ids"].numel()),
            "completion_tokens": None,
            "total_tokens": None
        }
    }

# 启动： uvicorn server:app --host 0.0.0.0 --port 8000
