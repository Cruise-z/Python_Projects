#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
count_tokens.py
- 计算本地 vLLM 模型对某段 prompt 的 token 数
- 支持三种方法：
  A) server: 通过本地 /v1/chat/completions 发起 max_tokens=1 的最小请求，读 usage.prompt_tokens（最匹配实际）
  B) hf:     用 HF 分词器 + chat template 本地计算（需安装 transformers）
    用法: `python count_tokens.py --prompt_path ./SnakeGame.java.prompt.txt --method hf --model "Qwen/Qwen2.5-Coder-32B-Instruct"`
  C) api:    调 vLLM 的 /tokenize 或 /v1/tokenize（若你的服务版本开启了 Tokenizer API）
"""

import os, json, argparse, sys
from pathlib import Path

# 禁用代理，直连本地
for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")

DEFAULT_BASE   = "http://127.0.0.1:8000"
DEFAULT_MODEL  = "Qwen/Qwen2.5-Coder-32B-Instruct"

def read_text(path: str) -> str:
    p = Path(path)
    return p.read_text(encoding="utf-8", errors="ignore")

# ---------------- A) 通过 chat.completions 拿 usage.prompt_tokens ----------------
def count_via_server(messages, base_url=DEFAULT_BASE, model=DEFAULT_MODEL, timeout_s=600):
    import httpx
    from openai import OpenAI

    client = OpenAI(
        base_url=f"{base_url}/v1",
        api_key="EMPTY",
        http_client=httpx.Client(
            proxies=None, trust_env=False,
            timeout=httpx.Timeout(connect=10.0, read=timeout_s, write=timeout_s, pool=60.0),
        ),
    )
    # 只让它生成 1 个 token，读取 usage.prompt_tokens
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=1,
        temperature=0,
        stream=False,
    )
    u = resp.usage
    # 有些版本字段在 resp.usage，或 resp.to_dict()['usage']
    if u:
        return {
            "prompt_tokens": getattr(u, "prompt_tokens", None),
            "completion_tokens": getattr(u, "completion_tokens", None),
            "total_tokens": getattr(u, "total_tokens", None),
            "method": "server(chat.completions, max_tokens=1)"
        }
    # 兜底
    u2 = getattr(resp, "usage", None) or {}
    return {"prompt_tokens": u2.get("prompt_tokens"), "completion_tokens": u2.get("completion_tokens"),
            "total_tokens": u2.get("total_tokens"), "method": "server(chat.completions, max_tokens=1)"}

# ---------------- B) 用 HF 分词器 + chat template 本地计算 ----------------
def count_via_hf(messages, model=DEFAULT_MODEL):
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model, trust_remote_code=True)
    # 把 messages 套模板（与 vLLM 的 chat.completions 一致的思路）
    # 注意：如果你还有 system role，请把它放在 messages[0]
    ids = tok.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,  # 与 chat.completions 用法对齐
        return_tensors=None,
    )
    # 上面返回的就是 token id 列表
    if isinstance(ids, list):
        length = len(ids)
    else:
        # 某些老版本可能返回 tensor
        length = len(ids[0]) if hasattr(ids, "__len__") else int(ids.shape[-1])
    return {"prompt_tokens": length, "method": "hf(tokenizer.apply_chat_template + tokenize)"}

# ---------------- C) 调 vLLM 的 Tokenizer API（若开启） ----------------
def count_via_vllm_tokenizer(text, base_url=DEFAULT_BASE, model=DEFAULT_MODEL, timeout_s=60):
    """
    vLLM 文档：Tokenizer API 是 HF 的封装，通常有 /tokenize（或 /v1/tokenize）
    端点的确切 schema 可能有差异，这里做了尝试式调用：
      1) POST /v1/tokenize {"model": "...", "text": "..."}
      2) POST /v1/tokenize {"text": "..."}
      3) POST /tokenize    {"text": "..."}
    返回体里可能是 {"tokens":[...]} 或 {"input_ids":[...]} 之一
    """
    import httpx
    sess = httpx.Client(proxies=None, trust_env=False, timeout=timeout_s)
    payloads = [
        (f"{base_url}/v1/tokenize", {"model": model, "text": text}),
        (f"{base_url}/v1/tokenize", {"text": text}),
        (f"{base_url}/tokenize",    {"text": text}),
    ]
    last_err = None
    for url, body in payloads:
        try:
            r = sess.post(url, json=body)
            if r.status_code == 200:
                data = r.json()
                toks = data.get("tokens") or data.get("input_ids")
                if toks:
                    return {"prompt_tokens": len(toks), "method": f"vllm {url}"}
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Tokenizer API not available or schema mismatched; last_err={last_err}")

def to_messages(text: str, role: str = "user", system: str = None):
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": role, "content": text})
    return msgs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt_path", type=str, required=True, help="要统计的 prompt 文本文件路径（会作为 user 消息）")
    ap.add_argument("--method", choices=["server", "hf", "api"], default="server",
                    help="server=chat.completions usage, hf=本地分词器, api=vLLM Tokenizer API")
    ap.add_argument("--base_url", type=str, default=DEFAULT_BASE, help="本地 vLLM 服务根，如 http://127.0.0.1:8000")
    ap.add_argument("--model", type=str, default=DEFAULT_MODEL, help="vLLM 的 served 模型名")
    ap.add_argument("--system", type=str, default=None, help="可选：加一个 system 消息")
    args = ap.parse_args()

    text = read_text(args.prompt_path)
    messages = to_messages(text, role="user", system=args.system)

    if args.method == "server":
        out = count_via_server(messages, base_url=args.base_url, model=args.model)
    elif args.method == "hf":
        out = count_via_hf(messages, model=args.model)
    else:
        out = count_via_vllm_tokenizer(text, base_url=args.base_url, model=args.model)

    print(json.dumps({
        "model": args.model,
        "base_url": args.base_url,
        "method": out["method"],
        "prompt_tokens": out["prompt_tokens"],
        "tips": "server 方法最能反映 vLLM 实际上下文拼接与特殊符号；hf 方法需确保 transformers 版本新且模型带 chat template。"
    }, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
