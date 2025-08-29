# test_parallel.py
import os
from openai import OpenAI

# 1) 指向你的本地服务（OpenAI 兼容）
BASE_URL = os.getenv("OPENAI_API_BASE", "http://127.0.0.1:8000/v1")
API_KEY  = os.getenv("OPENAI_API_KEY", "sk-local-anything")  # 给个非空即可
MODEL    = os.getenv("OPENAI_MODEL_NAME", "Qwen/Qwen2.5-Coder-32B-Instruct")

# 强烈建议绕过代理（否则可能 502）
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

client = OpenAI(base_url=BASE_URL, api_key=API_KEY)

def call(messages, max_tokens=256, **extra):
    """extra 里塞 parallel / internal_processor_names / external_processor_names 等自定义参数"""
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=max_tokens,
        # 关键：把自定义字段放到 extra_body
        extra_body=extra,
    )
    return resp

def show(resp):
    print(f"choices = {len(resp.choices)}")
    for ch in resp.choices:
        variant = getattr(ch, "variant", None)  # 你的服务会在并行时带 variant
        print("="*60)
        if variant: print(f"[variant] {variant}")
        print(ch.message.content)

if __name__ == "__main__":
    msgs = [{"role":"user","content":"讲讲 BFS 与 DFS 的差异并举例，尽量简短。"}]

    print("\n[Case 1] 非并行、无处理器（基线）")
    r1 = call(msgs)
    show(r1)

    print("\n[Case 2] 并行：路0=仅内置，路1=内置+外置")
    # 替换成你实际注册的处理器名称；外置可以传多个
    r2 = call(
        msgs,
        parallel=True,
        internal_processor_names=[],
        external_processor_names=["wllm", "sweet"],
        max_tokens=256,
    )
    show(r2)

    print("\n[Case 3] 并行：仅内置（外置为空）——用于观察两路在采样/贪心下的表现")
    # 提示：如果你的服务端全局 SERVER_DO_SAMPLE=0（贪心），两路应自然一致；
    # 若为采样，两路可能分叉（因为各自独立抽样）
    r3 = call(
        msgs,
        parallel=True,
        internal_processor_names=[],
        external_processor_names=[],
        max_tokens=256,
    )
    show(r3)
