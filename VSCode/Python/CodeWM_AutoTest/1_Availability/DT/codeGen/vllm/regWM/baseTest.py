from openai import OpenAI
import httpx, os
import json

# 强制本地直连
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(k, None)
# 强烈建议绕过代理（否则可能 502）
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="EMPTY",
)

def ask(use_wm: bool):
    xargs = {"wm": bool(use_wm)}
    if use_wm:
        # ⚠️ 这版 vLLM 要求复杂对象先 JSON 字符串化
        xargs["dualroute"] = json.dumps({
            "apply_order": "wllm",
            "exclude_special": True,
            "wllm_impl":  "regWM.libWM.watermark:WatermarkLogitsProcessor",
            "wllm_kwargs": {"gamma": 0.5, "delta": 10},
            "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
            "sweet_kwargs": {"gamma": 0.5, "delta": 10, "entropy_threshold": 0.5},
        })

    resp = client.chat.completions.create(
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
        messages=[{"role":"user","content":"详细介绍BFS"}],
        temperature=0,      # 非 0，更容易看出差异
        max_tokens=256,
        extra_body={"vllm_xargs": xargs},   # 关键：通过 extra_body 注入
    )
    return resp.choices[0].message.content

if __name__ == "__main__":
    print("baseline:", ask(False))
    print("wm:",       ask(True))