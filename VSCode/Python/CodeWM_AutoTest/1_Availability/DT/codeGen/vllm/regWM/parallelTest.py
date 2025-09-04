# regWM/parallelTest.py
from openai import OpenAI
import os, time, json, difflib

# —— 强制直连本地 vLLM（避免代理导致的 502）——
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(k, None)
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="EMPTY",
)

PROMPT = (
    "请用简洁中文用 1 段话介绍 BFS（广度优先搜索），"
    "尽量包含英文缩写、时间/空间复杂度、一个迷你示例，并避免列点。"
)

def run_once():
    t0 = time.time()

    # 注意：vllm_xargs 里只放“标量”，嵌套 dict 用 JSON 字符串
    vllm_xargs = {
        "wm_compare": True,            # 方案A：并行两路（base vs. wm）
        "apply_order": "sweet",         # 由处理器读取（已做“先走一步再分路”的逻辑）
        "exclude_special": True,
        "wllm_impl":  "regWM.libWM.watermark:WatermarkLogitsProcessor",
        "wllm_kwargs": json.dumps({"gamma": 0.5, "delta": 10}),
        "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
        "sweet_kwargs": json.dumps({"gamma": 0.5, "delta": 30, "entropy_threshold": 0.7}),
        # 可选：shared_kwargs 也可传，仍需 JSON 字符串
        # "shared_kwargs": json.dumps({"some_shared_flag": True}),
    }

    resp = client.chat.completions.create(
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
        messages=[{"role": "user", "content": PROMPT}],
        n=2,                         # 并行两路（choices[0]=base, choices[1]=wm）
        temperature=0.5,
        top_p=0.95,
        max_tokens=200,
        seed=7,                      # 固定随机性（vLLM 支持时生效）
        extra_body={"vllm_xargs": vllm_xargs},
    )
    el_ms = (time.time() - t0) * 1000
    return resp, el_ms

def main():
    resp, ms = run_once()
    choices = resp.choices or []
    print(f"== done in {ms:.1f} ms, choices={len(choices)} ==")

    if len(choices) < 2:
        print("!! 期望 2 个并行输出，但只返回 1 个。")
        print("   排查：1) 启动命令带 --logits-processors regWM.regWM_v1:DualRouteWatermarkProcessor")
        print("         2) 本脚本里 n=2；3) 服务器日志无 “ignored: {'vllm_xargs'}” 警告")
        return

    base = choices[0].message.content or ""
    wm   = choices[1].message.content or ""

    print("\n===== BASE (choices[0]) =====\n")
    print(base)
    print("\n===== WM (choices[1]) =====\n")
    print(wm)

    # 简易差异
    sim = difflib.SequenceMatcher(a=base, b=wm).ratio()
    print(f"\n[diff] char-similarity: {sim:.3f}  (越低差异越大)")

    if base.strip() == wm.strip():
        print("\n⚠️ 两份输出几乎一致。可尝试：")
        print("   - 提高 temperature（如 1.0）/ max_tokens")
        print("   - 调整 (gamma, delta, entropy_threshold) 增强处理器影响")
        print("   - 换更开放的提示，减小模型收敛到同一句式的概率")

if __name__ == "__main__":
    main()
