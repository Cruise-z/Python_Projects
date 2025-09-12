# regWM/parallelTest_stream_compat.py
from openai import OpenAI
from pathlib import Path
import os, time, json, difflib, argparse, httpx, sys

import sys, shutil
try:
    from wcwidth import wcswidth
except Exception:
    # 退化兜底：不精确，但至少不报错
    def wcswidth(s: str) -> int:
        try: return sum((2 if ord(c) > 0x3000 else 1) for c in s)
        except: return len(s)

class SideBySidePanel:
    """左右两栏实时输出（左=BASE/idx 0，右=WM/idx 1），宽字符友好，不软换行。"""
    def __init__(self, left_tag='BASE', right_tag='WM', sep=' │ ', max_rows=30):
        self.left_tag, self.right_tag = left_tag, right_tag
        self.sep = sep
        self.buffers = {0: [], 1: []}
        self.last_height = 0
        self.is_tty = sys.stdout.isatty()
        self.max_rows = max_rows
        self.cursor_hidden = False

    @staticmethod
    def _wrap_by_cols(text: str, width_cols: int):
        """按显示列宽包装（逐字符累加 wcswidth，确保不超列宽）。"""
        lines = []
        for raw in text.replace('\r', '').splitlines():
            line, cur = "", 0
            for ch in raw:
                w = wcswidth(ch)
                if w < 0:  # 控制字符等
                    continue
                if cur + w > width_cols:
                    lines.append(line)
                    line, cur = ch, w
                else:
                    line += ch
                    cur += w
            lines.append(line)
        if not lines:
            lines = [""]
        return lines

    @staticmethod
    def _pad_to_cols(s: str, width_cols: int):
        """用空格把可见宽度补到指定列宽。"""
        pad = width_cols - max(0, wcswidth(s))
        if pad > 0:
            s += " " * pad
        return s

    def _hide_cursor(self):
        if self.is_tty and not self.cursor_hidden:
            sys.stdout.write("\x1b[?25l")
            sys.stdout.flush()
            self.cursor_hidden = True

    def _show_cursor(self):
        if self.is_tty and self.cursor_hidden:
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()
            self.cursor_hidden = False

    def update(self, idx: int, chunk: str):
        self.buffers.setdefault(idx, []).append(chunk)

        # 非交互终端：逐行输出，简单可靠
        if not self.is_tty:
            tag = self.left_tag if idx == 0 else self.right_tag
            print(f"[{tag}] {chunk}", flush=True)
            return

        cols = shutil.get_terminal_size((120, 25)).columns
        sep = self.sep
        lw = (cols - wcswidth(sep)) // 2
        rw = cols - wcswidth(sep) - lw

        left_text  = ''.join(self.buffers.get(0, []))
        right_text = ''.join(self.buffers.get(1, []))

        # 先计算内容行，再加标题行，并限制显示的最大行数
        left_lines  = self._wrap_by_cols(left_text,  lw)
        right_lines = self._wrap_by_cols(right_text, rw)

        # 只保留尾部 N 行（标题行另算）
        left_body  = left_lines[-self.max_rows:]
        right_body = right_lines[-self.max_rows:]

        left_view  = [f"[{self.left_tag}]"]  + left_body
        right_view = [f"[{self.right_tag}]"] + right_body

        h = max(len(left_view), len(right_view))
        left_view  += [''] * (h - len(left_view))
        right_view += [''] * (h - len(right_view))

        # 每一行“硬填充”到栏宽，避免软换行
        rows = []
        for i in range(h):
            L = self._pad_to_cols(left_view[i],  lw)
            R = self._pad_to_cols(right_view[i], rw)
            rows.append(L + sep + R)

        self._hide_cursor()

        # 回到上次面板起点
        if self.last_height:
            sys.stdout.write(f"\x1b[{self.last_height}F")

        # 重绘
        for line in rows:
            sys.stdout.write("\x1b[2K\r")    # 清整行
            sys.stdout.write(line + "\n")
        sys.stdout.flush()

        self.last_height = h

    def finalize(self):
        if self.is_tty and self.last_height:
            # 光标移到面板下方一行
            sys.stdout.write("\n")
            sys.stdout.flush()
        self._show_cursor()

# —— 强制直连本地 vLLM（避免代理导致的 502）——
for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="EMPTY",
    http_client=httpx.Client(
        # proxies=None,
        trust_env=False,  # 不读系统代理
        timeout=httpx.Timeout(connect=10, read=1800, write=1800, pool=60),  # 30 分钟读/写
        limits=httpx.Limits(max_keepalive_connections=0, max_connections=4),
    ),
)

def run_stream(prompt: str):
    t0 = time.time()

    # 注意：vllm_xargs 里只放“标量”，嵌套 dict 用 JSON 字符串
    vllm_xargs = {
        "wm_compare": True,            # 并行两路（base vs. wm）
        "apply_order": "sweet",
        "exclude_special": True,
        "wllm_impl":  "regWM.libWM.watermark:WatermarkLogitsProcessor",
        "wllm_kwargs": json.dumps({"gamma": 0.5, "delta": 10}),
        "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
        "sweet_kwargs": json.dumps({"gamma": 0.5, "delta": 10, "entropy_threshold": 0.7}),
    }

    parts = {0: [], 1: []}  # 累积每路的片段

    # 兼容写法：直接在 create(..., stream=True) 上迭代 chunk
    stream = client.chat.completions.create(
        model="NTQAI/Nxcode-CQ-7B-orpo",
        messages=[{"role": "user", "content": prompt}],
        n=2,                         # choices[0]=base, choices[1]=wm
        temperature=0.5,
        top_p=0.95,
        max_tokens=1500,
        seed=7,
        stream=True,                 # ← 关键
        extra_body={"vllm_xargs": vllm_xargs},
    )

    panel = SideBySidePanel(left_tag='BASE', right_tag='WM')

    try:
        for chunk in stream:
            if not hasattr(chunk, "choices") or not chunk.choices:
                continue
            for ch in chunk.choices:
                idx = getattr(ch, "index", 0) or 0     # 0=BASE, 1=WM
                delta = getattr(ch, "delta", None)
                if delta is None:
                    continue
                content = getattr(delta, "content", None)
                if content:
                    parts.setdefault(idx, []).append(content)
                    panel.update(idx, content)         # ← 侧边并排实时更新
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            try: close()
            except Exception: pass
        panel.finalize()

        base = "".join(parts.get(0, []))
        wm   = "".join(parts.get(1, []))
        el_ms = (time.time() - t0) * 1000.0
        return base, wm, el_ms

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--promptPath", type=str, required=True, help="prompt文件路径")
    args = parser.parse_args()

    promptPath = Path(args.promptPath).resolve()
    prompt = promptPath.read_text(encoding="utf-8", errors="ignore")
    prompt = "请用一句话介绍BFS算法"

    base, wm, ms = run_stream(prompt)
    print(f"\n== stream done in {ms:.1f} ms ==")

    if not base or not wm:
        print("!! 期望 2 个并行输出，但其中一路为空。")
        print("   排查：1) vLLM 启动时启用你的 DualRouteWatermarkProcessor")
        print("         2) 本脚本里 n=2；3) 服务器日志无 “ignored: {'vllm_xargs'}” 警告")
        print("         4) 如仍不稳，改为顺序两次流式调用分别跑 base/wm")
        return

    print("\n===== BASE (choices[0]) =====\n")
    print(base)
    print("\n===== WM (choices[1]) =====\n")
    print(wm)

    sim = difflib.SequenceMatcher(a=base, b=wm).ratio()
    print(f"\n[diff] char-similarity: {sim:.3f}  (越低差异越大)")
    if base.strip() == wm.strip():
        print("\n⚠️ 两份输出几乎一致。可尝试：")
        print("   - 提高 temperature（如 1.0）/ max_tokens")
        print("   - 调整 (gamma, delta, entropy_threshold) 增强处理器影响")
        print("   - 换更开放的提示，减小模型收敛到同一句式的概率")

if __name__ == "__main__":
    main()
