# 操作指南

## 启动模型服务

模型启动方式：
SERVER_DO_SAMPLE=1 SAMPLING_MODE=lenient_openai uvicorn server:app --host 0.0.0.0 --port 8000

DEBUG启动：
uvicorn server:app \
  --host 0.0.0.0 --port 8000 \
  --http httptools \
  --loop uvloop \
  --log-level debug \
  --access-log \
  --timeout-keep-alive 300

# 单 worker，超时都拉长
gunicorn server:app \
  -k uvicorn.workers.UvicornWorker \
  -w 1 -b 0.0.0.0:8000 \
  --timeout 600 --graceful-timeout 600 --keep-alive 300 \
  --log-level debug

模型包装测试：
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/_processors
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "messages":[{"role":"user","content":"讲讲BFS与DFS差异并举例"}],
    "temperature":0.7,
    "internal_processor_names":[],
    "external_processor_names":["sweet"],
    "parallel": true,
    "max_tokens": 2048
  }' | jq .
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "temperature": 0,
    "max_tokens": 64
  }' | jq .

## 运行代理

代理启动方式：
自定义配置代理文件`agent.py`后直接python启动即可


压力测试：
python3 - <<'PY' | curl --noproxy 127.0.0.1,localhost -sS http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' -d @- | jq .
import json
N_CHUNKS = 11   # 先小到 50/100 验证，再逐步加到 800/2000/5000

header = (
  "你现在是一个严格的审校器。请阅读下面的超长技术文档片段集合，"
  "最后仅输出“OK:已读完毕且可解析”。不要复述内容。\n\n"
  "====== 文档开始 ======\n"
)
def chunk(i:int)->str:
    nums = ",".join(str((i*j)%997) for j in range(96))
    code = f"def f_{i}(x):\\n    return (x**2 + {i}) % 997\\n"
    kvs  = { "idx": i, "sha": f"{i:04x}{(i*i)%65535:04x}", "tags": ["llm","stress","ctx","中文","混排"], "nums_len": 96 }
    lines = [
        f"### 段落 {i:04d} —— 混合中英/符号/代码/CSV",
        "BFS vs DFS quick note: BFS explores level by level; DFS dives deep; 这句是token化噪声。",
        f"CSV::{nums}",
        "公式: S(n)=n(n+1)/2，附加冗余字符提升token密度——αβγδεζηθκλμνξοπρστυφχψω。",
        "JSON::" + json.dumps(kvs, ensure_ascii=False),
        "CODE::\\n" + code
    ]
    return "\\n".join(lines) + "\\n"

body = "".join(chunk(i) for i in range(N_CHUNKS))
tail = "====== 文档结束 ======\\n"

payload = {
  "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
  "messages":[{"role":"user","content": header + body + tail}],
  "temperature":0.0,
  "top_p":1.0,
  "max_tokens":16,
  "stream": False
}
print(json.dumps(payload, ensure_ascii=False))
PY

python3 - <<'PY' | curl --max-time 120 --noproxy 127.0.0.1,localhost -sS http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' -d @- | jq .
import json
N_CHUNKS = 120
header = "并行压测：请读完整个大段文本后仅回复“OK:parallel”。\\n\\n"
def chunk(i): return f"[{i:04d}] 压测行 {i} —— tokens*mix —— 0123456789 ABC abc XYZ。\\n"
body = "".join(chunk(i) for i in range(N_CHUNKS))
payload = {
  "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
  "messages":[{"role":"user","content": header + body}],
  "temperature":0.0, "top_p":1.0,
  "max_tokens":16, "stream": False,
  "internal_processor_names": [],
  "external_processor_names": ["sweet"],
  "parallel": True
}
print(json.dumps(payload, ensure_ascii=False))
PY