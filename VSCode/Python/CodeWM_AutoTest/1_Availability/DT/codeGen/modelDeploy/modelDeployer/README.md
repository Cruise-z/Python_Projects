# 操作指南

## 启动模型服务

模型启动方式：
SERVER_DO_SAMPLE=1 SAMPLING_MODE=lenient_openai uvicorn server:app --host 0.0.0.0 --port 8000

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