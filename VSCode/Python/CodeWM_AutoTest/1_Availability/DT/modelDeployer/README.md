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
