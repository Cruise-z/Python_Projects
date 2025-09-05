# 操作指南

## vllm环境建立
> **参考：**
>
> - `github`链接：[vllm](https://github.com/vllm-project/vllm)
> - `vllm`源码安装：
>
>   - `uv`包管理器安装：[UV docs](https://docs.astral.sh/uv/)
>   - 轮子构建(源代码)：[Build wheel from source](https://docs.vllm.ai/en/latest/getting_started/installation/gpu.html#build-wheel-from-source)
> - 双路并行生成：
>
>   - 示例文件：
>     `1_Availability/DT/codeGen/vllm/vllm/engine/output_processor/single_step.py`
>   - `Openai`原生并行参数`n`：[spring.ai.openai.chat.options.n](https://docs.spring.io/spring-ai/reference/api/chat/openai-chat.html?utm_source=chatgpt.com#:~:text=spring.ai.openai.chat.options.n)
>   - `vllm`输出`engine`：[单步token生成处理模块](https://docs.vllm.ai/en/latest/api/vllm/engine/output_processor/single_step.html?h=singlestepoutputprocessor)
>   - `seq_id`对应序列施加掩码：[vllm.sequence](https://docs.vllm.ai/en/v0.10.1.1/api/vllm/sequence.html)
>   
> - `Logits`处理器可扩展性：
>   - 开发者文档：
>     - 指南：[v1_guide](https://docs.vllm.ai/en/latest/usage/v1_guide.html)
>     - 注册加载方式示例：[reg_exp](https://docs.vllm.ai/en/v0.10.1/examples/offline_inference/logits_processor.html?utm_source=chatgpt.com)
>   - `RFC`文档：
>     - https://github.com/vllm-project/vllm/issues/17799
>     - https://github.com/vllm-project/vllm/issues/21672
>

## vllm启动方式

启动命令：

```bash
(CodeWM) zhaorz@rubick:~/project/CodeWM/vllm$ python -m vllm.entrypoints.openai.api_server \
  --model "Qwen/Qwen2.5-Coder-32B-Instruct" \
  --port 8000 \
  --max-model-len 16384 \
  --logits-processors regWM.regWM_v1:DualRouteWatermarkProcessor
```

## vllm传参设置

### curl

```bash
# 把所有自定义开关都放进 vllm_xargs.extra_args，并把它设为一个 JSON 字符串
# 服务端会把它直接塞进 SamplingParams.extra_args，你的处理器会自动 json.loads 并解析
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "n": 2,
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "max_tokens": 64,
    "vllm_xargs": {
      "extra_args": "{\"wm_compare\":true, \"special_token_ids\":[151643], \"dualroute\": {\"apply_order\":\"wllm\",\"exclude_special\":true, \"wllm_impl\":\"regWM.libWM.watermark:WatermarkLogitsProcessor\", \"wllm_kwargs\":{\"gamma\":0.5,\"delta\":1}, \"sweet_impl\":\"regWM.libWM.sweet:SweetLogitsProcessor\",\"sweet_kwargs\":{\"gamma\":0.5,\"delta\":1,\"entropy_threshold\":0.9}} }"
    }
  }'

# 把 dualroute / special_token_ids 等直接放到 vllm_xargs
# 注意：这些值依旧要是JSON 字符串（因为 vLLM 的 Pydantic 对 vllm_xargs 内部约束较严格），处理器会自动 json.loads
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "n": 2,
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "max_tokens": 64,
    "vllm_xargs": {
      "wm_compare": "true",
      "special_token_ids": "[151643,151645]",
      "dualroute": "{\"apply_order\":\"wllm\",\"exclude_special\":true, \"wllm_impl\":\"regWM.libWM.watermark:WatermarkLogitsProcessor\",\"wllm_kwargs\":{\"gamma\":0.5,\"delta\":1}, \"sweet_impl\":\"regWM.libWM.sweet:SweetLogitsProcessor\",\"sweet_kwargs\":{\"gamma\":0.5,\"delta\":1,\"entropy_threshold\":0.9}}"
    }
  }'

# 全部不加水印
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "max_tokens":64,
    "vllm_xargs": { "extra_args": "{\"wm\":false}" }
  }'
  
# 全部加水印
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "max_tokens":64,
    "vllm_xargs": {
      "extra_args": "{\"wm\":true, \"dualroute\":{\"apply_order\":\"wllm\",\"exclude_special\":true, \"wllm_impl\":\"regWM.libWM.watermark:WatermarkLogitsProcessor\",\"wllm_kwargs\":{\"gamma\":0.5,\"delta\":1}, \"sweet_impl\":\"regWM.libWM.sweet:SweetLogitsProcessor\",\"sweet_kwargs\":{\"gamma\":0.5,\"delta\":1,\"entropy_threshold\":0.9}} }"
    }
  }'
  
# 你也可以直接传 wm_mask（布尔列表，JSON 字符串），精确指定哪些 batch 行加水印（例如并行 n=2 时只让第二路生效）
# 注意：你现在的 SingleStepOutputProcessor 在 wm_compare=true 时，会自动在首个解码步全透传，并在后续步用 mask 只对“wm”分支生效；除非你确实要手动控制，不然无需自己传 wm_mask
curl --noproxy 127.0.0.1,localhost http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen2.5-Coder-32B-Instruct",
    "n": 2,
    "messages":[{"role":"user","content":"用一句话介绍BFS"}],
    "max_tokens":64,
    "vllm_xargs": {
      "extra_args": "{\"wm_mask\":[false,true], \"dualroute\":{\"apply_order\":\"wllm\",\"exclude_special\":true, \"wllm_impl\":\"regWM.libWM.watermark:WatermarkLogitsProcessor\",\"wllm_kwargs\":{\"gamma\":0.5,\"delta\":1}, \"sweet_impl\":\"regWM.libWM.sweet:SweetLogitsProcessor\",\"sweet_kwargs\":{\"gamma\":0.5,\"delta\":1,\"entropy_threshold\":0.9}} }"
    }
  }'
```

### openai

```python
extra_args = {
    "wm_compare": True,                # 并行对比：n>=2 时自动两路
    "special_token_ids": [151643],     # 可选：显式屏蔽特殊 token
    "dualroute": {
        "apply_order": "wllm",
        "exclude_special": True,
        "wllm_impl": "regWM.libWM.watermark:WatermarkLogitsProcessor",
        "wllm_kwargs": {"gamma": 0.5, "delta": 1},
        "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
        "sweet_kwargs": {"gamma": 0.5, "delta": 1, "entropy_threshold": 0.9},
    },
}

resp = client.chat.completions.create(
    model="Qwen/Qwen2.5-Coder-32B-Instruct",
    messages=[{"role": "user", "content": "用一句话介绍BFS"}],
    n=2,
    max_tokens=64,
    extra_body={"vllm_xargs": {"extra_args": json.dumps(extra_args)}},
)
print(resp.choices[0].message.content)
print("-----")
print(resp.choices[1].message.content)
```

```python
dualroute = {
    "apply_order": "wllm",
    "exclude_special": True,
    "wllm_impl": "regWM.libWM.watermark:WatermarkLogitsProcessor",
    "wllm_kwargs": {"gamma": 0.5, "delta": 1},
    "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
    "sweet_kwargs": {"gamma": 0.5, "delta": 1, "entropy_threshold": 0.9},
}

resp = client.chat.completions.create(
    model="Qwen/Qwen2.5-Coder-32B-Instruct",
    messages=[{"role": "user", "content": "用一句话介绍BFS"}],
    n=2,
    max_tokens=64,
    extra_body={
        "vllm_xargs": {
            "wm_compare": "true",                           # 布尔值也可写成 "true"/"false"
            "special_token_ids": json.dumps([151643]),      # 列表要 json.dumps
            "dualroute": json.dumps(dualroute),             # 嵌套字典要 json.dumps
        }
    },
)
print(resp.choices[0].message.content)
print("-----")
print(resp.choices[1].message.content)
```

