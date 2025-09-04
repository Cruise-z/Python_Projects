# 操作指南

## vllm环境建立
> 参考：
>
> - `github`链接：[vllm](https://github.com/vllm-project/vllm)
>
> - `vllm`源码安装：
>
>   - `uv`包管理器安装：[UV docs](https://docs.astral.sh/uv/)
>   - 轮子构建(源代码)：[Build wheel from source](https://docs.vllm.ai/en/latest/getting_started/installation/gpu.html#build-wheel-from-source)
>
> - 双路并行生成：
>
>   - 示例文件：
>     `1_Availability/DT/codeGen/vllm/vllm/engine/output_processor/single_step.py`
>   - `Openai`原生并行参数`n`：[spring.ai.openai.chat.options.n](https://docs.spring.io/spring-ai/reference/api/chat/openai-chat.html?utm_source=chatgpt.com#:~:text=spring.ai.openai.chat.options.n)
>  - 
> 
>- `Logits`处理器可扩展性：
>   - 开发者文档：[v1_guide](https://docs.vllm.ai/en/latest/usage/v1_guide.html)
>     - 注册加载方式示例：[reg_exp](https://docs.vllm.ai/en/v0.10.1/examples/offline_inference/logits_processor.html?utm_source=chatgpt.com)
>     - 
>   - `RFC`文档：https://github.com/vllm-project/vllm/issues/17799
>
>   

## vllm引擎启动方式
python -m vllm.entrypoints.openai.api_server \
  --model "Qwen/Qwen2.5-Coder-32B-Instruct" \
  --port 8000 \
  --max-model-len 16384 \
  --logits-processors regWM.regWM_v1:DualRouteWatermarkProcessor