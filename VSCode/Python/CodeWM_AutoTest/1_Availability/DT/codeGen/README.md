# 代码生成指南

------

## ==agent架构设计==

代码使用`agent:MetaGPT`辅助生成，

在`MetaGPT`的`[Action]->[Role]`实现框架中，为不同角色配置不同的模型进行生成：

- 项目架构设计：由`openai`官方模型`gpt-4`/`gpt-4o`完成

- 代码编写生成：由本地部署的`Qwen/Qwen2.5-Coder-32B-Instruct`完成

  > `Qwen/Qwen2.5-Coder-32B-Instruct`是当前开源大模型中代码生成表现非常优秀的模型之一
  > 参考：[`Hugging Face`开源代码模型排行榜](https://huggingface.co/spaces/bigcode/bigcode-models-leaderboard)

### `config`配置

两个模型的`config`文件内容如下：

- `openai`官方模型：

  ```bash
  (base) zhaorz@rubick:~/.metagpt$ cat openai.yaml 
  llm:
    api_type: openai
    base_url: https://api.chatanywhere.tech/v1
    # base_url: http://127.0.0.1:8000/v1
    api_key: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    model: gpt-4
    # model: NTQAI/Nxcode-CQ-7B-orpo
    # model: Qwen/Qwen2.5-Coder-32B-Instruct 
    use_proxy: true
    stream: true
  ```

- 本地开源模型(默认配置)：

  ```bash
  (base) zhaorz@rubick:~/.metagpt$ cat config2.yaml 
  llm:
    api_type: open_llm                  
    base_url: http://127.0.0.1:8000/v1
    model: Qwen/Qwen2.5-Coder-32B-Instruct
    # model: NTQAI/Nxcode-CQ-7B-orpo     
    api_key: EMPTY
    use_proxy: false
    stream: false
    timeout: 1200
    # request_timeout: 1200
  repair_llm_output: true
  ```

### `prompt`设计

针对不同项目的提示词已归类至`./prompts`文件夹内；

### 配置参数并运行

为使用方便，一些经常修改的**模型生成参数**以及**水印相关参数**放置在了`xargs`字段中；

`xargs`字段如下示例：

```python
xargs = {
    "temperature": 0.7,
    "max_tokens": 4096,
    "parallel": True,
    "rng_seed": 123456,
    "internal_processor_names": [],
    "external_processor_names": ["sweet"],
    "external_processor_params": {
        "sweet": {"gamma": 0.5, "delta": 5, "entropy_threshold": 0.60},
        "wllm": {"gamma": 0.4, "delta": 1},
    },
}
```



------

## ==从提示词生成==

在`./agent.py`中修改`xargs`参数并运行即可；

------

## ==从框架生成==

在使用`MetaGPT`的==从提示词生成==模式生成高质量可用的项目架构后，若想复用其架构进行代码生成，可以采取如下方式：

- 运行`./agentArchGen.py`：先使用`openai`的模型生成高质量可用的架构仓库
- 运行`./agentCodeGen.py`：在上述架构仓库的基础上使用开源模型自定义生成代码

**注意：**

- 建议在生成可用的架构仓库后将其备份，方便之后多次生成代码
- 标准示例架构仓库文件在`./MetaGPT/workspace`中给出