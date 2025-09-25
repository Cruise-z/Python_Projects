#=====================================基础环境配置=====================================#
import os
# os.chdir("/home/zhaorz/project/CodeWM/sweet-watermark/DT/workspace")

# 1) 让官方 OpenAI 走代理（按你的梯子改端口）
os.environ["HTTPS_PROXY"] = os.environ.get("HTTPS_PROXY", "http://127.0.0.1:7890")
os.environ["HTTP_PROXY"]  = os.environ.get("HTTP_PROXY",  "http://127.0.0.1:7890")
# 有些环境会读 ALL_PROXY，也统一设一下
os.environ["ALL_PROXY"]   = os.environ.get("ALL_PROXY",   os.environ["HTTPS_PROXY"])

# 2) 让本地回环地址永远直连（不走代理）
no_proxy = set(filter(None, os.environ.get("NO_PROXY", "").split(",")))
no_proxy.update({"127.0.0.1", "localhost", "::1"})
os.environ["NO_PROXY"] = ",".join(no_proxy)
os.environ["no_proxy"] = os.environ["NO_PROXY"]  # 兼容小写
#=====================================基础环境配置=====================================#

import prompts
import asyncio, json, httpx
from openai import AsyncOpenAI
from metagpt.config2 import Config
from metagpt.actions.write_code import WriteCode
from metagpt.roles.engineer import Engineer
# from metagpt.roles.di.data_interpreter import DataInterpreter
from metagpt.roles.product_manager import ProductManager
from metagpt.roles.architect import Architect
from metagpt.roles.project_manager import ProjectManager
from metagpt.team import Team
from metagpt.environment import Environment
        
async def main():
    
    # 1) 加载两套配置（与官方示例一致）
    local_vllm = Config.default()                      # 来自 ~/.metagpt/config2.yaml
    gpt_openai = Config.from_home("openai.yaml")       # 来自 ~/.metagpt/local_vllm.yaml
    try:
        local_vllm.llm.timeout = max(getattr(local_vllm.llm, "timeout", 0) or 0, 1200)
        # 某些提交使用 request_timeout 字段：
        if hasattr(local_vllm.llm, "request_timeout"):
            local_vllm.llm.request_timeout = max(getattr(local_vllm.llm, "request_timeout", 0) or 0, 1200)
    except Exception:
        pass
    
    xargs = {
        "temperature": 0.7,
        "max_tokens": 4096,
        "parallel": True,
        "rng_seed": 123456,
        "internal_processor_names": [],
        "external_processor_names": ["sweet"],
        "external_processor_params": {
            "sweet": {"gamma": 0.7, "delta": 2, "entropy_threshold": 0.85},
            "wllm": {"gamma": 0.4, "delta": 1},
        },
    }
    
    # 其它角色
    pm, arch, pmgr = ProductManager(config=gpt_openai), Architect(config=gpt_openai), ProjectManager(config=gpt_openai)
    # 工程师用派生类（内部已把写码动作固定到本地）
    eng = Engineer(config=local_vllm)
    # eng = DataInterpreter(config=local_vllm)
    eng.llm.config.__dict__["xargs"] = xargs

    team = Team(env=Environment(desc=prompts.java.snakegame.desc), roles=[pm, arch, pmgr, eng])
    idea = prompts.java.snakegame.idea

    await team.run(n_round=5, idea=idea)
    
if __name__ == "__main__":
    asyncio.run(main())