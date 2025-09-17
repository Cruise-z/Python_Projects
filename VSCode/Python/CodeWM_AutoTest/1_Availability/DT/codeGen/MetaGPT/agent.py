# -*- coding: utf-8 -*-
# agent.py
# 2024/6/18 15:28
# zhaorz
# description: 用MetaGPT生成代码工程的代理脚本
# MetaGPT version: 0.8.2

import metagpt, importlib, traceback, sys
print("metagpt from:", metagpt.__file__)
try:
    from metagpt import __version__
    print("metagpt version:", __version__)
except Exception as e:
    print("no __version__", e)

def chk_cfg(cfg, name):
    llm = getattr(cfg, "llm", None)
    print(f"[CHECK] {name}:",
          "OK" if (llm and getattr(llm, "model", None) and getattr(llm, "base_url", None) is not None) else "MISSING",
          getattr(llm, "api_type", None),
          getattr(llm, "base_url", None),
          getattr(llm, "model", None))

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


import asyncio, json, httpx
from openai import AsyncOpenAI
from metagpt.config2 import Config
from metagpt.actions.write_code import WriteCode
from metagpt.roles.engineer import Engineer
from metagpt.roles.product_manager import ProductManager
from metagpt.roles.architect import Architect
from metagpt.roles.project_manager import ProjectManager
from metagpt.team import Team
from metagpt.environment import Environment

# # 可选：附加 vLLM 扩展字段
# # 注意：vllm_xargs 里只放“标量”，嵌套 dict 用 JSON 字符串
# vllm_xargs = {
#     "wm_compare": True,            # 方案A：并行两路（base vs. wm）
#     "apply_order": "sweet",         # 由处理器读取（已做“先走一步再分路”的逻辑）
#     "exclude_special": True,
#     "wllm_impl":  "regWM.libWM.watermark:WatermarkLogitsProcessor",
#     "wllm_kwargs": json.dumps({"gamma": 0.5, "delta": 10}),
#     "sweet_impl": "regWM.libWM.sweet:SweetLogitsProcessor",
#     "sweet_kwargs": json.dumps({"gamma": 0.5, "delta": 30, "entropy_threshold": 0.7}),
#     # 可选：shared_kwargs 也可传，仍需 JSON 字符串
#     # "shared_kwargs": json.dumps({"some_shared_flag": True}),
# }
        
async def main():
    
    # 1) 加载两套配置（与官方示例一致）
    gpt_openai = Config.default()                      # 来自 ~/.metagpt/config2.yaml
    local_vllm = Config.from_home("local_vllm.yaml")   # 来自 ~/.metagpt/local_vllm.yaml
    try:
        local_vllm.llm.timeout = max(getattr(local_vllm.llm, "timeout", 0) or 0, 1200)
        # 某些提交使用 request_timeout 字段：
        if hasattr(local_vllm.llm, "request_timeout"):
            local_vllm.llm.request_timeout = max(getattr(local_vllm.llm, "request_timeout", 0) or 0, 1200)
    except Exception:
        pass
    
    chk_cfg(gpt_openai, "gpt_openai")
    chk_cfg(local_vllm, "local_vllm")
    
    # # A. 云端（如果你要用 OpenAI 角色）
    # gpt_openai = Config(llm={
    #     "type": "openai",
    #     "base_url": "https://api.chatanywhere.tech/v1",
    #     "api_key": "sk-5pzatlsS3ukKWKdQ8TW40Z5BhnS8UW5rEcdzeSndTGxvmKH9",
    #     "model": "gpt-4o",     # 你可换成自己可用的
    # })

    # # B. 本地 vLLM（Engineer 用）
    # local_vllm = Config(llm={
    #     "type": "open_llm",                 # 多数本地端点走 OpenAI 兼容协议
    #     "base_url": "http://127.0.0.1:8000/v1",
    #     "api_key": "EMPTY",               # 占位
    #     "model": "Qwen/Qwen2.5-Coder-32B-Instruct",  # 你的本地模型名
    #     "timeout": 1200,
    # })
    
    # 其它角色
    pm, arch, pmgr = ProductManager(config=gpt_openai), Architect(config=gpt_openai), ProjectManager(config=gpt_openai)
    # 工程师用派生类（内部已把写码动作固定到本地）
    eng = Engineer(config=local_vllm)

    team = Team(env=Environment(desc="Build tiny Java project"), roles=[pm, arch, pmgr, eng])
    idea = """你是一名只写 Java 的资深工程师。请基于以下规格实现一个完整、可编译、可运行的 Java Swing 贪吃蛇：

【硬性约束】
- 语言：仅 Java（JDK 17）
- 构建：Maven
- 目录结构（必须完全匹配）：
  - pom.xml
  - src/main/java/correct/SnakeGame.java
  - src/test/java/correct/SnakeGameTest.java（可最小化）
- 运行命令（需可直接运行 GUI）：
  mvn -q -DskipTests exec:java -Dexec.mainClass=correct.SnakeGame

【功能需求】
• Game Board:\n⋄ Create a grid-based game board.\n⋄ Define the dimensions of the grid (e.g., 10x10).\n⋄ Display the grid on the screen.\n• Snake Initialization:\n⋄ Place the snake on the game board.\n⋄ Define the initial length and starting position of the snake.\n⋄ Choose a direction for the snake to start moving (e.g., right).\n• Snake Movement:\n⋄ Implement arrow key controls for snake movement.\n⋄ Ensure the snake moves continuously in the chosen direction.\n⋄ Update the snake's position on the grid.\n• Food Generation:\n⋄ Generate food at random positions on the game board.\n⋄ Ensure food doesn't appear on the snake's body.\n• Collision Handling:\n⋄ Detect collisions between the snake and the game board boundaries.\n⋄ Detect collisions between the snake's head and its body.\n⋄ Detect collisions between the snake's head and the food.\n• Snake Growth:\n⋄ Increase the length of the snake when it consumes food.\n⋄ Add a new segment to the snake's body.\n• Score Display:\n⋄ Implement a scoring system.\n⋄ Display the current score on the screen.\n• Game Over Condition:\n⋄ Trigger a game over scenario when the snake collides with the boundaries.\n⋄ Trigger a game over scenario when the snake collides with its own body.\n⋄ Display a game over message.\n⋄ Allow the player to restart the game.\n• Graphics and User Interface:\n⋄ Use graphics or ASCII characters to represent the snake and food.\n⋄ Design a user-friendly interface with clear instructions and score display.\n• Animations and Effects:\n⋄ Add animations for snake movement and growth.\n⋄ Implement visual effects for collisions and food consumption.

【实现要点】
- 使用 javax.swing.JFrame + JPanel 绘制网格、蛇、食物
- 方向键控制，记分，Game Over 后弹窗可重开
- 代码整洁、必要注释
- 直接给出完整 SnakeGame.java 源码，包含 package correct; 与 import

【交付物】
- 完整 Maven 工程（包含 pom.xml 与源码）
- SnakeGame.java 必须包含 package correct;
"""
    await team.run(n_round=5, idea=idea)
    
if __name__ == "__main__":
    asyncio.run(main())