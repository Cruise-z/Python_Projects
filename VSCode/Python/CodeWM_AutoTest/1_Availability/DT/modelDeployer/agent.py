# -*- coding: utf-8 -*-
# agent.py
# 2024/6/18 15:28
# zhaorz
# description: 用MetaGPT生成代码工程的代理脚本
# MetaGPT version: 0.8.2
import os
os.chdir("/home/zhaorz/project/CodeWM/sweet-watermark/DT/workspace")
# === 1) 关掉系统代理，确保本地地址直连 ===
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(k, None)
# 强烈建议绕过代理（否则可能 502）
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")

from metagpt.utils import mermaid
# 有些版本提供 setter
if hasattr(mermaid, "set_engine"):
    mermaid.set_engine("playwright")
else:
    # 没有 setter 就直接改默认引擎字段（不同版本命名可能略有不同）
    for name in ("ENGINE", "DEFAULT_ENGINE", "MERMAID_ENGINE"):
        if hasattr(mermaid, name):
            setattr(mermaid, name, "playwright")

from metagpt.config2 import Config 
cfg = Config.default()

import asyncio
from metagpt.team import Team
from metagpt.roles import ProductManager, Architect, ProjectManager, Engineer

async def main():

    team = Team(config=cfg)  # 如果用环境变量法，也可以 Team() 不传
    team.hire([
        ProductManager(),
        Architect(),
        ProjectManager(),
        Engineer()
    ])

    # 这里写你的需求：生成什么工程仓库
    idea = "用Python写一个带CLI的Todo应用，要求支持新增、列表、完成、持久化到本地JSON，附带README与基本单测。"
    await team.run(n_round=3, idea=idea)

if __name__ == "__main__":
    asyncio.run(main())