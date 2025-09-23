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

from pathlib import Path
import os
from metagpt.software_company import generate_repo

# === 1) 你的项目路径（旧仓库，仅保留非代码产物） ===
# MetaGPT 会在该路径进行增量生成
PROJECT_PATH = Path("/home/zhaorz/project/CodeWM/MetaGPT/workspace/java_snake_game").resolve()
RECOVER_PATH = Path("/home/zhaorz/project/CodeWM/MetaGPT/workspace/team").resolve()

# === 2) 校验必要目录 ===
assert (PROJECT_PATH / "docs").exists(), f"缺少 docs/ 目录：{PROJECT_PATH/'docs'}"
# resources/ 不是必须；有就会被流程利用（如果你在 MetaGPT 中启用相关读取）

# === 3) 运行（仅实施，关闭评审/测试；基于 docs 增量生成） ===
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

repo = generate_repo(
    idea="",
    inc=True,                         # 增量模式：复用 PROJECT_PATH 下的文档资产
    project_path=str(PROJECT_PATH),   # 指定旧仓库根路径
    recover_path=str(RECOVER_PATH),   # 从上次 checkpoint 恢复（可选）
    implement=True,                   # 打开实施阶段（Engineer 写代码）
    code_review=False,                # 仅 Engineer：关掉 CodeReview
    run_tests=False,                  # 如需同时生成/运行测试可改 True
    n_round=5,                        # 回合数，可按复杂度增减
    archCFG="openai.yaml",            # 指定架构师配置文件
    xargs=xargs,                      # 传递给 Engineer 的 LLM 扩展参数
)

print("✅ 已触发 MetaGPT 增量生成（Engineer）。")
print(f"项目路径：{PROJECT_PATH}")
print("提示：代码将写入该项目的工作区（通常位于项目路径下的 workspace/ 或既有代码目录约定处）。")