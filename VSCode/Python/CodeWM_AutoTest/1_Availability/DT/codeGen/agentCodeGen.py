#=====================================基础环境配置=====================================#
import os
import json
from typing import List
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

import asyncio
from pathlib import Path
from types import SimpleNamespace
from metagpt.config2 import Config
from metagpt.context import Context
from metagpt.team import Team
from metagpt.roles.engineer import Engineer
from metagpt.actions.write_code import WriteCode
from metagpt.utils.git_repository import GitRepository
from metagpt.utils.project_repo import ProjectRepo

PROJECT_PATH = Path("/home/zhaorz/project/CodeWM/MetaGPT/workspace/java_snake_game").resolve()
RECOVER_ROOT = Path("/home/zhaorz/project/CodeWM/MetaGPT/workspace/storage/team").resolve()
PROJECT_HINT = "java_snake_game"  # 你的项目前缀（按你的目录命名习惯调整）

from metagpt.utils.git_repository import GitRepository
from metagpt.utils.project_repo import ProjectRepo
from metagpt.schema import Document

async def _run_actions_manually(company: Team, eng: Engineer, actions: List[WriteCode]):
    """
    直接逐个执行 WriteCode 实例，绕过 Team 调度差异。
    为动作绑定 context/env/llm/rc，确保 run() 有完整依赖。
    """
    ctx = getattr(company, "context", None)
    env = getattr(company, "env", None)
    # 选一个可用的 llm：优先 Engineer.llm，其次 Context.config.llm
    llm = getattr(eng, "llm", None)
    if llm is None:
        try:
            llm = getattr(getattr(ctx, "config", None), "llm", None)
            if llm is not None:
                setattr(eng, "llm", llm)
        except Exception:
            pass

    # ★ 关键修复：把 company.context.repo / git_repo 注入到动作用的 context 中
    repo_obj = getattr(getattr(company, "context", None), "repo", None)
    git_repo = getattr(repo_obj, "git_repo", None) if repo_obj is not None else None
    # 注入到 context
    if ctx is not None and repo_obj is not None:
        try:
            if getattr(ctx, "repo", None) is None:
                ctx.repo = repo_obj
        except Exception:
            ctx.__dict__["repo"] = repo_obj
    if ctx is not None and git_repo is not None:
        try:
            ctx.git_repo = git_repo
        except Exception:
            ctx.__dict__["git_repo"] = git_repo
    # 调试：看一下 workdir 是否可用
    try:
        print(">> ctx.git_repo.workdir =", getattr(getattr(ctx, "git_repo", None), "workdir", None))
    except Exception:
        pass
    
    for i, act in enumerate(actions, 1):
        # --- 预写入 docs：把 i_context 中的设计/任务文档落到仓库，以便后续依赖引用 ---
        try:
            i_ctx = getattr(act, "i_context", None)
            i_ctx_json = {}
            if isinstance(i_ctx, Document):
                # i_ctx.content 是 JSON 字符串
                i_ctx_json = json.loads(getattr(i_ctx, "content", "") or "{}")
            elif isinstance(i_ctx, dict):
                i_ctx_json = i_ctx
            dd = (i_ctx_json or {}).get("design_doc") or {}
            td = (i_ctx_json or {}).get("task_doc") or {}
            if dd.get("filename") is not None:
                await ctx.repo.docs.system_design.save(
                    filename=dd["filename"],
                    content=dd.get("content", ""),
                    dependencies=[]
                )
            if td.get("filename") is not None:
                await ctx.repo.docs.task.save(
                    filename=td["filename"],
                    content=td.get("content", ""),
                    dependencies=[]
                )
        except Exception as e:
            print(">> warn: pre-save docs failed:", e)
        # 绑定必要依赖（存在才注入，兼容不同版本）
        for setter, value in [
            (getattr(act, "set_context", None), ctx),
            (getattr(act, "set_env", None), env),
            (getattr(act, "set_llm", None), llm),
        ]:
            if callable(setter) and value is not None:
                setter(value)
        if getattr(act, "context", None) is None and ctx is not None:
            try: act.context = ctx
            except Exception: pass
        if getattr(act, "rc", None) is None and getattr(eng, "rc", None) is not None:
            try: act.rc = eng.rc
            except Exception: pass
            
        # 补齐 config（WriteCode.run 会访问 self.config.inc）
        if getattr(act, "config", None) is None and getattr(ctx, "config", None) is not None:
            try: act.config = ctx.config
            except Exception:
                try: act.__dict__["config"] = ctx.config
                except Exception: pass
        # 兼容 Document / dict 两种 i_context 形态
        i_ctx = getattr(act, "i_context", None)
        if isinstance(i_ctx, Document):
            fname = getattr(i_ctx, "filename", "unknown")
        elif isinstance(i_ctx, dict):
            fname = i_ctx.get("filename", "unknown")
        else:
            fname = "unknown"
        print(f">> [manual] Run {i}/{len(actions)}: WriteCode -> {fname}")
        # 执行动作，拿到 CodingContext
        coding_context = await act.run()

        # --- 落盘 src 并更新依赖（Replica of Engineer._act_sp_with_cr 的关键部分） ---
        try:
            deps = set()
            if getattr(coding_context, "design_doc", None):
                # 优先用 root_relative_path；没有就拼接
                ddoc = coding_context.design_doc
                deps.add(getattr(ddoc, "root_relative_path", None) or f"{ddoc.root_path}/{ddoc.filename}")
            if getattr(coding_context, "task_doc", None):
                tdoc = coding_context.task_doc
                deps.add(getattr(tdoc, "root_relative_path", None) or f"{tdoc.root_path}/{tdoc.filename}")
            if getattr(ctx.config, "inc", False) and getattr(coding_context, "code_plan_and_change_doc", None):
                cpc = coding_context.code_plan_and_change_doc
                deps.add(getattr(cpc, "root_relative_path", None) or f"{cpc.root_path}/{cpc.filename}")

            # WriteCode.run 里可能把最终文件名改成 *_both.ext，所以以 code_doc.filename 为准
            out_filename = getattr(getattr(coding_context, "code_doc", None), "filename", None) or coding_context.filename
            out_content  = getattr(getattr(coding_context, "code_doc", None), "content", "")

            await act.repo.srcs.save(
                filename=out_filename,
                dependencies=[d for d in deps if d],
                content=out_content,
            )
            print(f">> saved: src/{out_filename}")
        except Exception as e:
            print(">> error: save src failed:", e)

async def main():
    # 1) 用与你原先创建快照一致的配置载入上下文
    local_vllm = Config.default() 
    local_vllm.update_via_cli(str(PROJECT_PATH), project_name=PROJECT_HINT, inc=False, reqa_file="", max_auto_summarize_code=0)
    ctx = Context(config=local_vllm)
    ctx.config.inc = False

    # 2) 精确指向“某一次运行”的快照目录（不是根目录）
    RECOVER = RECOVER_ROOT
    print(">> recovering from:", RECOVER)

    # 不再依赖 Team.deserialize 的 Engineer；只用 team.json 取 code_todos
    print(">> team.json exists:", (RECOVER / "team.json").exists(), "path:", RECOVER / "team.json")

    # --- 新建最小可用的 Context.repo/git_repo/src_workspace ---
    PROJECT_PATH.mkdir(parents=True, exist_ok=True)
    # 约定 src_workspace：与 MetaGPT 一致，workdir/name 结构
    src_workspace = PROJECT_PATH / PROJECT_PATH.name
    src_workspace.mkdir(parents=True, exist_ok=True)
    docs_sd = PROJECT_PATH / "docs/system_design"; docs_sd.mkdir(parents=True, exist_ok=True)
    docs_task = PROJECT_PATH / "docs/task"; docs_task.mkdir(parents=True, exist_ok=True)
    resources_dir = PROJECT_PATH / "resources"; resources_dir.mkdir(parents=True, exist_ok=True)

    try:
        git_repo = GitRepository(str(PROJECT_PATH))
    except TypeError:
        git_repo = GitRepository(workdir=str(PROJECT_PATH))
    ctx.git_repo = git_repo
    ctx.repo = ProjectRepo(git_repo)
    ctx.src_workspace = src_workspace
    print(">> ctx.git_repo.workdir =", getattr(ctx.git_repo, "workdir", None))

    # --- 读取 team.json 中的 code_todos（直接作为权威来源）---
    team_json = RECOVER / "team.json"
    with team_json.open("r", encoding="utf-8") as f:
        team_obj = json.load(f)
    roles_obj = ((team_obj or {}).get("env") or {}).get("roles") or {}
    eng_obj = roles_obj.get("Engineer") or roles_obj.get("engineer") or {}
    code_todos_raw = list(eng_obj.get("code_todos") or [])
    if not code_todos_raw:
        raise RuntimeError("team.json 中 Engineer.code_todos 为空，无法继续。")

    # --- 仅为兼容 _run_actions_manually 的签名，构造一个简易 company stub ---
    company_stub = SimpleNamespace(context=ctx, env=None)

    # 3) 新建一个“干净”的 Engineer，绑定 LLM/Context（不反序列化）
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
    eng = Engineer(config=local_vllm)
    eng.config = ctx.config
    eng.context = ctx
    eng.llm.config.__dict__["xargs"] = xargs
    # 进一步确保角色层也关闭增量模式
    # try: eng.config.inc = False
    # except Exception: pass

    # 4) 定位 Engineer，切换到 BY_ORDER，并用 set_actions 设置待执行动作
    # 若反序列化后 code_todos 为空：先从 RECOVER/team.json 回填；若仍为空再尝试 docs/* 重建
    code_todos = code_todos_raw  # 直接使用快照里的待办列表
    
    try:
        from metagpt.const import ReActMode
        eng._set_react_mode(ReActMode.BY_ORDER)
    except Exception:
        eng._set_react_mode(react_mode="by_order")

    # 将 code_todos 显式实例化为 WriteCode() 动作并注入（带上 i_context/prefix/desc）
    actions = []
    for td in code_todos:
        if td is None:
            continue
        if not isinstance(td, dict):
            continue
        # 用 schema.Document 还原 i_context（更稳，不用裸 dict）
        i_ctx_dict = td.get("i_context") or {}
        doc = Document(**i_ctx_dict)
        act = WriteCode(i_context=doc, context=ctx, llm=eng.llm)
        # 同步 prefix/desc（可选）
        if "prefix" in td: setattr(act, "prefix", td.get("prefix", ""))
        if "desc" in td:   setattr(act, "desc", td.get("desc", ""))
        actions.append(act)
    if not actions:
        raise RuntimeError("Engineer.code_todos 为空或格式异常，无法生成 WriteCode 动作。")
    # 可选：仅用于日志显示，不依赖 Team 调度
    try:
        eng.set_actions(actions)
        setattr(eng, "enabled", True)
    except Exception:
        pass

    # 显式复位运行指针到动作起点（不同版本字段名略有出入，能设就设）
    if hasattr(eng, "rc"):
        try:
            # 尽量多复位几个常见字段名
            for k, v in [
                ("cur_action_idx", 0),
                ("state", 0),                # -1(未入场) -> 0(准备执行)
                ("reacted_cnt", 0),
                ("cur_action", None),
            ]:
                if hasattr(eng.rc, k):
                    setattr(eng.rc, k, v)
        except Exception:
            pass

    # 5) 观察当前断点
    code_todos = code_todos or []
    print("eng.code_todos:", [
        (td.get("i_context", {}) if isinstance(td, dict) else {}).get("filename")
        for td in code_todos
    ])
    print(">> ready, ctx.git_repo.workdir =", getattr(getattr(ctx, "git_repo", None), "workdir", None))
    
    # 6) 不依赖 Team 调度，直接手动逐个执行动作（最稳妥）
    await _run_actions_manually(
        # 传入我们构造的最小 company_stub（只需要 .context / .env）
        company_stub,
        eng,
        actions
    )
    print(">> [manual] all WriteCode actions finished.")

if __name__ == "__main__":
    asyncio.run(main())
