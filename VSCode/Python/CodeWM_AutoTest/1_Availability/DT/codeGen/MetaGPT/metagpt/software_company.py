#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
from pathlib import Path

import agentops
import typer
from typing import Dict, Any, Optional

from metagpt.const import CONFIG_ROOT
from metagpt.utils.project_repo import ProjectRepo

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)


def generate_repo(
    idea: str,
    investment: float=3.0,
    n_round: int=5,
    code_review: bool=True,
    run_tests: bool=False,
    implement: bool=True,
    project_name: str="",
    inc: bool=False,
    project_path: str="",
    reqa_file: str="",
    max_auto_summarize_code: int=0,
    recover_path: Optional[str]=None,
    *,
    archCFG: str="openai.yaml",
    xargs: Optional[Dict[str, Any]] = None,
) -> ProjectRepo:
    """Run the startup logic. Can be called from CLI or other Python scripts."""
    from metagpt.config2 import Config
    from metagpt.context import Context
    from metagpt.roles import (
        Architect,
        Engineer,
        ProductManager,
        ProjectManager,
        QaEngineer,
    )
    from metagpt.team import Team

    config_arch = Config.from_home(archCFG)
    if config_arch is None:
        raise FileNotFoundError(f"~/.metagpt/{archCFG} 不存在")
    config_eng = Config.default()
    if config_arch.agentops_api_key != "":
        agentops.init(config_arch.agentops_api_key, tags=["software_company"])

    # 上下文内容两个配置都需要同步更新
    config_arch.update_via_cli(project_path, project_name, inc, reqa_file, max_auto_summarize_code)
    config_eng.update_via_cli(project_path, project_name, inc, reqa_file, max_auto_summarize_code)
    # 手动传入 xargs 字段
    if xargs is not None:
        config_eng.llm.__dict__.setdefault("xargs", {})
        config_eng.llm.__dict__["xargs"].update(xargs)
    ctx_arch = Context(config=config_arch)

    if not recover_path:
        company = Team(context=ctx_arch)
        company.hire(
            [
                ProductManager(config=config_arch),
                Architect(config=config_arch),
                ProjectManager(config=config_arch),
            ]
        )

        if implement or code_review:
            engineer = Engineer(n_borg=5, use_code_review=code_review, config=config_eng)
            company.hire([engineer])

        if run_tests:
            company.hire([QaEngineer(config=config_arch)])
            if n_round < 8:
                n_round = 8  # If `--run-tests` is enabled, at least 8 rounds are required to run all QA actions.
    else:
        stg_path = Path(recover_path)
        if not stg_path.exists() or not str(stg_path).endswith("team"):
            raise FileNotFoundError(f"{recover_path} not exists or not endswith `team`")

        company = Team.deserialize(stg_path=stg_path, context=ctx_arch)
        if xargs is not None:
            #TODO: 通过查找`MetaGPT/metagpt/team.py`的`class Team(BaseModel).hire`方法可知角色信息在`Team.env`中
            #TODO: 通过查找`MetaGPT/metagpt/environment/base_env.py`的`class Environment(ExtEnv)`可知角色信息为该类中的字段:
            #TODO: `roles: dict[str, SerializeAsAny["Role"]] = Field(default_factory=dict, validate_default=True)`
            for r in company.env.roles.values():
                if isinstance(r, Engineer):
                    # 改它的 config（供后续可能的 LLM 重建/worker 使用）
                    r.config.llm.__dict__.setdefault("xargs", {})
                    r.config.llm.__dict__["xargs"].update(xargs)
                    # 也改当前已存在的 llm 对象
                    if getattr(r, "llm", None):
                        r.llm.config.__dict__.setdefault("xargs", {})
                        r.llm.config.__dict__["xargs"].update(xargs)
                    # 如果有 borg/子工程师，也一并覆盖
                    for b in getattr(r, "borgs", []):
                        b.config.llm.__dict__.setdefault("xargs", {})
                        b.config.llm.__dict__["xargs"].update(xargs)
        idea = company.idea

    company.invest(investment)
    company.run_project(idea)
    asyncio.run(company.run(n_round=n_round))

    if config_arch.agentops_api_key != "":
        agentops.end_session("Success")

    return ctx_arch.repo


@app.command("", help="Start a new project.")
def startup(
    idea: str = typer.Argument(None, help="Your innovative idea, such as 'Create a 2048 game.'"),
    investment: float = typer.Option(default=3.0, help="Dollar amount to invest in the AI company."),
    n_round: int = typer.Option(default=5, help="Number of rounds for the simulation."),
    code_review: bool = typer.Option(default=True, help="Whether to use code review."),
    run_tests: bool = typer.Option(default=False, help="Whether to enable QA for adding & running tests."),
    implement: bool = typer.Option(default=True, help="Enable or disable code implementation."),
    project_name: str = typer.Option(default="", help="Unique project name, such as 'game_2048'."),
    inc: bool = typer.Option(default=False, help="Incremental mode. Use it to coop with existing repo."),
    project_path: str = typer.Option(
        default="",
        help="Specify the directory path of the old version project to fulfill the incremental requirements.",
    ),
    reqa_file: str = typer.Option(
        default="", help="Specify the source file name for rewriting the quality assurance code."
    ),
    max_auto_summarize_code: int = typer.Option(
        default=0,
        help="The maximum number of times the 'SummarizeCode' action is automatically invoked, with -1 indicating "
        "unlimited. This parameter is used for debugging the workflow.",
    ),
    recover_path: str = typer.Option(default=None, help="recover the project from existing serialized storage"),
    init_config: bool = typer.Option(default=False, help="Initialize the configuration file for MetaGPT."),
):
    """Run a startup. Be a boss."""
    if init_config:
        copy_config_to()
        return

    if idea is None:
        typer.echo("Missing argument 'IDEA'. Run 'metagpt --help' for more information.")
        raise typer.Exit()

    return generate_repo(
        idea,
        investment,
        n_round,
        code_review,
        run_tests,
        implement,
        project_name,
        inc,
        project_path,
        reqa_file,
        max_auto_summarize_code,
        recover_path,
    )


DEFAULT_CONFIG = """# Full Example: https://github.com/geekan/MetaGPT/blob/main/config/config2.example.yaml
# Reflected Code: https://github.com/geekan/MetaGPT/blob/main/metagpt/config2.py
# Config Docs: https://docs.deepwisdom.ai/main/en/guide/get_started/configuration.html
llm:
  api_type: "openai"  # or azure / ollama / groq etc.
  model: "gpt-4-turbo"  # or gpt-3.5-turbo
  base_url: "https://api.openai.com/v1"  # or forward url / other llm url
  api_key: "YOUR_API_KEY"
"""


def copy_config_to():
    """Initialize the configuration file for MetaGPT."""
    target_path = CONFIG_ROOT / "config2.yaml"

    # 创建目标目录（如果不存在）
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # 如果目标文件已经存在，则重命名为 .bak
    if target_path.exists():
        backup_path = target_path.with_suffix(".bak")
        target_path.rename(backup_path)
        print(f"Existing configuration file backed up at {backup_path}")

    # 复制文件
    target_path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    print(f"Configuration file initialized at {target_path}")


if __name__ == "__main__":
    app()
