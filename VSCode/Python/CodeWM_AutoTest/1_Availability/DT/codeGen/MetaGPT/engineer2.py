# example demo file
# MetaGPT/metagpt/roles/di/engineer2.py

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field

from metagpt.logs import logger

# from metagpt.actions.write_code_review import ValidateAndRewriteCode
from metagpt.prompts.di.engineer2 import (
    CURRENT_STATE,
    ENGINEER2_INSTRUCTION,
    WRITE_CODE_PROMPT,
    WRITE_CODE_SYSTEM_PROMPT,
)
from metagpt.roles.di.role_zero import RoleZero
from metagpt.schema import UserMessage
from metagpt.strategy.experience_retriever import ENGINEER_EXAMPLE
from metagpt.tools.libs.cr import CodeReview
from metagpt.tools.libs.deployer import Deployer
from metagpt.tools.libs.git import git_create_pull
from metagpt.tools.libs.image_getter import ImageGetter
from metagpt.tools.libs.terminal import Terminal
from metagpt.tools.tool_registry import register_tool
from metagpt.utils.common import CodeParser, awrite
from metagpt.utils.report import EditorReporter
from metagpt.utils.role_zero_utils import get_plan_status


@register_tool(include_functions=["write_new_code"])
class Engineer2(RoleZero):
    name: str = "Alex"
    profile: str = "Engineer"
    goal: str = "Take on game, app, web development and deployment."
    instruction: str = ENGINEER2_INSTRUCTION
    terminal: Terminal = Field(default_factory=Terminal, exclude=True)
    deployer: Deployer = Field(default_factory=Deployer, exclude=True)
    tools: list[str] = [
        "Plan",
        "Editor",
        "RoleZero",
        "Terminal:run_command",
        "Browser:goto,scroll",
        "git_create_pull",
        "SearchEnhancedQA",
        "Engineer2",
        "CodeReview",
        "ImageGetter",
        "Deployer",
    ]
    # SWE Agent parameter
    run_eval: bool = False
    output_diff: str = ""
    max_react_loop: int = 40

    async def _think(self) -> bool:
        await self._format_instruction()
        res = await super()._think()
        return res

    async def _format_instruction(self):
        """
        Display the current terminal and editor state.
        This information will be dynamically added to the command prompt.
        """
        current_directory = (await self.terminal.run_command("pwd")).strip()
        self.editor._set_workdir(current_directory)
        state = {
            "editor_open_file": self.editor.current_file,
            "current_directory": current_directory,
        }
        self.cmd_prompt_current_state = CURRENT_STATE.format(**state).strip()

    def _update_tool_execution(self):
        # validate = ValidateAndRewriteCode()
        cr = CodeReview()
        image_getter = ImageGetter()
        self.exclusive_tool_commands.append("Engineer2.write_new_code")
        if self.run_eval is True:
            # Evalute tool map
            self.tool_execution_map.update(
                {
                    "git_create_pull": git_create_pull,
                    "Engineer2.write_new_code": self.write_new_code,
                    "ImageGetter.get_image": image_getter.get_image,
                    "CodeReview.review": cr.review,
                    "CodeReview.fix": cr.fix,
                    "Terminal.run_command": self._eval_terminal_run,
                    "RoleZero.ask_human": self._end,
                    "RoleZero.reply_to_human": self._end,
                    "Deployer.deploy_to_public": self._deploy_to_public,
                }
            )
        else:
            # Default tool map
            self.tool_execution_map.update(
                {
                    "git_create_pull": git_create_pull,
                    "Engineer2.write_new_code": self.write_new_code,
                    "ImageGetter.get_image": image_getter.get_image,
                    "CodeReview.review": cr.review,
                    "CodeReview.fix": cr.fix,
                    "Terminal.run_command": self.terminal.run_command,
                    "Deployer.deploy_to_public": self._deploy_to_public,
                }
            )

    def _retrieve_experience(self) -> str:
        return ENGINEER_EXAMPLE

    async def write_new_code(self, path: str, file_description: str = "") -> str:
        """Write a new code file.

        Args:
            path (str): The absolute path of the file to be created.
            file_description (optional, str): Brief description and important notes of the file content, must be very concise and can be empty. Defaults to "".
        """
        # If the path is not absolute, try to fix it with the editor's working directory.
        path = self.editor._try_fix_path(path)
        plan_status, _ = self._get_plan_status()
        file_name = os.path.basename(path)
        file_ext = os.path.splitext(path)[1].lower()
        created_file_path="/root/wanghao/ast/MetaGPT/metagpt/roles/di/created_code.txt"
        with open(created_file_path, "r", encoding="utf-8") as f:
            file_content=f.read()
        # Handle Python files with watermark approach
        if file_ext == '.py' or file_ext == '.java':
            prompt = WM_PROMPT1.format(
                user_requirement=self.planner.plan.goal,
                file_description=file_description,
                file_name=file_name,
            )
            pattern = r"(/[^ '\"]*docs[^ '\"]*)"
            matches = re.findall(pattern, prompt)
            md_filepath = matches[0] if matches else ""
            md_content = ""
            if not md_filepath:
                print("未找到包含 'docs' 的路径。")
            else:
                docs_path = Path(md_filepath)
                parts = docs_path.parts
                if "docs" in parts:
                    docs_index = parts.index("docs")
                    docs_path = Path(*parts[:docs_index+1])
                    md_filename = list(docs_path.glob("*.md"))
                    try:
                        with open(md_filename[0], "r", encoding="utf-8") as file:
                            md_content = file.read()
                    except FileNotFoundError:
                        md_content = ""        
                    prompt = WM_PROMPT2.format(
                        user_requirement=self.planner.plan.goal,
                        file_description=file_description,
                        file_name=file_name,
                        md_content=md_content,
                        created_code=f"The following are other Python files that have been generated (please refer to their implementation):\n{file_content}" if file_content.strip() else ""
                    )

            with open("/root/wanghao/ast/MetaGPT/metagpt/roles/di/prompt_memory.log", "a", encoding="utf-8") as f:
                f.write(f"Prompt:\n{prompt}\n")

            if file_ext == '.py':
            # Call watermark generation API
                result = generate_watermark_code(
                    prompt=prompt,
                    language='python',
                    model_name="deepseek",
                    target_size=60
                )
            elif file_ext == '.java':
                result = generate_watermark_code(
                    prompt=prompt,
                    language='java',
                    model_name="deepseek",
                    target_size=60
                )

            # 添加详细的调试信息
            print(f"generate_watermark_code 返回结果类型: {type(result)}")
            print(f"generate_watermark_code 返回结果内容: {result}")
            
            # Check if result is an error message
            if isinstance(result, str) and result.startswith(("请求错误", "生成失败", "解析响应失败", "未知错误", "连接错误")):
                raise Exception(f"生成带水印的代码失败: {result}")

            # Extract generated code from result
            if isinstance(result, dict) and result.get("success", False):
                if "res" in result and "code" in result["res"]:
                    code = result["res"]["code"]
                else:
                    print(f"警告: result['res'] 结构异常: {result.get('res', 'res键不存在')}")
                    raise Exception(f"生成带水印的代码失败: 响应中缺少 code 字段，实际结构: {result}")
            else:
                print(f"错误: result 不是字典或 success 不为 True")
                print(f"result 是否为字典: {isinstance(result, dict)}")
                if isinstance(result, dict):
                    print(f"success 字段值: {result.get('success', '不存在')}")
                raise Exception(f"生成带水印的代码失败: 响应格式无效，实际结果: {result}")

        # Handle other file types with standard approach
        else:
            prompt = WRITE_CODE_PROMPT.format(
                user_requirement=self.planner.plan.goal,
                plan_status=plan_status,
                file_path=path,
                file_description=file_description,
                file_name=file_name,
            )
            # Sometimes the Engineer repeats the last command to respond.
            # Replace the last command with a manual prompt to guide the Engineer to write new code.
            memory = self.rc.memory.get(self.memory_k)[:-1]
            context = self.llm.format_msg(memory + [UserMessage(content=prompt)])

            async with EditorReporter(enable_llm_stream=True) as reporter:
                await reporter.async_report({"type": "code", "filename": Path(path).name, "src_path": path}, "meta")
                rsp = await self.llm.aask(context, system_msgs=[WRITE_CODE_SYSTEM_PROMPT])
                code = CodeParser.parse_code(text=rsp)
                await reporter.async_report(path, "path")

        # Write the code to file
        await awrite(path, code)
        if file_ext == '.py':
            #if md_content:
                with open(created_file_path, "a", encoding="utf-8") as f:
                    f.write(f"\n ===== {file_name} =====\n{code}\n")

        return f"文件 {path} 已成功创建，包含内容:\n{code}"

    async def _deploy_to_public(self, dist_dir):
        """fix the dist_dir path to absolute path before deploying
        Args:
            dist_dir (str): The dist directory of the web project after run build. This must be an absolute path.
        """
        # Try to fix the path with the editor's working directory.
        if not Path(dist_dir).is_absolute():
            default_dir = self.editor._try_fix_path(dist_dir)
            if not default_dir.exists():
                raise ValueError("dist_dir must be an absolute path.")
            dist_dir = default_dir
        return await self.deployer.deploy_to_public(dist_dir)

    async def _eval_terminal_run(self, cmd):
        """change command pull/push/commit to end."""
        if any([cmd_key_word in cmd for cmd_key_word in ["pull", "push", "commit"]]):
            # The Engineer2 attempts to submit the repository after fixing the bug, thereby reaching the end of the fixing process.
            logger.info("Engineer2 use cmd:{cmd}\nCurrent test case is finished.")
            # Set self.rc.todo to None to stop the engineer.
            self._set_state(-1)
        else:
            command_output = await self.terminal.run_command(cmd)
        return command_output

    async def _end(self):
        if not self.planner.plan.is_plan_finished():
            self.planner.plan.finish_all_tasks()
        return await super()._end()
