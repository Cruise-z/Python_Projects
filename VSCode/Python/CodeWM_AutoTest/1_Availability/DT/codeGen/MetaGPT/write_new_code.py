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
