#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构建“MetaGPT 写代码(WriteCode)最终一步”会打包给模型的上下文，
并为目标文件（pom.xml、SnakeGame.java、SnakeGameTest.java）分别生成完整 Prompt。

使用方法：
    python build_writecode_prompts.py --root [metagpt仓库路径] --out [prompt输出路径]

默认假设你的仓库结构为：
java_swing_snake_game/
  ├─ docs/...
  ├─ resources/...
  └─ java_swing_snake_game/
       ├─ pom.xml
       └─ src/...

脚本会尽量“贴近 MetaGPT 0.8 的写码阶段风格”，在每个 Prompt 中包含：
- 严格的输出要求（只输出文件完整内容；不要解释；覆盖目标路径）
- 任务上下文（PRD、System Design、Task、Requirements、Code Plan/Change、Code Summary、Sequence/Analysis 视图等）
- 现有目录树/已有文件（帮助模型理解工程结构）
- 目标文件的精确路径与语言/构建约束（JDK 17、Maven 等）

注意：
- 为防止模型输入过长，脚本对各段做了“可配置”的字符上限裁剪（保持原始开头 + 结尾片段）。
- 若某些目录/文件缺失，脚本会自动跳过该段落。
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

# -----------------------------
# 一些可调参数（预算/裁剪）
# -----------------------------
CHAR_LIMITS = {
    "prd": 60000,
    "system_design": 60000,
    "task": 40000,
    "requirements": 15000,
    "code_plan_change": 40000,
    "code_summary": 20000,
    "seq_flow": 20000,
    "data_api_design": 20000,
    "competitive_analysis": 20000,
    "project_tree": 8000,
    "existing_code": 40000,
}

PROJECT_DIR_NAME = "java_swing_snake_game"  # 工程目录名（外层同名）
SRC_MAIN_JAVA = "java_swing_snake_game/src/main/java/correct/SnakeGame.java"
SRC_TEST_JAVA = "java_swing_snake_game/src/test/java/correct/SnakeGameTest.java"
POM_XML = "java_swing_snake_game/pom.xml"

# -----------------------------
# 工具函数
# -----------------------------
def read_text(fp: Path, max_chars: Optional[int] = None) -> str:
    if not fp.exists() or not fp.is_file():
        return ""
    try:
        data = fp.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        data = fp.read_bytes().decode("utf-8", errors="ignore")
    data = data.replace("\r\n", "\n").replace("\r", "\n")
    if max_chars and len(data) > max_chars:
        head = data[: max_chars // 2]
        tail = data[-max_chars // 2 :]
        data = head + "\n\n... (truncated) ...\n\n" + tail
    return data.strip()

def read_json_pretty(fp: Path, max_chars: Optional[int] = None) -> str:
    if not fp.exists() or not fp.is_file():
        return ""
    try:
        obj = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
        data = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        # 如果 json 解析失败，按文本读
        data = read_text(fp, max_chars=None)
    if max_chars and len(data) > max_chars:
        head = data[: max_chars // 2]
        tail = data[-max_chars // 2 :]
        data = head + "\n\n... (truncated) ...\n\n" + tail
    return data.strip()

def list_latest_by_timestamp(dirp: Path, exts: Tuple[str, ...]) -> Optional[Path]:
    """按文件名中的时间戳（如 20250901144833）或修改时间取最新"""
    if not dirp.exists() or not dirp.is_dir():
        return None
    files = [p for p in dirp.glob("*") if p.is_file() and p.suffix.lower() in exts]
    if not files:
        return None

    def ts_from_name(p: Path) -> int:
        m = re.search(r"(\d{14})", p.name)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return 0
        # 退化：用 mtime 排序
        return int(p.stat().st_mtime)

    files.sort(key=lambda x: ts_from_name(x), reverse=True)
    return files[0]

def build_tree(root: Path, max_depth: int = 6, exclude_dirs: Tuple[str, ...] = (".git", "target", ".idea", ".venv", "__pycache__")) -> str:
    """生成目录树（适度限制深度）"""
    lines: List[str] = []
    root = root.resolve()

    def rel(p: Path) -> str:
        try:
            return str(p.relative_to(root))
        except Exception:
            return str(p)

    for base, dirs, files in os.walk(root):
        base_p = Path(base)
        # 过滤
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        depth = len(base_p.relative_to(root).parts) if base_p != root else 0
        if depth > max_depth:
            continue
        indent = "│   " * depth
        # 当前目录
        if base_p == root:
            lines.append(f"{base_p.name}/")
        else:
            lines.append(f"{indent}├── {base_p.name}/")
        # 文件
        for i, fn in enumerate(sorted(files)):
            fline = f"{indent}│   ├── {fn}"
            if i == len(files) - 1:
                fline = f"{indent}│   └── {fn}"
            lines.append(fline)
    tree_txt = "\n".join(lines)
    if len(tree_txt) > CHAR_LIMITS["project_tree"]:
        tree_txt = tree_txt[: CHAR_LIMITS["project_tree"]] + "\n... (truncated) ..."
    return tree_txt

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# -----------------------------
# 收集上下文
# -----------------------------
def collect_context(repo_root: Path) -> dict:
    """
    从给定仓库树中，抓取 MetaGPT 写码常用上下文素材。
    """
    ctx = {}

    docs = repo_root / "docs"
    res = repo_root / "resources"
    proj = repo_root / PROJECT_DIR_NAME

    # PRD
    prd_json = list_latest_by_timestamp(docs / "prd", (".json",))
    prd_md   = list_latest_by_timestamp(res / "prd", (".md",))
    ctx["prd"] = read_json_pretty(prd_json, CHAR_LIMITS["prd"]) if prd_json else ""
    if not ctx["prd"]:
        ctx["prd"] = read_text(prd_md, CHAR_LIMITS["prd"]) if prd_md else ""

    # System Design
    sd_json = list_latest_by_timestamp(docs / "system_design", (".json",))
    sd_md   = list_latest_by_timestamp(res / "system_design", (".md",))
    ctx["system_design"] = read_json_pretty(sd_json, CHAR_LIMITS["system_design"]) if sd_json else ""
    if not ctx["system_design"]:
        ctx["system_design"] = read_text(sd_md, CHAR_LIMITS["system_design"]) if sd_md else ""

    # Task
    task_json = list_latest_by_timestamp(docs / "task", (".json",))
    ctx["task"] = read_json_pretty(task_json, CHAR_LIMITS["task"]) if task_json else ""

    # Requirements（两处）
    req_txt_docs = docs / "requirement.txt"
    req_txt_root = repo_root / "requirements.txt"
    reqs = []
    r1 = read_text(req_txt_docs, CHAR_LIMITS["requirements"])
    r2 = read_text(req_txt_root, CHAR_LIMITS["requirements"])
    if r1: reqs.append(f"[docs/requirement.txt]\n{r1}")
    if r2: reqs.append(f"[requirements.txt]\n{r2}")
    ctx["requirements"] = "\n\n".join(reqs).strip()

    # Code Plan & Change（优先 docs，其次 resources）
    cpc_docs = docs / "code_plan_and_change"
    cpc_res  = res / "code_plan_and_change"
    def fold_dir_text(d: Path, label: str, exts=(".md", ".txt", ".json", ".yaml", ".yml")) -> str:
        if not d.exists() or not d.is_dir():
            return ""
        parts = []
        for p in sorted(d.glob("*")):
            if p.is_file() and p.suffix.lower() in exts:
                parts.append(f"\n# {label}/{p.name}\n{read_text(p, CHAR_LIMITS['code_plan_change']//4)}")
        return "\n".join(parts).strip()

    cpc = fold_dir_text(cpc_docs, "docs/code_plan_and_change")
    if not cpc:
        cpc = fold_dir_text(cpc_res, "resources/code_plan_and_change")
    ctx["code_plan_change"] = cpc

    # Code Summary（优先 docs、其次 resources）
    cs_docs = docs / "code_summary"
    cs_res  = res / "code_summary"
    ctx["code_summary"] = fold_dir_text(cs_docs, "docs/code_summary", exts=(".md", ".txt", ".json"))
    if not ctx["code_summary"]:
        ctx["code_summary"] = fold_dir_text(cs_res, "resources/code_summary", exts=(".md", ".txt", ".json"))

    # 其他辅助图（Mermaid 等）
    ctx["seq_flow"] = read_text(list_latest_by_timestamp(res / "seq_flow", (".mmd",)), CHAR_LIMITS["seq_flow"]) or ""
    ctx["data_api_design"] = read_text(list_latest_by_timestamp(res / "data_api_design", (".mmd",)), CHAR_LIMITS["data_api_design"]) or ""
    ctx["competitive_analysis"] = read_text(list_latest_by_timestamp(res / "competitive_analysis", (".mmd",)), CHAR_LIMITS["competitive_analysis"]) or ""

    # 现有代码（有时写码阶段会参考已有）
    ctx["existing_pom"] = read_text(proj / "pom.xml", CHAR_LIMITS["existing_code"])
    ctx["existing_main"] = read_text(repo_root / SRC_MAIN_JAVA, CHAR_LIMITS["existing_code"])
    ctx["existing_test"] = read_text(repo_root / SRC_TEST_JAVA, CHAR_LIMITS["existing_code"])

    # 工程树
    ctx["project_tree"] = build_tree(repo_root, max_depth=6)

    return ctx

# -----------------------------
# Prompt 拼装
# -----------------------------
BASE_HEADER = """You are a senior Java engineer acting as MetaGPT's WriteCode action. Your job is to generate the COMPLETE content of ONE target file, strictly following the constraints and context below.

# Output Rules (VERY IMPORTANT)
- Output ONLY the full file content for the requested path. No explanations, no comments outside the file.
- Do NOT wrap the whole file inside Markdown fences unless explicitly requested; just return raw file content.
- Ensure the result compiles (JDK 17) and runs with Maven in this project layout.
- Respect the package names and paths exactly.

"""

CONSTRAINTS = """# Project Constraints
- Language: **Java (JDK 17)**
- Build: **Maven**
- Required layout (must match exactly):
  - pom.xml
  - src/main/java/correct/SnakeGame.java
  - src/test/java/correct/SnakeGameTest.java
- Run GUI:
  mvn -q -DskipTests exec:java -Dexec.mainClass=correct.SnakeGame
"""

def mk_section(title: str, body: str) -> str:
    if not body:
        return ""
    return f"\n\n# {title}\n{body}"

def assemble_prompt(ctx: dict, target_path: str, file_hint: str) -> str:
    """构造单文件写码 Prompt"""
    pieces = [
        BASE_HEADER,
        f"# Target File\n{target_path}\n",
        CONSTRAINTS,
        mk_section("Primary Requirements (PRD)", ctx.get("prd", "")),
        mk_section("System Design", ctx.get("system_design", "")),
        mk_section("Task (Latest)", ctx.get("task", "")),
        mk_section("Requirements Files", ctx.get("requirements", "")),
        mk_section("Code Plan & Change", ctx.get("code_plan_change", "")),
        mk_section("Code Summary", ctx.get("code_summary", "")),
        mk_section("Sequence / Flow (Mermaid)", ctx.get("seq_flow", "")),
        mk_section("Data API Design (Mermaid)", ctx.get("data_api_design", "")),
        mk_section("Competitive Analysis (Mermaid)", ctx.get("competitive_analysis", "")),
        mk_section("Project Tree (partial)", ctx.get("project_tree", "")),
        mk_section("Existing File Snapshot (if present)", file_hint),
        "\n# Final Instruction\nPlease output the COMPLETE content of the target file ONLY.",
    ]
    return "\n".join([p for p in pieces if p]).strip() + "\n"

def build_prompts(repo_root: Path, out_dir: Path):
    ensure_dir(out_dir)
    ctx = collect_context(repo_root)

    # 针对三个目标文件分别构建 Prompt
    targets = [
        (POM_XML, ctx.get("existing_pom", "")),
        (SRC_MAIN_JAVA, ctx.get("existing_main", "")),
        (SRC_TEST_JAVA, ctx.get("existing_test", "")),
    ]

    for path_str, hint in targets:
        prompt = assemble_prompt(ctx, target_path=path_str, file_hint=hint)
        out_fp = out_dir / (Path(path_str).name + ".prompt.txt")
        out_fp.write_text(prompt, encoding="utf-8")
        print(f"[OK] prompt written -> {out_fp}")

    # 也可生成一个“合并总提示”，指导模型按顺序产出三个文件（不强制）
    merged = []
    for path_str, hint in targets:
        merged.append(assemble_prompt(ctx, target_path=path_str, file_hint=hint))
    merged_fp = out_dir / "ALL_FILES_sequential.prompts.txt"
    merged_fp.write_text("\n\n\n" + ("=" * 80) + "\n\n\n".join(merged), encoding="utf-8")
    print(f"[OK] merged prompts -> {merged_fp}")

# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=str, default=".", help="仓库根目录（包含 docs/ resources/ 和工程目录）")
    parser.add_argument("--out", type=str, default="./prompts", help="输出 Prompt 的目录")
    args = parser.parse_args()

    repo_root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()

    # 轻量检查
    must_exist = ["docs", "resources", PROJECT_DIR_NAME]
    for d in must_exist:
        if not (repo_root / d).exists():
            print(f"[WARN] {d} not found under {repo_root}, script will continue with available parts.")
    build_prompts(repo_root, out_dir)

if __name__ == "__main__":
    main()
