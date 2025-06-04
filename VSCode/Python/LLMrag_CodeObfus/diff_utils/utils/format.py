from tree_sitter import Language, Parser
from enum import Enum
from dataclasses import dataclass, fields, is_dataclass
from typing import List, Optional, Tuple, Any
import subprocess
import textwrap
import re

content_tag1_1 = """
This obfuscation type targets the names of user-defined symbols within a function or method. It performs randomized renaming of function (method) names, parameter names, and local variable names, while strictly preserving program semantics.

The transformation is governed by the following constraints:
- All renamed identifiers must be semantically equivalent to their originals, with no change to logic, behavior, or type correctness.
- Function names may be renamed as long as **all corresponding call sites are updated consistently**.
- Parameter names can be replaced with arbitrary but valid alternatives, provided **all references within the function body are correctly updated**.
- Local variable names may be renamed, individually or in batches, with **consistent substitutions across all reads and writes** within their scope.
- Renamed identifiers must **not** collide with existing global names, imported symbols, or scoped declarations.

Identifier names can be generated in different styles to increase variability or mimic realistic coding practices. These include:
- Completely random but syntactically valid identifiers (e.g., `a9fG_23`), ensuring they comply with language-specific naming rules (e.g., not starting with a digit).
- Patterned or style-based naming conventions such as:
  - `camelCase` (e.g., `processedData`)
  - `PascalCase` (e.g., `ProcessedData`)
  - `snake_case` (e.g., `processed_data`)
  - `_underscore_init` (e.g., `_tempVar`)
These styles may be applied uniformly or mixed randomly to confuse naming-based heuristics or stylistic pattern recognition.

This form of obfuscation aims to disrupt name-based heuristics in static analysis, reverse engineering, or learning-based models, without altering the runtime behavior of the program.

Typical changes include:
- Renaming function names (e.g., `calculateSum` → `f_XY21`) while updating all invocation points.
- Changing parameter names to opaque identifiers (e.g., `count` → `a7_b`) without modifying any logic.
- Replacing descriptive local variable names with randomized or stylized alternatives, preserving all references.
- Ensuring **consistent, scope-aware symbol resolution** to avoid shadowing or leakage issues.

This strategy is effective at eliminating semantic clues carried in identifier names, while maintaining structural and operational correctness of the code.
"""
content_tag1_2 = """
This obfuscation type targets named local variable declarations within a function. It performs randomized reordering of their declaration and initialization positions, while strictly preserving semantic correctness and program behavior.

The transformation is governed by the following constraints:
- Both **declaration** and **initialization** must remain strictly **within the lexical scope** in which the variable was originally declared (e.g., inside a `try`, `if`, or `loop` block).
- The **declaration must appear before the initialization**, and the **initialization must appear before the variable’s first usage** in the control flow.
- If a variable is declared and initialized together (e.g., `int i = 0;`), they may be **split** into separate statements (e.g., `int i; i = 0;`).
- Variable names, types, and modifiers **must remain unchanged**.

This form of obfuscation aims to confuse tools or models that rely on the typical proximity between declaration, initialization, and usage, without changing the runtime behavior of the program.

Typical changes include:
- Splitting `declaration + initialization` into separate lines (e.g., transforming `int i = 0;` into `int i; i = 0;`).
- Relocating local variable declarations to earlier positions within their valid lexical scope, as long as they occur before the variable's first usage in the control flow.
- Moving variable `declarations` and/or `initializations` either to the beginning of the function or closer to their first usage, based on the randomization strategy, while ensuring that **declarations precede initializations**, and both occur **before the first usage within their valid lexical scope**.
- Splitting or merging declarations of multiple variables of the same type (e.g., `int i, j;` vs. `int i; int j;`), provided their scope and usage order remain valid.
- Ensuring that all variable references, types, and modifiers remain unchanged, so the semantic behavior of the program is fully preserved.

This strategy is subtle but effective at confusing static analyzers and semantic models that expect tight locality between variable lifecycle events.
"""
class ObfusType(Enum):
    tag1_1 = {
        "id": "1-1",
        "desc": "Function nameable entity randomization renaming.",
        "content": content_tag1_1
    }
    
    tag1_2 = {
        "id": "1-2",
        "desc": "Randomized repositioning of variable declarations and initializations within their lexical scope, ensuring that declarations precede initializations, and both precede the first usage in the control flow.", 
        "content": content_tag1_2
    }
    
    @property
    def desc(self):
        return self.value["desc"]
    
    @property
    def content(self):
        return self.value["content"]

@dataclass
class renameableEntity:
    entity: str                   # 实体名，如函数名、变量名
    kind: str                     # 类型，如 function / parameter / local_variable
    type: Optional[str]           # 数据类型，如 void / int / String 等
    modifiers: List[str]          # 修饰符，如 ["public", "static"]
    scope: List[str]              # 作用域，如 method_declaration / parameter / local
    start: int                    # 起始字节位置
    end: int                      # 结束字节位置
    decPos: Optional[Tuple[str, int]] # 声明位置，(声明语句, 行号)
    initPos: Optional[Tuple[str, int]] # 初始化位置，(初始化语句, 行号)
    useFPos: Optional[Tuple[str, int]] # 首次使用位置，(使用语句, 行号)
    
    def __str__(self):
        return f"{self.kind} '{self.entity}' ({self.scope}, {self.type}) @ {self.start}-{self.end} {self.decPos} first used at {self.useFPos}"

@dataclass
class diffTag1_1:
    """
    用于存储混淆等级1.1的差异信息。
    """
    entity: str               # 实体名差异
    kind: str                 # 类型，如 function / parameter / local_variable
    type: Optional[str]       # 数据类型，如 void / int / String 等
    modifiers: List[str]      # 修饰符，如 ["public", "static"]
    scope: List[str]          # 原始作用域路径，如 method_declaration / parameter / local

@dataclass
class diffTag1_2:
    """
    用于存储混淆等级1.2的差异信息。
    """
    entity: str               # 实体名
    kind: str                 # 类型，如 function / parameter / local_variable
    type: Optional[str]       # 数据类型，如 void / int / String 等
    modifiers: List[str]      # 修饰符，如 ["public", "static"]
    scope: List[str]          # 原始作用域路径，如 method_declaration / parameter / local
    # 原始及混淆后声明位置，([声明语句, 行号], [声明语句, 行号])
    decPosDiff: Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]]
    # 原始及混淆首次初始化位置，([初始化语句, 行号], [初始化语句, 行号])
    initPosDiff: Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]] 
    # 原始及混淆首次使用位置，([声明语句, 行号], [声明语句, 行号])
    useFPosDiff: Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]] 


def format_func(codefunc:str, lang:str) -> str:
    """
    使用 google-java-format 对 Java 源码进行格式化。
    """
    Wrapped_func = f"public class Example {{\n{codefunc}\n}}"
    if lang == 'java':
        jar_path = "build/CodeFormat_adapter/google-java-format-1.27.0-all-deps.jar"
        process = subprocess.Popen(
            ["java", "-jar", jar_path, "--aosp", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(Wrapped_func)
        if process.returncode != 0:
            raise RuntimeError(f"格式化失败: {stderr}")
    
    format_func = stdout
    # match = re.search(r"public class Example \{\n(.*)\n\}", stdout, re.DOTALL)
    # format_func = textwrap.dedent(match.group(1))
    return format_func

def attach_lineNum_func(formatcode: str) -> str:
    lines = formatcode.splitlines()
    width = len(str(len(lines)))  # 计算最大行号宽度
    numbered_lines = [
        f"{str(idx).rjust(width)} | {line}"
        for idx, line in enumerate(lines, start=1)
    ]
    return "\n".join(numbered_lines)

def print_node(node, source_code, prefix="", is_last=True):
    # 当前节点前缀符号
    connector = "└── " if is_last else "├── "

    # 获取当前节点文本（避免换行）
    text = source_code[node.start_byte:node.end_byte].strip().replace("\n", "\\n")
    if node.type == "identifier" or node.type.endswith("_identifier") or node.type == "type_identifier":
        display = f'{node.type} "{text}"'
    elif node.is_named:
        display = f"{node.type}"
    else:
        display = f'"{text}"'

    print(f"{prefix}{connector}{display}")

    # 子节点处理
    child_prefix = prefix + ("    " if is_last else "│   ")
    child_count = len(node.children)
    for i, child in enumerate(node.children):
        is_last_child = (i == child_count - 1)
        print_node(child, source_code, child_prefix, is_last_child)

def printAST(format_code: str, lang: str):
    LANGUAGE = Language('build/languages.so', lang)
    parser = Parser()
    parser.set_language(LANGUAGE)
    
    tree = parser.parse(format_code.encode("utf8"))
    root = tree.root_node
    print_node(root, format_code)

# 单个实体格式化为字符串
def field_formatter(entity: Any, field) -> str:
    name = field.name
    value = getattr(entity, name)

    #!对renameableEntity实体
    if name == "scope" and isinstance(value, list):
        return f"  - scope: {' -> '.join(value)}"
    elif name == "modifiers" and value:
        return f"  - modifiers: {', '.join(value)}"
    elif name == "decPos":
        return (
            f"  - declared at line {value[1]}: {value[0]}"
            if value else
            "  - declared at: [unknown]"
        )
    elif name == "initPos":
        return (
            f"  - initialized at line {value[1]}: {value[0]}"
            if value else
            "  - initialized at: [unknown]"
        )
    elif name == "useFPos":
        return (
            f"  - first used at line {value[1]}: {value[0]}"
            if value else
            "  - first used at: [not found]"
        )
    #!对diffTag1_2实体
    elif name == "decPosDiff":
        if value[0] and value[1]:
            return f"  - declared at line: {value[0][1]}: {value[0][0]}\n    →obfuscated to line {value[1][1]}: {value[1][0]}"
        else:
            return "  - declared at: [unknown]"
    elif name == "initPosDiff":
        if value[0] and value[1]:
            return f"  - first init at line: {value[0][1]}: {value[0][0]}\n    →obfuscated to line {value[1][1]}: {value[1][0]}"
        else:
            return "  - first init at: [unknown]"
    elif name == "useFPosDiff":
        if value[0] and value[1]:
            return f"  - first used at line: {value[0][1]}: {value[0][0]}\n    →obfuscated to line {value[1][1]}: {value[1][0]}"
        else:
            return "  - first used at: [unknown]"
    else:
        return f"  - {name}: {value}"

def format_entity(entity: Any) -> str:
    if not is_dataclass(entity):
        raise TypeError("format_entity() expects a dataclass instance.")

    kind = getattr(entity, "kind", "[unknown kind]")
    entityName = getattr(entity, "entity", "[unknown name]")

    lines = [f"[{kind}] {entityName}"]

    for field in fields(entity):
        if field.name in ("kind", "entity"):
            continue
        lines.append(field_formatter(entity, field))

    lines.append("")
    return "\n".join(lines)
