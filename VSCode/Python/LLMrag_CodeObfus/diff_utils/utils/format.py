from tree_sitter import Language, Parser
from enum import Enum
from dataclasses import dataclass, fields, is_dataclass
from typing import List, Optional, Tuple, Any
import subprocess
import textwrap
import re

class ObfusType(Enum):
    tag1_1 = {
        "id": "1-1",
        "desc": "Function nameable entity randomization renaming.",
        "content": "Randomly rename function (method) names, parameter names, and various local variable names within the function while preserving semantics."
    }
    
    tag1_2 = {
        "id": "1-2",
        "desc": "Named local variable entity declaration position randomization.", 
        "content": "Randomize the declared positions of local variable entities that can be named within a function, while limiting their positions to before the variable's first use and within its scope."
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
    oriDecPos: Optional[Tuple[str, int]]  # 原始声明位置，(声明语句, 行号)
    newDecPos: Optional[Tuple[str, int]]  # 混淆后声明位置，(声明语句, 行号)
    oriUseFPos: Optional[Tuple[str, int]]  # 原始首次使用位置，(使用语句, 行号)
    newUseFPos: Optional[Tuple[str, int]]  # 混淆后首次使用位置，(使用语句, 行号)


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

    elif name == "useFPos":
        return (
            f"  - first used at line {value[1]}: {value[0]}"
            if value else
            "  - first used at: [not found]"
        )

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
