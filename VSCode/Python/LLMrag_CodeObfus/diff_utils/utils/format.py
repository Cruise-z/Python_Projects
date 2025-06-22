from tree_sitter import Language, Parser
from enum import Enum
from dataclasses import dataclass, fields, is_dataclass
from typing import List, Optional, Tuple, Any
from difflib import SequenceMatcher
import subprocess
import textwrap
import re

content_tag1_1 = """
This obfuscation type targets the names of user-defined symbols within a function or method. It performs randomized renaming of function (method) names, parameter names, and local variable names, while strictly preserving program semantics.

This form of obfuscation aims to disrupt name-based heuristics in static analysis, reverse engineering, or learning-based models, without altering the runtime behavior of the program.

This strategy is effective at eliminating semantic clues carried in identifier names, while maintaining structural and operational correctness of the code.
"""

constraints_tag1_1 = """
The transformation is governed by the following constraints:
- All renamed identifiers must be semantically equivalent to their originals, with no change to logic, behavior, or type correctness.
- Function names may be renamed as long as **all corresponding call sites are updated consistently**.
- Parameter names can be replaced with arbitrary but valid alternatives, provided **all references within the function body are correctly updated**.
- Local variable names may be renamed, individually or in batches, with **consistent substitutions across all reads and writes** within their scope.
- Renamed identifiers must **not** collide with existing global names, imported symbols, or scoped declarations.
"""

typical_changes_tag1_1 = """
Identifier names can be generated in different styles to increase variability or mimic realistic coding practices. These include:
- Completely random but syntactically valid identifiers (e.g., `a9fG_23`), ensuring they comply with language-specific naming rules (e.g., not starting with a digit).
- Patterned or style-based naming conventions such as:
  - `camelCase` (e.g., `processedData`)
  - `PascalCase` (e.g., `ProcessedData`)
  - `snake_case` (e.g., `processed_data`)
  - `_underscore_init` (e.g., `_tempVar`)
These styles may be applied uniformly or mixed randomly to confuse naming-based heuristics or stylistic pattern recognition.

Typical changes include:
- Renaming function names (e.g., `calculateSum` → `f_XY21`) while updating all invocation points.
- Changing parameter names to opaque identifiers (e.g., `count` → `a7_b`) without modifying any logic.
- Replacing descriptive local variable names with randomized or stylized alternatives, preserving all references.
- Ensuring **consistent, scope-aware symbol resolution** to avoid shadowing or leakage issues.
"""

algorithm_tag1_1 = """
"""

content_tag1_2 = """
This obfuscation type targets **named local variable declarations** within a function or block scope. For each variable:
- If a declaration and initialization appear in a single statement (e.g., `int x = 5;`), the transformation will split this into two separate statements (`int x;` and `x = 5;`).
- Both declaration and initialization will then be randomly relocated, as long as:
  1. The declaration appears **before** the initialization.
  2. Both appear **before** the first usage of the variable.
  3. All movements remain within the original lexical scope.

The transformation must preserve:
- Variable names, types, modifiers (e.g., annotations).
- The control-flow behavior and semantic correctness of the program.
- The original position of the **first usage**.

This form of obfuscation is designed to confuse static analyzers and models by breaking common assumptions about variable lifecycle locality.
"""

constraints_tag1_2 = """
The transformation is governed by the following constraints:
- This transformation applies to the **declaration and initialization positions** of each variable.
- Both **declaration** and **initialization** must remain strictly **within the lexical scope** in which the variable was originally declared (e.g., inside a `try`, `if`, or `loop` block).
- The **declaration must appear before the initialization**, and the **initialization must appear before the variable’s first usage** in the control flow.
- If a variable is declared and initialized together (e.g., `int i = 0;`), they may be **split** into separate statements (e.g., `int i; i = 0;`).
- Variable names, types, modifiers, the initialization value, and the first use position **must all remain unchanged**：
    - Variable **declaration and initialization** may be split, but must **remain in order**: declaration → initialization → first use.
    - Variable **usage lines** must remain unchanged in line number and structure.
    - No renaming, inlining, merging, hoisting, or deletion is allowed.
    - All transformations must be performed **within the variable’s declared lexical scope** only (e.g., loop body, method block).
"""

typical_changes_tag1_2 = """
Typical changes include:
- Splitting `declaration + initialization` into separate lines (e.g., transforming `int i = 0;` into `int i; i = 0;`).
- Splitting or merging declarations of multiple variables of the same type (e.g., `int i, j;` vs. `int i; int j;`), provided their scope and usage order remain valid.
- Relocating local variable `declarations` and/or `initializations` randomly between **the beginning of its lexical scope** and **its first usage position**, while ensuring that **declarations precede initializations**, and both occur **before the first usage**.
- Ensuring that each variable's name, type, modifiers, the initialization value, and the first use position remain unchanged, so the semantic behavior of the program is fully preserved.
"""

algorithm_tag1_2 = """
For each local variable:
1. Detect the line where it is declared and initialized (may be the same line).
2. Identify the earliest line where the variable is first used.
3. Split declaration and initialization into two statements, if not already split.
4. Randomly position the declaration and initialization within the allowable range:
   - Declaration can go anywhere from the start of the lexical scope to just before initialization.
   - Initialization can go anywhere after the declaration but before the first use.
5. Ensure first use line is untouched and still receives the correct value.
**FALLBACK: If a variable cannot be legally moved (e.g., used in a lambda, or control-flow-sensitive position), skip its transformation and leave it unchanged.
"""

class ObfusType(Enum):
    tag1_1 = {
        "id": "1-1",
        "desc": "Function nameable entity randomization renaming.",
        "content": content_tag1_1,
        "constraints": constraints_tag1_1,
        "typical_changes": typical_changes_tag1_1,
        "algorithm": algorithm_tag1_1,
    }
    
    tag1_2 = {
        "id": "1-2",
        "desc": "Randomized repositioning of variable declarations and initializations strictly within their lexical scope. For each variable, the declaration must appear before its initialization, and both must precede the variable's first use in the control flow. This process preserves semantic correctness while disrupting variable lifecycle locality.", 
        "content": content_tag1_2,
        "constraints": constraints_tag1_2,
        "typical_changes": typical_changes_tag1_2,
        "algorithm": algorithm_tag1_2,
    }
    
    @property
    def desc(self):
        return self.value["desc"]
    
    @property
    def content(self):
        return self.value["content"]
    
    @property
    def constraints(self):
        return self.value["constraints"]
    
    @property
    def typical_changes(self):
        return self.value["typical_changes"]
    
    @property
    def algorithm(self):
        return self.value["algorithm"]

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
    strategy: str             # 重命名策略，默认为 "rename"

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
    useFPos: Optional[Tuple[str, int]]
    strategy: str             # 位置随机化策略，默认为 "rename"

def highlight_print(text, fg='white', bg=None, bold=True):
    color_codes = {
        'black': 30, 'red': 31, 'green': 32, 'yellow': 33,
        'blue': 34, 'magenta': 35, 'cyan': 36, 'white': 37
    }
    bg_codes = {k: v + 10 for k, v in color_codes.items()}

    parts = ['\033[']
    if bold:
        parts.append('1;')
    parts.append(str(color_codes.get(fg, 37)))  # default to white

    if bg:
        parts.append(f';{bg_codes.get(bg, 40)}')  # default bg to black if unknown

    parts.append('m')
    parts.append(str(text))
    parts.append('\033[0m\n')

    print(''.join(parts))


def format_func_deprecated(class_name:str, codefunc:str, lang:str) -> str:
    """
    使用 google-java-format 对 Java 源码进行格式化。
    """
    Wrapped_func = f"public class {class_name} {{\n{codefunc}\n}}"
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

def preprocess_code(code: str) -> str:
    """
    预处理 Java 等类 C 语言代码字符串：
    - 移除所有换行符、缩进符（\r \n \t 等）
    - 移除单行注释（//...）与多行注释（/*...*/）
    - 保留字符串与字符字面量，含转义字符
    - 输出一行干净的代码文本
    """

    _STRING_PLACEHOLDER = "__<STR:%d>__"
    literals: List[str] = []

    def freeze_literals(src: str) -> str:
        """用占位符替换字符串与字符字面量"""
        def _store(match):
            idx = len(literals)
            literals.append(match.group(0))
            return _STRING_PLACEHOLDER % idx

        pattern = r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])'"  # 支持字符串和字符
        return re.sub(pattern, _store, src)

    def remove_comments(src: str) -> str:
        """移除单行和多行注释"""
        no_block_comments = re.sub(r'/\*.*?\*/', '', src, flags=re.DOTALL)
        no_line_comments = re.sub(r'//.*$', '', no_block_comments, flags=re.MULTILINE)
        return no_line_comments

    def collapse_whitespace(src: str) -> str:
        """将所有空白符折叠为单个空格"""
        return re.sub(r'\s+', ' ', src).strip()

    def restore_literals(src: str) -> str:
        """恢复之前冻结的字符串字面量"""
        def _restore(match):
            idx = int(match.group(1))
            return literals[idx]
        return re.sub(r'__<STR:(\d+)>__', _restore, src)

    # === 执行流程 ===
    code_frozen = freeze_literals(code)
    code_no_comments = remove_comments(code_frozen)
    code_flat = collapse_whitespace(code_no_comments)
    code_restored = restore_literals(code_flat)

    return code_restored

def valid_check(codefunc: str, lang: str) -> bool:
    if lang == 'java':
        jar_path = "build/CodeFormat_adapter/google-java-format-1.27.0-all-deps.jar"
        try:
            proc = subprocess.run(
                ["java", "-jar", jar_path, "--dry-run", "-"],
                input=codefunc,
                stdout=subprocess.DEVNULL,  # 避免收集不必要输出
                stderr=subprocess.DEVNULL,  # 降低 I/O 延迟
                text=True,
                timeout=10.0  # 防止卡死
            )
            return proc.returncode == 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False
    else:
        return False

def format_func(class_name:str, codefunc:str, lang:str) -> str:
    """
    使用 Eclipse-java-format 对 Java 源码进行自定义格式化。
    依赖外部 Eclipse 安装和 formatter 配置。
    """
    codefunc = preprocess_code(codefunc)  # 预处理代码，移除注释和多余空格
    
    if lang == 'java':
        Wrapped_func = f"public class {class_name} {{{codefunc}}}"
        if not valid_check(Wrapped_func, lang):
            raise RuntimeError("Failed")
        highlight_print(f"Valid check passed for func:\n{Wrapped_func}", fg='black', bg='yellow')
        eclipse_path = "/home/zrz/software/eclipse-java/eclipse/eclipse"
        workspace_path = "/home/zrz/Projects/EclipseProject"
        config_path = "build/CodeFormat_adapter/format_style.xml"
        temp_path = "/media/zrz/SSD/temp.java"
        # 写入临时 Java 文件
        with open(temp_path, "w", encoding="utf-8") as tmpfile:
            tmpfile.write(Wrapped_func)
            
        subprocess.run(
            [
                eclipse_path,
                "-nosplash",
                "-data", workspace_path,
                "-application", "org.eclipse.jdt.core.JavaCodeFormatter",
                "-config", config_path,
                temp_path,
                "-vmargs", "-Dfile.encoding=UTF-8"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # 读取格式化后的 Java 文件内容
        with open(temp_path, "r", encoding="utf-8") as formatted_file:
            format_func = formatted_file.read()
        format_func = format_func.replace('\t', '    ')
    else:
        format_func = codefunc  # 对于未集成格式化插件的语言，直接返回原始代码
    return format_func

# 1. Normalize lines (with literal abstraction)
def normalize_code_line_literal_aware(line: str) -> str:
    """
    Normalize code line by:
    - Removing all whitespace characters
    - Removing trailing semicolons
    - Converting to lowercase
    """
    line = re.sub(r'\s+', '', line)         # 移除所有空白字符
    line = re.sub(r';+$', '', line)         # 去除末尾分号（包括多个 ;;）
    line = line.lower()                     # 全部转为小写
    return line

# 2. Reverse token similarity with normalization
def reversed_suffix_similarity(line1: str, line2: str) -> float:
    s1 = normalize_code_line_literal_aware(line1)
    s2 = normalize_code_line_literal_aware(line2)
    rev1 = s1[::-1]
    rev2 = s2[::-1]

    match_len = 0
    for c1, c2 in zip(rev1, rev2):
        if c1 == c2:
            match_len += 1
        else:
            break
    if match_len == 0:
        return 0.0
    # 使用乘积相似度
    return (match_len / max(len(s1), 1)) * (match_len / max(len(s2), 1))

# 3. Stable alignment of line blocks
def stable_pair_blocks(A: List[str], B: List[str], base_threshold=0.3, lookahead_window=15) -> Tuple[List[str], List[str]]:
    alignedA, alignedB = [], []
    i, j = 0, 0  # j 是 B 中当前位置

    while i < len(A):
        lineA = A[i]
        best_sim = 0.0
        best_j = -1

        # 滑动窗口：从当前 j 向前看
        for k in range(j, min(j + lookahead_window, len(B))):
            sim = reversed_suffix_similarity(lineA, B[k])
            if sim > best_sim:
                best_sim = sim
                best_j = k

        # 动态阈值
        lenA = len(normalize_code_line_literal_aware(lineA))
        if best_j != -1:
            lenB = len(normalize_code_line_literal_aware(B[best_j]))
            dynamic_threshold = max(0.15, base_threshold * (1 - abs(lenA - lenB) / max(lenA, lenB, 1)))
        else:
            dynamic_threshold = 1.0

        if best_sim >= dynamic_threshold and best_j != -1:
            # 补齐 B 中未对齐行
            while j < best_j:
                alignedA.append("")
                alignedB.append(B[j])
                j += 1
            # 正常对齐
            alignedA.append(lineA)
            alignedB.append(B[best_j])
            j = best_j + 1
        else:
            # 无匹配
            alignedA.append(lineA)
            alignedB.append("")
        i += 1

    # 补齐剩余 B
    while j < len(B):
        alignedA.append("")
        alignedB.append(B[j])
        j += 1

    return alignedA, alignedB

# 4. Align wrapper with blank-line filtering
def align_CodeBlocks(code1: str, code2: str) -> Tuple[str, str]:
    lines1 = code1.splitlines()
    lines2 = code2.splitlines()
    
    aligned_clean1, aligned_clean2 = stable_pair_blocks(lines1, lines2)
    return "\n".join(aligned_clean1), "\n".join(aligned_clean2)

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
    #!对所有diffTag中共同出现的实体
    elif name == "strategy":
        return f"  - strategy: \n{textwrap.indent(value, '    ')}"
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
