from ._datacls import *
from .funcReg import register
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *
from ..format import *
from copy import deepcopy
import random

# !混淆等级1.2: 随机化变量声明位置
content_tag1_2 = """
This obfuscation type targets **Named Local Variable Declarations** within a function or block scope. 
When working with variables, you can declare and initialize them in one go(e.g., `int x = 5;`), or split the process into two steps — first declare, then initialize(`int x;` and `x = 5;`). 
For each variable:
- If a declaration and initialization appear in a single statement (e.g., `int x = 5;`), the transformation will split this into two separate statements (`int x;` and `x = 5;`).
- Declaration will then be randomly relocated, as long as:
  1. The declaration appears **before** the initialization.
  2. All movements remain within the original lexical scope.

The transformation must preserve:
- Variable names, types, modifiers (e.g., annotations).
- The control-flow behavior and semantic correctness of the program.
- The original position of the **initialization**.

This form of obfuscation is designed to confuse static analyzers and models by breaking common assumptions about variable lifecycle locality.
"""

constraints_tag1_2 = """
The transformation is governed by the following constraints:
- This transformation applies to the **declaration position** of each variable.
- **Declaration** must remain strictly **within the lexical scope** in which the variable was originally declared (e.g., inside a `try`, `if`, or `loop` block).
- The **declaration must appear before the initialization** in the control flow.
- If a variable is declared and initialized together (e.g., `int i = 0;`), they may be **split** into separate statements (e.g., `int i; i = 0;`).
- Variable names, types, modifiers, the initialization value **must all remain unchanged**：
    - Variable **declaration and initialization** may be split, but must **remain in order**: declaration → initialization.
    - No renaming, inlining, merging, hoisting, or deletion is allowed.
    - All transformations must be performed **within the variable’s declared lexical scope** only (e.g., loop body, method block).
"""

typical_changes_tag1_2 = """
Typical changes include:
- Splitting `declaration + initialization` into separate lines (e.g., transforming `int i = 0;` into `int i; i = 0;`).
- Splitting or merging declarations of multiple variables of the same type (e.g., `int i, j;` vs. `int i; int j;`), provided their scope and usage order remain valid.
- Relocating local variable `declarations` randomly between **the beginning of its lexical scope** and **its initialization position**, while ensuring that **declarations precede initializations**.
- Ensuring that each variable's name, type, modifiers, the initialization value remain unchanged, so the semantic behavior of the program is fully preserved.
"""

algorithm_tag1_2 = """
1. Find all local variables from the data stream `extracted_entities` extracted by Tool.
2. For each local variable:
	- Identify the `usage_context` field and the `DeclPos_rearrangeable_gaps` field. The `DeclPos_rearrangeable_gaps` defines legal code intervals about the declaration of the variable where they can be safely repositioned, provided it's declaration appears before the variable’s initialization and within its lexical scope. So you **don't need to consider whether this is reasonable**, just execute according to the given optional gaps.
	- In `usage_context`:
        - if the `declaration` and `initialization` are in the same line:
            - Split declaration and initialization into two statements
        - if the `declaration` and `initialization` are separated:
            - (Optional) Merge `declaration` and `initialization` into a single statement.
	- Randomly choose **one gap** in `DeclPos_rearrangeable_gaps` field to reposition the declaration:  
        - if the `declaration` and `initialization` are merged:
            - The merged declaration and initialization must be positioned at the original initialization location.
3. Only relocate declaration lines. Ensure the other part of code is **untouched** and **Finally output the converted complete code**!
"""

fallback_rule_tag1_2 = [
    f"If a variable cannot find any gap in `DeclPos_rearrangeable_gaps` field, skip its transformation and leave it unchanged.",
]

@register("tag1_2_entFetch")
def fetchEnt_tag1_2(wparser: WParser, format_origin: str)-> List[renameableEntity]:
    """
    Fetches renameable entities from the original code.
    :param wparser: WParser instance for parsing the code.
    :param format_origin: The original formatted code.
    :return: A list of local variable entities.
    """
    _, _, ln, _, _, _ = extract_renameable_entities(format_origin, wparser)
    return ln

@register("tag1_2_entExt")
def jsonEnt_tag1_2(entity: renameableEntity, ori_fcode: str) -> Dict[str, Any]:
    return {
        "Entity information": {
            "name": entity.entity,
            "kind": entity.kind,
            "type": entity.type,
            "modifiers": entity.modifiers,
            "scope": entity.scope,
            "usage_context": {
                "declaration": {
                    "line": entity.decPos[1],
                    "content": entity.decPos[0]
                },
                "initialization": {
                    "line": entity.initPos[1],
                    "content": entity.initPos[0]
                },
                "first_use(as rvalue)": {
                    "line": entity.useFPos[1],
                    "content": entity.useFPos[0]
                },
            },
            "DeclPos_rearrangable_gaps": {
                "description": [
                    "Following are the code gaps where the declaration of this variable can be rearranged.",
                    "These gaps are determined by the analysis tool, which ensures that variable declarations are certainly before initialization and first use.",
                    "You can choose any gap in these gaps to rearrange the declaration of this variable.",
                ],
                "gaps": varScopeGaps(ori_fcode, entity.entity, entity.decPos[1], entity.initPos[1]),
            }
        }
    }

def get_insert_index(ori_code: str, obf_code: str, obf_decPos: int,
                     align_CodeBlocks) -> tuple[int, int]:
    obf_lines = obf_code.splitlines()
    # 对齐两段代码
    aligned_ori, aligned_obf = align_CodeBlocks(ori_code, obf_code)
    aligned_ori_lines = aligned_ori.splitlines()
    aligned_obf_lines = aligned_obf.splitlines()
    for idx, line in enumerate(aligned_obf_lines):
        if line.strip() == obf_lines[obf_decPos-1].strip():
            aligned_idx = idx
            break
    # 如果 aligned_pos 位置的行不是空行，说明是将声明合并到了初始化行
    if aligned_ori_lines[aligned_idx].strip() != '':
        ref_line = aligned_ori_lines[aligned_idx].strip()
        for j, line in enumerate(ori_code.splitlines()):
            if line.strip() == ref_line:
                return (j+1, j+1)
    # 向上查找 aligned_pos 之前在 ori_code 中存在的最近行
    for i in range(aligned_idx-1, -1, -1):
        if aligned_ori_lines[i].strip() != '':
            # 找到它在原始代码中的位置索引 j，则插入发生在第j+1行与j+2行之间
            ref_line = aligned_ori_lines[i].strip()
            for j, line in enumerate(ori_code.splitlines()):
                if line.strip() == ref_line:
                    return (j+1, j+2)
            break

    # 如果前面都为空行，说明是在最顶部插入的
    return (0, 1)

@register("tag1_2_entDiff")
def diffEntities_tag1_2(wparser: WParser, ori_fcode: str, obf_fcode: str) -> Tuple[List, List]:
    key_list = ["entity", "kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    diffs = []
    for items in matched_entities:
        for ori, obf in items:
            if ori.decPos is None or obf.decPos is None:
                continue
            if ori.decPos[0] != obf.decPos[0]:
                # 过滤掉提取或本身有问题的变量实体
                if ori.initPos is None or ori.useFPos is None or obf.initPos is None or obf.useFPos is None:
                    continue
                ori_lines = ori_fcode.splitlines()
                gaps = varScopeGaps(ori_fcode, ori.entity, ori.decPos[1], ori.useFPos[1])
                (a, b) = get_insert_index(ori_fcode, obf_fcode, obf.decPos[1], align_CodeBlocks=align_CodeBlocks)
                if a == b:
                    gap = {
                        "init_line": a,
                        "content": ori_lines[a-1],
                        "description": [
                            f"You can merge declaration to initialization line:",
                            f"{ori_lines[a-1]}",
                        ],
                    }
                else:
                    gap = {
                        "start_line": a,
                        "start_content": ori_lines[a-1],
                        "end_line": b,
                        "end_content": ori_lines[b-1],
                        "description": [
                            f"You can insert declaration between",
                            f"{ori_lines[a-1]}",
                            f"and",
                            f"{ori_lines[b-1]}",
                        ],
                    }
                # 如果原始代码中声明位置与初始化位置相同
                if ori.decPos == ori.initPos:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at the **same** location(line {ori.decPos[1]}: {ori.decPos[0]}): \nFirst, separate its declaration from this statement: {obf.decPos[0]} and {obf.initPos[0]}; Then randomly choose this gap from `DeclPos_rearrangable_gaps` to insert the declaration. Initialization position remains unchanged."
                else:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at **different** locations([line {ori.decPos[1]}: {ori.decPos[0]}] and [line {ori.initPos[1]}: {ori.initPos[0]}]): \nFirst, randomly choose this gap from `DeclPos_rearrangable_gaps` to rearrange the declaration. Initialization position remains unchanged. If you rearrange the declaration at the initialization line, merge its declaration and initialization into a single statement."
                # 创建diffTag1_2对象
                diff = diffTag1_2(
                    entity=f"{ori.entity}",
                    kind=ori.kind,
                    type=f"{ori.type}",
                    modifiers=ori.modifiers,
                    scope=generate_scope_diff(ori.scope, obf.scope),
                    scope_gaps=gaps,
                    decPosDiff=(ori.decPos, obf.decPos),
                    initPosDiff=(ori.initPos, obf.initPos),
                    useFPos=(ori.useFPos, obf.useFPos),
                    strategy=(gap, Strategy),
                )
                diffs.append(diff)

    return diffs

@register("tag1_2_diffExt")
def jsonDiff_tag1_2(diff: diffTag1_2) -> Dict[str, Any]:
    return {
        "Diff information": {
            "name": f"{diff.entity}",
            "kind": f"{diff.kind}",
            "type": f"{diff.type}",
            "modifiers": diff.modifiers,
            "scope": diff.scope,
            "declaration_position_diff": {
                "original": {
                    "line": diff.decPosDiff[0][1],
                    "content": diff.decPosDiff[0][0],
                },
                "obfuscated": {
                    "line": diff.decPosDiff[1][1],
                    "content": diff.decPosDiff[1][0],
                }
            },
            "initialization_position": {
                "content_original": diff.initPosDiff[0][0],
                "content_obfuscated": f"{diff.initPosDiff[1][0]}",
            },
            "first_use_position": {
                "content_original": diff.useFPos[0][0],
                "content_obfuscated": diff.useFPos[1][0],
            },
            "strategy": {
                "choose_gap": diff.strategy[0],
                "description": diff.strategy[1],
            },
        }
    }

def splitDeclInit(statement: str, lang: str) -> tuple[str, str]:
    """
    接收一句变量声明+初始化语句和语言名称，返回拆分后的声明和初始化两部分。

    示例输入：
        statement = "final int x = 5;"
        lang = "java"

    返回：
        ("final int x;", "x = 5;")
    """
    wparser = WParser(lang)
    parser = wparser.parser
    tree = parser.parse(bytes(statement, "utf8"))
    root = tree.root_node

    def find_decl(node):
        if node.type == "program":
            # 进入 program 的第一条语句
            node = node.children[0] if node.children else None

        if node and node.type == "local_variable_declaration":
            var_node = [c for c in node.children if c.type == "variable_declarator"][0]
            id_node = var_node.child_by_field_name("name")
            init_node = var_node.child_by_field_name("value")
            type_node = node.child_by_field_name("type")
            modifiers = " ".join(c.text.decode() for c in node.children if c.type == "modifier")

            var_name = id_node.text.decode()
            init_expr = statement[init_node.start_byte:init_node.end_byte]
            var_type = statement[type_node.start_byte:type_node.end_byte]

            full_decl = f"{modifiers} {var_type} {var_name};".strip()
            full_init = f"{var_name} = {init_expr};"

            return full_decl, full_init
        return None

    return find_decl(root)

def mergeDeclInit_str(decl: str, init: str, lang: str) -> str:
    """
    使用 Tree-sitter 合并声明和初始化语句为一条完整的变量初始化语句。

    输入：
        decl: "final int x;"
        init: "x = 5;"
        lang: "java"

    输出：
        "final int x = 5;"
    """

    # 解析声明部分
    wparser = WParser(lang)
    parser = wparser.parser

    # Parse declaration
    tree_decl = parser.parse(bytes(decl, "utf8"))
    root_decl = tree_decl.root_node
    decl_node = root_decl.children[0] if root_decl.children else None

    if not decl_node or decl_node.type != "local_variable_declaration":
        raise ValueError("声明语句格式不合法")

    # 提取声明内容
    var_node = [c for c in decl_node.children if c.type == "variable_declarator"][0]
    id_node = var_node.child_by_field_name("name")
    type_node = decl_node.child_by_field_name("type")
    modifiers = " ".join(c.text.decode() for c in decl_node.children if c.type == "modifier")

    var_name_decl = id_node.text.decode()
    var_type = decl[type_node.start_byte:type_node.end_byte]

    # Parse initialization
    tree_init = parser.parse(bytes(init, "utf8"))
    root_init = tree_init.root_node
    expr_stmt = root_init.children[0] if root_init.children else None

    if not expr_stmt or expr_stmt.type != "expression_statement":
        raise ValueError("初始化语句格式不合法")

    assignment = expr_stmt.child_by_field_name("expression")
    if not assignment or assignment.type != "assignment_expression":
        raise ValueError("不是赋值表达式")

    lhs = assignment.child_by_field_name("left").text.decode()
    rhs = init[assignment.child_by_field_name("right").start_byte : assignment.child_by_field_name("right").end_byte]

    if lhs != var_name_decl:
        raise ValueError(f"变量名不一致: 声明是 {var_name_decl}，初始化是 {lhs}")

    merged = f"{modifiers} {var_type} {lhs} = {rhs};".strip()
    return merged

def mergeDeclInit_str(decl: str, init: str, lang: str) -> str:
    """
    使用 Tree-sitter 合并声明和初始化语句为一条完整的变量初始化语句。

    输入：
        decl: "final int x;"
        init: "x = 5;"
        lang: "java"

    输出：
        "final int x = 5;"
    """

    wparser = WParser(lang)
    parser = wparser.parser

    # 将声明和初始化一起包裹进合法的 Java 类中
    wrapped_code = f"""
    class Dummy {{
        void dummy() {{
            {decl}
            {init}
        }}
    }}
    """

    tree = parser.parse(bytes(wrapped_code, "utf8"))
    root = tree.root_node

    # 递归查找所有需要的节点
    local_decl = None
    assignment = None

    def visit(node):
        nonlocal local_decl, assignment
        if node.type == "local_variable_declaration" and not local_decl:
            local_decl = node
        elif node.type == "assignment_expression" and not assignment:
            assignment = node
        for child in node.children:
            visit(child)

    visit(root)

    if not local_decl or not assignment:
        raise ValueError("未能找到完整的声明或赋值结构")

    # 提取声明部分
    var_node = [c for c in local_decl.children if c.type == "variable_declarator"][0]
    id_node = var_node.child_by_field_name("name")
    type_node = local_decl.child_by_field_name("type")
        # 提取修饰符（modifiers 节点中）
    modifiers_node = next((c for c in local_decl.children if c.type == "modifiers"), None)
    if modifiers_node:
        modifiers = " ".join(c.text.decode() for c in modifiers_node.children)
    else:
        modifiers = ""

    var_name_decl = id_node.text.decode()
    var_type = wrapped_code[type_node.start_byte:type_node.end_byte]

    # 提取初始化表达式
    lhs_node = assignment.child_by_field_name("left")
    rhs_node = assignment.child_by_field_name("right")

    lhs = lhs_node.text.decode()
    rhs = wrapped_code[rhs_node.start_byte:rhs_node.end_byte]

    if lhs != var_name_decl:
        raise ValueError(f"变量名不一致: 声明是 {var_name_decl}，初始化是 {lhs}")

    modifier_prefix = (modifiers + " ") if modifiers else ""
    merged = f"{modifier_prefix}{var_type} {lhs} = {rhs};"
    return merged

@register("tag1_2_instrExt")
def jsonInstr_tag1_2(entity: renameableEntity, ori_fcode: str, lang:str) -> Dict[str, Any]:
    # 找到可插入范围
    gaps = varScopeGaps(ori_fcode, entity.entity, entity.decPos[1], entity.initPos[1])
    # 随机选取一个`gaps`内的gap用来插入
    choice = random.choice(gaps)
    if entity.decPos[0] == entity.initPos[0]:
        # 如果声明和初始化在同一行，后续操作只需考虑split
        decl, init = splitDeclInit(entity.decPos[0], lang)
        instruction = {
            "name": entity.entity,
            "original_declaration": {
                "line": entity.decPos[1],
                "content": entity.decPos[0],
            },
            "split": True,
            "split_result": {
                "declaration": decl,
                "initialization": init,
            },
            "new_declaration_location": {
                "insert_between": [
                    f"line{choice['start_line']}: {choice['start_content']}",
                    f"line{choice['end_line']}: {choice['end_content']}"
                ]
            }
        }
    else:
        merged = mergeDeclInit_str(entity.decPos[0], entity.initPos[0], lang)
        # 如果声明和初始化在不同的行，后续操作只需考虑是否merge
        if(choice.get("merge", False)):
            instruction = {
                "name": entity.entity,
                "original_declaration": {
                    "line": entity.decPos[1],
                    "content": entity.decPos[0],
                },
                "merge": True,
                "merge_result": {
                    "decl&init": merged,
                },
                "new_declaration_location": {
                    "merge to initialization": [
                        f"line{choice['init_line']}: {choice['content']}",
                    ]
                }
            }
        else:
            instruction = {
                "name": entity.entity,
                "original_declaration": {
                    "line": entity.decPos[1],
                    "content": entity.decPos[0],
                },
                "merge": False,
                "new_declaration_location": {
                    "rearrange_between": [
                        f"line{choice['start_line']}: {choice['start_content']}",
                        f"line{choice['end_line']}: {choice['end_content']}"
                    ]
                }
            }
    return {
        f"{entity.kind}": instruction
    }
