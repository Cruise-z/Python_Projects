from ._datacls import *
from .funcReg import register
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

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
1. Find all local variables from the data stream **Entity information** extracted by Tool.
2. For each local variable:
	- Identify the `usage_context` field and the `DeclPos_rearrangeable_gaps` field. The `DeclPos_rearrangeable_gaps` defines legal code intervals about the declaration of the variable where they can be safely repositioned, provided it's declaration appears before the variable’s initialization and within its lexical scope.
	- In `usage_context`:
        - if the `declaration` and `initialization` are in the same line:
            - Split declaration and initialization into two statements
        - if the `declaration` and `initialization` are separated:
            - (Optional) Merge `declaration` and `initialization` into a single statement.
	- Randomly position the declaration based on the `DeclPos_rearrangeable_gaps` field, ensuring:
        - if the `declaration` and `initialization` are splited:
		    - `declaration` must appear before `initialization`
            - `declaration` can go anywhere but must be rearranged **between these `DeclInitPos_rearrangeable_gaps`**  
        - if the `declaration` and `initialization` are merged:
            - The merged declaration and initialization must be positioned at the original initialization location.
	Ensure initialization line is **untouched** and still receives the previous value!
3. Only relocate declaration lines. Keep all other code intact.
"""

fallback_rule_tag1_2 = [
    f"If a variable cannot be legally transformed (e.g., used in a lambda, or control-flow-sensitive position), skip its transformation and leave it unchanged.",
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
            "scope": {
                "class": entity.scope[0] if len(entity.scope) > 0 else None,
                "method": entity.scope[1] if len(entity.scope) > 1 else None,
                "block": ' -> '.join(entity.scope[2:]) if len(entity.scope) > 2 else "Not in block",
            },
            "usage_context": {
                "declaration": {
                    "line": entity.decPos[1],
                    "content": entity.decPos[0]
                },
                "initialization": {
                    "line": entity.initPos[1],
                    "content": entity.initPos[0]
                },
            },
            "DeclPos_rearrangable_gaps": varScopeGaps(ori_fcode, entity.entity, entity.decPos[1], entity.initPos[1]),
        }
    }

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
                gaps = varScopeGaps(ori_fcode, ori.entity, ori.decPos[1], ori.useFPos[1])
                # 如果原始代码中声明位置与初始化位置相同
                if ori.decPos == ori.initPos:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at the **same** location(line {ori.decPos[1]}: {ori.decPos[0]}): \nFirst identify its scope({ori.scope}). We can obtain **code gaps** for rearranging the declaration location of the variable:\n{gaps}\nThen, separate its declaration and initialization into two statements: {obf.decPos[0]} and {obf.initPos[0]}. Randomly place the declaration **within the code gaps**, ensuring that **the declaration comes before the initialization**."
                else:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at **different** locations([line {ori.decPos[1]}: {ori.decPos[0]}] and [line {ori.initPos[1]}: {ori.initPos[0]}]): \nFirst identify its scope({ori.scope}). We can obtain **code gaps** for rearranging the declaration location of the variable:\n{gaps}\nThen, Randomly place the declaration into another location and **within the code gaps**, ensuring that **the declaration comes before the initialization**. If you rearrange the declaration at the initialization line, you can merge its declaration and initialization into a single statement. The declaration finally rearranged at [line {obf.decPos[1]}: {obf.decPos[0]}]."
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
                    useFPos=ori.useFPos,
                    strategy=Strategy,
                )
                diffs.append(diff)

    return diffs

@register("tag1_2_diffExt")
def jsonDiff_tag1_2(diff: diffTag1_2) -> Dict[str, Any]:
    Modifiers = list(diff.modifiers)
    if Modifiers:
        Modifiers[-1] += " (unchanged)"
    else:
        Modifiers.append(" (unchanged)")
    Scope = list(diff.scope)
    if Scope:
        Scope[-1] += " (unchanged)"
    else:
        Scope.append(" (unchanged)")
    UseFpos = (
        (diff.useFPos[0] + " (unchanged)", diff.useFPos[1])
        if diff.useFPos is not None else None)
    return {
        "Diff information": {
            "name": f"{diff.entity} (unchanged)",
            "kind": f"{diff.kind} (unchanged)",
            "type": f"{diff.type} (unchanged)",
            "modifiers": Modifiers,
            "scope": {
                "class": Scope[0] if len(Scope) > 0 else None,
                "method": Scope[1] if len(Scope) > 1 else None,
                "block": ' -> '.join(Scope[2:]) if len(Scope) > 2 else "Not in block",
            },
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
                "line": f"{diff.initPosDiff[0][1]} (unchanged)",
                "content_original": diff.initPosDiff[0][0],
                "content_obfuscated": f"{diff.initPosDiff[1][0]} (unchanged)",
            },
            "strategy": diff.strategy,
        }
    }