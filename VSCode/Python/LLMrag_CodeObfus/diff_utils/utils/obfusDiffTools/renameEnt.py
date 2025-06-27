from ._datacls import *
from .funcReg import register
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

# !混淆等级1.1: 可命名实体随机化重命名
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

@register("tag1_1_entFetch")
def fetchEnt_tag1_1(wparser: WParser, format_origin: str)-> List[renameableEntity]:
    """
    Fetches renameable entities from the original code.
    :param wparser: WParser instance for parsing the code.
    :param format_origin: The original formatted code.
    :return: A list of local variable entities.
    """
    fn, pn, ln, cp, fv, lp = extract_renameable_entities(format_origin, wparser)
    return fn + pn + ln + cp + fv + lp

@register("tag1_1_entExt")
def jsonEnt_tag1_1(entity: renameableEntity, ori_fcode: str) -> Dict[str, Any]:
    return {
        "Entity information": {
            "name": entity.entity,
            "kind": entity.kind,
            "type": entity.type,
            "modifiers": entity.modifiers,
            "scope": {
                "class": entity.scope[0] if len(entity.scope) > 0 else None,
                "method": entity.scope[1] if len(entity.scope) > 1 else None,
                "block": ' -> '.join(entity.scope[2:]) if len(entity.scope) > 2 else [],
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
                "first_use": {
                    "line": entity.useFPos[1],
                    "content": entity.useFPos[0]
                }
            },
        }
    }

@register("tag1_1_entDiff")
def diffEntities_tag1_1(wparser: WParser, ori_fcode: str, obf_fcode: str) -> Tuple[List, List]:
    key_list = ["kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    diffs = []
    for items in matched_entities:
        for ori, obf in items:
            if ori.entity != obf.entity:
                Modifiers = list(ori.modifiers)
                if Modifiers:
                    Modifiers[-1] += " (unchanged)"
                else:
                    Modifiers.append(" (unchanged)")
                Scope = list(generate_scope_diff(ori.scope, obf.scope))
                if Scope:
                    Scope[-1] += " (unchanged)"
                else:
                    Scope.append(" (unchanged)")
                diff = diffTag1_1(
                    entity=f"{ori.entity} -> {obf.entity}",
                    kind=f"{ori.kind}",
                    type=f"{ori.type} (unchanged)",
                    modifiers=tuple(Modifiers),
                    scope=Scope,
                    strategy=f"For this {ori.kind} entity named {ori.entity}, first locate all its appearances within its scope {generate_scope_diff(ori.scope, obf.scope)}, including its definition and all valid references. Then rename it to {obf.entity} and substitute all occurrences consistently in the same scope. This transformation preserves type, modifiers, and semantic behavior."
                )
                diffs.append(diff)

    return diffs

