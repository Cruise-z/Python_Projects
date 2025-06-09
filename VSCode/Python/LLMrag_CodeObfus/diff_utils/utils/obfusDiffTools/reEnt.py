from .funcReg import register
from ..format import *
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

# !混淆等级1.1: 可命名实体随机化重命名
@register("tag1_1")
def diffEntities_tag1_1(wparser: WParser, ori_fcode: str, obf_fcode: str) -> Tuple[List, List]:
    key_list = ["kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    ents = []
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
                ents.append(ori)
                diffs.append(diff)

    return ents, diffs
