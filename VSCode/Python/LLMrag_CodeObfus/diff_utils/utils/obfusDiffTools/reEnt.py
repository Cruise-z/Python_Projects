from .funcReg import register
from ..format import *
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

# !混淆等级1.1: 可命名实体随机化重命名
@register("tag1_1")
def diffEntities_tag1_1(wparser: WParser, ori_fcode: str, obf_fcode: str) -> list:
    key_list = ["kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    diffs = []
    for items in matched_entities:
        for ori, obf in items:
            if ori.entity != obf.entity:
                diff = diffTag1_1(
                    entity=f"{ori.entity} -> {obf.entity}",
                    kind=ori.kind,
                    type=ori.type,
                    modifiers=ori.modifiers,
                    scope=generate_scope_diff(ori.scope, obf.scope),
                )
                diffs.append(diff)

    return diffs
