from .funcReg import register
from ..format import *
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

# !混淆等级1.2: 随机化变量声明位置
@register("tag1_2")
def diffEntities_tag1_2(wparser: WParser, ori_fcode: str, obf_fcode: str) -> list:
    key_list = ["entity", "kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    diffs = []
    for items in matched_entities:
        for ori, obf in items:
            if ori.decPos is None or obf.decPos is None:
                continue
            if ori.decPos[0] != obf.decPos[0]:
                diff = diffTag1_2(
                    entity=ori.entity,
                    kind=ori.kind,
                    type=ori.type,
                    modifiers=ori.modifiers,
                    scope=generate_scope_diff(ori.scope, obf.scope),
                    decPosDiff=(ori.decPos, obf.decPos),
                    useFPosDiff=(ori.useFPos, obf.useFPos),
                )
                diffs.append(diff)

    return diffs
