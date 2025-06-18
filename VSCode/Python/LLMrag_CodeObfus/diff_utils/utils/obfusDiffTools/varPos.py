from .funcReg import register
from ..format import *
from ..codeAnalysis.ast2inf import *
from ..codeAnalysis.infProcess import *

# !混淆等级1.2: 随机化变量声明位置
@register("tag1_2")
def diffEntities_tag1_2(wparser: WParser, ori_fcode: str, obf_fcode: str) -> Tuple[List, List]:
    key_list = ["entity", "kind", "type", "modifiers", "scope"]
    matched_entities = get_matched_entities(wparser, ori_fcode, obf_fcode, key_list)
    
    ents = []
    diffs = []
    for items in matched_entities:
        for ori, obf in items:
            if ori.decPos is None or obf.decPos is None:
                continue
            if ori.decPos[0] != obf.decPos[0]:
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
                
                # 过滤掉提取或本身有问题的变量实体
                if ori.decPos is None or ori.initPos is None or ori.useFPos is None or obf.decPos is None or obf.initPos is None or obf.useFPos is None:
                    continue
                # 如果原始代码中声明位置与初始化位置相同
                if ori.decPos == ori.initPos:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at the **same** location(line {ori.decPos[1]}: {ori.decPos[0]}): first identify its scope({ori.scope}) and the position of its first use(line {ori.useFPos[1]}: {ori.useFPos[0]}). Then, separate its declaration and initialization into two statements: {obf.decPos[0]} and {obf.initPos[0]}. Randomly place the declaration and initialization **within the entity's original scope**, ensuring both are positioned before the first use(the first use position remains **unchanged and fixed**), and that the initialization **comes after** the declaration. The final ordering must follow: Scope[declaration(random) → initialization(random) → first use(fixed)]."
                else:
                    Strategy = f"For this {ori.kind} entity named {ori.entity}, it's initially declared and initialized at **different** locations([line {ori.decPos[1]}: {ori.decPos[0]}] and [line {ori.initPos[1]}: {ori.initPos[0]}]): first identify its scope({ori.scope}) and determine the position of its first use(line {ori.useFPos[1]}: {ori.useFPos[0]}). Then, merge its declaration and initialization into a single statement: {obf.decPos[0]}. Randomly place this merged statement **within the entity's original scope**, ensuring it's positioned **before** the first use(the first use position remains **unchanged and fixed**). The final ordering must follow: Scope[merged dec&init(random) → first use(fixed)]."
                # 创建diffTag1_2对象
                diff = diffTag1_2(
                    entity=f"{ori.entity} (unchanged)",
                    kind=ori.kind,
                    type=f"{ori.type} (unchanged)",
                    modifiers=tuple(Modifiers),
                    scope=Scope,
                    decPosDiff=(ori.decPos, obf.decPos),
                    initPosDiff=(ori.initPos, obf.initPos),
                    useFPosDiff=(ori.useFPos, obf.useFPos),
                    strategy=Strategy,
                )
                ents.append(ori)
                diffs.append(diff)

    return ents, diffs
