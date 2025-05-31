from .wparser import WParser
from .ast2inf import *
from ..format import *
from collections import defaultdict
from typing import Dict, Callable

def make_key_fn(key_fields: List[str]) -> Callable[[renameableEntity], Tuple[Any, ...]]:
    """
    创建一个 key 构造函数，用于从 renameableEntity 中提取匹配 key。
    支持对 scope 和 modifiers 的预处理。

    :param key_fields: 要参与构建 key 的字段名列表
    :return: 可传入 match_entities_by_key 的 key_fn
    """
    def key_fn(entity: renameableEntity) -> Tuple:
        values = []
        for field in key_fields:
            val = getattr(entity, field)
            if field == 'scope':
                # 清洗 scope 中从第3级开始的 @line 信息
                val = tuple(s.split('@')[0] for s in val[2:])
            elif field == 'modifiers':
                val = tuple(val)
            values.append(val)
        return tuple(values)
    return key_fn

def match_entities_by_key(
    ent1: List[renameableEntity],
    ent2: List[renameableEntity],
    key_fn: Callable[[renameableEntity], Tuple[Any, ...]]
) -> List[Tuple[renameableEntity, renameableEntity]]:
    """
    通用实体匹配函数：使用传入的 key_fn 构建实体索引，实现高效匹配。
    保持 ent2 中的实体优先匹配顺序。

    :param ent1: 第一个实体列表（待匹配源）
    :param ent2: 第二个实体列表（目标参考）
    :param key_fn: 用于生成匹配 key 的函数
    :return: 成对匹配的实体元组列表
    """
    # 构建 ent2 的 key -> 索引映射（支持重复）
    index_map: Dict[Tuple[Any, ...], List[int]] = defaultdict(list)
    for idx, e2 in enumerate(ent2):
        key = key_fn(e2)
        index_map[key].append(idx)

    used_indices = set()
    matched = []

    for e1 in ent1:
        key = key_fn(e1)
        candidate_indices = index_map.get(key, [])
        found = False
        for idx in candidate_indices:
            if idx not in used_indices:
                matched.append((e1, ent2[idx]))
                used_indices.add(idx)
                found = True
                break
        if not found:
            print(f"[警告] 未找到匹配项: {e1}")

    return matched

def get_matched_entities(
    wparser: WParser, 
    ori_fcode: str, 
    obf_fcode: str,
    key_list: List[str],
) -> List[List[Tuple[renameableEntity, renameableEntity]]]:
    LANGUAGE = wparser.get_language()
    """
    对比两个 Java 函数中所有可重命名实体的变化，并返回差异摘要列表
    """
    fn1, pn1, ln1, cp1, fv1, lp1 = extract_renameable_entities(ori_fcode, wparser)
    fn2, pn2, ln2, cp2, fv2, lp2 = extract_renameable_entities(obf_fcode, wparser)
    
    matched_entities = []
    
    # 定义用于构建 key 的字段:如["kind", "type", "modifiers", "scope"]
    key_fn = make_key_fn(key_list)

    # 函数名
    matched_entities.append(match_entities_by_key(fn1, fn2, key_fn))
    # 参数名
    matched_entities.append(match_entities_by_key(pn1, pn2, key_fn))
    # 局部变量名
    matched_entities.append(match_entities_by_key(ln1, ln2, key_fn))
    # catch 参数
    matched_entities.append(match_entities_by_key(cp1, cp2, key_fn))
    # 增强 for 循环变量
    matched_entities.append(match_entities_by_key(fv1, fv2, key_fn))
    # lambda 参数
    matched_entities.append(match_entities_by_key(lp1, lp2, key_fn))
    
    return matched_entities

def generate_scope_diff(ori_scope:List[str], obf_scope:List[str]) -> list[str]:
    diff = []
    for ori, obf in zip(ori_scope, obf_scope):
        if ori == obf:
            diff.append(ori)
            continue

        if ori.startswith('Function') and obf.startswith('Function'):
            # Function 类项：提取函数名
            ori_name = ori[len('Function '):]
            obf_name = obf[len('Function '):]
            diff.append(f'Function {ori_name}(→{obf_name})')
        elif '@line:' in ori and '@line:' in obf:
            # Catch Clause 或其他含行号的项：仅替换 @line: 后面的内容
            ori_line = re.search(r'@line:\d+', ori)
            obf_line = re.search(r'@line:\d+', obf)
            if ori_line and obf_line:
                ori_line_text = ori_line.group()
                obf_line_text = obf_line.group()
                prefix = ori[:ori_line.start()]
                diff.append(f'{prefix}{ori_line_text}(→{obf_line_text})')
            else:
                diff.append(ori)  # 保守处理，格式异常时不变
        else:
            # 其他项不同则不 diff，仅保留 ori
            diff.append(ori)
    return diff


# def match_entities_by_key(
#     ent1: List[renameableEntity],
#     ent2: List[renameableEntity]
# ) -> List[Tuple[renameableEntity, renameableEntity]]:
#     """
#     加速版：构建索引，加快匹配速度，同时保留 ent2 的顺序优先。
#     """
#     # 1. 构建哈希索引：key -> list of indices in ent2（保序）
#     index_map = defaultdict(list)
#     for idx, e2 in enumerate(ent2):
#         scope_cleaned = tuple(s.split('@')[0] for s in e2.scope[2:])
#         key = (e2.kind, e2.type, tuple(e2.modifiers), scope_cleaned)
#         index_map[key].append(idx)

#     used_indices = set()
#     matched = []

#     for e1 in ent1:
#         scope_cleaned = tuple(s.split('@')[0] for s in e1.scope[2:])
#         key = (e1.kind, e1.type, tuple(e1.modifiers), scope_cleaned)
#         candidate_indices = index_map.get(key, [])
#         found = False
#         for idx in candidate_indices:
#             if idx not in used_indices:
#                 matched.append((e1, ent2[idx]))
#                 used_indices.add(idx)
#                 found = True
#                 break
#         if not found:
#             print(f"[警告] 未找到匹配项: {e1}")

#     return matched