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

def insertableVarPos(format_code: str, var_name: str, DecPos: int, FusePos: int) -> Tuple[int, int, List[Tuple[int, int]]]:
    lines = format_code.split('\n')
    declare_idx = DecPos - 1

    var_pos = lines[declare_idx].find(var_name)
    if var_pos == -1:
        raise ValueError(f"变量 `{var_name}` 未在第 {DecPos} 行中找到")

    upper_lines = lines[:declare_idx] + [lines[declare_idx][:var_pos]]
    stack = 0
    scope_start = None
    for i in range(len(upper_lines) - 1, -1, -1):
        for ch in reversed(upper_lines[i]):
            if ch == '}':
                stack += 1
            elif ch == '{':
                if stack > 0:
                    stack -= 1
                else:
                    scope_start = i + 1
                    break
        if scope_start is not None:
            break

    stack = 0
    block_stack = []
    all_block_ranges = []
    scope_end = None

    for i in range(scope_start - 1, len(lines)):
        line = lines[i]
        for ch in line:
            if ch == '{':
                block_stack.append(i + 1)
                stack += 1
            elif ch == '}':
                if stack > 0:
                    start_line = block_stack.pop()
                    all_block_ranges.append((start_line, i + 1))
                    stack -= 1
                    if scope_end is None and stack == 0:
                        scope_end = i + 1
        if scope_end is not None and stack == 0:
            break

    if scope_start is None or scope_end is None:
        raise ValueError("未能识别完整作用域")

    def get_max_blocks(blocks: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        blocks.sort()
        max_blocks = []
        last_start, last_end = -1, -1
        for start, end in blocks:
            if last_start <= start and end <= last_end:
                continue
            max_blocks.append((start, end))
            last_start, last_end = start, end
        return max_blocks

    scoped_blocks = [(s, e) for (s, e) in all_block_ranges if scope_start < s and e < scope_end]
    max_child_blocks = get_max_blocks(scoped_blocks)
        
    def insertable_boundaries(scope_start: int, scope_end: int, max_child_blocks: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not max_child_blocks:
            return [(scope_start, scope_end)]

        merged_blocks = []
        for block in sorted(max_child_blocks):
            if not merged_blocks:
                merged_blocks.append(block)
            else:
                last_start, last_end = merged_blocks[-1]
                curr_start, curr_end = block
                if last_end == curr_start:
                    merged_blocks[-1] = (last_start, curr_end)
                else:
                    merged_blocks.append(block)

        insert_boundaries = []
        curr = scope_start
        for start, end in merged_blocks:
            if curr < start:
                insert_boundaries.append((curr, start))
            curr = end
        if curr < scope_end:
            insert_boundaries.append((curr, scope_end))

        return insert_boundaries
    bounds = insertable_boundaries(scope_start, scope_end, max_child_blocks)
    if not bounds:
        raise ValueError("未找到可插入变量的位置")
    
    def filter_bounds_before_use(bounds: List[Tuple[int, int]], FusePos: int) -> List[Tuple[int, int]]:
        filtered = []
        for start, end in bounds:
            if end <= FusePos:
                filtered.append((start, end))
            elif start < FusePos:
                # 如果区间跨过了使用位置，只保留前半部分
                filtered.append((start, FusePos))
                break
            else:
                break
        return filtered
    bounds = filter_bounds_before_use(bounds, FusePos)
    if not bounds:
        raise ValueError("变量使用有误，未找到可插入位置")
    
    return bounds

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