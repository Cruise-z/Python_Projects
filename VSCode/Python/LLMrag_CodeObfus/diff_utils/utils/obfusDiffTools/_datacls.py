from dataclasses import dataclass, fields, is_dataclass
from typing import List, Optional, Tuple, Any

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
    entity: str                 # 实体名
    kind: str                   # 类型，如 function/parameter/local_variable
    type: Optional[str]         # 数据类型，如 void/int/String 等
    modifiers: List[str]        # 修饰符，如 ["public", "static"]
    scope: List[str]            # 原始作用域路径，如 method_declaration/parameter/local
    scope_gaps: dict[str, Any]  # 可重新安排声明与初始化的代码间隙
    # 原始及混淆后声明位置，([声明语句, 行号], [声明语句, 行号])
    decPosDiff: Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]]
    # 原始及混淆首次初始化位置，([初始化语句, 行号], [初始化语句, 行号])
    initPosDiff: Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]] 
    # 原始及混淆首次使用位置，([声明语句, 行号], [声明语句, 行号])
    useFPos: Optional[Tuple[str, int]]
    strategy: str               # 位置随机化策略，默认为 "rename"