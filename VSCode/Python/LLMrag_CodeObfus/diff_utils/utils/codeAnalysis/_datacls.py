from dataclasses import dataclass, fields, is_dataclass
from tree_sitter import Node
from typing import List, Optional, Tuple, Set, Dict
import copy

class ZASTNode:
    def __init__(
        self, 
        ts_node:Optional[Node] = None, 
        source_code:Optional[str] = None, 
        *, 
        node_type: Optional[str] = None, 
        extra_text: Optional[str] = None
    ):
        self.type: str = ""
        self.parent: Optional["ZASTNode"] = None
        self.children: List[ZASTNode] = []
        # self.start_byte: int = ts_node.start_byte
        # self.end_byte: int = ts_node.end_byte
        self.is_named: bool = True
        self.extra_text: Optional[str] = extra_text

        if ts_node and source_code:
            self.type = ts_node.type
            self.is_named = ts_node.is_named
            if len(ts_node.children) == 0 or not ts_node.is_named:
                self.extra_text = source_code[ts_node.start_byte:ts_node.end_byte]
            for child in ts_node.children:
                child_node = ZASTNode(ts_node=child, source_code=source_code)
                child_node.parent = self
                self.children.append(child_node)
        elif node_type:
            self.type = node_type  # for manually created node
            
    @classmethod
    def from_type(cls, node_type: str, extra_text: Optional[str] = None) -> "ZASTNode":
        return cls(node_type=node_type, extra_text=extra_text)

    def clone(self):
        return copy.deepcopy(self)

    def __repr__(self) -> str:
        return f"ZASTNode(type='{self.type}', children={len(self.children)})"
    
    def json(self, include_path=False, path="root") -> dict:
        json_node = {
            "type": self.type,
            "is_named": self.is_named,
            "leaf": len(self.children) == 0,
            "num_children": len(self.children),
            "children": [
                child.json(include_path=include_path, path=f"{path}/{child.type}")
                for child in self.children
            ]
        }

        # Only include extra_text if it's not None
        if self.extra_text is not None:
            json_node["extra_text"] = self.extra_text

        if include_path:
            json_node["path_hint"] = path

        return json_node


@dataclass
class ScopeRule:
    language: str
    boundary_nodes: Set[str]

    def is_scope_boundary(self, node_type: str) -> bool:
        return node_type in self.boundary_nodes

class ScopeRules:
    _rules: Dict[str, ScopeRule] = {
        "java": ScopeRule(
            language="java",
            boundary_nodes={
                "block",
                "for_statement",
                "while_statement",
                "do_statement",
                "if_statement",
                "switch_block",
                "catch_clause",
                "method_declaration",
                "constructor_declaration",
                "lambda_expression",
                "try_statement",
                "synchronized_statement",
            }
        ),
        "python": ScopeRule(
            language="python",
            boundary_nodes={
                "block",
                "function_definition",
                "if_statement",
                "for_statement",
                "while_statement",
                "try_statement",
                "with_statement",
                "except_clause",
                "async_function_definition",
            }
        ),
        "cpp": ScopeRule(
            language="cpp",
            boundary_nodes={
                "compound_statement",
                "function_definition",
                "if_statement",
                "for_statement",
                "while_statement",
                "switch_statement",
                "try_statement",
                "lambda_expression",
            }
        )
    }

    @classmethod
    def lang(cls, language: str) -> ScopeRule:
        language = language.lower()
        if language in cls._rules:
            return cls._rules[language]
        else:
            # 返回空规则防止异常
            return ScopeRule(language=language, boundary_nodes=set())


@dataclass
class renameableEntity:
    entity: str                   # 实体名，如函数名、变量名
    kind: str                     # 类型，如 function / parameter / local_variable
    type: Optional[str]           # 数据类型，如 void / int / String 等
    modifiers: List[str]          # 修饰符，如 ["public", "static"]
    scope: List[str]              # 作用域，如 method_declaration / parameter / local
    start: int                    # 起始字节位置
    end: int                      # 结束字节位置
    decPos: Optional[Tuple[str, int]] # 声明位置，(声明语句, 行号)
    initPos: Optional[Tuple[str, int]] # 初始化位置，(初始化语句, 行号)
    useFPos: Optional[Tuple[str, int]] # 首次使用位置，(使用语句, 行号)
    
    def __str__(self):
        return f"{self.kind} '{self.entity}' ({self.scope}, {self.type}) @ {self.start}-{self.end} {self.decPos} first used at {self.useFPos}"