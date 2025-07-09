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
        # return copy.deepcopy(self)
        # 创建新节点（复制类型和额外文本）
        cloned = ZASTNode.from_type(self.type, self.extra_text)
        cloned.is_named = self.is_named

        # 深度复制所有子节点，并设置父节点
        for child in self.children:
            child_clone = child.clone()
            child_clone.parent = cloned
            cloned.children.append(child_clone)

        return cloned

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

class LoopPatterns:
    # 语言支持的循环模式模板
    _PATTERNS = {
        "java": {
            "for_statement": [
                {
                    "pattern": [
                        "for", "(", 
                        {"init": ["local_variable_declaration", ["assignment_expression", ";"]]}, 
                        {"condition": ["binary_expression"]}, 
                        ";", 
                        {"update": ["assignment_expression", "update_expression"]}, 
                        ")", 
                        "block"
                    ],
                    "fields": ["init", "condition", "update", "block"]
                }
            ],
            "enhanced_for_statement": [
                
            ],
            "while_statement": [
                {
                    "pattern": ["while", "condition", "block"],
                    "fields": ["condition", "block"]
                }
            ],
            "do_statement": [
                {
                    "pattern": [
                        "do", 
                        "block", 
                        "while", 
                        {"condition": ["parenthesized_expression"]},  
                        ";"
                    ],
                    "fields": ["block", "condition"]
                }
            ]
        },
        "cpp": {
            "for_statement": [
                {
                    "pattern": ["for", "(", {"init": ["declaration"]}, ";", "condition", ";", "update", ")", "compound_statement"],
                    "fields": ["init", "condition", "update", "compound_statement"]
                },
                {
                    "pattern": ["for", "(", {"init": ["assignment_expression"]}, ";", "condition", ";", "update", ")", "compound_statement"],
                    "fields": ["init", "condition", "update", "compound_statement"]
                }
            ],
            "while_statement": [
                {
                    "pattern": ["while", "condition_clause", "compound_statement"],
                    "fields": ["condition_clause", "compound_statement"]
                }
            ],
            "do_statement": [
                {
                    "pattern": ["do", "compound_statement", "while", "(", "condition", ")", ";"],
                    "fields": ["compound_statement", "condition"]
                }
            ]
        }
    }

    def __init__(self, lang: str):
        if lang not in self._PATTERNS:
            raise ValueError(f"Unsupported language: {lang}")
        self.lang = lang
        self.patterns = self._PATTERNS[lang]

    def get_patterns(self, node_type: str) -> Optional[List[dict]]:
        """
        获取指定类型循环节点的所有可能模式定义，包含 pattern 和 fields
        """
        return self.patterns.get(node_type)

    def match(self, node: ZASTNode, node_type: str) -> Optional[dict]:
        """
        匹配节点是否符合指定类型的循环结构模板，并提取字段
        """
        patterns = self.get_patterns(node_type)
        if not patterns:
            return None

        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            fields = pattern_info["fields"]
            match_result = self._match_pattern(node, pattern, fields)
            if match_result:
                # 如果是 while 或 do-while 循环，则需要进一步处理 init 和 update
                if node_type in ["while_statement", "do_statement"]:
                    match_result = self._extract_init_update(match_result, node)
                return match_result
        
        return None

    def _match_pattern(self, node: ZASTNode, pattern: List[str], fields: List[str]) -> Optional[dict]:
        """
        核心匹配逻辑，检查节点的子结构是否符合 pattern，并提取相应的字段
        """
        children = node.children
        field_values = {}

        pattern_i = 0
        child_i = 0

        while pattern_i < len(pattern) and child_i < len(children):
            expected = pattern[pattern_i]
            actual_node = children[child_i]

            if isinstance(expected, dict):  # {"init": ["declaration", "assignment_expression"]}
                key = list(expected.keys())[0]
                candidates = expected[key]
                if actual_node.type in candidates:
                    field_values[key] = actual_node
                    pattern_i += 1
                    child_i += 1
                else:
                    return None
            elif expected == actual_node.type:
                field_values[expected] = actual_node
                pattern_i += 1
                child_i += 1
            elif expected in {";", "(", ")", ":", ","} and actual_node.extra_text == expected:
                pattern_i += 1
                child_i += 1
            else:
                return None

        if len(field_values) < len(fields):
            for field in fields:
                if field not in field_values:
                    field_values[field] = None  # optional fallback

        return field_values

    def _extract_init_update(self, match_result: dict, node: ZASTNode) -> dict:
        """
        在 while 或 do-while 循环中提取 init 和 update 部分
        1. 从 condition 提取变量名
        2. 在循环外和循环内查找 init 和 update
        """
        condition_node = match_result.get("condition")
        if not condition_node:
            return match_result
        
        # 提取 condition 中的变量名（假设是简单的标识符）
        condition_var = self._extract_variable_from_condition(condition_node)

        # 查找 init 和 update
        init_node = self._find_init_node(node, condition_var)
        update_node = self._find_update_node(node, condition_var)
        
        # 将 init 和 update 添加到匹配结果中
        if init_node:
            match_result["init"] = init_node
        if update_node:
            match_result["update"] = update_node

        return match_result

    def _extract_variable_from_condition(self, condition_node: ZASTNode) -> str:
        """
        从 condition 节点中提取涉及的变量名
        假设条件是一个二元表达式
        """
        if condition_node.type == "binary_expression":
            left_node = condition_node.children[0]
            right_node = condition_node.children[1]
            if left_node.type == "identifier":
                print("111111111111111111111111111111"+left_node.extra_text)
                return left_node.extra_text
            if right_node.type == "identifier":
                return right_node.extra_text
        return ""

    def _find_init_node(self, node: ZASTNode, var_name: str) -> Optional[ZASTNode]:
        """
        在循环外查找初始化节点
        这里可以根据变量名在循环外查找变量声明或赋值表达式
        """
        for child in node.parent.children:
            # 确保 child.extra_text 不是 None
            if child.type in ["local_variable_declaration", "assignment_expression", "declaration"]:
                if child.extra_text and var_name in child.extra_text:
                    return child
        return None

    def _find_update_node(self, node: ZASTNode, var_name: str) -> Optional[ZASTNode]:
        """
        在循环内查找更新节点
        这里可以根据变量名在循环体内查找更新操作
        """
        for child in node.children:
            if child.type == "update_expression" and child.extra_text and var_name in child.extra_text:
                return child
            elif child.type == "expression_statement":
                for inner_child in child.children:
                    if inner_child.type == "update_expression" and inner_child.extra_text and var_name in inner_child.extra_text:
                        return inner_child
        return None

    def __repr__(self):
        return f"<LoopPatterns lang='{self.lang}'>"

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