from dataclasses import dataclass, fields, is_dataclass
from tree_sitter import Node
from typing import List, Optional, Tuple, Set, Dict, Any
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

class LanguageASTMapper:
    def __init__(self, language: str):
        """
        初始化时指定语言类型，并设置相应的字段名与节点类型的映射。
        :param language: 编程语言类型，如 'java', 'cpp', 'python', 'javascript'
        """
        self.language = language.lower()
        
        # 定义不同语言的映射字典
        self.mapping = {
            "java": {
                "variable_declaration": "local_variable_declaration",
                "expression": "expression_statement",
                "assignment": "assignment_expression",
                "if_statement": "if_statement",
                "for_statement": "for_statement",
                "while_statement": "while_statement",
                "do_statement": "do_statement",
                "method_declaration": "method_declaration",
                "return_statement": "return_statement",
                "class_declaration": "class_declaration",
                "try_statement": "try_statement",
                "import_declaration": "import_declaration"
            },
            "cpp": {
                "variable_declaration": "declaration",
                "expression": "expression_statement",
                "assignment": "assignment_expression",
                "if_statement": "if_statement",
                "for_statement": "for_statement",
                "while_statement": "while_statement",
                "do_statement": "do_statement",
                "function_definition": "function_definition",
                "return_statement": "return_statement",
                "class_declaration": "class_declaration",
                "try_statement": "try_statement",
                "import_declaration": "import_declaration"
            },
            "python": {
                "variable_declaration": "Assign",
                "assignment": "Assign",
                "if_statement": "If",
                "while_statement": "While",
                "for_statement": "For",
                "function_definition": "FunctionDef",
                "return_statement": "Return",
                "class_declaration": "ClassDef",
                "try_statement": "Try",
                "import_declaration": "Import",
                "expression": "Expr",
                "lambda_expression": "Lambda",
                "binary_expression": "BinOp",
                "unary_expression": "UnaryOp",
                "list_comprehension": "ListComp",
                "dict_comprehension": "DictComp",
                "generator_expression": "GeneratorExp"
            },
            "javascript": {
                "variable_declaration": "variable_declaration",
                "assignment": "assignment_expression",
                "if_statement": "if_statement",
                "for_statement": "for_statement",
                "while_statement": "while_statement",
                "function_definition": "function_declaration",
                "return_statement": "return_statement",
                "class_declaration": "class_declaration",
                "try_statement": "try_statement",
                "import_declaration": "import_declaration"
            }
        }

        # 确保传入的语言在字典中有效
        if self.language not in self.mapping:
            raise ValueError(f"Unsupported language: {language}")

        # 设置该语言对应的映射
        self.language_mapping = self.mapping[self.language]

    def getType(self, field_name: str) -> str:
        """
        根据字段名，返回相应的节点类型。
        :param field_name: 字段名，如 'variable_declaration', 'if_statement'
        :return: 对应的 AST 节点类型，若没有找到，返回 'Not Found'
        在执行转换时，需要查看
        """
        # 查找并返回对应的节点类型
        return self.language_mapping.get(field_name.lower(), "Not Found")

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
                        {"init": [["local_variable_declaration"], ["assignment_expression", ";"], [";"]]}, 
                        {"condition": [["binary_expression", ";"], [";"]]},  
                        {"update": [["assignment_expression"], ["update_expression"], None]}, 
                        ")", 
                        {"block": [["block"]]}
                    ],
                    "fields": ["init", "condition", "update", "block"]
                }
            ],
            "enhanced_for_statement": [
                
            ],
            "while_statement": [
                {
                    "pattern": [
                        "while", 
                        {"condition": [["condition"]]}, 
                        {"block": [["block"]]}
                    ],
                    "fields": ["condition", "block"]
                }
            ],
            "do_statement": [
                {
                    "pattern": [
                        "do", 
                        {"block": [["block"]]}, 
                        "while", 
                        {"condition": [["parenthesized_expression"]]},  
                        ";"
                    ],
                    "fields": ["block", "condition"]
                }
            ]
        },
        "cpp": {
            "for_statement": [
                {
                    "pattern": [
                        "for", "(", 
                        {"init": [["declaration"], ["assignment_expression", ";"]]}, 
                        {"condition": [["binary_expression", ";"], [";"]]},  
                        {"update": [["assignment_expression"], ["update_expression"]]}, 
                        ")", 
                        {"block": [["compound_statement"]]}
                    ],
                    "fields": ["init", "condition", "update", "block"]
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
                    "pattern": [
                        "do", 
                        {"block": [["compound_statement"]]}, 
                        "while", 
                        {"condition": [["parenthesized_expression"]]}, 
                        ";"
                    ],
                    "fields": ["block", "condition"]
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

    def match(self, loopNode: ZASTNode, node_type: str) -> Optional[dict]:
        """
        匹配节点是否符合指定类型的循环结构模板，并提取字段
        """
        patterns = self.get_patterns(node_type)
        if not patterns:
            return None

        mapper = LanguageASTMapper(self.lang)
        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            fields = pattern_info["fields"]
            match_result = self._match_pattern(loopNode, pattern, fields)
            if match_result:
                # 如果是 while 或 do-while 循环，则需要进一步处理 init 和 update
                if node_type in [mapper.getType("while_statement"), mapper.getType("do_statement")]:
                    match_result = self._extract_init_update(match_result, loopNode)
                return match_result
        
        return None

    def _match_pattern(self, loopNode: ZASTNode, pattern: list, fields: list) -> Optional[dict]:
        """
        匹配循环节点和指定模式，返回匹配成功的字段
        """
        child_idx = 0
        matched_fields = {}
        
        for pattern_item in pattern:
            # 如果是普通的字符串类型，直接匹配
            if isinstance(pattern_item, str):
                if child_idx < len(loopNode.children) and loopNode.children[child_idx].type == pattern_item:
                    child_idx += 1  # 匹配成功，继续匹配下一个节点
                else:
                    return None  # 匹配失败，返回None
            # 如果是字段匹配（字典形式）
            elif isinstance(pattern_item, dict):
                for field_name, options in pattern_item.items():
                    # 尝试匹配字段的每一个选择项
                    for option in options:
                        if option is None:
                            matched_fields[field_name] = None
                            break
                        cnt = 0
                        matched = True
                        # 检查当前子节点是否与选项匹配
                        while cnt < len(option) and child_idx + cnt < len(loopNode.children):
                            if loopNode.children[child_idx + cnt].type != option[cnt]:
                                matched = False
                                break
                            cnt += 1
                        if matched:
                            # 匹配成功，更新该字段，并跳过相应数量的子节点
                            if loopNode.children[child_idx].type == ';':
                                matched_fields[field_name] = None
                            else:
                                matched_fields[field_name] = loopNode.children[child_idx]
                            child_idx += cnt  # 跳过已匹配的子节点
                            break
                    else:
                        # 如果所有选择项都不匹配，返回None
                        return None
            else:
                return None

        # 返回匹配成功的字段
        return {field: matched_fields[field] for field in fields if field in matched_fields}

    def _extract_init_update(self, match_result: dict, node: ZASTNode) -> dict:
        """
        在 while 或 do-while 循环中提取 init 和 update 部分
        1. 从 condition 提取变量名
        2. 在循环外和循环内查找 init 和 update
        """
        condition_node = match_result.get("condition")
        if not condition_node:
            return match_result
        
        block_node = match_result.get("block")
        if not block_node:
            return match_result
        
        # 提取 condition 中的变量名
        condition_var = self._extract_variable_from_condition(condition_node)
        print("condition var is:"+condition_var)
        # 查找 init 和 update
        init_node = self._find_init_node(node, condition_var)
        update_node = self._find_update_node(block_node, condition_var)
        print(init_node)
        print(update_node)
        # 将 init 和 update 添加到匹配结果中
        if init_node:
            match_result["init"] = init_node
        if update_node:
            match_result["update"] = update_node

        return match_result

    def _extract_variable_from_condition(self, condition_node: ZASTNode) -> str:
        """
        递归查找 condition_node 中所有的 'binary_expression' 节点，
        并提取涉及的变量名（标识符）。
        """
        # 1. 如果当前节点是二元表达式类型
        if condition_node.type == "binary_expression":
            left_node = condition_node.children[0]
            right_node = condition_node.children[1]

            # 2. 检查左边和右边的子节点是否为标识符
            if left_node.type == "identifier":
                return left_node.extra_text  # 返回左边的标识符

            if right_node.type == "identifier":
                return right_node.extra_text  # 返回右边的标识符

        # 3. 如果当前节点不是二元表达式，递归检查它的所有子节点
        for child in condition_node.children:
            result = self._extract_variable_from_condition(child)
            if result:  # 如果递归返回了标识符，直接返回
                return result

        # 4. 如果没有找到标识符，返回空字符串
        return ""

    def _find_init_node(self, node: ZASTNode, var_name: str) -> Optional[ZASTNode]:
        """
        在循环外查找初始化节点，找到离 node 最近的节点
        这里可以根据变量名在循环外查找变量声明或赋值表达式
        !可能需要进一步改进
        """
        mapper = LanguageASTMapper(self.lang)
        print("Inspecting node:", node)
        print("Inspecting node parent:", node.parent)

        # 找到 node 在父节点中的索引位置
        node_index = node.parent.children.index(node)
        closest_init_node = None

        # 从 node_index-1 开始逆序遍历父节点的子节点，检查每个子节点
        for i in range(node_index - 1, -1, -1):  # 逆序遍历，直到第一个节点
            child = node.parent.children[i]
            print("Checking child:", child)

            # 确保 child.extra_text 不是 None，并且 child 是我们关心的节点类型
            if child.type == mapper.getType("variable_declaration"):
                # 查找 variable_declarator 中的 identifier
                assignment = child.children[1]  # 获取 variable_declarator 子节点
                identifier_node = assignment.children[0]  # 获取 identifier 子节点
                print("Variable name in declaration:", identifier_node.extra_text)

                # 如果 var_name 与 identifier 节点中的变量名相匹配
                if var_name == identifier_node.extra_text:
                    print("Found matching initialization node:", child)
                    closest_init_node = child  # 记录找到的节点
                    break  # 找到最近的节点后立即停止遍历
            elif child.type == mapper.getType("expression"):
                # 查找 variable_declarator 中的 identifier
                assignment = child.children[0]  # 获取 variable_declarator 子节点
                if assignment.type == mapper.getType("assignment"):
                    identifier_node = assignment.children[0]  # 获取 identifier 子节点
                    print("Variable name in expression:", identifier_node.extra_text)

                    # 如果 var_name 与 identifier 节点中的变量名相匹配
                    if var_name == identifier_node.extra_text:
                        print("Found matching initialization node:", child)
                        closest_init_node = child  # 记录找到的节点
                        break  # 找到最近的节点后立即停止遍历
        # 返回找到的最接近的初始化节点
        return closest_init_node

    def _find_update_node(self, block_node: ZASTNode, var_name: str) -> Optional[ZASTNode]:
        """
        在循环内查找更新节点
        这里可以根据变量名在循环体内查找更新操作
        """
        mapper = LanguageASTMapper(self.lang)
        for child in reversed(block_node.children):
            # 如果是包含更新表达式的 expression_statement
            if child.type == mapper.getType("expression"):
                update = child.children[0]
                for update_child in update.children:
                    if update_child.type == "identifier" and update_child.extra_text == var_name:
                        print(f"Found update expression inside expression statement: {update_child.extra_text}")
                        return update
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