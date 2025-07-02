from ._datacls import *
from .wparser import WParser
from tree_sitter import Node
from collections import defaultdict
import re

class ZASTNode:
    def __init__(self, ts_node: Node, source_code: str):
        self.type: str = ts_node.type
        self.children: List[ZASTNode] = []
        # self.start_byte: int = ts_node.start_byte
        # self.end_byte: int = ts_node.end_byte
        self.is_named: bool = ts_node.is_named
        self.extra_text: Optional[str] = None

        # 仅在叶子节点或非命名 token 节点上存储源码片段
        if len(ts_node.children) == 0 or not ts_node.is_named:
            self.extra_text = source_code[ts_node.start_byte:ts_node.end_byte]

        # 递归构建子节点
        for child in ts_node.children:
            self.children.append(ZASTNode(child, source_code))

    def __repr__(self) -> str:
        return f"ZASTNode(type='{self.type}', children={len(self.children)})"

def build_zast(source_code:str, lang:str)-> ZASTNode:
    wparser = WParser(lang)
    parser = wparser.parser
    
    tree = parser.parse(source_code.encode("utf8"))
    return ZASTNode(tree.root_node, source_code)

def print_zast(node, prefix="", is_last=True):
    connector = "└── " if is_last else "├── "
    extra = f' "{node.extra_text}"' if node.extra_text else ""
    print(f"{prefix}{connector}{node.type}{extra}")
    
    child_prefix = prefix + ("    " if is_last else "│   ")
    for i, child in enumerate(node.children):
        print_zast(child, child_prefix, i == len(node.children) - 1)

# 提取函数中所有可重命名实体（函数名、参数名、局部变量名）及其详细信息
def extract_renameable_entities(format_code:str, wparser:WParser) -> list:
    parser = wparser.parser
    tree = parser.parse(format_code.encode("utf8"))
    root = tree.root_node
    source_lines = format_code.splitlines()
    
    # 作用域栈: 用于跟踪当前的作用域，帮助处理嵌套函数和局部变量
    scope_stack = []
    # 用于记录每个函数作用域内各类结构计数
    # 栈结构，和 scope_stack 对应，元素是 dict，如 {"if_statement": 2}
    counter_stack = []
    
    func_name = []
    param_names = []
    local_var_names = []
    catch_params = []
    foreach_vars = []
    lambda_params = []
    
    # 在深度优先遍历中记录已声明的实体
    declared_entities = {} # key: (name, scope), value: renameableEntity
    
    def get_node_text(node):
        return format_code[node.start_byte:node.end_byte]
    
    def extract_modifiers(node):
        mod_node = node.child_by_field_name("modifiers")
        if not mod_node:
            mod_node = next((c for c in node.children if c.type == "modifiers"), None)

        if mod_node:
            return [get_node_text(child) for child in mod_node.children if child.type != "," and child.type != ";"]
        return []
    
    def normalize_type(type_str:str) -> str:
        if not type_str:
            return ""
        # 去掉所有空白字符（包括换行、缩进）
        type_str = re.sub(r"\s+", "", type_str)
        if "." in type_str:
            type_str = type_str.split(".")[-1]  # 保留简单类名
        return type_str
    
    def normalize_modifiers(modifiers:List[str]) -> Tuple[str, ...]:
        normed = []
        for m in modifiers:
            m = m.strip()
            # 如果是注解，提取出 @Name("...") → @Name
            m = re.sub(r'@(\w+)\s*\(.*?\)', r'@\1', m)
            normed.append(m)
        return tuple(sorted(normed))

    def make_scope_label(node):
        node_type = node.type
        line = node.start_point[0] + 1

        if node_type == "class_declaration":
            name_node = node.child_by_field_name("name")
            return f"Class {get_node_text(name_node)}"

        elif node_type == "method_declaration":
            name_node = node.child_by_field_name("name")
            return f"Function {get_node_text(name_node)}"

        elif node_type in {"if_statement", "catch_clause", "for_statement", "while_statement"}:
            # 查找当前函数作用域内的结构编号
            if counter_stack:
                counter_dict = counter_stack[-1]
                counter_dict[node_type] += 1
                index = counter_dict[node_type]
            else:
                index = 1
            label = f"{node_type.replace('_', ' ').title()}[{index}]@line:{line}"
            return label

        return f"{node_type}@line:{line}"
    
    def is_identifier_method_or_field_use(node):
        """
        判断 identifier 是否是方法名调用或字段访问的一部分，避免误认为变量使用
        """
        if not node or node.type != "identifier":
            return False
        parent = node.parent
        if not parent:
            return False

        # 情况 1: 方法调用时作为函数名
        if parent.type == "method_invocation" and node == parent.child_by_field_name("name"):
            return True

        # 情况 2: 作为字段调用一部分（如 obj.offer）
        if parent.type in {"field_access", "field_expression"}:
            return True

        return False

    
    def find_InitUse_Fpos_in_node(entity, name, root_node):
        """
        在指定语法块node中查找变量首次初始化位置和首次真正使用(非左值），同时避免作用域穿越。
        """
        def recurse(node):
            # 🎯 特殊处理赋值语句
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                operator_node = node.child_by_field_name("operator")
                operator_str = get_node_text(operator_node) if operator_node else "="

                # 左值匹配当前变量
                if left and left.type == "identifier" and get_node_text(left) == name:
                    # 👉 情况1: 普通赋值 (=) → 初始化
                    #!更改实体字段名后在这里也需要更改
                    if operator_str == "=" and right:
                        if entity.initPos is None:
                            line = right.start_point[0] + 1
                            text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                            entity.initPos = (text, line)
                        else:
                            pass  # 已经有初始化位置了，不需要重复记录

                    # 👉 情况2: 复合赋值 (+=, -=...) → 使用但不是初始化
                    elif operator_str in {"*=", "+=", "-=", "/=", "%=", "&=", "|=", "^=", ">>=", "<<=", ">>>="}:
                        #!更改实体字段名后在这里也需要更改
                        if entity.useFPos is None:
                            line = node.start_point[0] + 1
                            text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                            entity.useFPos = (text, line)

                    return False  # 无论哪种赋值，都不算使用（除非是右值）

            # 🎯 排除一元 ++ / -- 自增自减（写操作，不算使用）
            if node.type == "unary_expression":
                operand = node.child_by_field_name("argument")
                operator_node = node.child_by_field_name("operator")
                operator = get_node_text(operator_node) if operator_node else ""
                if operand and operand.type == "identifier" and get_node_text(operand) == name:
                    if operator in ("++", "--"):
                        return False

            # 🎯 函数调用检测（确保只记录真正的自调用）
            # ✅ Java-specific method invocation: method_invocation node
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")  # e.g. identifier 'offer'
                object_node = node.child_by_field_name("object")  # e.g. 'this' or another object
                if name_node and get_node_text(name_node) == name:
                    # 自调用必须没有 object（隐式 this）或明确 this
                    if object_node is None or get_node_text(object_node) == "this":
                        if not (entity.start <= name_node.start_byte <= entity.end):
                            if entity.useFPos is None:
                                line = name_node.start_point[0] + 1
                                text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                                entity.useFPos = (text, line)
                                return True

            # 🎯 非调用形式下的 identifier 使用（变量/参数等）
            # ✅ 真正的 identifier 使用（排除声明本身 + 非方法名/字段调用）
            if node.type == "identifier" and get_node_text(node) == name:
                if not (entity.start <= node.start_byte <= entity.end):
                    # 排除方法/字段用法
                    if not is_identifier_method_or_field_use(node): 
                        if entity.useFPos is None:
                            line = node.start_point[0] + 1
                            text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                            entity.useFPos = (text, line)
                            return True

            # 深度优先递归访问子节点
            for child in node.children:
                if recurse(child):
                    return True
            return False

        recurse(root_node)

    
    def traverse(node, parent=None):
        if node.type in {
            "class_declaration", "method_declaration", "if_statement",
            "for_statement", "while_statement", "catch_clause"}:
            label = make_scope_label(node)
            scope_stack.append(label)
        
        # 函数声明
        if node.type == "method_declaration":
            counter_stack.append(defaultdict(int))  # 新函数作用域，开始计数
            fn_name_node = node.child_by_field_name("name")
            fn_name = get_node_text(fn_name_node)
            line = fn_name_node.start_point[0] + 1
            code = source_lines[line - 1].strip()

            return_type_node = node.child_by_field_name("type")
            fn_type = get_node_text(return_type_node) if return_type_node else None

            entity = renameableEntity(
                entity=fn_name,
                kind="function",
                type=normalize_type(fn_type),
                modifiers= normalize_modifiers(
                    extract_modifiers(node)
                    ),
                scope=list(scope_stack),
                start=fn_name_node.start_byte,
                end=fn_name_node.end_byte,
                decPos=(code, line),
                initPos=(code, line),
                useFPos=None
            )
            
            func_name.append(entity)
            # 记录函数第一次自调用位置
            body_node = node.child_by_field_name("body")
            if body_node:
                find_InitUse_Fpos_in_node(entity, entity.entity, body_node)

            # 函数参数
            parameters = node.child_by_field_name("parameters")
            if parameters:
                for param in parameters.named_children:
                    if param.type == "formal_parameter":
                        type_node = param.child_by_field_name("type")
                        name_node = param.child_by_field_name("name")
                        if name_node:
                            line = name_node.start_point[0] + 1
                            code = source_lines[line - 1].strip()
                            entity = renameableEntity(
                                entity=get_node_text(name_node),
                                kind="parameter",
                                type=normalize_type(get_node_text(type_node) if type_node else None),
                                modifiers= normalize_modifiers(
                                    extract_modifiers(node)
                                    ),
                                scope=list(scope_stack),
                                start=name_node.start_byte,
                                end=name_node.end_byte,
                                decPos=(code, line),
                                initPos=None,
                                useFPos=None
                            )
                            param_names.append(entity)
                            declared_entities[(entity.entity, tuple(scope_stack))] = entity
                            
            # 函数体中的参数使用分析
            body_node = node.child_by_field_name("body")
            if body_node:
                for entity in param_names[-len(parameters.named_children):]:
                    find_InitUse_Fpos_in_node(entity, entity.entity, body_node)

        # 局部变量声明
        if node.type == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        line = name_node.start_point[0] + 1
                        code = source_lines[line - 1].strip()
                        
                        # 提取初始化位置：用位置匹配法提取初始化节点，被赋值节点不一定是value节点
                        init_node = None
                        for i, c in enumerate(child.children):
                            if get_node_text(c) == "=" and i + 1 < len(child.children):
                                init_node = child.children[i + 1]
                                break
                        
                        init_pos = None
                        if init_node:
                            init_line = init_node.start_point[0] + 1
                            if 0 <= init_line - 1 < len(source_lines):
                                init_code = source_lines[init_line - 1].strip()
                                init_pos = (init_code, init_line)
                        
                        entity = renameableEntity(
                            entity=get_node_text(name_node),
                            kind="local_variable",
                            type=normalize_type(get_node_text(type_node) if type_node else None),
                            modifiers= normalize_modifiers(
                                extract_modifiers(node)
                                ),
                            scope=list(scope_stack),
                            start=name_node.start_byte,
                            end=name_node.end_byte,
                            decPos=(code, line),
                            initPos=init_pos,
                            useFPos=None
                        )
                        local_var_names.append(entity)
                        declared_entities[(entity.entity, tuple(scope_stack))] = entity
                        
                        parent_block = parent if parent else root
                        find_InitUse_Fpos_in_node(entity, entity.entity, parent_block)
        
        # 异常捕获参数
        if node.type == "catch_clause":
            for child in node.children:
                if child.type == "catch_formal_parameter":
                    # 手动提取 catch_type 和 name
                    catch_type_node = None
                    name_node = None
                    for c in child.children:
                        if c.type == "catch_type":
                            catch_type_node = c
                        elif c.type == "identifier":
                            name_node = c

                    type_str = ""

                    if catch_type_node:
                        first_child = catch_type_node.children[0] if catch_type_node.children else None

                        # 情况 1：联合类型（IOException | SQLException）
                        if first_child and first_child.type == "union_type":
                            type_list = []

                            def dfs_union(n):
                                if n.type == "type_identifier":
                                    type_list.append(normalize_type(get_node_text(n)))
                                for c in n.children:
                                    dfs_union(c)

                            dfs_union(first_child)
                            type_str = "|".join(type_list)

                        # 情况 2：单一类型（scoped_type_identifier 或 type_identifier）
                        else:
                            type_str = get_node_text(catch_type_node)

                    if name_node:
                        line = name_node.start_point[0] + 1
                        code = source_lines[line - 1].strip()
                        entity = renameableEntity(
                            entity=get_node_text(name_node),
                            kind="catch_param",
                            type=normalize_type(type_str),
                            modifiers=normalize_modifiers(extract_modifiers(child)),
                            scope=list(scope_stack),
                            start=name_node.start_byte,
                            end=name_node.end_byte,
                            decPos=(code, line),
                            initPos=None,
                            useFPos=None
                        )
                        catch_params.append(entity)
                        declared_entities[(entity.entity, tuple(scope_stack))] = entity
                        
                        catch_body = next((c for c in reversed(node.children) if c.is_named and c.type == "block"), None)
                        if catch_body:
                            find_InitUse_Fpos_in_node(entity, entity.entity, catch_body)

        # 剩下变量随后补齐
        for child in node.children:
            traverse(child, node)
            
        if node.type in {
            "class_declaration", "method_declaration", "if_statement",
            "for_statement", "while_statement", "catch_clause"}:
            scope_stack.pop()
            if node.type == "method_declaration":
                counter_stack.pop()

    traverse(root)
    
    return func_name, param_names, local_var_names, catch_params, foreach_vars, lambda_params
