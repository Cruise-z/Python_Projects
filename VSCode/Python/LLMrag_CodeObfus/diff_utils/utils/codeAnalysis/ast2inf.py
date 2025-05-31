from .wparser import WParser
from ..format import *
from collections import defaultdict

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
    
    def find_first_usage_in_node(entity, name, root_node):
        """
        在指定语法块 node 中查找 name 的首次使用，避免作用域穿越。
        """
        def recurse(node):
            if node.type == "identifier" and get_node_text(node) == name:
                if not (entity.start <= node.start_byte <= entity.end):
                    line = node.start_point[0] + 1
                    text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                    entity.use_fpos = (text, line)
                    return True  # 提前返回
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
                useFPos=None
            )
            
            func_name.append(entity)

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
                                useFPos=None
                            )
                            param_names.append(entity)
                            declared_entities[(entity.entity, tuple(scope_stack))] = entity
                            
            # 函数体中的参数使用分析
            body_node = node.child_by_field_name("body")
            if body_node:
                for entity in param_names[-len(parameters.named_children):]:
                    find_first_usage_in_node(entity, entity.entity, body_node)

        # 局部变量声明
        if node.type == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        line = name_node.start_point[0] + 1
                        code = source_lines[line - 1].strip()
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
                            useFPos=None
                        )
                        local_var_names.append(entity)
                        declared_entities[(entity.entity, tuple(scope_stack))] = entity
                        
                        parent_block = parent if parent else root
                        find_first_usage_in_node(entity, entity.entity, parent_block)
        
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
                            useFPos=None
                        )
                        catch_params.append(entity)
                        declared_entities[(entity.entity, tuple(scope_stack))] = entity
                        
                        catch_body = next((c for c in reversed(node.children) if c.is_named and c.type == "block"), None)
                        if catch_body:
                            find_first_usage_in_node(entity, entity.entity, catch_body)

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
