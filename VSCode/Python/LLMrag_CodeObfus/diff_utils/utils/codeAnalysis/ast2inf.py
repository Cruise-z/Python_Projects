from ._datacls import *
from .wparser import WParser
from collections import defaultdict
import re

def build_zast(source_code:str, lang:str) -> ZASTNode:
    wparser = WParser(lang)
    parser = wparser.parser
    
    tree = parser.parse(source_code.encode("utf8"))
    return ZASTNode(tree.root_node, source_code)

def print_zast(node:ZASTNode, prefix="", is_last=True):
    connector = "└── " if is_last else "├── "
    extra = f' "{node.extra_text}"' if node.extra_text else ""
    print(f"{prefix}{connector}{node.type}{extra}")
    
    child_prefix = prefix + ("    " if is_last else "│   ")
    for i, child in enumerate(node.children):
        print_zast(child, child_prefix, i == len(node.children) - 1)

# Find all local variable declarations
def find_local_varDecls(root: ZASTNode) -> List[Tuple[str, ZASTNode]]:
    declarations = []

    def visit(node: ZASTNode):
        if node.type == "local_variable_declaration":
            for child in node.children:
                if child.type == "variable_declarator":
                    # 只取第一个 identifier 子节点
                    for sub in child.children:
                        if sub.type == "identifier":
                            declarations.append((sub.extra_text, node))
                            break  # 只取第一个 identifier，跳出
        for child in node.children:
            visit(child)

    visit(root)
    return declarations

# Find variable enclosing block
def find_scopeNode(varDeclNode: ZASTNode, lang:str) -> Optional[ZASTNode]:
    rule = ScopeRules.lang(lang)
    current = varDeclNode.parent
    while current:
        if rule.is_scope_boundary(current.type):
            return current
        current = current.parent
    return None

# Find the initialization node
def find_initFNode(varName: str, scopeNode: ZASTNode) -> Tuple[Optional[ZASTNode], bool]:
    """
    返回变量 varName 的第一次初始化所在的 scopeNode 子树内的“顶层子节点” result_node，
    以及该节点是否就是初始化语句本身（is_direct = True 表示它就是赋值语句/声明语句本身）。
    若未找到初始化节点，则返回 (None, False)
    """
    
    result_node = None
    is_directInit = False

    def dfs(node: ZASTNode, path: list) -> bool:
        nonlocal result_node, is_directInit
        # 情况 1：声明即初始化
        if node.type == "local_variable_declaration":
            for decl in node.children:
                if decl.type == "variable_declarator":
                    has_equal = any(grand.type == "=" for grand in decl.children)
                    for id_node in decl.children:
                        if id_node.type == "identifier" and id_node.extra_text == varName:
                            if has_equal:
                                result_node = path[1] if len(path) > 1 else node
                                return True
        # 情况 2：赋值初始化
        if node.type == "assignment_expression":
            lhs = node.children[0]
            if lhs.type == "identifier" and lhs.extra_text == varName:
                result_node = path[1] if len(path) > 1 else node
                is_directInit = (node.parent == result_node)
                return True
        # 递归查找子节点
        for child in node.children:
            if dfs(child, path + [child]):
                return True
        return False

    dfs(scopeNode, [scopeNode])
    return result_node, is_directInit

# Extract variable declaration from original declaration node
def extractVarDecl(varName: str, oriDeclNode: ZASTNode) -> Tuple[Optional[ZASTNode], Optional[ZASTNode], bool]:
    """
    从 ori_decl_node 中提取变量 var_name 的声明和初始化部分。

    返回:
        - 新声明节点 (local_variable_declaration)
        - 初始化节点 (expression_statement)
        - bool：原始节点是否为空
    """

    # 1. 获取类型修饰部分（如 int, final 等）
    fixed_parts = [c for c in oriDeclNode.children if c.type not in {"variable_declarator", ",", ";"}]
    fixed_parts_clone = [c.clone() for c in fixed_parts]

    # 初始化新声明节点
    new_decl_node = ZASTNode.from_type("local_variable_declaration")
    new_decl_node.children.extend(fixed_parts_clone)

    new_init_node = None
    new_var_decl = None
    new_children = []

    i = 0
    children = oriDeclNode.children

    while i < len(children):
        node = children[i]

        if node.type == "variable_declarator":
            # 判断是否为目标变量
            is_target = any(c.type == "identifier" and c.extra_text == varName for c in node.children)

            if is_target:
                # 提取声明部分
                new_var_decl = ZASTNode.from_type("variable_declarator")
                for c in node.children:
                    if c.type == "identifier" and c.extra_text == varName:
                        new_var_decl.children.append(c.clone())
                        break
                new_decl_node.children.append(new_var_decl)

                # 提取初始化表达式
                if any(c.type == "=" for c in node.children):
                    eq_idx = next(i for i, c in enumerate(node.children) if c.type == "=")
                    lhs = [c.clone() for c in node.children[:eq_idx]]
                    eq = ZASTNode.from_type("=", "=")
                    rhs = [c.clone() for c in node.children[eq_idx + 1:]]

                    assign_expr = ZASTNode.from_type("assignment_expression")
                    assign_expr.children.extend(lhs + [eq] + rhs)

                    new_init_node = ZASTNode.from_type("expression_statement")
                    new_init_node.children.extend([assign_expr, ZASTNode.from_type(";", ";")])

                # 删除相关逗号
                if i > 0 and children[i - 1].type == ",":
                    new_children.pop()  # 删除前逗号
                elif i + 1 < len(children) and children[i + 1].type == ",":
                    i += 1  # 跳过后逗号
            else:
                new_children.append(node)

        elif node.type == ",":
            new_children.append(node)

        elif node.type == ";":
            pass  # 分号稍后处理

        else:
            if node not in fixed_parts:
                new_children.append(node)

        i += 1

    # 添加分号到原始和新声明中
    semi = next((c for c in children if c.type == ";"), None)
    if semi:
        if semi not in new_children:
            new_children.append(semi)
        new_decl_node.children.append(semi.clone())

    # 更新原始声明节点的 children
    oriDeclNode.children = fixed_parts + new_children
    is_ori_empty = all(c.type != "variable_declarator" for c in oriDeclNode.children)

    return (new_decl_node if new_var_decl else None, new_init_node, is_ori_empty)

def mergeDeclInit(decl_node: ZASTNode, init_node: ZASTNode) -> ZASTNode:
    """
    合并变量声明节点和初始化节点，生成一个新的 local_variable_declaration 节点。

    参数:
    - decl_node: 含类型和 identifier 的 local_variable_declaration 节点（不含初始化）
    - init_node: 含 assignment_expression 的 expression_statement 节点

    返回:
    - 合并后的 local_variable_declaration 节点
    """

    # 创建合并节点
    merged_node = ZASTNode.from_type("local_variable_declaration")

    # 类型部分拷贝
    type_parts = [c.clone() for c in decl_node.children if c.type not in {"variable_declarator", ";"}]
    merged_node.children.extend(type_parts)

    # 获取变量名
    var_decl = next((c for c in decl_node.children if c.type == "variable_declarator"), None)
    if var_decl is None:
        raise ValueError("Declaration node missing variable_declarator")

    var_id = next((c for c in var_decl.children if c.type == "identifier"), None)
    if var_id is None:
        raise ValueError("No identifier found in declaration")
    var_name = var_id.extra_text

    # 初始化节点检查
    if not init_node.children or init_node.children[0].type != "assignment_expression":
        raise ValueError("Initialization node does not contain assignment_expression")

    assign_expr = init_node.children[0]
    lhs, eq, *rhs = assign_expr.children
    if lhs.type != "identifier" or lhs.extra_text != var_name:
        raise ValueError("LHS identifier does not match declaration name")

    # 构造新的 variable_declarator
    new_var_decl = ZASTNode.from_type("variable_declarator")
    new_var_decl.children.append(var_id.clone())      # identifier
    new_var_decl.children.append(eq.clone())          # "="
    new_var_decl.children.extend([c.clone() for c in rhs])  # RHS

    merged_node.children.append(new_var_decl)

    # 分号处理
    semi = next((c for c in decl_node.children if c.type == ";"), None)
    if semi:
        merged_node.children.append(semi.clone())
    else:
        merged_node.children.append(ZASTNode.from_type(";", ";"))

    return merged_node

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
