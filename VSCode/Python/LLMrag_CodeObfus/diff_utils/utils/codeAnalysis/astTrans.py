from ._datacls import *
from .wparser import WParser

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