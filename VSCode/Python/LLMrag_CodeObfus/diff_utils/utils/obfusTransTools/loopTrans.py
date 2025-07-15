from ..codeAnalysis.astTrans import *
from ..codeAnalysis.funcReg import register, tagFunc
from ..format import *
import random

@register("for2while")
def convert_for_to_while(for_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 for 循环转换为 while 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(for_node, "for_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    # 克隆 body 并在末尾添加 update
    body.children.insert(len(body.children) - 1, update)
    update.parent = body
    # 修改 AST 结构：在 for_node 前插入 init，替换 for_node 为 while_node
    parent = for_node.parent
    if parent is None:
        raise ValueError("for_node has no parent")
    index = parent.children.index(for_node)
    parent.children.insert(index, init)    # 插入初始化语句
    init.parent = parent

    # 构造 while 循环节点
    while_node = ZASTNode.from_type(mapper.getType("while_statement"))
    conNode = ZASTNode.from_type(mapper.getType("while_condition"))
    conNode.parent = while_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = conNode
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = conNode
    condition.parent = while_node
    conNode.children = [
        lparenNode,
        condition,
        rparenNode
    ]
    
    while_str = ZASTNode.from_type("while", "while")
    while_str.parent = while_node
    while_node.children = [
        while_str,
        conNode, 
        body
    ]
    body.parent = while_node
    while_node.parent = parent

    return while_node

@register("for2dowhile")
def convert_for_to_do(for_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 for 循环转换为 do-while 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(for_node, "for_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    # 在 body 末尾添加 update
    body.children.insert(len(body.children) - 1, update)
    update.parent = body
    # 修改 AST 结构：在 for_node 前插入 init，替换 for_node 为 while_node
    parent = for_node.parent
    if parent is None:
        raise ValueError("for_node has no parent")
    index = parent.children.index(for_node)
    parent.children.insert(index, init)    # 插入初始化语句
    init.parent = parent

    # 构造 while 循环节点
    do_node = ZASTNode.from_type(mapper.getType("do_statement"))
    conNode = ZASTNode.from_type(mapper.getType("dowhile_condition"))
    conNode.parent = do_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = conNode
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = conNode
    condition.parent = do_node
    conNode.children = [
        lparenNode,
        condition,
        rparenNode
    ]
    
    do_str = ZASTNode.from_type("do", "do")
    do_str.parent = do_node
    while_str = ZASTNode.from_type("while", "while")
    while_str.parent = do_node
    do_node.children = [
        do_str,
        body,
        while_str,
        conNode
    ]
    body.parent = do_node
    do_node.parent = parent

    return do_node

@register("while2for")
def convert_while_to_for(while_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 while 循环转换为 for 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(while_node, "while_statement")
    
    parent = while_node.parent
    if not match:
        raise ValueError(f"Unsupported while loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    if condition:
        condition = condition.children[1]
    
    for_node = ZASTNode.from_type(mapper.getType("for_statement"))
    for_str = ZASTNode.from_type("for", "for")
    for_str.parent = for_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = for_node
    semicolon1 = ZASTNode.from_type(";", ";")
    semicolon1.parent = for_node
    semicolon2 = ZASTNode.from_type(";", ";")
    semicolon2.parent = for_node
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = for_node
    
    init.parent = for_node
    condition.parent = for_node
    update.parent = for_node
    body.parent = for_node
    
    for_node.children = [
        for_str,
        lparenNode,
        init,
        semicolon1,
        condition,
        semicolon2,
        update,
        rparenNode,
        body
    ]
    for_node.parent = parent
    
    return for_node

@register("while2dowhile")
def convert_while_to_do(while_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 while 循环转换为 do-while 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(while_node, "while_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    if condition:
        condition = condition.children[1]
    
    # 在 body 末尾添加 update
    body.children.insert(len(body.children) - 1, update)
    update.parent = body
    # 修改 AST 结构：在 for_node 前插入 init，替换 for_node 为 while_node
    parent = while_node.parent
    if parent is None:
        raise ValueError("for_node has no parent")
    index = parent.children.index(while_node)
    parent.children.insert(index, init)    # 插入初始化语句
    init.parent = parent

    # 构造 while 循环节点
    do_node = ZASTNode.from_type(mapper.getType("do_statement"))
    conNode = ZASTNode.from_type(mapper.getType("dowhile_condition"))
    conNode.parent = do_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = conNode
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = conNode
    condition.parent = do_node
    conNode.children = [
        lparenNode,
        condition,
        rparenNode
    ]
    
    do_str = ZASTNode.from_type("do", "do")
    do_str.parent = do_node
    while_str = ZASTNode.from_type("while", "while")
    while_str.parent = do_node
    do_node.children = [
        do_str,
        body,
        while_str,
        conNode
    ]
    body.parent = do_node
    do_node.parent = parent

    return do_node

@register("dowhile2while")
def convert_do_to_while(do_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 do-while 循环转换为 while 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(do_node, "do_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    if condition:
        condition = condition.children[1]
    
    # 克隆 body 并在末尾添加 update
    body.children.insert(len(body.children) - 1, update)
    update.parent = body
    # 修改 AST 结构：在 for_node 前插入 init，替换 for_node 为 while_node
    parent = do_node.parent
    if parent is None:
        raise ValueError("for_node has no parent")
    index = parent.children.index(do_node)
    parent.children.insert(index, init)    # 插入初始化语句
    init.parent = parent

    # 构造 while 循环节点
    while_node = ZASTNode.from_type(mapper.getType("while_statement"))
    conNode = ZASTNode.from_type(mapper.getType("while_condition"))
    conNode.parent = while_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = conNode
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = conNode
    condition.parent = while_node
    conNode.children = [
        lparenNode,
        condition,
        rparenNode
    ]
    
    while_str = ZASTNode.from_type("while", "while")
    while_str.parent = while_node
    while_node.children = [
        while_str,
        conNode, 
        body
    ]
    body.parent = while_node
    while_node.parent = parent

    return while_node

@register("dowhile2for")
def convert_do_to_for(do_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 while 循环转换为 for 循环
    """
    adapter = LoopPatterns(lang)
    mapper = LanguageASTMapper(lang)
    match = adapter.match(do_node, "do_statement")
    
    parent = do_node.parent
    if not match:
        raise ValueError(f"Unsupported while loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"]

    if condition:
        condition = condition.children[1]
    
    for_node = ZASTNode.from_type(mapper.getType("for_statement"))
    for_str = ZASTNode.from_type("for", "for")
    for_str.parent = for_node
    lparenNode = ZASTNode.from_type("(", "(")
    lparenNode.parent = for_node
    semicolon1 = ZASTNode.from_type(";", ";")
    semicolon1.parent = for_node
    semicolon2 = ZASTNode.from_type(";", ";")
    semicolon2.parent = for_node
    rparenNode = ZASTNode.from_type(")", ")")
    rparenNode.parent = for_node
    
    init.parent = for_node
    condition.parent = for_node
    update.parent = for_node
    body.parent = for_node
    
    for_node.children = [
        for_str,
        lparenNode,
        init,
        semicolon1,
        condition,
        semicolon2,
        update,
        rparenNode,
        body
    ]
    for_node.parent = parent
    
    return for_node

def random_loop_conversion(zast_tree:ZASTNode, lang:str) -> ZASTNode:
    """
    随机将 ZAST 树中的所有循环结构转换为其他两种循环类型之一
    """
    # 创建 LoopPatterns 适配器，支持不同语言的转换
    mapper = LanguageASTMapper(lang)

    # 用于收集循环节点
    loop_nodes = []

    # 遍历树的所有节点，收集所有循环节点
    def collect_loop_nodes(node: ZASTNode):
        # 遍历树的节点，收集循环节点
        for field in ["for_statement", "while_statement", "do_statement"]:
            node_type = mapper.getType(field)
            if node_type != "Not Found" and node.type == node_type:
                loop_nodes.append(node)
                break  # 找到匹配的类型后退出匹配循环
        
        # 递归遍历子节点
        for child in node.children:
            collect_loop_nodes(child)
    
    # 收集所有循环节点
    collect_loop_nodes(zast_tree)

    def convert_loop_type(loop_node, lang, mapper):
        """
        通用的循环转换函数，根据不同循环类型进行转换。
        """
        # 获取当前循环类型
        loop_type = loop_node.type
        
        # 定义一个空的操作列表
        ops = []

        # 根据当前循环类型，添加可以转换到的类型
        if loop_type == "for_statement":
            if mapper.getType("while_statement") != "Not Found":
                ops.append("for2while")
            if mapper.getType("do_statement") != "Not Found":
                ops.append("for2dowhile")
        
        elif loop_type == "while_statement":
            if mapper.getType("for_statement") != "Not Found":
                ops.append("while2for")
            if mapper.getType("do_statement") != "Not Found":
                ops.append("while2dowhile")
        
        elif loop_type == "do_statement":
            if mapper.getType("for_statement") != "Not Found":
                ops.append("dowhile2for")
            if mapper.getType("while_statement") != "Not Found":
                ops.append("dowhile2while")

        # 如果有可以转换的类型，随机选择一个进行转换
        if ops:
            choice = random.choice(ops)
            # 使用转换类型调用相应的转换函数
            new_node = tagFunc(choice, loop_node, lang)
            
            # 替换原循环节点
            parent = loop_node.parent
            index = parent.children.index(loop_node)
            parent.children[index] = new_node
            new_node.parent = parent
    
    # 调用上述函数来处理所有的循环节点
    for loop_node in loop_nodes:
        convert_loop_type(loop_node, lang, mapper)

    return zast_tree

def print_matched_fields(match:dict):
    """
    打印匹配结果中的所有字段及其对应的节点类型和子节点信息。
    
    :param match: 一个字典，包含匹配的字段及其对应的 ZASTNode 对象。
    """
    if match:
        print("Matched Fields:")
        for field, node in match.items():
            if node:
                print(f"Field: {field}, Node Type: {node.type}")
                print_ZASTNode(node)
    else:
        print("No match found.")