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

def convert_while_to_for(while_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 while 循环转换为 for 循环
    """
    adapter = LoopPatterns(lang)
    match = adapter.match(while_node, "while_statement")
    
    if not match:
        raise ValueError(f"Unsupported while loop structure in {lang} AST")

    condition = match["condition"]
    body = match["block"] or match.get("compound_statement")

    # 假设 init 和 update 是需要外部定义或从其他地方提取
    init_node = ZASTNode.from_type("init_declaration", "int i = 0")  # 模拟初始化
    update_node = ZASTNode.from_type("update_expression", "i++")  # 模拟更新

    for_node = ZASTNode.from_type(adapter.get_patterns("for_statement"))
    for_node.children = [
        ZASTNode.from_type("(", "("),
        init_node,
        ZASTNode.from_type(";", ";"),
        condition.clone(),
        ZASTNode.from_type(";", ";"),
        update_node,
        ZASTNode.from_type(")", ")"),
        body.clone()
    ]
    
    return for_node

def convert_do_to_while(do_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 do-while 循环转换为 while 循环
    """
    adapter = LoopPatterns(lang)
    match = adapter.match(do_node, "do_statement")
    
    if not match:
        raise ValueError(f"Unsupported do-while loop structure in {lang} AST")

    body = match["block"]
    condition = match["condition"]

    # 创建新的 while 循环
    while_node = ZASTNode.from_type(adapter.get_patterns("while_statement"))
    while_node.children = [condition.clone(), body.clone()]

    return while_node

def convert_while_to_do(while_node:ZASTNode, lang:str) -> ZASTNode:
    """
    将 while 循环转换为 do-while 循环
    """
    adapter = LoopPatterns(lang)
    match = adapter.match(while_node, "while_statement")
    
    if not match:
        raise ValueError(f"Unsupported while loop structure in {lang} AST")

    condition = match["condition"]
    body = match["block"] or match.get("compound_statement")

    # 创建新的 do-while 循环
    do_node = ZASTNode.from_type(adapter.get_patterns("do_statement"))
    do_node.children = [
        ZASTNode.from_type("do", "do"),
        body.clone(),
        ZASTNode.from_type("while", "while"),
        ZASTNode.from_type("(", "("),
        condition.clone(),
        ZASTNode.from_type(")", ")"),
        ZASTNode.from_type(";", ";")
    ]
    
    return do_node

def random_loop_conversion(zast_tree:ZASTNode, lang:str) -> ZASTNode:
    """
    随机将 ZAST 树中的所有循环结构转换为其他两种循环类型之一
    """
    # 创建 LoopPatterns 适配器，支持不同语言的转换
    adapter = LoopPatterns(lang)
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

    # 对收集到的所有循环节点进行处理
    for loop_node in loop_nodes:
        # 根据不同的循环类型进行随机转换
        if loop_node.type == "for_statement":
            match = adapter.match(loop_node, "for_statement")
            print_matched_fields(match)
            if match:
                ops = []
                if mapper.getType("while_statement"):
                    ops.append("for2while")
                if mapper.getType("do_statement"):
                    ops.append("for2dowhile")
                choice = random.choice(ops)
                new_node = tagFunc(choice, loop_node, lang)
                # 替换原循环节点
                parent = loop_node.parent
                index = parent.children.index(loop_node)
                parent.children[index] = new_node
                new_node.parent = parent

        elif loop_node.type == "while_statement":
            match = adapter.match(loop_node, "while_statement")
            if match:
                # 随机选择转化为 for 或 do
                new_node = random.choice([convert_while_to_for(loop_node, lang), convert_while_to_do(loop_node, lang)])
                # 替换原循环节点
                parent = loop_node.parent
                index = parent.children.index(loop_node)
                parent.children[index] = new_node
                new_node.parent = parent

        elif loop_node.type == "do_statement":
            match = adapter.match(loop_node, "do_statement")
            if match:
                # 随机选择转化为 for 或 while
                new_node = random.choice([convert_do_to_for(loop_node, lang), convert_do_to_while(loop_node, lang)])
                # 替换原循环节点
                parent = loop_node.parent
                index = parent.children.index(loop_node)
                parent.children[index] = new_node
                new_node.parent = parent

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