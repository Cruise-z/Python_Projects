from ..codeAnalysis.astTrans import *
from ..format import *
import random

def convert_for_to_while(for_node: ZASTNode, lang: str = "java") -> ZASTNode:
    """
    将 for 循环转换为 while 循环
    """
    adapter = LoopPatterns(lang)
    match = adapter.match(for_node, "for_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"] or match.get("compound_statement")

    # 克隆 body 并在末尾添加 update
    body_copy = body.clone()
    if body_copy.type in {"block", "compound_statement"}:
        body_copy.children.append(update.clone())

    # 构造 while 循环节点
    while_node = ZASTNode.from_type(adapter.get_patterns("while_statement"))
    while_node.children = [condition.clone(), body_copy]

    return while_node

def convert_for_to_do(for_node: ZASTNode, lang: str = "java") -> ZASTNode:
    """
    将 for 循环转换为 do-while 循环
    """
    adapter = LoopPatterns(lang)
    match = adapter.match(for_node, "for_statement")
    
    if not match:
        raise ValueError(f"Unsupported for loop structure in {lang} AST")

    init = match["init"]
    condition = match["condition"]
    update = match["update"]
    body = match["block"] or match.get("compound_statement")

    # 克隆 body 并在末尾添加 update
    body_copy = body.clone()
    if body_copy.type in {"block", "compound_statement"}:
        body_copy.children.append(update.clone())

    # 创建 do-while 循环节点
    do_node = ZASTNode.from_type(adapter.get_patterns("do_statement"))
    do_node.children = [
        ZASTNode.from_type("do", "do"),
        body_copy,
        ZASTNode.from_type("while", "while"),
        ZASTNode.from_type("(", "("),
        condition.clone(),
        ZASTNode.from_type(")", ")"),
        ZASTNode.from_type(";", ";")
    ]

    return do_node

def convert_while_to_for(while_node: ZASTNode, lang: str = "java") -> ZASTNode:
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

def convert_do_to_while(do_node: ZASTNode, lang: str = "java") -> ZASTNode:
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

def convert_while_to_do(while_node: ZASTNode, lang: str = "java") -> ZASTNode:
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


def random_loop_conversion(zast_tree: ZASTNode, lang: str = "java") -> ZASTNode:
    """
    随机将 ZAST 树中的所有循环结构转换为其他两种循环类型之一
    """
    # 创建 LoopPatterns 适配器，支持不同语言的转换
    adapter = LoopPatterns(lang)
    
    loop_types = ["for_statement", "while_statement", "do_statement"]
    
    # 遍历树的所有节点，找到循环节点并进行随机转换
    def traverse_and_convert(node: ZASTNode):
        # 遍历当前节点的所有子节点
        for child in node.children:
            # 根据节点类型选择适当的转换方法
            if child.type == "for_statement":
                # 使用 LoopPatterns 匹配并提取字段
                match = adapter.match(child, "for_statement")
                print_matched_fields(match)
                # if match:
                #     # highlight_print("111111111")
                #     # 随机选择转化为 while 或 do
                #     new_node = random.choice([convert_for_to_while(child, lang), convert_for_to_do(child, lang)])
                #     # 替换原循环节点
                #     node.children.remove(child)
                #     node.children.append(new_node)

            elif child.type == "while_statement":
                # 使用 LoopPatterns 匹配并提取字段
                match = adapter.match(child, "while_statement")
                print_matched_fields(match)
                # if match:
                #     # 随机选择转化为 for 或 do
                #     new_node = random.choice([convert_while_to_for(child, lang), convert_while_to_do(child, lang)])
                #     # 替换原循环节点
                #     node.children.remove(child)
                #     node.children.append(new_node)

            elif child.type == "do_statement":
                # 使用 LoopPatterns 匹配并提取字段
                match = adapter.match(child, "do_statement")
                print_matched_fields(match)
                # if match:
                #     # 随机选择转化为 for 或 while
                #     new_node = convert_do_to_while(child, lang)
                #     # 替换原循环节点
                #     node.children.remove(child)
                #     node.children.append(new_node)

            # 递归遍历子节点
            traverse_and_convert(child)
    
    # 从根节点开始遍历并转换循环
    traverse_and_convert(zast_tree)

    return zast_tree

def print_matched_fields(match: dict):
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