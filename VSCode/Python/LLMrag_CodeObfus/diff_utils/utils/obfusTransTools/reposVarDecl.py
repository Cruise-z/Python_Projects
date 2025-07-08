from ..codeAnalysis.astTrans import *
from ..format import *
import random

def reorg_varDecl(varName: str, scopeNode: ZASTNode, oriDeclNode: ZASTNode) -> Tuple[Optional[ZASTNode], Optional[ZASTNode], int, Optional[List[int]], bool]:
    """_summary_
    Args:
        varName (str): 需要重新组织声明位置的变量名
        scopeNode (ZASTNode): 这个变量的作用域节点
        varDeclNode (ZASTNode): 这个变量的声明节点
    Returns:
        Tuple[Optional[ZASTNode], Optional[ZASTNode], Optional[List[int]], bool]
            - Optional[ZASTNode]: 返回重新组织的声明节点
            - Optional[ZASTNode]: 返回重新组织的初始化节点(若存在)
            - int: 返回初始化节点的索引
            - Optional[List[int]]: 返回可重新插入声明节点的列表(若存在)否则为None
            - bool: 返回处理后原声明节点是否还存在内容
    Logic:
    -----
    - 判断`scopeNode`是否为`block`类型(是才有插入空间)
    - 寻找初始化所在`scopeNode`的子节点`initFNode`
    - 判断`DeclNode`与`initFNode`是否相等(后续从`DeclNode`拆分出`Decl`):
        - = -> 拆分出`Decl`部分后原结点必然存在内容(起码有该变量初始化):
            - 存在其他相同类型变量的声明初始化 -> 可插入范围在`initFNode`+1之前即可
            - 不存在其他相同类型变量的声明初始化 -> 可插入范围在`initFNode`之前即可
        - != -> 拆分出`Decl`部分后原结点是否存在内容(如其他相同类型的变量的声明初始化):
            - 存在 -> 只需在`initFNode`之前即可
            - 不存在 -> 排除掉自身索引`index`和`index-1`
            同时判断`initFNode`本身是不是初始化节点:
                - 是 -> 增加`Decl`和`Init`合并的选择(添加索引`-1`表示这种选择)
    """
    # 1. 当scopeNode为`block`类型才有插入空间
    assert scopeNode.type == 'block', f"变量无可插入空间"
    # 2. 获取作用域下的子节点列表
    child_nodes = scopeNode.children
    assert child_nodes, f"作用域无子节点异常"
    assert oriDeclNode in child_nodes, "oriDeclNode 不在 child_nodes 中"
    oriDeclIdx = child_nodes.index(oriDeclNode)
    # 3. 尝试找初始化所在子节点及声明节点索引
    initFnode, isDirect = find_initFNode(varName, scopeNode)
    # 4. 找到 init_node 的索引（如果存在）
    if initFnode:
        try:
            InitIdx = child_nodes.index(initFnode)
        except ValueError:
            InitIdx = len(child_nodes)
    else:
        InitIdx = len(child_nodes)
    newDeclNode, newInitNode, is_ori_empty = extractVarDecl(
        varName,
        oriDeclNode
    )
    assert newDeclNode, f"声明节点提取失败"
    if oriDeclNode == initFnode:
        assert newInitNode != None, f"初始化节点提取失败(声明和初始化同时进行)"
        assert oriDeclIdx == InitIdx, f"声明初始化节点相同但索引不同"
        valid_idx = [i for i in range(InitIdx+1)]
    else:
        assert newInitNode == None, f"初始化提取函数提取错误"
        assert oriDeclIdx != InitIdx, f"声明初始化节点不同但索引相同"
        if is_ori_empty:
            valid_idx = [
                i for i in range(InitIdx)
                if i!=oriDeclIdx-1 and i!=oriDeclIdx
            ]
        else:
            valid_idx = [i for i in range(InitIdx)]
        if isDirect and initFnode:
            valid_idx.append(-1)

    return (
        newDeclNode, 
        newInitNode if newInitNode else None,  
        InitIdx,
        valid_idx if valid_idx else None,
        is_ori_empty
    )

def reposVarDecl(varName:str, oriDeclNode:ZASTNode, lang:str):
    scopeNode = find_scopeNode(oriDeclNode, lang)
    declNode, splitInitNode, oriInitIdx, index, isempty = reorg_varDecl(varName, scopeNode, oriDeclNode)
    if index:
        if splitInitNode:
            # 说明原语句声明和初始化同时进行
            # 从index中随机选取两个值插入声明和初始化
            assert scopeNode.children[oriInitIdx] == oriDeclNode, f"初始化提取错误"
            Dpos, Ipos = sorted(random.sample(index, 2))
            scopeNode.children.insert(Dpos+1, declNode)
            scopeNode.children.insert(Ipos+2, splitInitNode)
            if isempty:
                # 删除原声明节点
                scopeNode.children.remove(oriDeclNode)
        else:
            pos = random.choice(index)
            if pos == -1:
                InitNode = scopeNode.children[oriInitIdx]
                mergeNode = mergeDeclInit(declNode, InitNode)
                scopeNode.children[oriInitIdx] = mergeNode
            else:
                scopeNode.children.insert(pos+1, declNode)
            if isempty:
                # 删除原声明节点
                scopeNode.children.remove(oriDeclNode)

def reposVarsDecl(zroot:ZASTNode, lang:str):
    decls = find_local_varDecls(zroot)
    for (varName, oriDeclNode) in decls:
        try:
            highlight_print(f"varname is: {varName}")
            reposVarDecl(varName, oriDeclNode, lang)
            print_ZASTNode(zroot)
        except:
            continue
        