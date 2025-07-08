from ..codeAnalysis.astTrans import *
from ..format import *
import random

def whileCondTrans(root: ZASTNode):
    """
    在ZAST树中查找所有的while语句，将其条件在 true <-> 1 之间切换。
    """
    def dfs(node: ZASTNode):
        if node.type == "while_statement":
            for child in node.children:
                if child.type == "condition" and child.children:
                    cond_inner = child.children[1]  # condition: ( ( cond_expr ) )
                    if cond_inner.type == "decimal_integer_literal" and cond_inner.extra_text == "1":
                        cond_inner.type = "true"
                        cond_inner.extra_text = "true"
                    elif cond_inner.type == "true":
                        cond_inner.type = "decimal_integer_literal"
                        cond_inner.extra_text = "1"
        for c in node.children:
            dfs(c)

    dfs(root)

