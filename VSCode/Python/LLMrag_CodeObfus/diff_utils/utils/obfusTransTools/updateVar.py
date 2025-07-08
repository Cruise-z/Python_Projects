from ..codeAnalysis.astTrans import *
from ..format import *
import random

def updateIncDec(zroot: ZASTNode):
    import random

    def dfs(node: ZASTNode):
        for child in node.children:
            dfs(child)

        match = match_inc_dec_pattern(node)
        if match:
            var_name, is_inc = match
            variants = generate_equivalent_variants(var_name, is_inc)
            new_node = random.choice(variants)
            replace_node(node, new_node)

    def match_inc_dec_pattern(node: ZASTNode) -> Optional[Tuple[str, bool]]:
        # Pattern 1: update_expression → i++, ++i, i--, --i
        if node.type == "update_expression" and len(node.children) == 2:
            t0, t1 = node.children[0], node.children[1]
            if t0.type == "identifier" and t1.extra_text in ("++", "--"):
                return (t0.extra_text, t1.extra_text == "++")
            if t1.type == "identifier" and t0.extra_text in ("++", "--"):
                return (t1.extra_text, t0.extra_text == "++")

        # Pattern 2: assignment_expression → i += 1 / i -= 1
        if node.type == "assignment_expression" and len(node.children) == 3:
            lhs, op, rhs = node.children
            if (lhs.type == "identifier" and
                op.extra_text in ("+=", "-=") and
                rhs.type == "decimal_integer_literal" and rhs.extra_text == "1"):
                return (lhs.extra_text, op.extra_text == "+=")

        # Pattern 3: assignment_expression → i = i + 1 / i - 1
        if node.type == "assignment_expression" and len(node.children) == 3:
            lhs, eq, rhs = node.children
            if eq.extra_text != "=" or rhs.type != "binary_expression":
                return None
            if len(rhs.children) == 3:
                a, op, b = rhs.children
                if (a.type == "identifier" and b.type == "decimal_integer_literal" and
                    b.extra_text == "1" and lhs.extra_text == a.extra_text):
                    return (lhs.extra_text, op.extra_text == "+")
        return None

    def generate_equivalent_variants(var: str, is_inc: bool) -> list:
        op = "++" if is_inc else "--"
        op_eq = "+=" if is_inc else "-="
        bin_op = "+" if is_inc else "-"

        variants = []

        # i++;
        u1 = ZASTNode.from_type("update_expression")
        u1.children = [ZASTNode.from_type("identifier", var), ZASTNode.from_type(op, op)]
        variants.append(u1)

        # ++i;
        u2 = ZASTNode.from_type("update_expression")
        u2.children = [ZASTNode.from_type(op, op), ZASTNode.from_type("identifier", var)]
        variants.append(u2)

        # i += 1;
        a1 = ZASTNode.from_type("assignment_expression")
        a1.children = [
            ZASTNode.from_type("identifier", var),
            ZASTNode.from_type(op_eq, op_eq),
            ZASTNode.from_type("decimal_integer_literal", "1")
        ]
        variants.append(a1)

        # i = i + 1;
        bin_expr = ZASTNode.from_type("binary_expression")
        bin_expr.children = [
            ZASTNode.from_type("identifier", var),
            ZASTNode.from_type(bin_op, bin_op),
            ZASTNode.from_type("decimal_integer_literal", "1")
        ]
        a2 = ZASTNode.from_type("assignment_expression")
        a2.children = [
            ZASTNode.from_type("identifier", var),
            ZASTNode.from_type("=", "="),
            bin_expr
        ]
        variants.append(a2)

        return variants

    def replace_node(old: ZASTNode, new_node: ZASTNode):
        if old.parent:
            for i, c in enumerate(old.parent.children):
                if c is old:
                    new_node.parent = old.parent
                    old.parent.children[i] = new_node
                    break

    dfs(zroot)
