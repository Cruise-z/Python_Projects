from tree_sitter import Language, Parser
from .format import *

# !混淆等级1.2: 可命名实体声明赋值位置随机化(在使用位置之前,作用域内)

# 编译并加载 Java parser（只需运行一次）
# Language.build_library('build/my-languages.so', ['tree-sitter-java'])  ← 如已构建好可跳过
LANGUAGE = Language('build/languages.so', 'java')
parser = Parser()
parser.set_language(LANGUAGE)


def get_line_offsets(code):
    """用于将字节偏移转换为行号和列号"""
    lines = code.split('\n')
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    return offsets


def byte_offset_to_line_col(byte_offset, line_offsets):
    for i, offset in enumerate(line_offsets):
        if i + 1 == len(line_offsets) or byte_offset < line_offsets[i + 1]:
            return i + 1, byte_offset - offset + 1
    return -1, -1


def extract_variable_declarations_and_usages(code: str):
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node
    line_offsets = get_line_offsets(code)

    declared_vars = {}
    used_vars = {}
    scope_vars = set()

    def walk(node):
        nonlocal declared_vars, used_vars, scope_vars

        if node.type == 'local_variable_declaration':
            declarators = node.child_by_field_name('declarators')

            if declarators is None:
                print("Warning: declaration missing 'declarators':", code[node.start_byte:node.end_byte])
                return

            for declarator in declarators.children:
                if declarator.type != 'variable_declarator':
                    continue

                var_id = declarator.child_by_field_name('name')
                init = declarator.child_by_field_name('value')

                if var_id is None:
                    continue

                name = code[var_id.start_byte:var_id.end_byte]
                if init is None:
                    # 记录未初始化声明
                    declared_vars[name] = {
                        'decl_stmt': code[node.start_byte:node.end_byte],
                        'decl_line': byte_offset_to_line_col(node.start_byte, line_offsets)[0]
                    }
                    scope_vars.add(name)

        elif node.type == 'identifier':
            name = code[node.start_byte:node.end_byte]
            if name in scope_vars and name not in used_vars:
                # 向上找使用语句
                parent = node
                while parent and parent.type not in ['expression_statement', 'local_variable_declaration', 'return_statement']:
                    parent = parent.parent
                if parent:
                    used_vars[name] = {
                        'use_stmt': code[parent.start_byte:parent.end_byte],
                        'use_line': byte_offset_to_line_col(parent.start_byte, line_offsets)[0]
                    }

        for child in node.children:
            walk(child)

    walk(root_node)

    return declared_vars, used_vars


# =============================
# 示例 Java 函数片段
# =============================

java_code = """
public class Example {
    void example() {
        int x, y, z = 1;
        x = 5;
        System.out.println(z);
        y = x + 1;
    }
}
"""

# declared, used = extract_variable_declarations_and_usages(java_code)


# printAST(java_code, 'java')

# =============================
# 输出结构化分析结果
# =============================
# for name in declared:
#     print(f"变量 `{name}`：")
#     print(f"  声明位置：第 {declared[name]['decl_line']} 行")
#     print(f"  声明语句：{declared[name]['decl_stmt']}")
#     if name in used:
#         print(f"  第一次使用位置：第 {used[name]['use_line']} 行")
#         print(f"  使用语句：{used[name]['use_stmt']}")
#     else:
#         print("  从未被使用")
#     print()
