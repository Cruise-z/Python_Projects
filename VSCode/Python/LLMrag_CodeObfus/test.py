from tree_sitter import Language, Parser
from pathlib import Path
import sys
import os

# 添加 ./diff_utils 到 Python 模块搜索路径
sys.path.append(os.path.abspath('./diff_utils'))

# 然后就可以导入 diff_utils.utils.some_module
from utils import *

LANGUAGE = Language('build/languages.so', 'java')
parser = Parser()
parser.set_language(LANGUAGE)

def get_line_offsets(code):
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

        # 处理变量声明（如：int x, y, z = 1;）
        if node.type == 'local_variable_declaration':
            for child in node.children:
                if child.type == 'variable_declarator':
                    var_id = child.child_by_field_name('name')
                    init = child.child_by_field_name('value')
                    if var_id is None:
                        continue
                    name = code[var_id.start_byte:var_id.end_byte]
                    if init is None:
                        declared_vars[name] = {
                            'decl_stmt': code[node.start_byte:node.end_byte],
                            'decl_line': byte_offset_to_line_col(node.start_byte, line_offsets)[0]
                        }
                        scope_vars.add(name)

        # 检查首次使用（identifier）
        elif node.type == 'identifier':
            name = code[node.start_byte:node.end_byte]
            if name in scope_vars and name not in used_vars:
                # 向上查找其所属语句
                parent = node
                while parent and parent.type not in ['expression_statement', 'return_statement', 'assignment_expression', 'method_invocation']:
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


# 示例代码（来自你的结构）
java_code = "@SuppressWarnings(\"unchecked\")\n    public static <T, R> boolean tryScalarXMapSubscribe(Publisher<T> source,\n            Subscriber<? super R> subscriber,\n            Function<? super T, ? extends Publisher<? extends R>> mapper) {\n        if (source instanceof Callable) {\n            T t;\n\n            try {\n                t = ((Callable<T>)source).call();\n            } catch (Throwable ex) {\n                Exceptions.throwIfFatal(ex);\n                EmptySubscription.error(ex, subscriber);\n                return true;\n            }\n\n            if (t == null) {\n                EmptySubscription.complete(subscriber);\n                return true;\n            }\n\n            Publisher<? extends R> r;\n\n            try {\n                r = ObjectHelper.requireNonNull(mapper.apply(t), \"The mapper returned a null Publisher\");\n            } catch (Throwable ex) {\n                Exceptions.throwIfFatal(ex);\n                EmptySubscription.error(ex, subscriber);\n                return true;\n            }\n\n            if (r instanceof Callable) {\n                R u;\n\n                try {\n                    u = ((Callable<R>)r).call();\n                } catch (Throwable ex) {\n                    Exceptions.throwIfFatal(ex);\n                    EmptySubscription.error(ex, subscriber);\n                    return true;\n                }\n\n                if (u == null) {\n                    EmptySubscription.complete(subscriber);\n                    return true;\n                }\n                subscriber.onSubscribe(new ScalarSubscription<R>(subscriber, u));\n            } else {\n                r.subscribe(subscriber);\n            }\n\n            return true;\n        }\n        return false;\n    }"



format_code = format_func(java_code, 'java')

printAST(format_code, 'java')

declared, used = extract_variable_declarations_and_usages(java_code)

for name in declared:
    print(f"变量 `{name}`：")
    print(f"  声明位置：第 {declared[name]['decl_line']} 行")
    print(f"  声明语句：{declared[name]['decl_stmt']}")
    if name in used:
        print(f"  第一次使用位置：第 {used[name]['use_line']} 行")
        print(f"  使用语句：{used[name]['use_stmt']}")
    else:
        print("  从未被使用")
    print()