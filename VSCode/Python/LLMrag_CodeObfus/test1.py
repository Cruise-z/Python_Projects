import re
from typing import List, Tuple, Optional
from tree_sitter import Parser
from collections import defaultdict
from dataclasses import dataclass

@dataclass
class renameableEntity:
    entity: str
    kind: str  # 'function', 'parameter', 'local_variable', etc.
    type: Optional[str]
    modifiers: Tuple[str, ...]
    scope: List[str]
    start: int
    end: int
    dec_pos: Optional[Tuple[str, int]] = None
    use_fpos: Optional[Tuple[str, int]] = None

def extract_renameable_entities(format_code: str, parser: Parser):
    tree = parser.parse(format_code.encode("utf8"))
    root = tree.root_node
    source_lines = format_code.splitlines()

    func_name = []
    param_names = []
    local_var_names = []
    catch_params = []
    foreach_vars = []
    lambda_params = []

    scope_stack = []
    counter_stack = []
    declared_entities = {}

    def get_node_text(node):
        return format_code[node.start_byte:node.end_byte]

    def extract_modifiers(node):
        mod_node = node.child_by_field_name("modifiers")
        if not mod_node:
            mod_node = next((c for c in node.children if c.type == "modifiers"), None)
        if mod_node:
            return [get_node_text(child) for child in mod_node.children if child.type not in {",", ";"}]
        return []

    def normalize_type(type_str: str) -> str:
        if not type_str:
            return ""
        type_str = re.sub(r"\s+", "", type_str)
        if "." in type_str:
            type_str = type_str.split(".")[-1]
        return type_str

    def normalize_modifiers(modifiers: List[str]) -> Tuple[str, ...]:
        normed = []
        for m in modifiers:
            m = m.strip()
            m = re.sub(r'@(\w+)\s*\(.*?\)', r'@\1', m)
            normed.append(m)
        return tuple(sorted(normed))

    display_names = {
        "if_statement": "If",
        "for_statement": "For",
        "while_statement": "While",
        "catch_clause": "Catch"
    }

    def make_scope_label(node):
        node_type = node.type
        line = node.start_point[0] + 1
        if node_type == "class_declaration":
            name_node = node.child_by_field_name("name")
            return f"Class {get_node_text(name_node)}"
        elif node_type == "method_declaration":
            name_node = node.child_by_field_name("name")
            return f"Function {get_node_text(name_node)}"
        elif node_type in display_names:
            if counter_stack:
                counter_dict = counter_stack[-1]
                counter_dict[node_type] += 1
                index = counter_dict[node_type]
            else:
                index = 1
            return f"{display_names[node_type]}[{index}]@line:{line}"
        return f"{node_type}@line:{line}"

    def find_first_usage(entity, name, body_node):
        for node in body_node.walk():
            if node.type == "identifier":
                if get_node_text(node) == name:
                    if not (entity.start <= node.start_byte <= entity.end):
                        line = node.start_point[0] + 1
                        text = source_lines[line - 1].strip() if line - 1 < len(source_lines) else ""
                        entity.use_fpos = (text, line)
                        return

    def traverse(node):
        if node.type in {"class_declaration", "method_declaration", "if_statement", "for_statement", "while_statement", "catch_clause"}:
            scope_stack.append(make_scope_label(node))
            if node.type == "method_declaration":
                counter_stack.append(defaultdict(int))

        # 方法定义
        if node.type == "method_declaration":
            fn_name_node = node.child_by_field_name("name")
            fn_type_node = node.child_by_field_name("type")
            line = fn_name_node.start_point[0] + 1
            code = source_lines[line - 1].strip()
            entity = renameableEntity(
                entity=get_node_text(fn_name_node),
                kind="function",
                type=normalize_type(get_node_text(fn_type_node) if fn_type_node else None),
                modifiers=normalize_modifiers(extract_modifiers(node)),
                scope=list(scope_stack),
                start=fn_name_node.start_byte,
                end=fn_name_node.end_byte,
                dec_pos=(code, line)
            )
            func_name.append(entity)

            # 参数
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
                                modifiers=normalize_modifiers(extract_modifiers(node)),
                                scope=list(scope_stack),
                                start=name_node.start_byte,
                                end=name_node.end_byte,
                                dec_pos=(code, line)
                            )
                            param_names.append(entity)
                            declared_entities[entity.entity] = entity

            # 函数体中的参数使用分析
            body_node = node.child_by_field_name("body")
            if body_node:
                for entity in param_names[-len(parameters.named_children):]:
                    find_first_usage(entity, entity.entity, body_node)

        # 局部变量声明
        if node.type == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        line = name_node.start_point[0] + 1
                        code = source_lines[line - 1].strip()
                        entity = renameableEntity(
                            entity=get_node_text(name_node),
                            kind="local_variable",
                            type=normalize_type(get_node_text(type_node) if type_node else None),
                            modifiers=normalize_modifiers(extract_modifiers(node)),
                            scope=list(scope_stack),
                            start=name_node.start_byte,
                            end=name_node.end_byte,
                            dec_pos=(code, line)
                        )
                        local_var_names.append(entity)
                        declared_entities[entity.entity] = entity

        # catch 参数
        if node.type == "catch_clause":
            for child in node.children:
                if child.type == "catch_formal_parameter":
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
                        if first_child and first_child.type == "union_type":
                            type_list = []

                            def dfs_union(n):
                                if n.type == "type_identifier":
                                    type_list.append(normalize_type(get_node_text(n)))
                                for cc in n.children:
                                    dfs_union(cc)

                            dfs_union(first_child)
                            type_str = "|".join(type_list)
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
                            dec_pos=(code, line)
                        )
                        catch_params.append(entity)
                        declared_entities[entity.entity] = entity

        for child in node.children:
            traverse(child)

        if node.type in {"class_declaration", "method_declaration", "if_statement", "for_statement", "while_statement", "catch_clause"}:
            scope_stack.pop()
            if node.type == "method_declaration":
                counter_stack.pop()

    def find_usages_for_all(node):
        for child in node.children:
            find_usages_for_all(child)
        if node.type == "identifier":
            name = get_node_text(node)
            if name in declared_entities:
                entity = declared_entities[name]
                if not (entity.start <= node.start_byte <= entity.end):
                    if entity.use_fpos is None:
                        line = node.start_point[0] + 1
                        code = source_lines[line - 1].strip()
                        entity.use_fpos = (code, line)

    traverse(root)
    find_usages_for_all(root)

    return func_name, param_names, local_var_names, catch_params, foreach_vars, lambda_params
