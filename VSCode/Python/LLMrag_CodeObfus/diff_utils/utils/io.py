import os
import pickle
import json
from .obfusDiffTools._tagDesc import ObfusType
from .obfusDiffTools.funcReg import tagFunc
from .obfusDiffTools.renameEnt import *
from .obfusDiffTools.reposVarDecl import *
from .format import *
from tree_sitter import Language, Parser
from langchain.schema import Document
from typing import List, Literal
from tqdm import tqdm
from pathlib import Path
from io import StringIO

# 多个实体列表处理与输出控制
def print_renameable_entities(
    groups: List[List['renameableEntity']],
    output_path: Optional[str] = None
):
    output = StringIO()

    for group in groups:
        for ent in group:
            formatted = format_entity(ent)
            output.write(formatted + "\n")

    final_output = output.getvalue()
    output.close()

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_output)
    else:
        print(final_output)

def print_with_line_numbers(code: str):
    lines = code.splitlines()
    width = len(str(len(lines)))  # 计算最大行号宽度
    for idx, line in enumerate(lines, start=1):
        print(f"{str(idx).rjust(width)} | {line}")

def save_documents(documents: List[Document], file_path: str, format: str = "pkl"):
    """
    将 langchain Document 列表保存为指定格式的文件。

    参数:
        documents: List[Document] - 要保存的文档列表
        file_path: str - 输出文件路径（建议以 .pkl 或 .json 结尾）
        format: str - 保存格式，支持 'pkl' 或 'json'
    """
    if format == "pkl":
        with open(file_path, "wb") as f:
            pickle.dump(documents, f)
        print(f"✅ 文档成功保存为 pickle 文件: {file_path}")
    
    elif format == "json":
        # 将 Document 转为 dict
        dict_list = [
            {"page_content": doc.page_content, "metadata": doc.metadata}
            for doc in documents
        ]
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(dict_list, f, ensure_ascii=False, indent=2)
        print(f"✅ 文档成功保存为 JSON 文件: {file_path}")
    
    else:
        raise ValueError("❌ 不支持的格式，仅支持 'pkl' 或 'json'")
    
def struct_doc(lang:Literal["java", "cpp", "js"], 
               raw_name:str, 
               obfus_type:ObfusType):
    # 获取当前脚本的绝对路径
    script_path = os.path.abspath(__file__)
    root = os.path.dirname(os.path.dirname(os.path.dirname(script_path)))
    os.chdir(root)
    # 加载 parser
    wparser = WParser(lang)
    
    raw_json_dir = "./jsonData/raw"
    categorized_json_dir = "./jsonData/categorized"
    doc_name = f"{obfus_type.name}.pkl"
    
    json_path = os.path.join(raw_json_dir, raw_name)
    dest_path = os.path.join(categorized_json_dir, doc_name)
    
    raw_lines = []
    db_content = []
    
    with open(json_path, 'r', encoding='utf-8') as f:
        for line in f:
            raw_lines.append(line)
        
    for line in tqdm(raw_lines,
                     total=len(raw_lines),
                     desc="Processing lines", 
                     unit="line"):
        json_data = json.loads(line)
        
        # if json_data["after_obfus"] == "":
        if json_data["after_watermark"] == "":
            continue
        
        func_name = json_data["func_name"]
        class_name = func_name.split(".")[0]
        
        try:
            format_origin = format_func(class_name, json_data["code"], lang)
            # format_obfus = format_func(class_name, json_data["after_obfus"], lang)
            format_obfus = format_func(class_name, json_data["after_watermark"], lang)
            # format_origin, format_obfus = align_CodeBlocks(origin, obfus)
        except RuntimeError as e:
            continue
        
        fEnts = []
        fDiffs = []
        ents = tagFunc(f"{obfus_type.name}_entFetch", wparser, format_origin)
        diffs = tagFunc(f"{obfus_type.name}_entDiff", wparser, format_origin, format_obfus)
        for ent in ents:
            fEnt = tagFunc(f"{obfus_type.name}_entExt", ent, format_origin)
            fEnts.append(fEnt)
        for diff in diffs:
            fDiff = tagFunc(f"{obfus_type.name}_diffExt", diff)
            fDiffs.append(fDiff)
        
        if not diffs:
            continue
        
        item = {
            "repo": json_data["repo"],
            "path": json_data["path"],
            "func_name": json_data["func_name"],
            "class_name": class_name,
            "language": json_data["language"],
            "docstring": json_data["docstring"],
            "url": json_data["url"],
            "obfus_level": obfus_type.name,
            "obfus_desc": obfus_type.desc,
            "constraints": obfus_type.constraints,
            "typical_changes": obfus_type.typical_changes,
            "algorithm": obfus_type.algorithm,
            "extracted_entities": fEnts,
            "original_code": format_origin,
            "obfuscated_code": format_obfus,
            "diff": fDiffs,
        }
        
        doc = Document(
            page_content=obfus_type.content,
            metadata=item
        )
        
        db_content.append(doc)
        print(doc)
    
    suffix = Path(doc_name).suffix.lstrip('.') 
    save_documents(db_content, dest_path, format=suffix)
    
def doc2embedData(obfus_type:ObfusType):
    # 获取当前脚本的绝对路径
    script_path = os.path.abspath(__file__)
    root = os.path.dirname(os.path.dirname(os.path.dirname(script_path)))
    os.chdir(root)
    doc_dir = "./jsonData/categorized"
    doc_name = f"{obfus_type.name}.pkl"
    doc_path = os.path.join(doc_dir, doc_name)
    Extern_dir = "/media/zrz/SSD/LLMrag_CodeObfus/jsonData/categorized"
    with open(doc_path, 'rb') as f:
        documents = pickle.load(f)
    dest_dir = os.path.join(Extern_dir, f"{documents[0].metadata['obfus_level']}")
    os.makedirs(dest_dir, exist_ok=True)
    
    width = len(str(len(documents)))  # 计算文件名宽度
    # 将每个文档写入单独的文本文件
    for i, doc in tqdm(enumerate(documents),
                       total=len(documents),
                       desc="Writing documents to files", 
                       unit="file"):
        content = doc.page_content
        metadata = doc.metadata
        item = {
            "obfuscation_strategy": {
                "id": obfus_type.name,
                "name": obfus_type.id,
                "description": obfus_type.desc,
                "content": content,
                "constraints": obfus_type.constraints, 
                "typical_changes": obfus_type.typical_changes,
                "algorithm": obfus_type.algorithm, 
                "fallback_rule": obfus_type.fallback,
            },
            "input_example":{
                "original_code": metadata['original_code'].splitlines(),
                "extracted_entities": metadata['extracted_entities'],
            },
            "transformation_example":{
                "obfuscated_code": metadata['obfuscated_code'].splitlines(),
                "diff": metadata['diff'],
            },
            "prompt_spec":{
                "role": "You are a code transformation engine.",
                "task_instruction": f"Apply {obfus_type.name} obfuscation based on the configuration and extracted entities.",
                "input_format": "Input will be JSON including 'original_code' and 'extracted_entities'.",
                "output_format": {
                    "language": f"{metadata['language']}",
                    "style": f"Return only transformed {metadata['language']} code inside a ```{metadata['language']} code block. No explanation or commentary.",
                    "strict": True,
                }
            },
        }
        formatted = json.dumps(item, indent=4, ensure_ascii=False)
        
        file_name = f"{obfus_type.name}_{i:0{width}}.txt"
        with open(os.path.join(dest_dir, file_name), "w", encoding="utf-8") as f:
            f.write(formatted)
            
def prompt_gen(code: str, lang: str, obfus_type: ObfusType) -> str:
    # 加载 parser
    wparser = WParser(lang)
    instEnts = []
    try:
        fcode = format_func('test', code, lang)
        ents = tagFunc(f"{obfus_type.name}_entFetch", wparser, fcode)
        for ent in ents:
            instEnt = tagFunc(f"{obfus_type.name}_instrExt", ent, fcode, lang)
            instEnts.append(instEnt)
    except RuntimeError as e:
        raise RuntimeError(f"Error formatting code: {e}")
    
    task = {
        "task_name": obfus_type.id,
        "instructions": instEnts,
        "code_language": lang,
        "input_code": fcode.splitlines(),
        "output_style": [
            f"return modified {lang} code only",
            f"return as a Markdown code block"
        ],
    }
    formatted = json.dumps(task, indent=4, ensure_ascii=False)
    
    prompt = [
        f"You are a code transformation engine. Your task is to execute {obfus_type.name}:{obfus_type.id} obfuscation based on the structured configuration.",
        f"",
        f"### Task Information:",
        # f"You are given {lang} code along with related transformation metadata.",
        # f"#### Description:",
        # f"{obfus_type.desc}",
        # f"#### Constraints:",
        # f"{obfus_type.constraints}",
        # f"#### Typical Changes:",
        # f"{obfus_type.typical_changes}",
        # f"#### Algorithm:",
        # f"{obfus_type.algorithm}",
        # f"",
        # f"---",
        # f"### Input format:",
        # f"You are given a JSON object with:",
        # f"- `input_code`: The original {lang} code, line by line;",
        # f"- `extracted_entities`: A list of local variables, each with:",
        # f"    - `usage_context`: Decl & init line;",
        # f"    - `DeclPos_rearrangeable_gaps`: Legal locations to move the declaration into.",
        # f"#### Input JSON:",
        f"{formatted}",
        # f"",
        # f"---",
        # f"### Output format:",
        # f"- Return only the final **Java source code** as a Markdown code block;",
        # f"- You must output the code line-by-line, preserving indentation and all non-declaration lines;",
        # f"- Do **not** explain anything, do **not** add comments or descriptions.",
        # f"### Warning:",
        # # f"Do not interpret or explain code meaning",
        # f"Do not change initialization lines",
        # f"Do not modify logic",
        # # f"Do not output thoughts, logs, or annotations",
        # f"Only reposition declarations as allowed",
        # f"Only touch the variable’s declaration line",
        # f"Only within allowed ranges from metadata",
        # f"",
        # f"Proceed to apply the transformation strictly as instructed and output the final obfuscated Java code only.",
    ]
    
    return "\n".join(prompt)