import os
import pickle
import json
from .obfusDiffTools.funcReg import tagDiff
from .obfusDiffTools.reEnt import *
from .obfusDiffTools.varPos import *
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
        
        try:
            format_origin = format_func(json_data["code"], lang)
            # format_obfus = format_func(json_data["after_obfus"], lang)
            format_obfus = format_func(json_data["after_watermark"], lang)
        except RuntimeError as e:
            continue
        
        diffs = tagDiff(obfus_type.name, wparser, format_origin, format_obfus)
        
        if not diffs:
            continue
        
        item = {
            "repo": json_data["repo"],
            "path": json_data["path"],
            "func_name": json_data["func_name"],
            "language": json_data["language"],
            "docstring": json_data["docstring"],
            "url": json_data["url"],
            "obfus_level": obfus_type.name,
            "obfus_desc": obfus_type.desc,
            "original_code": json_data["code"],
            # "obfuscated_code": json_data["after_obfus"],
            "obfuscated_code": json_data["after_watermark"],
            "diff": "\n".join(format_entity(diff) for diff in diffs),
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
    with open(doc_path, 'rb') as f:
        documents = pickle.load(f)
    dest_dir = os.path.join(doc_dir, f"{documents[0].metadata['obfus_level']}")
    os.makedirs(dest_dir, exist_ok=True)
    
    width = len(str(len(documents)))  # 计算文件名宽度
    # 将每个文档写入单独的文本文件
    for i, doc in tqdm(enumerate(documents),
                       total=len(documents),
                       desc="Writing documents to files", 
                       unit="file"):
        content = doc.page_content
        metadata = doc.metadata
        lines = []
        if metadata.get("obfus_level"):
            lines.append(f"[obfus_level] {metadata['obfus_level']}")
        if metadata.get("obfus_desc"):
            lines.append(f"[obfus_desc] {metadata['obfus_desc']}")
        lines.append(f"[content] {content}\n\n")
        if metadata.get("language"):
            lines.append(f"[code_language] {metadata['language']}")
        if metadata.get("original_code"):
            format_origin = format_func(metadata['original_code'], metadata["language"])
            attach_lineNum_ori = attach_lineNum_func(format_origin)
            lines.append(f"[original_code]\n{attach_lineNum_ori}\n")
        if metadata.get("obfuscated_code"):
            format_obfus = format_func(metadata['obfuscated_code'], metadata["language"])
            attach_lineNum_obfus = attach_lineNum_func(format_obfus)
            lines.append(f"[obfuscated_code]\n{attach_lineNum_obfus}\n")
        if metadata.get("diff"):
            lines.append(f"<diff>:\n{metadata['diff']}")
        
        full_content = "\n".join(lines)
        
        file_name = f"{obfus_type.name}_{i:0{width}}.txt"
        with open(os.path.join(dest_dir, file_name), "w", encoding="utf-8") as f:
            f.write(full_content)