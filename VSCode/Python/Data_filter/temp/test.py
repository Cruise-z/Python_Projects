from datasets import load_dataset
import re
from tqdm import tqdm  # 导入 tqdm 库

# 关键词列表
keywords = ["keyword1", "keyword2"]  # 替换为您自己的关键词

# 定义关键词过滤函数
def keyword_filter(example):
    text = example["content"]  # 假设要筛选的字段是 "content"
    
    # 遍历关键词列表
    for keyword in keywords:
        # 使用正则匹配关键词（确保是完整单词，忽略大小写）
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            return True  # 找到匹配关键词时返回 True 保留该条记录
    return False  # 没有匹配到关键词则返回 False，过滤掉该记录

# 加载数据集（假设需要使用流式加载）
# ds = load_dataset("HuggingFaceFW/fineweb-edu", data_files="https://hf-mirror.com/datasets/HuggingFaceFW/fineweb-edu", streaming=True)
ds = load_dataset("HuggingFaceFW/fineweb-edu", "CC-MAIN-2013-20")

# 包装数据集的迭代器，添加 tqdm 进度条
tqdm_ds = tqdm(ds, desc="Processing")

# 筛选数据集并显示进度条
filtered_data = [example for example in tqdm_ds if keyword_filter(example)]
