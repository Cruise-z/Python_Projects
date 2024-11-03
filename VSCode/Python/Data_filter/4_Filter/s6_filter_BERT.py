# 正式清洗的脚本
from transformers import DistilBertForSequenceClassification, AutoTokenizer
import torch
import os
#TODO:本地设置当前目录
os.chdir("./4_Filter")
import configparser
import json
import re
from tqdm import tqdm
import subprocess

def write_to_temp_file(temp_file: str, filtered_data: list):
    """将筛选后的数据写入临时文件"""
    with open(temp_file, 'w', encoding='utf-8') as file:
        for item in filtered_data:
            json_data = json.dumps(item, ensure_ascii=False)
            file.write(json_data + '\n')

def append_temp_to_target(temp_file: str, target_file: str):
    """将临时文件的内容追加到目标文件"""
    with open(temp_file, 'r', encoding='utf-8') as temp_file_read:
        with open(target_file, 'a', encoding='utf-8') as target:
            target.write(temp_file_read.read())

def filter(model, tokenizer, texts):
    # 预处理输入数据
    inputs = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs)
    # 获取 logits 和预测结果
    logits = outputs.logits
    probabilities = torch.nn.functional.softmax(logits, dim=-1)
    predicted_labels = torch.argmax(probabilities, dim=-1)
    label_map = {0: 0, 1: 1}
    predicted_labels = [label_map[label.item()] for label in predicted_labels]
    return predicted_labels

def count_lines_in_jsonl(file_path):
    # 执行 wc -l 命令
    result = subprocess.run(['wc', '-l', file_path], capture_output=True, text=True)
    
    # result.stdout 的格式为 '  1234 your_file.jsonl'，需要提取数字
    line_count = int(result.stdout.split()[0])
    return line_count

def local(model, tokenizer, 
          spilt_name:str, batch_size:int, 
          result_dir:str, log_file_name:str):
    filtered_data = []
    total_written = 0
    
    os.makedirs(local_dir, exist_ok=True)
    os.makedirs(result_dir, exist_ok=True)
    jsonl_kw_path = os.path.join(local_dir, f"{spilt_name}_kw.jsonl")
    log_file = os.path.join(local_dir, log_file_name)
    temp_file = os.path.join(local_dir, f"{spilt_name}_Bert.jsonl.tmp")
    target_file = os.path.join(result_dir, f"{spilt_name}_Bert.jsonl")
    
    model.eval()
    
    # 使用 wc -l 命令读取文件并计算总行数
    total_lines = count_lines_in_jsonl(jsonl_kw_path)
    # 读取上次中断的位置
    start_index = 0
    if os.path.exists(log_file):
        with open(log_file, 'r') as log:
            start_index = int(log.read().strip())
    
    # 逐行读取.jsonl文件
    with open(jsonl_kw_path, 'r') as f:
        for idx, line in tqdm(enumerate(f), total=total_lines, desc="Processing", unit="line"):
            if idx < start_index:
                continue  # 跳过已处理的索引
            
            item = json.loads(line)
            label = filter(model, tokenizer, item['text'])
            if label == [1]:
                filtered_data.append({"text": item['text'], "label": label[0]})
            
                # 如果达到批次大小，则进行预测
                if len(filtered_data) == batch_size:
                    # 将数据转换为 JSON 行，并逐行写入临时文件
                    write_to_temp_file(temp_file, filtered_data)
                    
                    # 清空 filtered_data 并更新统计
                    filtered_data = []
                    total_written += batch_size
                    print(f"Written {total_written} entries to {target_file}")
                    
                    #TODO:写入目标文件并更新日志
                    # 将临时文件的内容追加到目标文件
                    append_temp_to_target(temp_file, target_file)
                    # 更新日志文件
                    with open(log_file, 'w') as log:
                        log.write(str(idx + 1))
        
        # 处理剩余的文本
        if filtered_data:
            # 将数据转换为 JSON 行，并逐行写入临时文件
            write_to_temp_file(temp_file, filtered_data)
                    
            total_written += len(filtered_data)
            print(f"Written the final {len(filtered_data)} entries to {target_file}")

        # 将临时文件的内容追加到目标文件
        append_temp_to_target(temp_file, target_file)
        # 更新日志文件
        with open(log_file, 'w') as log:
            log.write(str(idx + 1))  # 记录总数

        print(f"Data written to {target_file} successfully! Total entries: {total_written}")
    

# 创建配置解析器
config = configparser.ConfigParser()
# 读取 .ini 文件
config.read('config.ini')
jump_host = config['default']['jump_host']
jump_user = config['default']['jump_user']
target_host = config['default']['target_host']
target_user = config['default']['target_user']
target_passwd = config['default']['target_passwd']
remote_load_path = config['default']['remote_load_path']
remote_cache_path = config['default']['remote_cache_path']
local_dir = config['default']['local_dir']

# 加载训练好的模型和分词器
model = DistilBertForSequenceClassification.from_pretrained("../results/checkpoint-15849")
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

# 定义批次大小
batch_size = 100

spilt_name = "CC-MAIN-2013-20"

local(model, tokenizer, spilt_name, batch_size, './data/results', "log_Bert.txt")
    