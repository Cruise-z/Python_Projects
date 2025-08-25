import json
from transformers import AutoTokenizer

# 加载 tokenizer
tokenizer = AutoTokenizer.from_pretrained("bigcode/starcoder")

# 读取jsonl文件并计算每条数据的token数
def load_data_and_count_tokens(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line.strip())
            # 获取"prompt" + "prefix" 作为输入文本
            input_text = data.get('prompt', '') + " " + data.get('prefix', '')
            # 计算token数量
            tokenized_input = tokenizer(input_text)
            token_count = len(tokenized_input['input_ids'])  # 获取token的数量
            print(f"Task ID: {data['task_id']}, Token count: {token_count}")

# 使用示例
input_file = './datasets/projectDev_java.jsonl'  # 输入你的JSONL文件路径
load_data_and_count_tokens(input_file)
