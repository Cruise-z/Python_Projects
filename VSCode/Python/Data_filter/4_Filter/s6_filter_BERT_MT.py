from transformers import DistilBertForSequenceClassification, AutoTokenizer
import json
import subprocess
import torch
import os
#TODO:本地设置当前目录
os.chdir("./4_Filter")
import configparser
import concurrent.futures
from tqdm import tqdm

# 检查是否有可用的 GPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

def count_lines_in_jsonl(file_path):
    """计算文件总行数"""
    result = subprocess.run(['wc', '-l', file_path], capture_output=True, text=True)
    line_count = int(result.stdout.split()[0])
    return line_count

def filter(device, model, tokenizer, texts):
    # 预处理输入数据
    inputs = tokenizer(texts, 
                       padding=True, 
                       truncation=True, 
                       return_tensors="pt").to(device)# 将输入数据也移到 GPU
    with torch.no_grad():
        outputs = model(**inputs)
    # 获取 logits 和预测结果
    logits = outputs.logits
    probabilities = torch.nn.functional.softmax(logits, dim=-1)
    predicted_labels = torch.argmax(probabilities, dim=-1)
    label_map = {0: 0, 1: 1}
    predicted_labels = [label_map[label.item()] for label in predicted_labels]
    return predicted_labels

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

def process_chunk(model, tokenizer, chunk, 
                  chunk_index, batch_size, 
                  output_dir):
    """处理一个数据块，清洗并写入文件"""
    processed = 0
    start_index = 0
    chunk_file_path = os.path.join(output_dir, f'chunk_{chunk_index}.jsonl')
    temp_file_path = os.path.join(output_dir, f'chunk_{chunk_index}.jsonl.tmp')

    # 初始化日志文件
    log_file = os.path.join(output_dir, f'log_{chunk_index}.txt')
    if os.path.exists(log_file):
        with open(log_file, 'r') as log:
            start_index = int(log.read().strip())

    # 处理数据并每处理100条就写入临时文件
    filtered_data = []
    for idx, line in tqdm(enumerate(chunk), 
                          total=len(chunk), 
                          desc=f"Processing chunk-{chunk_index}", 
                          unit="line"):
        if idx < start_index:
            continue  # 跳过已处理的索引
        
        try:
            item = json.loads(line)
        except:
            continue
        
        label = filter(device, model, tokenizer, item['text'])
        if label == [1]:
            filtered_data.append({"text": item['text'], "label": label[0]})
            
            # 如果达到批次大小，则进行预测
            if len(filtered_data) == batch_size:
                # 将数据转换为 JSON 行，并逐行写入临时文件
                write_to_temp_file(temp_file_path, filtered_data)
                    
                # 清空 filtered_data 并更新统计
                filtered_data = []
                processed += batch_size
                    
                #TODO:写入目标文件并更新日志
                # 将临时文件的内容追加到目标文件
                append_temp_to_target(temp_file_path, chunk_file_path)
                # 更新日志文件
                with open(log_file, 'w') as log:
                    log.write(str(idx + 1))

    # 处理剩余的文本
    if filtered_data:
        # 将数据转换为 JSON 行，并逐行写入临时文件
        write_to_temp_file(temp_file_path, filtered_data)   
        processed += len(filtered_data)
        # 将临时文件的内容追加到目标文件
        append_temp_to_target(temp_file_path, chunk_file_path)
    
    # 更新日志文件
    with open(log_file, 'w') as log:
        log.write(str(idx + 1))  # 记录总数

    #!:注意[这里需要返回chunk_file的存放路径:chunk_file_path]       
    # 每个 future 的 result() 方法会返回一个值，而这个值通常是由 process_chunk 函数返回的。如果 process_chunk 返回的是 None，那么 future.result() 也会返回 None。
    return chunk_file_path


def read_jsonl_in_chunks(file_path, chunk_size):
    """按块读取大文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        chunk = []
        for line in f:
            chunk.append(line)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def process_file(model, tokenizer,
                 input_filename, temp_dir, output_filename, 
                 num_threads, batch_size, chunk_size):
    """处理大文件并生成结果"""
    total_lines = count_lines_in_jsonl(input_filename)  # 获取总行数
    total_chunks = total_lines // chunk_size + (1 if total_lines % chunk_size > 0 else 0)  # 计算总的块数
    
    # 创建进度条（总进度条显示所有行的进度）
    with tqdm(total=total_chunks, 
              dynamic_ncols=True, 
              desc="Processing file", 
              unit="chunk") as pbar:
        output_dir = os.path.dirname(output_filename)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 创建线程池
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            futures_idx = []
            chunk_index = 0

            # 读取文件并分块
            chunk_queue = read_jsonl_in_chunks(input_filename, chunk_size)

            while chunk_index < total_chunks:
                # 如果线程池中有 num_threads 个任务在运行，则等待一个线程完成
                if len(futures) >= num_threads:
                    # 获取已完成的任务并更新进度
                    completed_future, _ = concurrent.futures.wait(
                        futures, 
                        return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in futures:
                        if future.done():  # 如果任务已完成
                            try:
                                pbar.update(1)  # 更新总进度条
                                futures.remove(future)
                            except Exception as e:
                                print(f"Error processing chunk: {e}")
                    # futures = [f for f in futures if not f.done()]  # 移除已完成的任务

                # 获取下一个数据块
                chunk = next(chunk_queue, None)
                if chunk is not None:
                    # 提交当前块的任务，并且更新进度条
                    future = executor.submit(
                        process_chunk, 
                        model, tokenizer, chunk, 
                        chunk_index, batch_size, 
                        temp_dir)
                    #TODO:将[chunk_index]和[future]绑定成一个元组
                    #便于后续通过[chunk_index]对[future]进行排序
                    futures.append(future)
                    futures_idx.append((chunk_index, future))
                    chunk_index += 1
                    # 在每次提交新任务时，更新进度条的状态
                    ## 可选，显示当前正在处理的块的进度
                    pbar.set_postfix({"Chunks": chunk_index})

            # 等待所有任务完成后，合并所有剩余的结果
            concurrent.futures.wait(futures)
            # 根据 chunk_index 排序 futures
            futures_idx = sorted(futures_idx, key=lambda x: x[0])
            for future in futures:
                pbar.update(1)  # 确保最后未计数的任务在此处更新
            for _, future in futures_idx:
                temp_file_path = future.result()
                append_temp_to_target(temp_file_path, output_filename)


if __name__ == "__main__":
    
    # 创建配置解析器
    config = configparser.ConfigParser()
    
    config.read('runtime.ini')
    num_threads = int(config['default']['num_threads'])
    # 定义批次大小
    batch_size = int(config['default']['batch_size'])
    chunk_size = int(config['default']['chunk_size'])
    spilt_name = config['default']['spilt_name']
    
    config.read('config.ini')
    jump_host = config['default']['jump_host']
    jump_user = config['default']['jump_user']
    target_host = config['default']['target_host']
    target_user = config['default']['target_user']
    target_passwd = config['default']['target_passwd']
    remote_load_path = config['default']['remote_load_path']
    remote_cache_path = config['default']['remote_cache_path']
    local_dir = config['default']['local_dir']
    result_dir = config['default']['result_dir']
    temp_dir = os.path.join(config['default']['temp_dir'], spilt_name)
    
    os.makedirs(local_dir, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(result_dir, exist_ok=True)
    jsonl_kw_path = os.path.join(local_dir, f"{spilt_name}_kw.jsonl")
    
    target_file = os.path.join(result_dir, f"{spilt_name}_Bert.jsonl")
    
    # 加载训练好的模型和分词器
    model = DistilBertForSequenceClassification.from_pretrained("../results/checkpoint-15849")
    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    
    # 将模型移到 GPU 或 CPU
    model = model.to(device)
    model.eval()

    process_file(model, tokenizer, 
                 jsonl_kw_path, temp_dir, target_file, 
                 num_threads=num_threads, 
                 batch_size=batch_size, 
                 chunk_size=chunk_size)
