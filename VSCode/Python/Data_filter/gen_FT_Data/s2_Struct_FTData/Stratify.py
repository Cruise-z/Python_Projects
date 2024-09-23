# TODO:Stratified Sampling(分层抽样)
from datasets import load_dataset
from colorama import init, Fore, Back, Style
import json
import random
import ijson
import os

os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

init(autoreset=True)  # 初始化colorama，并设置autoreset=True使每条打印信息后自动重置样式

def process_large_json(file_path):
    # 打开JSON文件
    with open(file_path, 'rb') as file:
        # 创建一个ijson解析器对象，使用YAJL2后端（如果已安装）
        parser = ijson.parse(file)
        for prefix, event, value in parser:
            if prefix.endswith('.text'):  # 根据需要调整路径
                print('Text:', value)
            elif prefix.endswith('.label'):  # 根据需要调整路径
                print(Fore.BLUE + Back.YELLOW + Style.BRIGHT + f"Label:{value}")

def load_json(file_dir:str):
    with open(file_dir, 'r') as json_file:
        return json.load(json_file)

# 保存混合后的数据为 JSON 文件
def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

# 从列表中分离出不同类别的数据
def separate_by_label(data):
    class_0 = [item for item in data if item['label'] == 0]
    class_1 = [item for item in data if item['label'] == 1]
    return class_0, class_1

# 分层抽样生成平衡的 mini-batch，包含过采样
def create_balanced_batches_with_oversampling(class_0, class_1, batch_size):
    max_len = max(len(class_0), len(class_1))
    
    # 对较少的类别进行过采样
    if len(class_0) < max_len:
        class_0 = class_0 * (max_len // len(class_0)) + random.sample(class_0, max_len % len(class_0))
    elif len(class_1) < max_len:
        class_1 = class_1 * (max_len // len(class_1)) + random.sample(class_1, max_len % len(class_1))
    
    # 生成平衡的批次
    for i in range(0, max_len, batch_size // 2):
        batch_class_0 = class_0[i:i + batch_size // 2]
        batch_class_1 = class_1[i:i + batch_size // 2]
        batch = batch_class_0 + batch_class_1
        
        # 打乱 batch 内的顺序
        random.shuffle(batch)
        
        yield batch
        
# 组织分层抽样数据，使用过采样
def stratified_sample_batches_with_oversampling(CSdata, nCSdata, batch_size):
    # 添加标签: 1 为 CSdata, 0 为 nCSdata
    for item in CSdata:
        item['label'] = 1
    for item in nCSdata:
        item['label'] = 0
    
    # 将数据按标签分类
    class_0, class_1 = separate_by_label(CSdata + nCSdata)
    
    # 使用分层抽样生成平衡的 mini-batch
    balanced_batches = list(create_balanced_batches_with_oversampling(class_0, class_1, batch_size))
    
    return balanced_batches

# 分割训练集和验证集
def split_train_val(data, train_ratio=0.8):
    train_size = int(len(data) * train_ratio)
    train_data = data[:train_size]
    val_data = data[train_size:]
    return train_data, val_data

# 将数据转换为 BERT 所需的格式 {"text": [], "label": []}
def convert_to_bert_format(data):
    text_list = [item['text'] for item in data]
    label_list = [item['label'] for item in data]
    return {"text": text_list, "label": label_list}


CS_dir = './gen_FT_Data/Raw_Data/CS/CS.json'
nCS_dir = './gen_FT_Data/Raw_Data/nCS/nCS.json'
mix_data_dir = './gen_FT_Data/'
train_data_path = './FT_Data/'

CSdata = load_json(CS_dir)
nCSdata = load_json(nCS_dir)

# 设置批次大小
batch_size = 32

# 使用分层抽样生成平衡的批次
balanced_batches = stratified_sample_batches_with_oversampling(CSdata, nCSdata, batch_size)

save_json(os.path.join(mix_data_dir, "mix.json"), balanced_batches)
# process_large_json(os.path.join(mix_data_dir, 'mix.json'))

# 将数据合并回训练集，并打乱顺序
training_data = [item for batch in balanced_batches for item in batch]
random.shuffle(training_data)

# 将数据分割为训练集和验证集
train_data, val_data = split_train_val(training_data)
print(f"训练集大小: {len(train_data)}，验证集大小: {len(val_data)}")
train_data = convert_to_bert_format(train_data)
val_data = convert_to_bert_format(val_data)
save_json(os.path.join(train_data_path, "train_data.json"), train_data)
save_json(os.path.join(train_data_path, "eval_data.json"), val_data)

