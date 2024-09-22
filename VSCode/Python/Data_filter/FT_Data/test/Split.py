from datasets import load_dataset
from sklearn.model_selection import train_test_split, KFold
import json
import os

# 网络安全数据集生成：爬取https://www.darkreading.com/ 新闻社区文章进行数据标注

# 设置代理
os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

# 加载数据集
dataset = load_dataset("AlaaElhilo/Wikipedia_ComputerScience")

# 打印数据集结构
print(dataset)

# 选择训练集部分
data = dataset['train']

# 将数据转换为列表
data = list(data)

# 设置随机种子
random_state = 42

# 先分出测试集
test_size = 0.15
train_val_data, test_data = train_test_split(data, test_size=test_size, random_state=random_state)

# 保存测试集
with open('./FT_Data/gen_data_1/test_data.json', 'w', encoding='utf-8') as f:
    json.dump(test_data, f, ensure_ascii=False, indent=4)

# 设置 KFold 交叉验证
kf = KFold(n_splits=5, shuffle=True, random_state=random_state)

# 选择其中一个折来作为验证集，其余作为训练集
for fold, (train_index, val_index) in enumerate(kf.split(train_val_data), start=1):
    train_data = [train_val_data[i] for i in train_index]
    val_data = [train_val_data[i] for i in val_index]
    
    # 保存数据集
    with open(f'./FT_Data/gen_data_1/train_data_fold{fold}.json', 'w', encoding='utf-8') as f:
        json.dump(train_data, f, ensure_ascii=False, indent=4)
        
    with open(f'./FT_Data/gen_data_1/val_data_fold{fold}.json', 'w', encoding='utf-8') as f:
        json.dump(val_data, f, ensure_ascii=False, indent=4)

    print(f"Fold {fold} 的训练集和验证集已成功保存为 train_data_fold{fold}.json 和 val_data_fold{fold}.json")
    print("测试集已保存为 test_data.json")

    # 如果只需要保存一个折的数据，可以在这里退出循环
    # break
