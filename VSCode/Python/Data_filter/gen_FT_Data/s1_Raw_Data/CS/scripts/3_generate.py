import json
import os

work_dir = './gen_FT_Data/s1_Raw_Data/CS'
path = '/articles'  # 下载文件位置

# 初始化列表来存储所有的文本数据
texts_CS = []

# 遍历目录中的所有文件
for root, dirs, files in os.walk(work_dir+path):
    for filename in files:
        file_path = os.path.join(root, filename)  # 构造完整的文件路径
        if os.path.isfile(file_path):  # 确保是文件
            with open(file_path, 'r', encoding='utf-8') as file:  # 打开文件
                content = file.read()  # 读取文件内容
                texts_CS.append({"text": content, "label": 1})

# 将数据保存到JSON文件
with open(os.path.join(work_dir, "CS.json"), 'w', encoding='utf-8') as f:
    json.dump(texts_CS, f, ensure_ascii=False, indent=4)