from transformers import DistilBertForSequenceClassification, AutoTokenizer
import torch
import os
import json
import re

def filter(model, tokenizer, texts):
    # 预处理输入数据
    inputs = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
    # 进行预测
    model.eval()
    with torch.no_grad():
        outputs = model(**inputs)
    # 获取 logits 和预测结果
    logits = outputs.logits
    probabilities = torch.nn.functional.softmax(logits, dim=-1)
    predicted_labels = torch.argmax(probabilities, dim=-1)
    label_map = {0: 0, 1: 1}
    predicted_labels = [label_map[label.item()] for label in predicted_labels]
    return predicted_labels


work_dir = "./3_Bert_test/test"
with open(os.path.join(work_dir, "filter_keywords.json"), "rb") as f:
    data = json.load(f)

# 加载训练好的模型和分词器
model = DistilBertForSequenceClassification.from_pretrained("./results/checkpoint-15849")
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

CS_related = []

for item in data:
    content = re.sub(r'\s+', ' ', item["text"]).strip()
    text = [content]
    label = filter(model, tokenizer, text)
    print(label)
    if label == [1]:
        item["label"] = 1
        CS_related.append({"text": item["text"], "label": 1})
        
# 将数据保存到JSON文件
with open(os.path.join(work_dir, "filter_keywords.json"), 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=4)
with open(os.path.join(work_dir, "filter_Bert.json"), 'w', encoding='utf-8') as f:
    json.dump(CS_related, f, ensure_ascii=False, indent=4)