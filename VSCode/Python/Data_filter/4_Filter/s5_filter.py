# 正式清洗的脚本
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

