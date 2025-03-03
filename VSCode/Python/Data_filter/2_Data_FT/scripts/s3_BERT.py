from transformers import DistilBertForSequenceClassification, Trainer, TrainingArguments, AutoTokenizer
from datasets import Dataset
import os
import json
os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

## 参考：
# https://mp.weixin.qq.com/s/lInH4a0a5ifXpusz7Pxc3g
# 

# 训练数据导入
with open("./2_FT_Data/train_data.json", "rb") as f:
    train_data = json.load(f)

with open("./2_FT_Data/eval_data.json", "rb") as f:
    eval_data = json.load(f)

# 初始化 tokenizer
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

# 将文本数据编码为模型的输入格式
def tokenize_function(examples):
    return tokenizer(examples['text'], 
                     padding="max_length", 
                     truncation=True)

# 将字典转换为 Dataset 对象
train_dataset = Dataset.from_dict(train_data)
eval_dataset = Dataset.from_dict(eval_data)

# 应用 tokenizer
train_dataset = train_dataset.map(tokenize_function, batched=True)
eval_dataset = eval_dataset.map(tokenize_function, batched=True)

# 删除不需要的 'text' 字段
train_dataset = train_dataset.remove_columns(["text"])
eval_dataset = eval_dataset.remove_columns(["text"])

# 定义模型
model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased", 
    num_labels=2
)

# 训练参数
training_args = TrainingArguments(
    output_dir="./results",
    eval_strategy="epoch",  # 替换 deprecated 参数
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=3,
    warmup_ratio=0.1,
    learning_rate=5e-5,
    logging_dir='./logs',
)

# 创建 Trainer 实例
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
)

# 训练模型
trainer.train()