# tasks/my_task.py
import json
from lm_eval.base import Task

class MyCustomTask(Task):
    DATASET_PATH = None  # 如果你的数据集不是从 HuggingFace Hub 下载，则不需要配置此项
    DATASET_NAME = None  # 如果没有子集，设置为 None

    def __init__(self, data_path="/home/zrz/Projects/GitRepo/Repo/Python_Projects/VSCode/Python/CodeWM_AutoTest/datasets/projectDev_java_temp.jsonl", **kwargs):
        super().__init__(stop_words=["<|endoftext|>"], requires_execution=False)
        self.data_path = data_path
        self._data = []
        self._load_data()

    def _load_data(self):
        """加载 JSONL 数据文件"""
        with open(self.data_path, "r", encoding="utf-8") as f:
            for line in f:
                self._data.append(json.loads(line))

    def get_dataset(self):
        """返回数据集"""
        return self._data

    def get_prompt(self, doc):
        """构建用于生成的 prompt"""
        return f"{doc['prompt']}{doc['prefix']}"  # 使用 'prompt'+'prefix' 字段作为模型的输入

    def get_reference(self, doc):
        """参考答案，如果你的数据集中没有参考答案，可以返回 None 或空字符串"""
        return doc["reference"]  # 使用 'reference' 字段作为参考答案

    def postprocess_generation(self, generation, idx):
        """对生成的文本进行后处理"""
        return generation.strip()  # 这里可以添加一些处理逻辑

    def process_results(self, generations, references):
        """计算评测指标"""
        # 如果没有参考答案，你可以跳过评测，或者根据生成的内容与某些标准做对比
        # 这里做个简单的处理，如果没有参考答案，就返回一个空结果
        return {"results": "No reference to evaluate"}
