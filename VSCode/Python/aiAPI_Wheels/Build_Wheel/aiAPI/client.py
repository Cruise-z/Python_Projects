from .model import Model
from typing import *
from openai import OpenAI
import re
import configparser

class Client:
    def __init__(self, ConfigPath:str, ConfigType:str):
        # 读取.ini文件中的"api_key"以及"base_url"配置
        config = configparser.ConfigParser()
        config.read(ConfigPath)
        # 初始化 OpenAI 实例
        self.__api_key = config[ConfigType]['api_key']
        self.__base_url = config[ConfigType]['base_url']
        self.openai_client = OpenAI(
            api_key=self.__api_key, 
            base_url=self.__base_url
            )
        # 定义支持的模型列表
        if self.CheckType() == 'GPT_free':
            self.__supported_models = [
                Model.text_embed_ada_002, Model.text_embed_3_small, Model.text_embed_3_large,
                Model.gpt35t, Model.gpt35t_1106, Model.gpt35t_0613, Model.gpt35t_0301, Model.gpt35t_0125,
                Model.gpt4o, Model.gpt4o_240513, Model.gpt4, 
                ]
        elif self.CheckType() == 'GPT_paid':
            self.__supported_models = [model for model in Model 
                                       if model not in [Model.kimi_8k, Model.kimi_32k, Model.kimi_128k]]
        elif self.CheckType() == 'Kimi':
            self.__supported_models = [Model.kimi_8k, Model.kimi_32k, Model.kimi_128k]
        else:
            self.__supported_models = []

    # 此函数有待完善，主要是不清楚该api是如何生成免费以及付费的api_key的
    def CheckType(self):
        if re.match(r"^sk-PMS.*c2u", self.__api_key):
            return 'GPT_free'
        elif re.match(r"^sk-5pz.*KH9", self.__api_key):
            return 'GPT_paid'
        elif re.match(r"^sk-R5u.*7OB", self.__api_key):
            return 'Kimi'
        else:
            raise ValueError(f"API key format is incorrect!")
        
    def CheckModel(self, Model:Model):
        if Model not in self.supported_models:
            raise ValueError(f"Model {Model} is not supported!\nAvailable models are:\n{self.supported_models}")

    
    @property
    def supported_models(self):
        return self.__supported_models

