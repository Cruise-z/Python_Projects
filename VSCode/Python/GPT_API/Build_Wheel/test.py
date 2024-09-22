from openai import OpenAI
from enum import Enum
from transformers import GPT2LMHeadModel, GPT2Tokenizer
from nltk.tokenize import sent_tokenize
import nltk
import re
import configparser
from pathlib import Path

class Model(Enum):
    ## 下面的模型为GPT的专用模型
    text_embed_ada_002  = "text-embedding-ada-002"
    text_embed_3_small  = "text-embedding-3-small"
    text_embed_3_large  = "text-embedding-3-large"
    gpt35t              = "gpt-3.5-turbo"
    gpt35t_0125         = "gpt-3.5-turbo-0125"
    gpt35t_1106         = "gpt-3.5-turbo-1106"
    gpt35t_0613         = "gpt-3.5-turbo-0613"
    gpt35t_0301         = "gpt-3.5-turbo-0301"
    gpt4o               = "gpt-4o"
    gpt4o_240513        = "gpt-4o-2024-05-13"
    gpt4                = "gpt-4"
    # 上述模型对免费版客户端可用，gpt4以及gpt4o一天共计可用三次
    gpt35t_16k          = "gpt-3.5-turbo-16k"
    gpt35t_16k_0613     = "gpt-3.5-turbo-16k-0613"
    gpt35t_ca           = "gpt-3.5-turbo-ca"
    gpt35t_inst         = "gpt-3.5-turbo-instruct"
    gpt35t_inst_0914    = "gpt-3.5-turbo-instruct-0914"
    gpt4_0613           = "gpt-4-0613"
    gpt4_ca             = "gpt-4-ca"
    gpt4_1106_prev      = "gpt-4-1106-preview"
    gpt4_1106v_prev     = "gpt-4-1106-vision-preview"
    gpt4_0125_prev      = "gpt-4-0125-preview"
    gpt4v_prev          = "gpt-4-vision-preview"
    gpt4t               = "gpt-4-turbo"
    gpt4t_240409        = "gpt-4-turbo-2024-04-09"
    gpt4t_prev          = "gpt-4-turbo-preview"
    gpt4o_ca            = "gpt-4o-ca"
    gpt4t_ca            = "gpt-4-turbo-ca"
    gpt4t_prev_ca       = "gpt-4-turbo-preview-ca"
    claude              = "claude-3-5-sonnet-20240620"
    whisper             = "whisper-1"
    tts1                = "tts-1"
    tts1_1106           = "tts-1-1106"
    tts1_hd             = "tts-1-hd"
    tts1_hd_1106        = "tts-1-hd-1106"
    dall_e2             = "dall-e-2"
    dall_e3             = "dall-e-3"
    # 上述模型对GPT付费版均可用
    ## 下面的模型为Kimi的专用模型
    kimi_8k             = "moonshot-v1-8k"
    kimi_32k            = "moonshot-v1-32k"
    kimi_128k           = "moonshot-v1-128k"

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


# 非流式响应
def gpt_api(Client: Client, Model: Model, messages: list):
    """为提供的对话消息创建新的回答

    Args:
        messages (list): 完整的对话消息
    """
    Client.CheckModel(Model)
    completion = (Client.openai_client).chat.completions.create(model=Model.value, messages=messages)
    print(completion.choices[0].message.content)

def gpt_api_stream(Client: Client, Model: Model, messages: list):
    """为提供的对话消息创建新的回答 (流式传输)

    Args:
        messages (list): 完整的对话消息
    """
    Client.CheckModel(Model)
    stream = (Client.openai_client).chat.completions.create(
        model=Model.value,
        messages=messages,
        stream=True,
    )
    ans = ""
    for chunk in stream:
        if chunk.choices[0].delta.content is not None:
            print(chunk.choices[0].delta.content, end="")
            ans += chunk.choices[0].delta.content
    print("\n")
    return ans

def common_chat(Client: Client, Model: Model, Messages:list, StreamMode:bool):
    messages = []
    for Message in Messages:
        messages.append({'role': 'user','content': Message})
    if StreamMode is True: # 流式调用
        return gpt_api_stream(Client, Model, messages)
    else: # 非流式调用
        return gpt_api(Client, Model, messages)

def file_chat(Client: Client, Model: Model, filename:str, Messages:list, StreamMode:bool):
    File = Path(filename)
    if File.exists():
        messages = []
        file_object = (Client.openai_client).files.create(file=File, purpose="file-extract")
        file_content = (Client.openai_client).files.content(file_id=file_object.id).text
        (Client.openai_client).files.delete(file_id=file_object.id)
        messages.append({'role': 'system','content': file_content})
        for Message in Messages:
            messages.append({'role': 'user','content': Message})
        if StreamMode is True: # 流式调用
            return gpt_api_stream(Client, Model, messages)
        else: # 非流式调用
            return gpt_api(Client, Model, messages)
    else:
        print("File not exist!!!")
        return None

def count_tokens_in_file(file_path, tokenizer, model_max_length=1024):
    nltk.download('punkt')
    token_count = 0
    with open(file_path, 'r', encoding='utf-8') as file:
        text = file.read().strip()
        # 使用nltk进行句子分割
        sentences = sent_tokenize(text)
        for sentence in sentences:
            if len(tokenizer.encode(sentence, return_tensors='pt')) > model_max_length:
                # 如果单个句子超过最大长度，进行进一步分割
                while len(tokenizer.encode(sentence, return_tensors='pt')) > model_max_length:
                    sentence = sentence[:-10]  # 简化的分割逻辑，实际应用中可能需要更精细的处理
            encoded_sentence = tokenizer(sentence, return_tensors='pt')
            token_count += len(encoded_sentence['input_ids'][0])
    return token_count

def Data_quality_assessment(Client: Client, Model: Model, File_path):
    # 使用with语句自动管理文件的打开和关闭
    with open(File_path, 'r', encoding='utf-8') as file:
        content = file.read()  # 读取整个文件内容

    vuln_num_pattern = r'CVE-\d{4}-\d{4}'
    vuln_num = re.search(vuln_num_pattern, file.name).group()

    messages = [{'role': 'user',
                 'content': '请分析:' + content + '该内容是否与漏洞:' + vuln_num 
                          + '的描述信息或其POC(Proof Of Concept)信息相关?\n'
                          + '注：输出格式如下\n'
                          + '描述信息：(有/无)关'
                          + 'POC信息：(有/无)关'
                          + '内容概述：(对上述给出的内容作简要分析概述)'},]
    # 非流式调用
    # gpt_api(Client, Model, messages)
    # 流式调用
    return gpt_api_stream(Client, Model, messages)


    
if __name__ == '__main__':
    
    client_free = Client("../../GPT_API/config.ini", "free")

    client_paid = Client("../../GPT_API/config.ini", "paid")

    client_kimi = Client("../../GPT_API/config.ini", "kimi")

    messages = ["请保留这个文件中与漏洞POC强相关的内容以及.md的相应格式，剔除与POC无关的(比如html格式，commit对话等)内容"]

    file_chat(client_kimi, Model.kimi_8k, "test.md", messages, StreamMode=True)

    # chat_stream(client_paid, Model.gpt35t, messages)