from typing import *
from enum import Enum

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


from typing import *
import httpx
from nltk.tokenize import sent_tokenize
import nltk
import re
from pathlib import Path

'''
参考文档: 
1. https://github.com/chatanywhere/GPT_API_free/blob/main/demo.py
2. https://platform.openai.com/docs/guides/streaming-responses?api-mode=responses
'''

# 非流式响应
def openai_api(Client: Client, Model: Model, messages: list):
    """为提供的对话消息创建新的回答

    Args:
        messages (list): 完整的对话消息
    """
    Client.CheckModel(Model)
    completion = (Client.openai_client).chat.completions.create(model=Model.value, messages=messages)
    print(completion.choices[0].message.content)

def openai_api_stream(Client: Client, Model: Model, messages: list):
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
        if chunk.choices:
            if chunk.choices[0].delta.content is not None:
                print(chunk.choices[0].delta.content, end="")
                ans += chunk.choices[0].delta.content
    print("\n")
    return ans

upload_Cachefiles_ReturnType = List[Dict[str, Any]]

def upload_files(Client:Client, filepaths:List[str], cache_tag:Optional[str] = None) -> upload_Cachefiles_ReturnType:
    if Client.CheckType == "kimi":
        """
        upload_files 会将传入的文件（路径）全部通过文件上传接口 '/v1/files' 上传，并获取上传后的
        文件内容生成文件 messages。每个文件会是一个独立的 message，这些 message 的 role 均为
        system，Kimi 大模型会正确识别这些 system messages 中的文件内容。
    
        如果你设置了 cache_tag 参数，那么 upload_files 还会将你上传的文件内容存入 Context Cache
        上下文缓存中，后续你就可以使用这个 Cache 来对文件内容进行提问。当你指定了 cache_tag 的值时，
        upload_files 会生成一个 role 为 cache 的 message，通过这个 message，你可以引用已被缓存
        的文件内容，这样就不必每次调用 `/v1/chat/completions` 接口时都要把文件内容再传输一遍。
    
        注意，如果你设置了 cache_tag 的值，你需要把 upload_files 返回的 messages 放置在请求
        `/v1/chat/completions` 接口时 messages 参数列表的第一位（实际上，我们推荐不管是否启用
        cache_tag，都将 upload_files 返回的 messages 放置在 messages 列表的头部）。
    
        关于 Context Caching 的具体信息，可以访问这里：
    
        https://platform.moonshot.cn/docs/api/caching
    
        :param files: 一个包含要上传文件的路径的列表，路径可以是绝对路径也可以是相对路径，请使用字符串
            的形式传递文件路径。
        :param cache_tag: 设置 Context Caching 的 tag 值，你可以将 tag 理解为自定义的 Cache 名称，
            当你设置了 cache_tag 的值，就意味着启用 Context Caching 功能，默认缓存时间是 300 秒，每次
            携带缓存进行 `/v1/chat/completions` 请求都将刷新缓存存活时间（300 秒）。
        :return: 一个包含了文件内容或文件缓存的 messages 列表，请将这些 messages 加入到 Context 中，
            即请求 `/v1/chat/completions` 接口时的 messages 参数中。
        """
        messages = []
        file_objects = []
        # 对每个文件路径，我们都会上传文件并抽取文件内容，最后生成一个 role 为 system 的 message，并加入
        # 到最终返回的 messages 列表中。
        for file in filepaths:
            filePath = Path(file)
            if filePath.exists():
                file_object = (Client.openai_client).files.create(file=filePath, purpose="file-extract")
                file_objects.append(file_object)
                file_content = (Client.openai_client).files.content(file_id=file_object.id).text
                messages.append({"role": "system", "content": file_content,})
            else:
                print("File:" + str(filePath) + "not exist!!!")
        
        if cache_tag:
            # 当启用缓存（即 cache_tag 有值时），我们通过 HTTP 接口创建缓存，缓存的内容则是前文中通过文件上传
            # 和抽取接口生成的 messages 内容，我们为这些缓存设置一个默认的有效期 300 秒（通过 ttl 字段），并
            # 为这个缓存打上标记，标记值为 cache_tag（通过 tags 字段）。
            r = httpx.post(f"{(Client.openai_client).base_url}caching",
                        headers={
                            "Authorization": f"Bearer {(Client.openai_client).api_key}",
                        },
                        json={
                            "model": "moonshot-v1",
                            "messages": messages,
                            "ttl": 300,
                            "tags": [cache_tag],
                        })
    
            if r.status_code != 200:
                raise Exception(r.text)
    
            # 创建缓存成功后，我们不再需要将文件抽取后的内容原封不动地加入 messages 中，取而代之的是，我们可以设置一个
            # role 为 cache 的消息来引用我们已缓存的文件内容，只需要在 content 中指定我们给 Cache 设定的 tag 即可，
            # 这样可以有效减少网络传输的开销，即使是多个文件内容，也只需要添加一条 message，保持 messages 列表的清爽感。
            return [{
                "role": "cache",
                "content": f"tag={cache_tag};reset_ttl=300",
            }]
        else:
            for file_object in file_objects:
                (Client.openai_client).files.delete(file_id=file_object.id)
            return messages
    else:
        # messages = []
        # file_objects = []
        # # 对每个文件路径，我们都会上传文件并抽取文件内容，最后生成一个 role 为 system 的 message，并加入
        # # 到最终返回的 messages 列表中。
        # for file in filepaths:
        #     filePath = Path(file)
        #     if filePath.exists():
        #         file_object = (Client.openai_client).files.create(file=open(filePath, "rb"), purpose="user_data")
        #         file_objects.append(file_object)
        #         file_content = (Client.openai_client).files.content(file_id=file_object.id).text
        #         messages.append({"role": "system", "content": file_content,})
        #     else:
        #         print("File:" + str(filePath) + "not exist!!!")
        
        # if cache_tag:
        #     tag = []
        #     for file_obj in file_objects:
        #         tag.append({
        #             "role": "user",
        #             "content": [
        #                 {
        #                     "type": "input_file",
        #                     "file_id": file_obj.id,
        #                 }
        #             ]
        #         })
        #     return tag
        # else:
        #     return messages
        messages = []
        for file in filepaths:
            filePath = Path(file)
            if filePath.exists():
                with open(filePath, 'r', encoding='utf-8') as file:
                    file_content = file.read()
                messages.append({"role": "system", "content": file_content,})
        return messages

def files_chat(Client:Client, Model:Model, filePaths:list[str], Messages:list[str], StreamMode:bool, cache_tag:Optional[str] = None):
    messages = []
    messages.append(*upload_files(Client, filePaths, cache_tag=cache_tag))
    for Message in Messages:
        messages.append({'role': 'user','content': Message})
        if StreamMode is True: # 流式调用
            return openai_api_stream(Client, Model, messages)
        else: # 非流式调用
            return openai_api(Client, Model, messages)

def common_chat(Client:Client, Model:Model, Messages:list, StreamMode:bool, cache_tag:Optional[str] = None):
    messages = []
    if cache_tag:
        messages.append({
            "role": "cache",
            "content": f"tag={cache_tag};reset_ttl=300",
        })
    for Message in Messages:
        messages.append({'role': 'user','content': Message})
    if StreamMode is True: # 流式调用
        return openai_api_stream(Client, Model, messages)
    else: # 非流式调用
        return openai_api(Client, Model, messages)

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
    return openai_api_stream(Client, Model, messages)



if __name__ == '__main__':
    # client = Client("./config/config.ini", "kimi")
    client = Client("/home/zrz/.config/Personal_config/config_aiAPI.ini", "kimi")

    messages = ["上述文件内容涉及到道德以及法律相关的内容吗"]

    # files_chat(client, Model.gpt4o, ["./Test_Wheel/test.md"], messages, StreamMode=True)
    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test0.md"], messages, StreamMode=True)
    ans = common_chat(client, Model.kimi_128k, messages, StreamMode=True)
    print("ans is :" + ans)