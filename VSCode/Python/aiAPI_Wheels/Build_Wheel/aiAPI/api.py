from .model import Model
from .client import Client
from typing import *
import httpx
from nltk.tokenize import sent_tokenize
import nltk
import re
from pathlib import Path

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
        if chunk.choices[0].delta.content is not None:
            print(chunk.choices[0].delta.content, end="")
            ans += chunk.choices[0].delta.content
    print("\n")
    return ans

def common_chat(Client:Client, Model:Model, Messages:list, StreamMode:bool):
    messages = []
    for Message in Messages:
        messages.append({'role': 'user','content': Message})
    if StreamMode is True: # 流式调用
        return openai_api_stream(Client, Model, messages)
    else: # 非流式调用
        return openai_api(Client, Model, messages)

upload_Cachefiles_ReturnType = List[Dict[str, Any]]

def upload_Cachefiles(Client:Client, filepaths:List[str], cache_tag:Optional[str] = None) -> upload_Cachefiles_ReturnType:
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

def files_chat_interface(messages:upload_Cachefiles_ReturnType, Client:Client, Model:Model, filePaths:list[str], Messages:list[str], StreamMode:bool):
    messages.extend(upload_Cachefiles(Client, filePaths))
    for Message in Messages:
        messages.append({'role': 'user','content': Message})
        if StreamMode is True: # 流式调用
            return openai_api_stream(Client, Model, messages)
        else: # 非流式调用
            return openai_api(Client, Model, messages)

def files_chat(Client:Client, Model:Model, filePaths:list[str], Messages:list[str], StreamMode:bool):
    messages = []
    return files_chat_interface(messages, Client, Model, filePaths, Messages, StreamMode)

def cache_files_chat(Cachefiles:upload_Cachefiles_ReturnType, Client: Client, Model: Model, filePaths:list[str], Messages:list[str], StreamMode:bool):
    # 我们使用*语法，来解构file_messages消息，使其成为messages列表的前N条messages。
    messages = [*Cachefiles]
    return files_chat_interface(messages, Client, Model, filePaths, Messages, StreamMode)

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
