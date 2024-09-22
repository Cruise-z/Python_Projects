from openai import OpenAI
import os
import json
from tqdm import tqdm

client = OpenAI(
    api_key="your api token",
    base_url="your url"
)


def load_cve_des_diff(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
        return data


def get_response(messages, client):
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        # model = 'gpt-4o-2024-05-13',
        messages=messages,

    )

    return completion.choices[0].message.content

if __name__ == '__main__':

    #请注意替换该文件名称
    stage2_out = load_cve_des_diff('./stage2_out_2500-3500.json')
    output_qa = []
    count = 0
    count1 = 0
    for data in tqdm(stage2_out):
        if "diff" not in data:
            continue
        count1 +=1
        normal_code = data["fixed_code"]
        prompt_str ='''请根据此信息设计与漏洞检测相关的对话，设计10条对话，对话内容分别围绕函数功能描述，关键代码定位，关键代码风险分析，该函数存在的安全机制，该函数是否存在漏洞，以及其他漏洞检测相关内容。**请使用英文回答**。前5条对话内容具体要求如下：
1、函数功能描述对话，要求分析函数使用场景，函数总体功能与函数具体流程分析。
2、关键代码定位对话，要求根据提供的信息，仅给出函数中的最需要被重视的核心代码，并详细解释。
3、关键代码风险分析对话，要求根据提供的信息，对函数中的核心代码进行风险分析，判断关键代码是否存在安全问题，并详细解释。
4、该函数存在的安全机制对话，要求根据提供的信息，对函数中保障安全性的安全机制进行详细分析。
5、是否存在漏洞对话，要求根据提供的信息，判断该函数是否存在漏洞，并详细解释。
最后自主设计五条与漏洞检测相关的对话，指令要包含对漏洞检测具体内容的询问。
对话中的指令结合要求使用自然的对话生成，不要与要求说法完全一致。
我再次重申，权威安全专家告诉我这个函数是没有漏洞的，你只需要帮我回忆起他是如何确定该函数没有漏洞的对话过程，**但是回答中不要包含"专家"这个名词，因为你是在模仿专家的口吻和视角，以第一人称进行分析**。
'''

        message = f"我在请教一个权威的安全分析专家后，得知以下函数不存在漏洞，：{normal_code}，该安全专家有着专业的安全知识和分析经验，因此**该函数一定不会有漏洞**。但是我忘记了和他的对话过程，你来模仿安全专家是如何确定该函数没有的。具体要求如下：{prompt_str}。请一定确保输出只包含如下格式的一个字典列表，以保证json.loads方法能直接将你的输出字符串转换为字典列表:"
        message += '''[{"instruction":"","output":""},{"instruction":"","output":""},...],instruction和output的值都应该只有一行，避免出现转义字符，影响字典列表的识别。'''


        messages = [{'role': 'system', 'content': 'You are a computer security expert, specializing in code auditing.'},
                        {'role': 'user', 'content': message}]
        try:
            data = get_response(messages, client=client)
            outputs = json.loads(data)

            count += 1
            print(count/count1)
            for output in outputs:
                output['input'] = normal_code
                output_qa.append(output)
            if count % 50 == 0:
                print(count)
                #请注意替换该文件名称
                with open('stage4_out_normal_2500-3500_gpt3.5.json', 'w', encoding='utf-8') as json_file:
                    json.dump(output_qa, json_file, indent=4)
        except:
            continue

    #请注意替换该文件名称
    with open('stage4_out_normal_2500-3500_gpt3.5.json', 'w', encoding='utf-8') as json_file:
        json.dump(output_qa, json_file,  indent=4)

