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
    stage2_out = load_cve_des_diff('./stage2_out_3500-4500.json')
    output_qa = []
    pure_strs = []
    count = 0
    count1 = 0
    for data in tqdm(stage2_out):
        if "diff" not in data:
            continue
        count1 +=1
        vul_code = data["vul_code"]
        desc = data["description"]
        diff = data["diff"]
        prompt_str = '''
        请根据此信息设计与漏洞挖掘相关的对话，设计10条对话，对话内容分别围绕函数功能描述，敏感代码定位，敏感代码风险分析，安全风险的成因，安全风险是否被排除，风险怎么被排除，是否存在漏洞，应当如何修复，其他漏洞挖掘相关内容。请使用英文回答，不要提及补丁的存在。前8条对话内容具体要求如下：
        1、函数功能描述对话，要求分析函数使用场景，函数总体功能与函数具体流程分析
        2、敏感代码定位对话，要求根据提供的信息，仅给出函数中存在安全风险的核心代码，不要分析
        3、敏感代码风险分析对话，要求根据提供的信息，对函数中存在安全风险的核心代码进行详细的风险分析
        4、安全风险的成因对话，要求根据提供的信息，结合代码对函数中敏感代码的安全风险成因进行详细分析
        5、安全风险是否被排除对话，要求根据提供的信息，仅对安全风险是否被排除回答"是"或"否"，并详细回答原因
        6、安全风险怎么被排除对话，如果安全风险被排除，对安全风险怎么被排除进行详细分析
        7、是否存在漏洞对话，要求根据提供的信息，仅对函数中是否存在漏洞给出"是"或"否"，并详细回答原因
        8、应当如何修复对话，如果函数中存在漏洞，对漏洞应当如何进行修复进行详细分析，并给出修复涉及的代码变化
        最后自主设计两条与漏洞挖掘相关的对话，instruction为对类似的漏洞挖掘内容的询问，output为对该instruction的回答
        对话中的output一定要为instruction提供详细的讨论
        对话中的instruction要求使用自然的对话生成，不要与要求中的说法一致
        <<请保证问题的表述尽量多元化>>
        '''
       
        message = f"以下函数存在漏洞：{vul_code}\n该函数的漏洞描述如下：{desc}\n该漏洞的补丁是：{diff}。\n{prompt_str}。请一定确保输出只包含如下格式的一个字典列表，以保证json.loads方法能直接将你的输出字符串转换为字典列表:"
        message +='''[{"instruction":"","output":""},{"instruction":"","output":""}],instruction和output的值都应该只有一行，避免出现转义字符，影响字典列表的识别。'''

        messages = [{'role': 'system', 'content': 'You are a computer security expert, specializing in code auditing.'},
                    {'role': 'user', 'content': message}]
        try:
            data = get_response(messages, client=client)
            outputs = json.loads(data)
            count += 1
            print(count/count1)
            for output in outputs:
                output['input'] = vul_code
                output_qa.append(output)
            if count % 20 == 0:
                print(count)
                #请注意替换该文件名称
                with open('stage4_out_vul_3500-4500_gpt3.5.json', 'w', encoding='utf-8') as json_file:
                    json.dump(output_qa, json_file, indent=4)
        except:
            continue
    #请注意替换该文件名称
    with open('stage4_out_vul_3500-4500_gpt3.5.json', 'w', encoding='utf-8') as json_file:
        json.dump(output_qa, json_file, indent=4)



