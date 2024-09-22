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
def get_response(messages,client):

    completion = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        #model = 'gpt-4o-2024-05-13',
        messages = messages,
        )

    return completion.choices[0].message.content


if __name__ == '__main__':
    #请注意替换该文件名称
    data = load_cve_des_diff('./output_for_funcname.json')
    print(len(data))
    stage1_out = []
    count = 0
    #范围这里拆分处理了，也可以直接for i in tqdm(range(len(data)))，一次性处理全部数据
    for i in tqdm(range(2500,3500)):

        cve = data[i]["CVEid"]
        cwe = data[i]["CWEid"]
        commit = data[i]["commit_urls"]
        description = data[i]["desc"]
        diff = data[i]["diff"]
        message = f"下面是一次漏洞修复前后的不同代码，其中涉及到多个定义函数的变更，但是不一定所有的定义函数变更都与漏洞修复相关。你是经验丰富的安全专家，我向你提供漏洞的描述信息以及修复前后的代码，你来分析哪些**定义函数**的变更与漏洞修复相关。漏洞的描述信息为：{description}，漏洞的CWE类型为{cwe}，代码变更信息为：{diff}，请返回**漏洞相关的函数名**及**函数所在的文件名称**，形式为:[(filename1,function1),(filename2,function2),...]，filename和function以字符串形式，<请一定注意：返回的结果只是一个元组列表，不要包含其他信息。>"
        messages = [{'role': 'system', 'content': 'You are a computer security expert, specializing in code auditing.'},
                    {'role': 'user', 'content': message}]
        try:
            data1 = get_response(messages,client = client)
            #print(data1)
            vul_file_func_list = eval(data1)
            print(vul_file_func_list)
            for vul_file, vul_name in vul_file_func_list:
                dict = {}
                dict["CVE"] = cve
                dict["commit"] = commit
                dict["description"] = description
                dict['vul_filename'] = vul_file
                dict['vul_function'] = vul_name
                stage1_out.append(dict)
            count += 1
            print(count)
            if count % 30 == 0:
                #请注意替换该文件名称
                with open('stage1_out_2500-3500_bak.json', 'w', encoding='utf-8') as json_file:
                    json.dump(stage1_out, json_file, indent=4)
        except:
            continue

    print(len(stage1_out))
    print(count)
    #请注意替换该文件名称
    with open('stage1_out_2500-3500_bak.json', 'w', encoding='utf-8') as json_file:
        json.dump(stage1_out, json_file, indent=4)


    