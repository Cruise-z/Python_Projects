from gptAPI import *
import os
import random

if __name__ == '__main__':
    # messages0 = ["请给出一些类似于如下网站指向的开源模型，并指出这些模型用了多少数据去训练和微调：\n"
    #             + "https://github.com/luban-agi/Awesome-Domain-LLM?tab=readme-ov-file\n"
    #             + "https://github.com/HqWu-HITCS/Awesome-Chinese-LLM"]
    
    # messages1 = ["请分析此网页链接对应图片内容：https://miro.medium.com/v2/resize:fit:692/1*IOmxSVsyqXOUE8ou-ChkvA.jpeg"]
    # Common_Chat(Clients.client_paid, Model.gpt4, messages1)

    client = Client("./config.ini", "paid")

    root_dir = "./POC_Data/2023"
    file_selected = []

    model_name = "gpt2"
    model = GPT2LMHeadModel.from_pretrained(model_name)  # 加载模型
    tokenizer = GPT2Tokenizer.from_pretrained(model_name)  # 加载分词器

    for root, dirs, files in sorted(os.walk(root_dir)):
        for file in files:
            if file.endswith('ref.md'):
                file_selected.append(os.path.join(root, file))
    
    if len(file_selected) >= 50:
        selected_files = random.sample(file_selected, 3)
        print(selected_files)


    with open('./test.md', 'a', encoding='utf-8') as ans_file:
        for file in selected_files:
            if count_tokens_in_file(file, tokenizer) > 30000:
                continue
            ans = "## " + file + "\n"
            ans += Data_quality_assessment(client, Model.gpt4o, file)
            ans += "\n\n"
            ans_file.write(ans)

    