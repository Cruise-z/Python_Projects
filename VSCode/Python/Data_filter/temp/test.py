def extract_content(text):
    # 查找第一个": "的位置
    colon_index = text.find(": ")
    
    # 如果找到了": "，返回其后的所有内容
    if colon_index != -1:
        return text[colon_index + 2:]
    else:
        # 如果没有找到": "，返回原文本
        return text

# 您提供的文本
input_text = "text: you are bitch. : are you bitch?"

# 处理文本并打印结果
result = extract_content(input_text)
print(result)