from colorama import init, Fore, Back, Style
import ijson
import os

init(autoreset=True)  # 初始化colorama，并设置autoreset=True使每条打印信息后自动重置样式

def process_large_json(file_path):
    # 打开JSON文件
    with open(file_path, 'rb') as file:
        # 创建一个ijson解析器对象，使用YAJL2后端（如果已安装）
        parser = ijson.parse(file)

        for prefix, event, value in parser:
            if prefix.endswith('.text'):  # 根据需要调整路径
                print('Text:', value)
            elif prefix.endswith('.label'):  # 根据需要调整路径
                print(Fore.BLUE + Back.YELLOW + Style.BRIGHT + f"Label:{value}")

work_dir = './FT_Data/Raw_Data/nCS'

# 调用函数处理文件
process_large_json(os.path.join(work_dir, "nCS.json"))
