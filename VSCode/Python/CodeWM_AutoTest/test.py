import json

def read_file_and_create_json(file_path):
    """
    读取整个文件内容，将其作为一个字符串并存入 JSON 列表
    """
    try:
        # 打开文件并读取全部内容
        with open(file_path, 'r') as file:
            file_content = file.read()  # 读取文件所有内容

        # 创建包含文件内容的 JSON 列表
        json_list = [file_content]

        # 将 JSON 列表打印到控制台
        print(json.dumps(json_list, indent=4))
    
    except FileNotFoundError:
        print(f"文件 {file_path} 未找到，请检查路径是否正确。")
    except Exception as e:
        print(f"读取文件时发生错误: {e}")


# 示例使用
if __name__ == "__main__":
    file_path = '/home/zrz/Projects/GitRepo/Repo/Python_Projects/VSCode/Python/CodeWM_AutoTest/results/stdDemo/Calculator/Calculator.java'  # 替换为你文件的路径
    read_file_and_create_json(file_path)
