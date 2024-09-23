import subprocess
import json
import os

os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

work_dir = './gen_FT_Data/s1_Raw_Data/nCS'
path = '/fineweb_edu'  # 下载文件位置

# 分块下载数据
# 定义 curl 命令的 URL
offset = 0  # 替换为你想要的初始偏移量
length = 100  # 替换为你想要的偏移步长

def get_curl_command(offset, length):
    return [
        "curl",
        "-X", "GET",
        f"https://datasets-server.huggingface.co/rows?dataset=HuggingFaceFW%2Ffineweb-edu&config=default&split=train&offset={offset}&length={length}"
    ]

for i in range(2724, 2725):
    offset = i*100
    # 执行命令并捕获输出
    curl_command = get_curl_command(offset, length)
    result = subprocess.run(curl_command, capture_output=True, text=True)
    # 检查命令是否执行成功
    if result.returncode == 0:
        # 将返回的 JSON 数据存储到变量 data 中
        json_data = json.loads(result.stdout)  # 将输出解析为JSON
        json_string = json.dumps(json_data)
        # 通过 SFTP 打开远程文件进行写入
        with open(os.path.join(work_dir+path, f"{i}.json"), 'w') as file:
            # 将 JSON 数据写入远程文件
            file.write(json_string)
            print(f"Data written to {path}/{i}.json successfully!")
    else:
        print(f"命令执行失败，错误: {result.stderr}")
        with open(os.path.join(work_dir, "log.txt"), "a") as f:
            f.write(f"{i}.json\n")