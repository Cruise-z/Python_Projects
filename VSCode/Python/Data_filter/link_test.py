import paramiko
import subprocess
import json
import os
from sshtunnel import SSHTunnelForwarder
from datasets import load_dataset

os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

# 跳板机的配置
jump_host = '47.94.175.96'      # 跳板机的IP或域名
jump_user = 'public_jumphost'            # 跳板机的用户名
#jump_password = 'jump_password'    # 跳板机的密码

# 内网服务器的配置
target_host = '10.26.9.12'  # 内网服务器的IP或域名
target_user = 'zhaorz'          # 内网服务器的用户名
target_password = 'zhaoruizhi2024'  # 内网服务器的密码
remote_path = '/data/fineweb_edu'  # 服务器上的文件路径
local_file_path = './test.txt'  # 下载到本地的路径


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

# 设置SSH客户端使用系统的SSH Agent
ssh_agent = paramiko.Agent()

# 建立到跳板机的SSH隧道
with SSHTunnelForwarder(
    (jump_host, 22),
    ssh_username=jump_user,
    ssh_pkey=ssh_agent.get_keys()[0],  # 使用SSH Agent提供的私钥
    remote_bind_address=(target_host, 22)
) as tunnel:
    # 设置隧道本地端口
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # 连接到内网服务器
    client.connect('127.0.0.1', port=tunnel.local_bind_port, username=target_user, password=target_password)

    # 使用SFTP下载文件
    sftp = client.open_sftp()
    
    for i in range(3582, 5000):
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
            with sftp.file(os.path.join(remote_path, f"{i}.json"), 'w') as remote_file:
                # 将 JSON 数据写入远程文件
                remote_file.write(json_string.encode('utf-8'))
                print(f"Data written to {remote_path}/{i}.json successfully!")
        else:
            print(f"命令执行失败，错误: {result.stderr}")
            with open("./Raw_Data/log.txt", "a") as f:
                f.write(f"{i}.json\n")
    
    # sftp.get(remote_file_path, local_file_path)  # 下载文件
    sftp.close()
    client.close()

# print("文件下载完成")
