from aiAPI import *

if __name__ == '__main__':
    # client = Client("./config/config.ini", "kimi")
    client = Client("/home/zrz/.config/Personal_config/config_aiAPI.ini", "kimi")

    messages = ["请介绍该文件内容"]

    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test.md"], messages, StreamMode=True, cache_tag="upload_files")
    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test0.md"], messages, StreamMode=True)
    common_chat(client, Model.kimi_128k, messages, StreamMode=True, cache_tag="upload_files")