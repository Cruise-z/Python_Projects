from aiAPI import *

if __name__ == '__main__':
    # client = Client("./config/config.ini", "kimi")
    client = Client("/home/zrz/.config/Personal_config/config_aiAPI.ini", "kimi")

    messages = ["上述所有文件有涉及到道德和君子品行相关的内容吗"]

    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test.md"], messages, StreamMode=True, cache_tag="upload_files")
    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test0.md"], messages, StreamMode=True)
    common_chat(client, Model.kimi_128k, messages, StreamMode=True, refCache=True)