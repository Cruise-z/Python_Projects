from aiAPI import *


if __name__ == '__main__':
    # client = Client("./config/config.ini", "kimi")
    client = Client("/home/zrz/.config/Personal_config/config_aiAPI.ini", "paid")

    messages = ["你是弱智吧吧主吗？", "mirror中有几个r?", "请你回复上述所有问题"]

    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test.md"], messages, StreamMode=True)
    common_chat(client, Model.gpt4, messages, StreamMode=True)