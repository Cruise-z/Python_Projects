from aiAPI import *


if __name__ == '__main__':
    # client = Client("./config/config.ini", "kimi")
    client = Client("./config/config.ini", "paid")

    messages = ["你是AI吗，讲个笑话吧"]

    # files_chat(client, Model.kimi_128k, ["./Test_Wheel/test.md"], messages, StreamMode=True)
    common_chat(client, Model.gpt4o, messages, False)