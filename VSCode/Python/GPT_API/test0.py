from gptAPI import *
import os
import random

if __name__ == '__main__':
    client = Client("./config.ini", "kimi")
    messages = ["M1和Kimi有什么区别？"]
    chat_stream(client, Model.kimi_8k, messages)