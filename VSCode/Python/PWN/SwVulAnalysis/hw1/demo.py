from pwn import *

context.log_level = 'debug'

"""
对于在linux上运行PE格式文件，使用wine这个兼容层系统套件打开并运行:
->在/usr/bin/目录下寻找相关的wine套件即可
"""
p = process(['/usr/bin/deepin-wine8-stable', './CM.exe'])

p.recvuntil(b'Input Key1:')
p.sendline(b'EaSyStEp1')

p.recvuntil(b'Next Key:')
p.sendline(b'RWFTeVN0RXAy')

p.recvuntil(b'Next Key:')
p.sendline(b'#\x126\x1c$\x11#\x11U')

# Receive and print the response
response = p.recvline()
print("response is: " + str(response))

# Close the connection
p.close()
