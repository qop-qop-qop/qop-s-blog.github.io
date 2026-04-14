- ROPgadget --binary 程序名
搜索所有gadget

- ROPgadget --bianry 程序名 | grep "pop"
搜索所有pop指令

- ROPgadget --binary 程序名 | grep "pop rdi"
搜索特定gadget

- ROPgadget --binary 程序名 | grep "syscall"
搜索系统调用(64位: syscall)

- ROPgadget --binary 程序名 | grep "ret"
搜索ret来栈对齐

- ROPgadget --binary 程序名 | grep -E "pop rdi | pop rsi | pop rdx | syscall | ret"
一次性查找所有ROP必备gadget

- ROPgadget --binary 程序名 --string "/bin/sh"

- ROPgadget --binary ./程序名 | grep "int 0x80"
- ROPgadget --bianry ./libc路径 | grep "int 0x80"
ROP会列出所有int 0x80的地址(32位程序)

- ROPgadget --binary 程序名 | grep syscall
- ROPgadget --bianry libc路径 | grep syscall

- ROPgadget --binary libc路径或者文件名 --string "/bin/sh"
查程序或者libc里/bin/sh的地址