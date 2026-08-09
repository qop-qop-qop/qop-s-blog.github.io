# ptrace

ptrace 是 Linux 系统调用，可以让一个进程控制另一个进程。所以gdb本质上就是另起了一个进程用来操纵程序的进程。



```
#include <sys/ptrace.h>

ptrace(PTRACE_TRACEME, 0, 0, 0);      // 请求调试
ptrace(PTRACE_CONT, pid, 0, 0);       // 继续运行
ptrace(PTRACE_PEEKDATA, pid, addr, 0); // 读取内存
```

利用ptrace的这几个语句就可以对一个程序进行暂停读取内存等操纵。

我们所要做的仅仅是依托于这个些ptrace的运行搭建起一个外壳，对这些命令程序的输出进行美化，输入简化。

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("用法: %s <程序>\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(argv[1], argv[1], NULL);
        perror("execl");
        exit(1);
    } else {
        int status;
        wait(&status); 
        printf("子进程已启动，PID = %d\n", pid);
        ptrace(PTRACE_CONT, pid, 0, 0);
        wait(&status);  
        printf("子进程已退出\n");
    }
    return 0;
}
```

类似于这样。

在每一步结束出现设置printf打印提示词跟数据就能完成一次简单的调试。当我们fork一个程序进行调试的时候如果我们不用wait进行等待执行结束，那么整个程序的输入输出逻辑都会崩坏。

```
typedef struct {
    pid_t pid;               
    char *prog_path;        
    char **prog_argv;     
    int state;              
} debugger_t;
```

利用这样的一个结构体就能完整记录调试程序的所有信息。

# 设置断点

1. 读取断点地址的原始指令 (1字节)
2. 保存原始值
3. 写入 0xCC
4. 程序运行到这里会停下

至于为什么：

INT3 指令 (0xCC)

CPU 执行到这条指令会触发 SIGTRAP 信号，程序自动停下。

所以设置断点就是在断点之前写上记号，告诉cpu，这里停一下。

# 单步执行

CPU 有一个TF标志位：

TF = 1：每执行一条指令就触发 SIGTRAP

TF = 0：正常运行

PTRACE_SINGLESTEP 会自动设置 TF。

# 反汇编

使用 Capstone

Capstone 是一个反汇编引擎，可以将机器码转换为汇编指令。

```
#include <capstone/capstone.h>

void disassemble(debugger_t *d, uint64_t addr, int count) {
    // 初始化 Capstone
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    
    // 读取内存
    uint8_t code[256];
    read_memory(d, addr, code, sizeof(code));
    
    // 反汇编
    cs_insn *insn;
    size_t n = cs_disasm(handle, code, sizeof(code), addr, count, &insn);
    
    // 打印结果
    for (size_t i = 0; i < n; i++) {
        printf("0x%lx: %-12s %s\n", 
               insn[i].address,
               insn[i].mnemonic,
               insn[i].op_str);
    }
    
    cs_free(insn, n);
    cs_close(&handle);
}
```

这样搭建出一个外壳就行。

# 符号表

符号表记录了函数名和地址的对应关系。

类似于

```
main         -> 0x555555555149
add          -> 0x555555555130
printf@plt   -> 0x555555555030
```

libelf可以帮我们读取符号表。

```
#include <libelf.h>
#include <gelf.h>

void load_symbols(debugger_t *d) {
    int fd = open(d->prog_path, O_RDONLY);
    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);
        
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            
            for (int i = 0; i < count; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                
                if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
                    char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                    uint64_t addr = sym.st_value;
                    
                    // 保存符号
                    add_symbol(d, name, addr);
                }
            }
        }
    }
    
    elf_end(elf);
    close(fd);
}
```

