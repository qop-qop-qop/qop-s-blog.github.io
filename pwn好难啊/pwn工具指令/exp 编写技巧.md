- 获取elf文件中某个已知函数名的函数地址
elf = ELF("./test")  %% 程序路径 %%
system_addr = elf.symbols["system"]

- 获取elf文件中字符串地址
elf = ELF("./test") %%程序路径%%
bin_sh_addr = next(elf.search(b'/bin/sh'))
main_addr = elf.entry%%直接拿程序入口地址%%

- 获取程序的输出信息,并且将其转化为16进制数据(获取函数的真实地址)
1.直接获取一行的输出内容 :
io.recvuntil(b'But there is gift for you :\n') %%屏幕输出信息%%
addr = int(io.recvuntil(b'\n',drop=b'\n'),16)%%接受直到\n为止的输出内容,并将其转化为十六进制%%

- 附加gdb调试
gdb.attach(io)
pause() %%暂停执行后续的exp代码,按任意减继续,便于调试%%

- 链接程序和端口
1.
io = process("本地文件路径")
2.
io = remote("ip 地址" , 端口)
3.
io.close() %%关闭连接%%

- 发送payload
1.
io.sendafter(some_string,payload)
%%接受到some_string后,发送payload%%
2.
io.sendlineafter(some_string,payload)
%%接受到some_string后,发送payload,并进行换行(末尾\n)%%
3.
io.send(payload)
%%发送payload%%
4.
io.sendline(payload)
%%发送payload,并进行换行(末尾\n)%%

- 接受返回内容
1.
io.recv(N)
%%接受N个字符%%
2.
io.recvline()
%%直接接受一整行的输出%%
3.
io.recvlines(N)
%%接受N行的输出%%
4.
io.recvuntil(some_string)
%%接受到some_string为止%%
5.
io.recvuntil("\n",drop=True)
%%接收到\n为止,并且丢弃\n%%
6.
int(io.recv(10),16)
%%接受返回的内容,长度是10,把它转换成十六进制数值%%
7.
int(io.recv()[2:14],16)
%%接受返回的内容的第2 - 14为(从0开始),并将其转换为十六进制数值%%

- ELF文件操作
首先需要elf = ELF("本地文件路径")创建一个对象

elf.sysmbols["function"] %%找到function的地址%%
elf.got["function"]%%找到function的got%%
elf.plt["function"]%%找到function的plt%%
next(elf.search(b'some_characters'))%%找到包含some_characters的内容,可以是字符串,汇编代码或某个数值的地址%%
elf.bss()%%找到bss段的起始地址%%

ldd ./程序名
查看程序使用的libc路径(查看本地程序)



- 
context.bits = 64
确定程序位数

context.arch = 'amd64'
确定程序架构

context.log_level = 'debug'
调式时打开,能看到发送和接收的数据

u64(io.recv().ljust(8,b"\x00"))
把截获的地址补齐并且解码

libc = ELF('/libc路径')
binsh_addr = libc_base + libc.search(b'/bin/sh')
计算/bin/sh地址

io.clean()
在interactive之前执行这个指令可以清空管道缓存

payload = p64(backdoor) # 【最前面放后门！】 payload = payload.ljust(48, b'A') # 填满到48字节 payload += p64(buf_addr - 8)[:7] # 改7字节RBP

val = 1234
result = str(val).encode()