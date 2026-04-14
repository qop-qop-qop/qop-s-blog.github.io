- vmmap
列出所有内存段,一眼看到.bss段(未初始化数据段)

- disass main
反汇编main函数

- x/s 地址
查看该地址的字符串

- x/i 地址
看该地址的汇编指令

- x/20gx 地址
查看该地址或寄存器的前20*8字节的值(用16进制表示)

- b \*0x401170
在指定地点下断点

- info breakpoints
查看所有断点

- del 断点号
删除断点

- info registers
查看所有寄存器

- i r
查看寄存器指令的简写

- i r rax
只看rax

- stack
直接看栈

- bt 
查看函数调用栈 backtrace

- frame
栈帧号

- search "/bin/sh"
搜索字符串

- x/wx 地址
以4字节十六进制查看该地址的值

- info functions
查看所有函数

- info variables
查看全局变量

- p 变量名
打印变量

- p &变量名
打印变量地址

- info proc mapping
输出的第一个地址就是程序的基址(不是libc的基址)