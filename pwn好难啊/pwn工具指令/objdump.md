%%这是linux下的反汇编工具,同时也是一个非常强大的二进制文件分析工具,其实可以用IDA替代%%

objdump -M intel -d 文件名
反汇编应用程序

objdump -f 文件名
显示文件的头信息

objdump -h 文件名
显示文件的段信息

objdump -t 文件名
显示文件的符号表

objdump -s 文件名
显示指定section的完整内容,默认所有的非空section都会被显示

objdump -R ./程序名
查看函数GOT表

objdump -R ./程序名 | grep print
查看print函数的GOT表

objdump -d ./程序名 | grep -E "win|shell|backdoor|system"
查看程序里有没有后门函数

objdump -d ./程序名 | grep -E "int.*0x80|cd 80"
查找程序本身的系统调用号地址(32位程序)

objdump -d libc路径 | grep -E "int.*0x80|cd 80"
查找libc库中的系统调用号(32为)

objdump -d 程序名 | grep -E "syscall|0f 05"
64查系统调用号

objdump -d libc路径 | grep syscall

