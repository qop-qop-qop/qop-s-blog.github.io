栈溢出保护机制

在程序栈上"返回地址"前面,放一个秘密值(canary)
函数返回前会检查这个值有没有被改变

从高位到低位 rip_addr rbp_addr canary_addr 
只要程序不重启,canary值不变,对任何栈帧都是这个值,且canary最低位一个字节的值恒定为0