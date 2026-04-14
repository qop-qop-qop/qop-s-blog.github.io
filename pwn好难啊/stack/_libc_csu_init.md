是每个程序开头必备的万能gadget,可以利用里面的gadget实现任意函数传参和函数调用,但是整体笨重,需要溢出空间大才能使用
<__libc_csu_init+64>: 
pop rbx 
pop rbp 
pop r12 
pop r13 
pop r14 
pop r15 
ret

<__libc_csu_init+90>: 
mov rdx, r15 
mov rsi, r14 
mov edi, r13d 
call QWORD PTR [r12+rbx*8]
自己看这阴不阴.

使用教程如下:
1.
- 先 `ret` 到 `csu_front_addr`，通过栈溢出给 `rbx/rbp/r12/r13/r14/r15` 赋值：
    
    - `r13` → 函数第一个参数（rdi）
    - `r14` → 函数第二个参数（rsi）
    - `r15` → 函数第三个参数（rdx）
    - `r12` → 指向目标函数的 GOT 地址（比如 `read@got`）
    - `rbx` 通常设为 0，`rbp` 设为 1（用来控制循环结束）
2.
- 执行完 `csu_front_addr` 后，会 `ret` 到 `csu_end_addr`，自动完成：
    
    asm
    
    ```
    mov rdx, r15
    mov rsi, r14
    mov edi, r13d
    call [r12]
    ```
    
- 这样就实现了一次**完整的函数调用**，和直接用 `pop rdi; ret` 效果一样。

在pwntool里可以i用elf.sym['_libc_scu_init'] + offset
偏移自己去gdb里看


有点坑,注意的是scu里的是call [ addr] 而不是
call addr ,这意味着r12寄存器只能传送含指针的地址,也就是
1.got地址
2.某个内存地址(里面存了函数指针)