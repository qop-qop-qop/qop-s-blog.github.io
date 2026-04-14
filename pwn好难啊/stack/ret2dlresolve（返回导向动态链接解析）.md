程序调用 printf
    ↓
printf@plt:
    jmp *printf@got   -----> 第一次：got 指向下一行（push 0）；后续：直接跳转 printf 真实地址
    push 0           <---- 重定位表索引（0）
    jmp _dl_runtime_resolve
            ↓
   动态链接器使用索引 0 在 .rela.plt 中取出条目
            ↓
   从条目中得到符号索引，去 .dynsym 找符号
            ↓
   从符号中得到字符串表偏移，在 .dynstr 中找到 "printf"
            ↓
   在 libc.so 中查找 "printf" 地址，填入 printf@got
            ↓
   跳转到 printf 真实地址



重定位表项(.rel.plt)      ---8字节
- 高四字节是got表地址
- 第四字节        符号索引(高24位)   + 类型(低8位)

重定位表项、动态符号表、动态字符串表(链接过程需要的表项),这些表项都是只读的

- 伪造重定位表(..rel.plt)       告诉链接器:找第N个符号
- 伪造符号表(.dynsym)        告诉链接器:第N个符号的名字在字符串表的第M位
- 伪造字符串表(dynstr)        写system\x00
_dl_runtime_resolve想要的栈布局     (32位程序)
返回地址  (,如果直接system(/bin/sh)的话,返回地址没用,随便填)
参数1:      /bin/sh的地址
参数2:      伪造的重定位索引表索引
然后栈后面跟着我们伪造的数据
伪造的重定位表项
伪造的符号表项
"system"
"/bin/sh"


首先是索引值要计算好,让索引出来的地址指向我们伪造的地址

写不清楚,讲不清楚,自己看脚本去吧

32位:
dlresolve = Ret2dlresolvePayload(
elf,
symbol = "system",
args = [ "/bin/sh" ]
)
payload = b'a'*offset
payload += p32(elf.plt['resolve'])
paylaod +=  return_addr
paylaod += p32(dlresolve.reloc_arg)
paylaod += dlresolve.payload



64位程序:
用命令找：ROPgadget --binary vuln64 --only "setcontext" 
setcontext = 0x401219 + 53
dlresolve = Ret2dlresolvePayload
(
elf, symbol="system", # 要调用的函数 
args=["/bin/sh"] # 参数 
)
payload = b'a'*offset
payload += p64(setcontext)
payload += dlresolve.payload










====================== 神秘 ======================================
## 一.预备知识:动态链接器如何解析函数地址(延迟绑定)
由32位PLT桩代码为例:
dl_runtime_resolve需要两个参数
1.link_map  
由链接器初始化,是一个大结构里面存着:
- dynsym
- synstr
- .rel.plt
- lib基地址
- 所有加载的库信息
- ...所有动态链接需要的信息
2.reloc_index
由push指令压入栈

_dl_runtime_resolve执行过程:
- 用reloc_index定位.rel.plt表中的条目: rel = .rel.plt + reloc_index * sizeof(Elf32_Rel)
- 从rel中取出r_info,高24位是符号索引sym_indx,低8位是重定位类型(R_386_JMP_SLOT)
- 用sym_idx定位.dynsym表中的符号条目:sym = .dynsym + sym_idx * siezof(Elf32_Sym)
- 从sym中取出st_name(字符串偏移),在.dynstr中找到符号名字符串
- 在已加载的共享库(如libc)中查找该符号,获得真实地址
- 把该地址写入rea -> r_offset指向的GOT槽
- 跳转到该地址(即执行目标函数)

## 二.攻击思路: 伪造整个解析路径

虽然无法修改只读的.rel.plt     ,      .dynsym     ,      .dynstr      ,但可以控制   reloc_index   使其指向伪造
的,位于可写内存(如  .bss段)  中的伪造表项.   动态链接器不会检查  reloc_index  是否超出原表范围,  只要
计算出的地址  rel   落在刻度内存即可

因此  ,  需求如下 :

1.在可写内存中布置一个伪造的  Elf32_Rel   条目
2.紧跟着  (或者通过偏移)  不知一个伪造的   Elf32_Sym 条目
3.布置一个伪造的字符串   (如"system")  在可写内存中
4.控制  reloc_index的值 , 使得rel = .rel.plt + reloc_index * 8 恰好等于伪造Elf32_Rel 的地址.
5.同时 , 伪造Elf32_Rel 中的 r_info 指向伪造的Elf32_Sym (通过符号索引) , 而伪造Elf32_Sym中
的 st_name指向伪造的字符串.
6.在栈上提前布置好system函数所需的参数(如  "/bin/sh"  字符串地址)
7.触发动态链接器解析 (通常通过调用一个PLT桩,也就是触发  _ l d _ r u n t i m e _ r e s o l v e)