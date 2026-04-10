在一个数组上模拟栈指令pop，push的程序。难点有两个，一个是返回地址的位置，另一个就是数据格式的转换。

利用buf的第一位去充当esp。

pop函数：

```
int __cdecl stack_pop(_DWORD *buf)
{
  return buf[(*buf)--];
}
```

push函数：

```
int __cdecl stack_push(_DWORD *buf, int a2)
{
  int result; // eax

  result = (*buf)++;
  buf[result + 1] = a2;
  return result;
}
```

pop函数跟push函数都是利用buf的第一位去寻址。但是又没有任何检查，也就是说我们pop之后buf第一位会执行减去1的指令。之后再push就可以更改第一位实现栈上任意地址写入跟泄露了。这样主要的漏洞就出来了。

![](images\inndy1.png)

程序防护几乎全开。

gdb看一下我们可以从栈上获得什么信息。

![image-20260410185923174](images\inndy2.png)

栈上信息很丰富，但是我们所需要的是libc基址，所以需要泄露的位置是ebp+4。对应的buf下标就是0x59。之后利用程序的clear、函数将buf首位复原为0。

有了libc基址就需要我们去覆盖返回地址。push刚好可以用来覆盖。

![](F:\github\qop-s-blog.github.io\wp\stack\ret2libc\inndy_stack\images\inndy3.png)

但是通过找libc找到的地址输入后却是0x7fffffff。这个地方是卡了我不少时间。直到我回头去翻看输入逻辑，这里push压进去的不是字符串而是整型。

![](F:\github\qop-s-blog.github.io\wp\stack\ret2libc\inndy_stack\images\inndy4.png)

计算发现libc地址在转换为整型的时候是负数如果直接输入的话就超出了int型的范围，所以要进行转换，之后再利用无符号整型对负数的转换变回来。具体就是pop打印出来的负数去除符号然后利用& 0xFFFFFFFF进行转换为超大数（与取出的负数十六进制相同）。在此基础上进行计算。然后由于计算得到的数还是太大，于是需要反向转换为负数（与计算出地址十六进制相同）进行覆盖返回地址。

之后也就是最后一个难点，不知道看到这有没有注意到前面我覆盖的地址不是ebp+4，ebp之后存在两个相同的返回地址。我们在程序返回之前下个断点利用gdb去看一下栈顶。

![](F:\github\qop-s-blog.github.io\wp\stack\ret2libc\inndy_stack\images\inndy5.png)

由此可以看出程序的返回地址在0xffe69e7c，这刚好就是第二个返回地址的位置也就是ebp+0x14。但是为什么会这样呢。

让我们去main函数的汇编看看。

![](F:\github\qop-s-blog.github.io\wp\stack\ret2libc\inndy_stack\images\inndy6.png)

main函数在开始的时候没有像正常一样去执行

```
push    ebp
mov     ebp, esp
```

反而执行了一些保存旧寄存器内容的指令。虽然不知道有什么用。但是这也告诉我们ebp+4不一定就是返回地址，有时返回地址的位置还需要我们自己去调试寻找。