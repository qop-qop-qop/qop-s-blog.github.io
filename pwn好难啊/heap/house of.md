## house of Einherjar
unlink的变种，与传统unlink利用fd跟bk不一样的是，这的利用前提需要的是有程序地址与堆地址。
总的来说是需要有一个中间伪造的堆块使我们所要覆盖的地区并入topchunk，如此再次malloc的时候就取出我们想要的区域。
https://www.yuque.com/xiaocangxu/pwn/cqti34yragmulemp  ，具体看这个。

## house of force

与上面的house of Einherja类似，都是利用top chunk进行合并之后申请。不一样的是house of Einherjar是利用我们已经控制的堆块p头与in_use位去间接使top chunk指向我们所要申请的地址。这个则是直接去更改top chunk的大小而后申请。house of Einherjar可以利用off-by-unll完成。但是house of
force必须能控制topchunk的size段。

## house of spirit

利用的是free不会去验证释放地址是否是堆区（其实好像也验证）去释放非堆区（前提是要在特定的地方伪造头区），之后就可以再次申请获得地址权限。
当然所需漏洞面也比较大，正常情况来说很难利用此法完成攻击，所以要多考虑与其他手法结合。首先你要有所需的地址（pie防护的普及使我们必须先完成泄漏）之后你要能控制free的变量这个倒是还好。之后的堆溢出有时候确实很少有这么大字节的溢出。

## house of lore


## house of strom

条件比较苛刻，但是功能却是非常强大的。

主要是利用unsortedbin attack跟largebin attack的任意地址写入进行堆块伪造。

我们知道，largebin attack是可以进行任意地址写入，控制好写入地址就能让最高位的那个字节进行伪造size段。当然这里可能会失败，因为堆块的最高字节是随机的，如果最高位的二进制最后一位不是1，就会失败。

所以这个house of就是利用unsorted的一次main_arena地址的写入于副作用，写入地址并入unsortedbin链表与largebin的两次地址写入进行伪造放入unsortedbin的地址。

