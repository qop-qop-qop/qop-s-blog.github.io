## house of Einherjar
unlink的变种，与传统unlink利用fd跟bk不一样的是，这的利用前提需要的是有程序地址与堆地址。
总的来说是需要有一个中间伪造的堆块使我们所要覆盖的地区并入topchunk，如此再次malloc的时候就取出我们想要的区域。
https://www.yuque.com/xiaocangxu/pwn/cqti34yragmulemp  ，具体看这个。



## house of strom

条件比较苛刻，但是功能却是非常强大的。

主要是利用unsortedbin attack跟largebin attack的任意地址写入进行堆块伪造。

我们知道，largebin attack是可以进行任意地址写入，控制好写入地址就能让最高位的那个字节进行伪造size段。当然这里可能会失败，因为堆块的最高字节是随机的，如果最高位的二进制最后一位不是1，就会失败。

所以这个house of就是利用unsorted的一次main_arena地址的写入于副作用，写入地址并入unsortedbin链表与largebin的两次地址写入进行伪造放入unsortedbin的地址。

