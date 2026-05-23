# chunk基础

chunk有两个部分组成，头区跟数据区。头区又由**`prev_size`**跟**`size`**组成。

prev_size会在前一个堆块被释放后记录其大小（进入fastbin，tcache除外），主要利用于合并相邻堆块也被用来指示被释放堆的范围。

有时候可以通过伪造p头加上更改p头实现已释放地址拦截。

size则指示当前堆块的大小，包含数据区与头区，在堆块被使用时会加1个字节（这个1实际上是检查二进制的最后一位）表明上一个堆块正在被使用中。

数据区是储存输入数据的区域，再被释放后用于储存fd跟bk。

chunk对头区的检查比较严格，伪造chunk就是伪造头区。



# bins

free之后堆块的去向。大多数堆漏洞都与这个有关。

## Fastbins

在堆块小于一定数值的时候会被放入（64位是0x20 ~ 0x80，32位是0x10 ~ 0x80，**注意这里的值是可以被程序更改的，审查代码的时候要注意**）。

不同大小的堆块会被单链表串联，free之后数据区只会有fd。

取出堆块时采用先入后出的模式，这一个堆块的fd指向下一个要取的堆块。最后一个的fd是0x00。

以单链表的形式连接，对于double free有简单的检查，仅仅检查当前取出的堆块与下一个堆块是否相同。
在large bin触发malloc_conoliadte时会被整合合并相邻的堆块放入unsorted bin中。在glibc2.30+加入了key防护机制。

## Unsorted Bin

一般是大堆块的去向，采用双向链表储存。

会有fd指向下一个堆块，bk指向上一个堆块。free之后会先储存fd之后是bk。

取出chunk时就是unlink操作进行脱链。

unsorted bin不会对大小进行分类，所以被储存在里面的chunk是可以被分割的。并且被储存在unsorted bin里面的堆块还会主动向上或向下合并堆块。

这里还有一点关于libc的，第一个被放入的unsorted bin的会跟libc里面的main_arena相连。所以如果可以打印被释放的堆块信息，可以通过这样泄露libc地址。
## Tcache
tcache在程序运行的时候会被分配到一个结构体，结构体里面储存的有两个数组count，addr。count数组用于去储存每种大小堆块的数量。addr里面储存的则是下一个将要分配的地址。
与fastbin类似以单链连接，但是每一个大小只能储存7个堆块且多线程之间不互通。2.26版本几乎没有防护检查。2.27版本引入key防止double free。2.31加强了对count数组的检查，不会再出现负数溢出的情况。2.32引入safe—Link((pos >> 12)^ptr)以防止tcache poisoning。

## smallbin

管理结构类似于tcache，都是每个大小的堆块分开管理。

但是不一样的是，smallbin里面堆块之间是双链表连接，每个链表之间连接又类似于unsortedbin。

## largebin

largebin是最复杂的，里面有两个链表，一个用来快速查找，所以链表里面串联的是每个大小堆块最后放入的堆块，指针是fd_nextsize,bk_nextsize。

另一个是用来保证堆块完整的，以双链表连接所有堆块，并且对堆块之间进行降序排序。

## Top chunk

这个有点特殊，它会直接合并所有临近的空闲chunk。当然只有在相邻的堆块被释放时才会触发合并，已经被释放过并且放入其他bin的不会触发合并的。

# 基础漏洞

## 堆溢出

是指堆的数据区的输入超过了数据区的大小从而可以覆盖其余堆区的信息。

## UAF漏洞

全称为Use-After-Free。顾名思义就是释放后由于指针未设置NULL，导致可以通过指针使用已经被free的堆块。

由于堆块再free之后会被放入到链表中，可以通过指针对堆块里面的fd，bk进行修改。当再次利用chunk时系统就会自动认为修改过的fd，bk指向下一个未使用的chunk，从而实现任意地址读写。

## unlink操作

unlink漏洞产生主要是因为堆溢出。由于prev_size区是指代上方的chunk是否被释放，所以可以通过堆溢出去更改堆块指示下一个堆块的指示，然后在本堆块进行伪造被释放堆块从而让系统认为有两个相邻的堆块被释放从而触发unlink。

unlink是双联链表脱链的操作，具体就是通过fd，bk直接“左手倒右手”从而更改区域数据。

## double free

主要原因还是跟UAF一样堆块释放后指针未设置NULL。

fastbins对于double free会有一个简单的防护，它会检查被放入的chunk与上一个是否相同，所以需要在两次释放中间再释放一个其他的堆块绕过这个检查。之后的利用跟uaf类似，利用第一次取出的chunk进行伪造fd（这里因为fastbins在释放后是不改头区的，也就是说放在链表里的chunk与使用中的chunk头区是相同的），当两个相同的堆区被取出之后会被识别到fd指向的区域还有一个chunk空闲。再取一次就能取到伪造的chunk地址了。

## fastbins attack

利用堆溢出去修改被放入fastbins里面的堆块的fd，从而实现控制任意内存区域的目的。

## tcache poison
涉及到tcache的基本利用，tcache的fd头被用于储存下一个堆块的数据区。并且tcache在分配的时候不会去查看size头是否合法。所以可以通过double free，uaf或者任意地址写入去更改这个fd以实现对整个tcache的堆块分配链的投毒（也就是控制）。第一版的key防护，只需要去破坏key这个指针就行了。而之后引入随机数也就是2.34+，虽然key从一个固定的数变为了一个随机数，但是整体的检查没有变依旧是历遍整个数组查看是否相等。

## unsortedbin attack

victim（要取出unosrtedbin的堆）fwd（已经控制指针的堆）

```
victim = unsorted_chunks(av)->bk;  // 取出块
bck = victim->bk;                  // 获取目标块的 bk 指针
unsorted_chunks(av)->bk = bck;     // 将链表头指向目标块的 bk
bck->fd = unsorted_chunks(av);     // 将目标块 bk 指向的块的 fd 指针指向链表头
```

伪代码简化。

这里整个伪代码的过程是unsortedbin最后一块取出时发送的fd跟bk指针的变化。

我们知道正常情况下，第一块储存的都是mian_arena的地址。当最后一块取出的时候，glibc尝试将这个指针复原到最初的状态也就是自己指向自己，在低版本下堆管理器(<2.30)会在最后一步去检查这一过程的完整性于是会有一个双指针的查找。这个攻击方式正是利用了这一点。

通过控制bk就能实现向任意地址写入**mian_arena的地址**。

这里还会有一个副作用，当然也是扩大漏洞点的地方，我们写入数据的地方会被作为堆块并入unsortedbin里面。也就是说之后如果我们不能完善这个地方的堆块伪造unsorted就无法再申请出来堆块了。但是如果我们完善了这个伪造堆块就可以在这申请堆块。

## largebin attack

largebin有两个指针，也就是有了两个攻击点。如果能完全控制这两个指针就能实现任意地址写入**堆地址**。

伪代码简化

victim（要插入largebin的堆）fwd（已经控制指针的largebin堆）

```
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;

if (fwd->bk_nextsize != NULL) {
    fwd->bk_nextsize->fd_nextsize = victim;   ////这里控制了bk_nextsize就行
fwd->bk_nextsize = victim;                  

// 同时还会操作 fd/bk 链表
victim->fd = fwd;
victim->bk = fwd->bk;
fwd->bk->fd = victim;			//这里控制了bk就行
fwd->bk = victim;
```

与unsortedbin attack一样，整个利用过程产生的原因还是因为完整性检查。

触发条件是要有一个大于已经控制指针的堆块去插入到这个已控制堆块之前。就会进行两个链表指针的操作。



