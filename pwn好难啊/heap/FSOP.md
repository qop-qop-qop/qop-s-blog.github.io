打FSOP的时候一般都是控制IO结构体里面的chain或者干脆去打_IO_list_all，让整条链劫持到已经控制好的地方。

# house of orange之后打FSOP

这里要结合unsortedbinattack，去改IO_list_all为main_arena+88这时候下一个chain指向的位置就是smallbin的0x60。

所以只需要在那个被放入smallbin的堆块中设置好，然后触发unsortedbin的分配，让被布局的堆块进入smallbin中。此时触发刷新流就会历遍整个结构体。

![image-20260710231536328](images\image-20260710231536328.png)

这个大概就是此时FSOP的结构。



