readelf -s libc.so库的路径 | grep system
查看libc库中的sysem在libc中的偏移

readelf -s 文件名 
查看所有函数
全局变量
函数偏移

readelf -s 文件名
查看所有段:
.text 代码段
.data 数据段
.bss 全局变量
.rodata 字符串

readelf -r 文件名
查看got表

