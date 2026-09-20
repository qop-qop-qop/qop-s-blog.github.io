# 1创建磁盘镜像

**创建虚拟机[磁盘镜像](https://zhida.zhihu.com/search?content_id=256857057&content_type=Article&match_order=1&q=磁盘镜像&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3OTAwNTE0NTAsInEiOiLno4Hnm5jplZzlg48iLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyNTY4NTcwNTcsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6MSwiemRfdG9rZW4iOm51bGx9.xJ3qajbS-gODNeMUkwlQZ0mpTL5FEUkPkPDI3CpgNvA&zhida_source=entity)**：在使用 Qemu 创建虚拟机之前，需要先创建一个虚拟磁盘镜像，用于存储虚拟机的操作系统和数据 。可以使用qemu-img工具来创建磁盘镜像 。例如，要创建一个大小为 20GB，格式为 qcow2 的磁盘镜像文件 “myvm.qcow2”，可以在命令行中输入以下命令：

```
qemu-img create -f qcow2 myvm.qcow2 20G
```

其中，-f参数指定磁盘镜像的格式，qcow2是一种常用的磁盘镜像格式，具有写时复制等特性，可以有效节省磁盘空间 。myvm.qcow2是磁盘镜像文件的名称，20G表示磁盘镜像的大小为 20GB 。

# 启动虚拟机

创建好磁盘镜像后，就可以使用qemu-system-x86_64命令来启动虚拟机 。假设要启动刚才创建的虚拟机，并指定内存大小为 2GB，使用 Windows 10 的 ISO 镜像文件进行安装，可以使用以下命令：

```
qemu-system-x86_64 -m 2048 -cdrom /path/to/windows10.iso -drive file=myvm.qcow2,format=qcow2
```

其中，-m参数指定虚拟机的内存大小，单位为 MB，这里设置为 2048MB，即 2GB 。-cdrom参数指定用于安装操作系统的 ISO [镜像文件](https://zhida.zhihu.com/search?content_id=256857057&content_type=Article&match_order=5&q=镜像文件&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3OTAwNTE0NTAsInEiOiLplZzlg4_mlofku7YiLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyNTY4NTcwNTcsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6NSwiemRfdG9rZW4iOm51bGx9.3TeiX6B2DvH_xhaXmFLw7P26DTcTmJQTyfVQVryAizc&zhida_source=entity)的路径，/path/to/windows10.iso需要替换为实际的 Windows 10 ISO 镜像文件的路径 。-drive参数用于指定虚拟机的磁盘驱动器，file=myvm.qcow2指定使用前面创建的磁盘镜像文件，format=qcow2指定磁盘镜像的格式为 qcow2 。执行该命令后，会弹出一个窗口，显示虚拟机的启动界面，用户可以按照提示进行操作系统的安装 。

# 2.1系统架构解读

Qemu 的系统架构可以分为用户态和内核态两大部分，这种分层设计使得 Qemu 能够高效地实现硬件模拟和虚拟化功能，各部分组件相互协作，共同为虚拟机提供完整的运行环境。

在用户态，Qemu 包含了丰富的组件。用户接口是用户与 Qemu 交互的桥梁，用户可以通过命令行、图形界面或者 API 等方式，向 Qemu 发送各种指令，如创建虚拟机、启动虚拟机、配置虚拟机参数等 。设备模型是用户态的重要组成部分，它负责模拟各种硬件设备的行为。Qemu 通过设备模型模拟出虚拟的 CPU、内存、硬盘、网卡、显卡等设备，使得虚拟机中的操作系统能够像在真实硬件上一样访问这些设备。以虚拟网卡为例，设备模型会模拟网卡的接收和发送数据的功能，当虚拟机中的操作系统发送网络数据包时，设备模型会将这些数据包进行处理，并通过宿主机的网络接口发送出去；反之，当宿主机接收到网络数据包时，设备模型会将其转发给虚拟机中的操作系统。

虚拟[设备驱动程序](https://zhida.zhihu.com/search?content_id=256857057&content_type=Article&match_order=1&q=设备驱动程序&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3OTAwNTE0NTAsInEiOiLorr7lpIfpqbHliqjnqIvluo8iLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyNTY4NTcwNTcsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6MSwiemRfdG9rZW4iOm51bGx9.33ANJkJHw31ZttJrL6qRjz1L_BB7pJTOR5YRayUTA-E&zhida_source=entity)也是用户态的关键组件之一，它为虚拟机中的操作系统提供了访问虚拟设备的接口。这些驱动程序模拟了真实设备驱动程序的功能，使得操作系统能够正常识别和使用虚拟设备。例如，虚拟显卡的驱动程序会模拟真实显卡的功能，将虚拟机中的图形数据进行处理和渲染，然后通过宿主机的显示设备展示出来。

在内核态，Qemu 主要包含虚拟机监控程序（VMM）和虚拟机管理器（VM Manager） 。VMM 是 Qemu 的核心组件之一，它负责管理虚拟机的运行状态，监控虚拟机的指令执行，实现[硬件虚拟化](https://zhida.zhihu.com/search?content_id=256857057&content_type=Article&match_order=1&q=硬件虚拟化&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3OTAwNTE0NTAsInEiOiLnoazku7bomZrmi5_ljJYiLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyNTY4NTcwNTcsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6MSwiemRfdG9rZW4iOm51bGx9.1eqin1Ik5VunyfO1GGlOi5eyAKGvLk4x5ze1-tLtrjs&zhida_source=entity)的核心功能。VMM 通过与宿主机内核的交互，实现对 CPU、内存等硬件资源的[虚拟化管理](https://zhida.zhihu.com/search?content_id=256857057&content_type=Article&match_order=1&q=虚拟化管理&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3OTAwNTE0NTAsInEiOiLomZrmi5_ljJbnrqHnkIYiLCJ6aGlkYV9zb3VyY2UiOiJlbnRpdHkiLCJjb250ZW50X2lkIjoyNTY4NTcwNTcsImNvbnRlbnRfdHlwZSI6IkFydGljbGUiLCJtYXRjaF9vcmRlciI6MSwiemRfdG9rZW4iOm51bGx9.s9zBbtcbs-SAhrtZBPZ4kp2iVeyXUiZc3LFcBQ0UVW8&zhida_source=entity)。例如，在处理 CPU 虚拟化时，VMM 会负责模拟目标架构的指令集、寄存器等关键组件，使得虚拟机能够运行不同架构的操作系统。当虚拟机执行指令时，VMM 会捕获这些指令，并根据需要进行处理和转换，然后将其发送给宿主机 CPU 执行。

VM Manager 则主要负责虚拟机的创建、管理和调度。它根据用户的请求，创建新的虚拟机，并为其分配必要的资源，如内存、CPU 时间片等 。同时，VM Manager 还负责监控虚拟机的运行状态，在多个虚拟机之间进行资源调度，确保每个虚拟机都能够获得合理的资源分配，从而保证整个系统的性能和稳定性。当一个虚拟机需要更多的 CPU 时间片时，VM Manager 会根据预设的调度策略，调整各个虚拟机的 CPU 分配，使得系统资源得到合理利用。

用户态和内核态的组件之间通过特定的接口进行交互，以实现高效的协作。例如，用户态的设备模型通过与内核态的 VMM 进行交互，将虚拟机对硬件设备的访问请求传递给 VMM，VMM 再根据请求进行相应的处理，并将结果返回给设备模型，设备模型最后将结果返回给虚拟机中的操作系统 。这种交互机制确保了虚拟机能够在 Qemu 提供的模拟环境中正常运行，同时也保证了系统的性能和稳定性。

# 挂载固件文件系统

路由器环境已经备好，将binwalk提取出的固件文件系统，使用scp命令将文件系统传入qemu虚拟机。

```
scp -r ./squashfs-root root@192.168.153.2:/root/
```

```
然后挂载文件系统
命令：
mount -o bind /dev ./squashfs-root/dev/
mount -t proc /proc/ ./squashfs-root/proc/
chroot squashfs-root /bin/sh
```

# 开启服务

在qemu虚拟机中重现http服务，在/bin下开启upnp和mic服务，因为开启之后qemu虚拟机网络会改变，因此需要ssh远程开启服务

```
ssh root@192.168.153.2
chroot squashfs-root /bin/sh
./bin/upnp
./bin/mic
```

然后在以上qemu虚拟机中重新设置网络

```
ifconfig eth0 192.168.153.2/24 up
ifconfig br0 192.168.153.11/24 up
```

以上是我摘抄自：[IOT漏洞挖掘 | 路由器固件仿真配置(二) - IOTsec-Zone](https://www.iotsec-zone.com/article/364)

的段落。

下面讲一下自己的理解

ai在这种命令的使用上的优势远高于我们，但是我们还是要学，至少要有能力看懂它在干什么。不一定要能跟得上ai的思路去搭建一个完整的iot设备