obj-m += shadow_v1.o shadow_v2b.o
KDIR ?= /root/kernel/src

all:
	make -C $(KDIR) M=$(CURDIR) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules
