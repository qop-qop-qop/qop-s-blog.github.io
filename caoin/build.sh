#!/bin/bash
# caoin 用户态/测试目标全量构建（WSL aarch64 交叉环境）
set -e
cd "$(dirname "$0")"
CC=${CC:-aarch64-linux-gnu-gcc}
OBJCOPY=${OBJCOPY:-aarch64-linux-gnu-objcopy}
mkdir -p build

# 统一 CLI（纯 shell，安装/发布时与 caoin_prep 同目录）
install -m 755 cli/caoin build/caoin

# caoin_prep：KPM 流程自动化准备（远程符号解析 + 影子页/status 页准备 → args）
$CC -Wall -O2 -static cli/prep.c -o build/caoin_prep
# kpmctl：KPM ctl0 supercall 客户端（dump/read/capinfo/status + poke/cow）
# -nostdlib：本机 4.9 内核对 filesz=0 的 .bss PT_LOAD 会启动即 segfault，
# 源码里零未初始化静态存储（dump 缓冲运行时 mmap），必须保持
$CC -Wall -O2 -nostdlib -static -fno-pic cli/kpmctl.c -o build/kpmctl
# shtarget：caoin_prep 测试目标（动态链接 bionic，符号进 .dynsym 供远程解析）
$CC -Wall -O2 -nostdlib -pie tests/shtarget.c -o build/shtarget \
    -Wl,--dynamic-linker=/system/bin/linker64 \
    -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
    -Lbuild -l:libc_bionic.so
# shellwatch：ll 壳双层检测模拟样本（CRC 自检 + maps 扫描 + TracerPid）
$CC -Wall -O2 -nostdlib -pie tests/shellwatch.c -o build/shellwatch \
    -Wl,--dynamic-linker=/system/bin/linker64 \
    -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
    -Lbuild -l:libc_bionic.so
# selfread：实验 A 目标（自指数据读 → 验证独占页约束的真实边界）
# -fno-toplevel-reorder 是硬要求：-O2 默认开 -ftoplevel-reorder，会把顶层 asm 的
# 三个 .fill 全挪到函数之前（实测函数被挤到 section offset 0x1000），导致函数所在页
# 紧邻 .rodata（out_str 的字符串常量），受管页混进被读数据 → 污染"自指读"这个自变量。
$CC -Wall -O2 -fno-toplevel-reorder -nostdlib -pie tests/selfread.c -o build/selfread \
    -Wl,--dynamic-linker=/system/bin/linker64 \
    -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
    -Lbuild -l:libc_bionic.so
$CC -Wall -O2 -static tests/target_dummy.c -o build/target_dummy

# bionic 动态测试目标（用设备 libc.so 链接，导出 hook 目标符号）
$CC -Wall -O2 -nostdlib -pie tests/target_dyn.c -o build/target_dyn \
    -Wl,--dynamic-linker=/system/bin/linker64 \
    -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
    -Lbuild -l:libc_bionic.so

# 内核态注入 payload（固定基址，非 PIC；KPM vm_mmap 到 0x7f00000000 后跳入）
# --build-id=none：objcopy -O binary 无法处理 .note.gnu.build-id 段
$CC -Wall -O2 -nostdlib -static -fno-pic -Wl,--build-id=none -Ttext=0x7f00000000 -e payload_entry     tests/caoin_payload.c -o build/caoin_payload.elf
$OBJCOPY -O binary build/caoin_payload.elf build/caoin_payload.bin

# P1 原语回归
$CC -Wall -O2 -static -Ihook hook/tests/test_tramp_rt.c hook/tramp.c hook/reloc.c -o build/test_tramp_rt
$CC -Wall -O2 -static -Ihook hook/tests/test_adrp_rt.c hook/tramp.c hook/reloc.c -o build/test_adrp_rt
$CC -Wall -O2 -static -Ihook hook/tests/test_reloc_classify.c hook/tramp.c hook/reloc.c -o build/test_reloc_classify
echo "build ok"
