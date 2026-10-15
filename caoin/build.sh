#!/bin/bash
# caoin 全量构建（WSL aarch64 交叉环境）
set -e
cd "$(dirname "$0")"
CC=${CC:-aarch64-linux-gnu-gcc}
mkdir -p build

$CC -Wall -O2 -static cli/injector.c -o build/caoin_inject
# caoin_prep：KPM 流程自动化准备（远程符号解析 + 影子页/status 页准备 → args）
$CC -Wall -O2 -static cli/prep.c -o build/caoin_prep
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
$CC -Wall -O2 -static tests/target_dummy.c -o build/target_dummy
$CC -Wall -O2 -shared -fPIC -nostdlib agent/agent_dummy.c -o build/agent_dummy.so

# bionic 动态测试目标（用设备 libc.so 链接，导出 hook 目标符号）
$CC -Wall -O2 -nostdlib -pie tests/target_dyn.c -o build/target_dyn \
    -Wl,--dynamic-linker=/system/bin/linker64 \
    -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
    -Lbuild -l:libc_bionic.so

# caoin agent（no-libc，含 P1 hook 原语）
# -fno-builtin：禁 gcc 把手写循环惯用法换成对 libc memcpy/strlen 的调用，
#               保持零 UND（bionic 的 memcpy 是带版本 IFUNC，无版本引用绑定失败）
$CC -Wall -O2 -DCAOIN_NOLIBC -fno-builtin -shared -fPIC -nostdlib \
    -Ihook agent/agent_main.c agent/symsolve.c hook/tramp.c hook/reloc.c \
    -o build/caoin_agent.so

# 内核态注入 payload（固定基址，非 PIC；KPM vm_mmap 到 0x7f00000000 后跳入）
# --build-id=none：objcopy -O binary 无法处理 .note.gnu.build-id 段
$CC -Wall -O2 -nostdlib -static -fno-pic -Wl,--build-id=none -Ttext=0x7f00000000 -e payload_entry     tests/caoin_payload.c -o build/caoin_payload.elf
aarch64-linux-gnu-objcopy -O binary build/caoin_payload.elf build/caoin_payload.bin

# P1 原语回归
$CC -Wall -O2 -static -Ihook hook/tests/test_tramp_rt.c hook/tramp.c hook/reloc.c -o build/test_tramp_rt
$CC -Wall -O2 -static -Ihook hook/tests/test_adrp_rt.c hook/tramp.c hook/reloc.c -o build/test_adrp_rt
echo "build ok"
