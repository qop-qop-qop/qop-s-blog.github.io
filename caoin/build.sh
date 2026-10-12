#!/bin/bash
# caoin 全量构建（WSL aarch64 交叉环境）
set -e
cd "$(dirname "$0")"
CC=${CC:-aarch64-linux-gnu-gcc}
mkdir -p build

$CC -Wall -O2 -static cli/injector.c -o build/caoin_inject
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

# P1 原语回归
$CC -Wall -O2 -static -Ihook hook/tests/test_tramp_rt.c hook/tramp.c hook/reloc.c -o build/test_tramp_rt
$CC -Wall -O2 -static -Ihook hook/tests/test_adrp_rt.c hook/tramp.c hook/reloc.c -o build/test_adrp_rt
echo "build ok"
