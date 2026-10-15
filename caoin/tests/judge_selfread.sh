#!/bin/sh
# judge_selfread.sh — 判读实验 A（tests/selfread.c）的输出
#
# 用法:
#   tests/judge_selfread.sh <target.log> <dmesg.log>
#
# 采集（两阶段，见 tests/selfread.c 头部注释）:
#   终端 A:  adb shell "su -c '/data/local/tmp/selfread'" | tee target.log
#   终端 B:  挂 hook 之后再采 dmesg（caoin 的 flt 日志总量上限 100 条，
#            所以必须在 load 之前 dmesg -c 清一次，窗口才干净）:
#              adb shell "su -c 'dmesg'" > dmesg.log
#
# 判据（对应 tests/selfread.c 头部）:
#   活锁   = C3 打 start 无 done，且 dmesg 里 pc 与 far 同落受管页、ec 在 20/24 交替
#   EL1 线 = DUMP 行（只出现在"状态机未接管"的 fault，活锁的 fault 走不到那里）
#   桩失效 = C3 继续 done，但 hooked 不再是 777
#   读隐藏破 = C1 出现 match=0

T="$1"
D="$2"

if [ -z "$T" ] || [ -z "$D" ]; then
    echo "用法: $0 <target.log> <dmesg.log>"
    exit 2
fi
[ -f "$T" ] || { echo "找不到 target.log: $T"; exit 2; }
[ -f "$D" ] || { echo "找不到 dmesg.log: $D"; exit 2; }

INVALID=0
L1=$(head -1 "$T")
MP=$(echo "$L1" | sed -n 's/.*hooked=0x\([0-9a-f]*\).*/\1/p')
# 页前缀：去前导零后砍掉末 3 位十六进制。dmesg 打印的 pc/far 不带前导零，
# 而目标 out_hex 打 16 位带前导零，所以两边都必须先归一化再比，不能直接比字符串。
MPK=$(echo "$MP" | sed 's/^0*//; s/...$//')

echo "=============================================================="
echo " 实验 A 判读  (selfread)"
echo "=============================================================="

echo
echo "--- 0. 布局自检 ---"
if echo "$L1" | grep -q "same_page=1"; then
    echo "  [OK]   same_page=1"
else
    echo "  [作废] same_page != 1 —— 两个函数不在同一页，实验无意义"
    INVALID=1
fi
if echo "$L1" | grep -q "readers_differ=1"; then
    echo "  [OK]   readers_differ=1"
else
    echo "  [作废] readers_differ != 1 —— reader 被链接期 ICF 合并，C1 已退化成 C3"
    INVALID=1
fi
echo "  受管页基址 = 0x$(echo "$MP" | sed 's/^0*//')   (hooked=0x$MP)"

echo
echo "--- 1. 桩状态 ---"
H77=$(grep -c "hooked=777" "$T")
HTOT=$(grep -c "^R r=" "$T")
echo "  出现 hooked=777 的轮数 = $H77 / 总轮数 $HTOT"
if [ "$H77" -eq 0 ]; then
    echo "  [!]    从未出现 777 —— 桩没生效，或 KPM 没加载。后面的结论都不可信。"
fi

echo
echo "--- 2. C3（读指令在受管页内 + 读受管页）---"
S3=$(grep -c "C3 r=[0-9]* start" "$T")
D3=$(grep -c "C3 r=[0-9]* done" "$T")
LASTS=$(grep -o "C3 r=[0-9]* start" "$T" | tail -1 | sed 's/^C3 r=//; s/ start$//')
LASTD=$(grep -o "C3 r=[0-9]* done" "$T" | tail -1 | sed 's/^C3 r=//; s/ done$//')
echo "  start=$S3  done=$D3   最后 start 轮=$LASTS  最后 done 轮=$LASTD"
HUNG=0
if [ -n "$LASTS" ]; then
    if [ -z "$LASTD" ] || [ "$LASTD" -lt "$LASTS" ]; then
        echo "  [!!]   C3 在第 $LASTS 轮打 start 后没有 done —— 卡在这里"
        HUNG=1
    else
        echo "  [--]   C3 全部完成，没有卡住"
    fi
fi

echo
echo "--- 3. C1（读指令在页外 + 读受管页）：读隐藏是否有效 ---"
M1=$(grep "C1 r=" "$T" | grep -c "match=1")
M0=$(grep "C1 r=" "$T" | grep -c "match=0")
echo "  match=1: $M1    match=0: $M0"
if [ "$M0" -gt 0 ] && [ "$M1" -gt 0 ]; then
    echo "  [!]    挂 hook 后 match 由 1 翻 0 —— 读拿到的是影子页(桩字节)，读隐藏失效"
elif [ "$M0" -gt 0 ]; then
    echo "  [!]    全程 match=0 —— 读一直拿到影子页，读隐藏失效"
fi

echo
echo "--- 4. dmesg：故障分类 ---"
awk '
function strip0(h) { sub(/^0+/, "", h); return h }
function pk(h,   s) { s = strip0(h); if (length(s) <= 3) return ""; return substr(s, 1, length(s)-3) }
function vk(h,   s) { s = strip0(h); if (s == "") return "zero"; if (s ~ /^ffff/) return "kernel"; return "user" }

/flt#/ {
    ec=""; pc=""; far=""
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^ec=/)  { split($i, a, "="); ec  = a[2] }
        if ($i ~ /^pc=/)  { split($i, a, "="); pc  = a[2] }
        if ($i ~ /^far=/) { split($i, a, "="); far = a[2] }
    }
    nflt++
    cnt_ec[ec]++
    if (pk(pc) != "" && pk(pc) == MPK && pk(far) == MPK) samepage++
}
/DUMP/ {
    ec=""; far=""; view=""; esr=""
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^ec=/)   { split($i, a, "="); ec   = a[2] }
        if ($i ~ /^far=/)  { split($i, a, "="); far  = a[2] }
        if ($i ~ /^view=/) { split($i, a, "="); view = a[2] }
        if ($i ~ /^esr=/)  { split($i, a, "="); esr  = a[2] }
    }
    ndump++
    printf "  [DUMP] esr=%s ec=%s view=%s far=%s -> far 是 %s VA\n", esr, ec, view, far, vk(far)
    if (vk(far) == "user")   nuser++
    if (vk(far) == "kernel") nkern++
}
END {
    printf "  flt 行总数 = %d\n", nflt
    for (e in cnt_ec) printf "    ec=%s : %d 次\n", e, cnt_ec[e]
    printf "  pc 与 far 同落受管页的 flt = %d\n", samepage
    printf "  DUMP 行 = %d  (far 为用户 VA: %d, 内核 VA: %d)\n", ndump, nuser, nkern
    # 机器可读输出，供下面的结论判断
    print "SUMMARY " nflt+0 " " samepage+0 " " ndump+0 " " nuser+0 " " nkern+0
}' MPK="$MPK" "$D" > /tmp/_sr_awk.txt
grep -v "^SUMMARY " /tmp/_sr_awk.txt
SUM=$(grep "^SUMMARY " /tmp/_sr_awk.txt | tail -1)
NFLT=$(echo "$SUM"  | cut -d' ' -f2)
SAME=$(echo "$SUM"  | cut -d' ' -f3)
NDUMP=$(echo "$SUM" | cut -d' ' -f4)
NUSER=$(echo "$SUM" | cut -d' ' -f5)
NKERN=$(echo "$SUM" | cut -d' ' -f6)

echo
echo "=============================================================="
echo " 结论"
echo "=============================================================="

if [ "$INVALID" -eq 1 ]; then
    echo " [作废] 布局自检未过，先修 tests/selfread.c 的段布局（检查 -fno-toplevel-reorder）"
elif [ "$H77" -eq 0 ]; then
    echo " [不确定] 桩从未生效（hooked 里没有 777），无法判读"
elif [ "$HUNG" -eq 1 ] && [ "$SAME" -gt 0 ]; then
    echo " [假设成立] C3 卡死 + dmesg 有 pc/far 同落受管页的 fault"
    echo "            => 自指数据读导致 SHADOW/STEP 活锁。"
    echo "               独占页的真实边界 = 受管页内不能有自指数据访问。"
elif [ "$HUNG" -eq 1 ]; then
    echo " [存疑] C3 卡死，但 dmesg 里没有 pc/far 同落受管页的 fault"
    echo "        => 卡在别处（可能是日志上限 100 条吃光了窗口）。人工看 dmesg 原始输出。"
elif [ "$NDUMP" -gt 0 ]; then
    echo " [EL1 线] 出现 DUMP 行（状态机未接管的 fault）"
    if [ "$NUSER" -gt 0 ]; then
        echo "          far 是用户 VA => EL1 侧访问用户 VA（PAN 类）"
    fi
    if [ "$NKERN" -gt 0 ]; then
        echo "          far 是内核 VA => probe_* 在内核线性地址上 fault（extable 没接住）"
    fi
    echo "          注意：C3 没卡死，所以这条与活锁无关，是独立故障。"
else
    M0N=$(grep "C1 r=" "$T" | grep -c "match=0")
    if [ "$M0N" -gt 0 ]; then
        echo " [部分] C3 没卡死，但 C1 出现 match=0 —— 桩生效、读隐藏失效"
    else
        echo " [假设被证伪] C3 全程正常 done、桩生效(777)、读隐藏有效(match=1)、无 DUMP"
        echo "              => 自指数据读不致死锁。独占页约束另有成因，"
        echo "                 回到 README 另一条表述（页内有别的可执行代码），需另设计实验隔离。"
    fi
fi
echo
