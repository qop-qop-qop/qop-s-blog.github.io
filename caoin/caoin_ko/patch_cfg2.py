#!/usr/bin/env python3
"""caoin shadow_v2 配置打包（跷跷板版）。"""
import struct
import sys

MARKER = 0xDEADCA02DEADCA02
MAGIC = 0xCA02CA02CA02CA02

def main():
    if len(sys.argv) != 17:
        print("usage: patch_cfg2.py <in.ko> <out.ko> <pid> <target_va> <shadow_phys> "
              "<expect_phys> <status_va> <find_task> <probe_read> <printk> "
              "<do_mem_abort> <set_memory_rw> <set_memory_ro> <stop_machine> "
              "<probe_kernel_write> <swapper_pg_dir>")
        return 1
    a = sys.argv
    data = bytearray(open(a[1], "rb").read())
    off = data.find(struct.pack("<Q", MARKER))
    if off < 0:
        print("marker not found")
        return 1
    cfg = struct.pack("<10Q", MARKER, MAGIC, int(a[3]), int(a[4], 16),
                      int(a[5], 16), int(a[6], 16), int(a[7], 16),
                      int(a[8], 16), int(a[9], 16), int(a[10], 16))
    # 模块布局: p_abort, p_setrw(弃用), p_setro(弃用), p_stop, p_probe_write, p_swapper
    cfg += struct.pack("<6Q", int(a[11], 16), int(a[12], 16), int(a[13], 16),
                       int(a[14], 16), int(a[15], 16), int(a[16], 16))
    data[off:off + len(cfg)] = cfg
    open(a[2], "wb").write(data)
    print(f"cfg @ {off:#x} -> {a[2]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
