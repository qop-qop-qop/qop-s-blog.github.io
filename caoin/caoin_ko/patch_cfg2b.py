#!/usr/bin/env python3
"""caoin shadow_v2b（VBAR 路线）配置打包。"""
import struct
import sys

MARKER = 0xDEADCA03DEADCA03
MAGIC = 0xCA03CA03CA03CA03

def main():
    if len(sys.argv) != 12:
        print("usage: patch_cfg2b.py <in.ko> <out.ko> <pid> <target_va> <shadow_phys> "
              "<expect_phys> <status_va> <status_phys> <find_task> <probe_read> <printk>")
        return 1
    a = sys.argv
    data = bytearray(open(a[1], "rb").read())
    off = data.find(struct.pack("<Q", MARKER))
    if off < 0:
        print("marker not found")
        return 1
    # 布局: marker,magic,pid,tva,sphys,ephys,sva,find_task,probe,printk,status_phys(原 unused[0])
    cfg = struct.pack("<11Q", MARKER, MAGIC, int(a[3]), int(a[4], 16),
                      int(a[5], 16), int(a[6], 16), int(a[7], 16),
                      int(a[8], 16), int(a[9], 16), int(a[10], 16),
                      int(a[11], 16))
    data[off:off + len(cfg)] = cfg
    open(a[2], "wb").write(data)
    print(f"cfg @ {off:#x} -> {a[2]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
