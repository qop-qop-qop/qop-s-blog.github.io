#!/usr/bin/env python3
"""
caoin shadow 模块配置打包：按 marker 定位 cfg 块并写入实机值。
用法: patch_cfg.py <in.ko> <out.ko> <target_pid> <target_va> <shadow_phys>
      <expect_phys> <status_va> <find_task_by_vpid> <probe_kernel_read>
地址均为 hex（0x...），pid 十进制。
"""
import struct
import sys

MARKER = 0xDEADCA01DEADCA01
MAGIC = 0xCA01CA01CA01CA01

def main():
    if len(sys.argv) != 11:
        print(__doc__)
        return 1
    _, fin, fout, pid, tva, sphys, ephys, sva, ftask, probe, prn = sys.argv
    data = bytearray(open(fin, "rb").read())
    off = data.find(struct.pack("<Q", MARKER))
    if off < 0:
        print("marker not found")
        return 1
    cfg = struct.pack(
        "<13Q",
        MARKER, MAGIC,
        int(pid), int(tva, 16), int(sphys, 16),
        int(ephys, 16), int(sva, 16),
        int(ftask, 16), int(probe, 16), int(prn, 16),
        0,  # orig_pte 模块写回
        0, 0,  # mm_off / pgd_off 模块写回
    )
    data[off:off + len(cfg)] = cfg
    open(fout, "wb").write(data)
    print(f"cfg @ file offset {off:#x} -> {fout}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
