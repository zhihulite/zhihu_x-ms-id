# Decompile all 22 slot functions from table off_C1828
import ida_hexrays, ida_bytes, idc, os

OUT = "out"   # 相对当前工作目录（在仓库根目录运行）

for i in range(22):
    q = ida_bytes.get_qword(0xC1828 + 8 * i)
    try:
        cf = ida_hexrays.decompile(q)
        path = os.path.join(OUT, "slot_%02d_%x.c" % (i, q))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(str(cf))
        print("slot %2d -> %x ok" % (i, q))
    except Exception as e:
        print("slot %2d -> %x FAIL %r" % (i, q, e))

idc.qexit(0)
