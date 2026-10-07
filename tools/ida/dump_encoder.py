import ida_hexrays, idc, os
OUT = "out"   # 相对当前工作目录（在仓库根目录运行）
for ea, name in ((0x85DC4, "key"), (0x4BA28, "t0"), (0x4BB00, "t1"), (0x4BE04, "t2"), (0x4C29C, "t3"), (0x54180, "mac")):
    cf = ida_hexrays.decompile(ea)
    open(os.path.join(OUT, "enc_%s_%x.c" % (name, ea)), "w", encoding="utf-8").write(str(cf))
    print("dumped", name, hex(ea), "lines:", str(cf).count("\n"))
idc.qexit(0)
