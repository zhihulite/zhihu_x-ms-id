"""Batch decompile target functions of libdu.so to out/*.c"""
import idaapi
import ida_auto
import ida_hexrays
import ida_funcs
import idautils
import json
import os

OUT = "out"   # 相对当前工作目录（在仓库根目录运行）

ida_auto.auto_wait()

log = []
ok = ida_hexrays.init_hexrays_plugin()
log.append("hexrays_init=%s" % ok)

if ok:
    targets = {}
    # every function named by the user or a JNI export
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        name = idaapi.get_name(ea)
        if name and (name.startswith("JNI_") or name.startswith(".")):
            targets[ea] = name
    # plus whatever the caller asked via env-ish file
    ask_file = os.path.join(OUT, "ask_addrs.json")
    if os.path.isfile(ask_file):
        try:
            for a in json.load(open(ask_file)):
                targets[int(a, 0) if isinstance(a, str) else a] = "ask_0x%x" % int(a, 0)
        except Exception as e:
            log.append("ask_file_err=%s" % e)
    log.append("targets=%s" % sorted(hex(e) for e in targets))
    for ea, name in sorted(targets.items()):
        try:
            cf = ida_hexrays.decompile(ea)
            text = str(cf)
            fn = os.path.join(OUT, "%s_0x%x.c" % (name.replace(".", "_"), ea))
            open(fn, "w", encoding="utf-8").write(text)
            log.append("OK %s @0x%x -> %d bytes" % (name, ea, len(text)))
        except Exception as e:
            log.append("ERR %s @0x%x : %s" % (name, ea, e))
else:
    # dump the hexrays error
    try:
        idaapi.load_plugin("hexrays")
        log.append("load_plugin hexrays done/err")
    except Exception as e:
        log.append("load_plugin err=%s" % e)

open(os.path.join(OUT, "batch_decomp.log"), "w", encoding="utf-8").write("\n".join(log))
idc_ = idaapi.qexit(0)
