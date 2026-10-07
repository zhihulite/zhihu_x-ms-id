# Decrypt every data-symbol blob referenced by main request builder 0x27A0C, in order of first appearance
import re, os
import ida_hexrays, ida_bytes, idc

OUT = "out"   # 相对当前工作目录（在仓库根目录运行）
src = open(os.path.join(OUT, "asm_caller_27a0c.c"), encoding="utf-8").read()

# all data symbol refs (direct or via precomputed vars)
refs = re.findall(r"&?(?:dword|qword|byte|loc|unk|word)_[0-9A-Fa-f]+", src)
seen, ordered = set(), []
for r in refs:
    a = int(r.split("_")[1], 16)
    if a in seen:
        continue
    seen.add(a)
    ordered.append(a)

def decrypt_blob(addr):
    b = ida_bytes.get_bytes(addr, 512) or b""
    out = bytearray()
    k = 0
    while k < 200:
        idx = 2 * k + 1
        if idx >= len(b) or b[idx] == 0:
            break
        c = ((b[idx] - 1) & 0xFF) ^ k
        out.append(c)
        k += 1
    return out.decode("utf-8", "replace")

print("total unique refs:", len(ordered))
for a in ordered:
    s = decrypt_blob(a)
    printable = all(32 <= ord(ch) < 127 or ch in "\t" for ch in s) if s else False
    tag = "STR " if printable else "data"
    if printable and s:
        print("%s %x %r" % (tag, a, s))

idc.qexit(0)
