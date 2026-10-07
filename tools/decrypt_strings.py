"""Static decryptor for libdu.so obfuscated strings (sub_717C0 algorithm).

Algorithm recovered from decompilation:
  plain[k] = (enc[2k+1] - 1) ^ k,  k = 0,1,2,... until enc[2k+1] == 0
Blob starts at a 4-aligned address; even-offset bytes are unused filler.
"""
import struct
import sys

import os
_HERE = os.path.dirname(os.path.abspath(__file__))
SO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_HERE, "..", "sample", "libdu.so")

data = open(SO, "rb").read()

# vaddr -> file offset via PT_LOAD headers
phoff = struct.unpack_from("<Q", data, 0x20)[0]
phentsize = struct.unpack_from("<H", data, 0x36)[0]
phnum = struct.unpack_from("<H", data, 0x38)[0]
loads = []
for i in range(phnum):
    off = phoff + i * phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
    if p_type == 1:
        loads.append((p_vaddr, p_offset, p_filesz))
print("== PT_LOAD ==")
for v, o, fsz in loads:
    print("LOAD vaddr=0x%x off=0x%x filesz=0x%x" % (v, o, fsz))

def v2o(vaddr):
    for v, o, fsz in loads:
        if v <= vaddr < v + fsz:
            return o + (vaddr - v)
    return None

def decrypt_at(off):
    """Decode blob at raw file offset; return (plain_str, blob_len) or None."""
    out = bytearray()
    k = 0
    while True:
        idx = off + 2 * k + 1
        if idx >= len(data):
            return None
        e = data[idx]
        if e == 0:
            return bytes(out).decode("utf-8", "replace"), 2 * k + 2
        out.append((((e - 1) & 0xFF) ^ k) & 0xFF)
        k += 1
        if k > 512:
            return None

def printable(s):
    if not s or len(s) < 3:
        return False
    good = sum(1 for c in s if 32 <= ord(c) < 127)
    return good / len(s) > 0.9

if len(sys.argv) > 2 and sys.argv[2].startswith("0x"):
    # decrypt specific vaddrs
    for va in sys.argv[2:]:
        off = v2o(int(va, 16) & ~3)
        r = decrypt_at(off) if off is not None else None
        print("%s -> %r" % (va, r[0] if r else None))
    sys.exit(0)

# brute scan whole file, 4-aligned
results = {}
off = 0
n = len(data)
while off < n - 4:
    r = decrypt_at(off)
    if r and printable(r[0]) and len(r[0]) >= 4:
        results[off] = r[0]
        off += max(4, (r[1] + 3) & ~3)
    else:
        off += 4

print("== decrypted strings (%d) ==" % len(results))
for off, s in sorted(results.items()):
    print("0x%05x  %r" % (off, s))
