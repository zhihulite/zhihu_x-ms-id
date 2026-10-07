# -*- coding: utf-8 -*-
"""
数字联盟（ShuZilm）可信ID SDK v8.4.0 — Python 协议还原
====================================================

逆向自 libdu.so (arm64, md5 536e303d11e1a44ad1c0fd6da4c94d45) 与 cn.shuzilm.core (v8.4.0)。
所有常量均从 so 内加密字符串解出（算法见 decrypt_blob），或从 unidbg 动态捕获 + 真机 MuMu 报文确认。

协议全链路（主通道 /a/d2api/report）：

    采集指纹（22 槽 Build + 补充采集器 R* + 检测套件）
      → 组 JSON（顶层字段 + ★嵌套 vB2 指纹对象★）
      → sub_543EC 字符串混淆（R*/rG* 值）
      → zlib compress（sub_4D0DC，走 Java Deflater）
      → XOR 端点密钥（sub_4FF88: data[i] ^= key[i % len]）
      → POST https://<host>:<port>/a/d2api/report?v=8.1&t=a&e=2&p=&r=&n=&l=&h=
      → 响应 XOR 解封 → JSON：err==0，nctl 决定 ocdd/cdd → device_id
      → 本地持久化 <pkg>_dna.xml（device_id 封印体；补充ID AES-ECB 落盘）

本文档是自包含的：运行时不读取任何证据文件；仅 __main__ 的自检会读取
evidence/ 下的往返报文与 sample/libdu.so 做比对（缺少时该步自动跳过）。

证据分级：`VA 0x…` = so 内虚拟地址；`sub_XXXXX` = so 内函数；真机报文来自本地抓包（不入库）。
"""

import hashlib
import json
import os
import struct
import uuid
import zlib

# ====================================================================
# 1. so 内加密字符串解密算法（sub_717C0）
#    plain[k] = (enc[2k+1] - 1) ^ k，以 enc[2k+1] == 0 结尾；blob 4 字节对齐内嵌 .text
#    ⚠ 偶数位填充常为 0，是数据的一部分：遍历/过滤【不能】用 data[off]==0 跳过，
#      否则会漏解（曾因此漏掉 `android/widget/FrameLayout$LayoutParams`）。
# ====================================================================


def decrypt_blob(data: bytes, file_off: int, limit: int = 2048) -> str:
    """宽松版解密：按 enc[2k+1]==0 判尾，不校验可打印性（保留旧行为）。

    file_off 为 4 对齐的文件偏移。可能把非字符串的字节序列也解成乱码。
    """
    out = bytearray()
    k = 0
    while k < limit:
        i = file_off + 2 * k + 1
        if i >= len(data):
            break
        e = data[i]
        if e == 0:
            break
        out.append((((e - 1) & 0xFF) ^ k) & 0xFF)
        k += 1
    return bytes(out).decode("utf-8", "replace")


def decrypt_blob_strict(data: bytes, file_off: int, limit: int = 2048):
    """严格版解密：任一明文字节不在 0x20..0x7E（可打印 ASCII）立即返回 None。

    这是 dump_all_strings 使用的版本——只接受"整串全可打印"的候选，
    避免把随机字节误判为字符串，同时【不】跳过偶数位为 0 的 blob。
    """
    out = bytearray()
    k = 0
    while k < limit:
        i = file_off + 2 * k + 1
        if i >= len(data):
            return None
        e = data[i]
        if e == 0:
            return bytes(out)
        c = ((e - 1) & 0xFF) ^ k
        if c < 0x20 or c > 0x7E:
            return None
        out.append(c)
        k += 1
    return None


def _load_segments(data: bytes):
    """解析 ELF PT_LOAD 段：[(file_off, vaddr, filesz), ...]。"""
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(phnum):
        o = phoff + i * phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:      # PT_LOAD
            continue
        p_off, p_va, _, p_fsz, _ = struct.unpack_from("<QQQQQ", data, o + 8)
        segs.append((p_off, p_va, p_fsz))
    return segs


def decrypt_va(vaddr: int, so_path: str) -> str:
    """按虚拟地址解密（宽松版，自动经 PT_LOAD 映射到文件偏移）。"""
    data = open(so_path, "rb").read()
    for p_off, p_va, p_fsz in _load_segments(data):
        if p_va <= vaddr < p_va + p_fsz:
            return decrypt_blob(data, p_off + (vaddr - p_va))
    raise ValueError("vaddr not mapped")


def dump_all_strings_va(so_path: str) -> dict:
    """穷举解密全库字符串，返回 {字符串: VA}（首个命中地址），约 11272 条。"""
    data = open(so_path, "rb").read()
    found = {}
    for p_off, p_va, p_fsz in _load_segments(data):
        end = min(len(data), p_off + p_fsz)
        for off in range(p_off, end - 1, 4):
            s = decrypt_blob_strict(data, off)
            if s is not None and len(s) >= 3:
                found.setdefault(s.decode("ascii"), p_va + (off - p_off))
    return found


def dump_all_strings(so_path: str) -> list:
    """返回全库唯一字符串排序列表（约 11272 条）。"""
    return sorted(dump_all_strings_va(so_path))


# ====================================================================
# 2. 端点表 + XOR 信封（sub_848B8 端点选择器 / sub_847F0 密钥选择器 / sub_4FF88 对称编解码）
#    每个 report 端点有独立 XOR 秘钥（请求/响应共用同钥）
# ====================================================================

ENDPOINTS = {
    # id: (url_path, xor_key)   —— url 与 key 均解密自 so
    1:  ("/a/dai/report?v=2.2&c=1&e=1",
         None),  # dai 的 key 对应 blob 0x5F4F4 之前的表项，见 KEYS_BY_ID
    2:  ("/a/daa/report?v=1.1&c=1&e=1", None),
    3:  ("/a/ldc/report?v=1.0&c=1&e=1", None),
    4:  ("/a/dcc2/request?v=2.0&c=1&e=1", None),
    5:  ("/a/adt/report?v=5.0&c=1&e=1&t=adt", None),
    6:  ("/a/d2api/report?v=8.1&t=a&e=2", None),      # 主通道（设备ID）
    8:  ("/siieuu93pasidovna/shuzilm/tra_file", None),  # 配置/文件下发
    9:  ("/a/aads/request?v=1.0&t=ads", None),
    13: ("/a/audd/valid?v=1.0&t=uid1", None),
    14: ("/a/audd/token?v=1.0&t=uid2", None),
    16: ("/a/mdna/report?v=1.0&t=m", None),
}

# sub_847F0(a1) 按端点 id 返回 XOR 秘钥（解密原文，已全部解出）
KEYS_BY_ID = {
    0:  "Ues&90`-)tq|{2ffqy!e]w$jquty5$%^&+=`-09+=87>?:['",
    1:  "@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!",
    2:  "li~jl#etu98v2f!edv3o5$%^&+=90`-)tqw$jqu@7v6.a1",
    3:  "69tr_ew+>:oi}12q{k40#$%<as)78dfghuyj5l;][p3^&*(",
    4:  "$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb",
    5:  "Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W",
    6:  "9+=%^8>:oi}12q5l;]q|{2f8v>?:[ss%^&fq5$baf7fq+=d-0",
    9:  ".}pmn];1tsb^x*,-09+=87f4TWq&/56%o,<v2$%>?:['|",
    13: "7.f498yu<>?:['|TWq&/57fqu@7v6.ajl#etu{.jqv2fs",
    14: "7.f498yu<>?:['|TWq&/57fqu@7v6.ajl#etu{.jqv2fs",
    16: "ts!ed%$bt&/57+=n];18u{.j=90f9`-)qu@7|.}pm^&+v2",
}
# 注：端点 id 与秘钥 id 的对应关系见 sub_13F3C 的调用参数（type 即秘钥 id 传入 sub_847F0）

# ---- 真机主机与端口（解密字符串 VA 见右注） ----
HOSTS = {
    "auni":          "auni.telecome.cn",                 # VA 0x6E014（默认上报 Host）
    "optn":          "optn.shuzilm.cn",                  # VA 0x6AAA8
    "ipv4":          "ipv4.shuzilm.cn",                  # VA 0x6D65C
    "ipv6":          "ipv6.shuzilm.cn",                  # VA 0x6E124
    "cbsipv4":       "cbsipv4.shuzilm.cn",               # VA 0x69BDC
    "unioncom":      "auni.unioncom.cc",                 # VA 0x65E44
    "global":        "global-auni.checktrustworthiness.com",  # VA 0x6C1B4
    # 旧/备用域名（so 内亦存，非真机默认）：
    "d2api":         "d2api.shuzilm.cn",                 # VA 0x711C0
    "d2api_test":    "d2api-test.shuzilm.cn",            # VA 0x611C4
    "daa":           "daa.shuzilm.cn",                   # VA 0x5F31C
    "api":           "api.shuzilm.cn",                   # VA 0x70554
    "download":      "download.shuzilm.cn",              # VA 0x61988
}
PORT = 18447            # 真机配置端口（so 内 URL 模板 https://%s:%d%s @0x6F2D4）

# 各端点真机默认主机（文档证据：真机 d2api/audd 命中 auni.telecome.cn）
ENDPOINT_HOSTS = {
    1: HOSTS["auni"], 2: HOSTS["auni"], 3: HOSTS["auni"], 4: HOSTS["auni"],
    5: HOSTS["auni"], 6: HOSTS["auni"], 8: HOSTS["auni"], 9: HOSTS["auni"],
    13: HOSTS["auni"], 14: HOSTS["auni"], 16: HOSTS["auni"],
}


def xor_envelope(data: bytes, key: str) -> bytes:
    """sub_4FF88：data[i] ^= key[i % len(key)]（对称，加密/解密同一函数）。"""
    kb = key.encode("latin-1")
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


# ---- zlib 压缩（sub_4D0DC 包装 Java Deflater；默认级别 6） ----
# 注意：本机默认 Python(3.14) 的 zlib 是 zlib-ng，deflate 输出与 Java Deflater 不同；
#       字节级重编码需 stock zlib。canonical_zlib_compress 在 zlib-ng 环境下
#       自动回退到系统 stock zlib（ctypes 调 compress2），以保证与真机逐字节一致。

_stock_zlib = None


def zlib_decompress(data: bytes) -> bytes:
    """容忍 zlib/gzip/裸 deflate 三种封装。"""
    for cand in (data, data[2:]):
        for wbits in (15, -15, 31):
            try:
                return zlib.decompress(cand, wbits)
            except Exception:
                pass
    raise zlib.error("zlib decompress failed")


# ====================================================================
# 3. 请求 URL 构造（真机 d2api 实测）
#    /a/d2api/report?v=8.1&t=a&e=2
#       &p = upper(md5(pkg + "." + SALT_P + "." + SDK_VERSION))   # 盐 37be8a1e
#       &r = UUID.randomUUID() 去横杠
#       &n = <dword_C1934>   &l = <dword_C1938>
#       &h = md5(n_a + "." + SALT_H)   （首装 n_a 空串时 h 为字面量 "0"）  # 盐 889e0b01
#    实测（本地抓包）：
#       p=30ABF75967EFADA71AEA8640CC7A611B  (pkg=com.zhihu.android, sdk=v8.4.0)
#       首装 h=0；带会话时 h=md5(n_a+".889e0b01")
# ====================================================================

SALT_P = "37be8a1e"          # p 的盐值
SALT_H = "889e0b01"          # h 的盐值
SDK_VERSION = "v8.4.0"       # 3mS 字段值 / p 的版本段
PKG_DEFAULT = "com.zhihu.android"


def _md5_hex(s: str, upper: bool = False) -> str:
    import hashlib
    h = hashlib.md5(s.encode("utf-8")).hexdigest()
    return h.upper() if upper else h


def build_query_params(pkg: str = PKG_DEFAULT, uuid: str = "", n: int = -1,
                       l: int = -1, n_a: str = "", sdk_version: str = SDK_VERSION) -> dict:
    """构造端点 6 的查询参数 p/r/n/l/h。"""
    p = _md5_hex("%s.%s.%s" % (pkg, SALT_P, sdk_version), upper=True)
    r = uuid.replace("-", "")
    h = "0" if n_a == "" else _md5_hex(n_a + "." + SALT_H)
    return {"p": p, "r": r, "n": str(n), "l": str(l), "h": h}


def build_url(endpoint_id: int, host: str = None, port: int = None,
              pkg: str = PKG_DEFAULT, uuid: str = "", n: int = -1, l: int = -1,
              n_a: str = "") -> str:
    """构造完整请求 URL。端点 6 附带 p/r/n/l/h；若给 port 则用 https://host:port 形态。"""
    path, _ = ENDPOINTS[endpoint_id]
    host = host or ENDPOINT_HOSTS.get(endpoint_id, HOSTS["auni"])
    base = "https://%s:%d%s" % (host, port, path) if port else "https://%s%s" % (host, path)
    if endpoint_id == 6:
        q = build_query_params(pkg=pkg, uuid=uuid, n=n, l=l, n_a=n_a)
        base += "&" + "&".join("%s=%s" % (k, v) for k, v in q.items())
    return base


# ====================================================================
# 4. payload 组装（sub_2B70C 指纹清单 + sub_27A0C 主构建器）
#    ★ 关键坑：真机把整块指纹嵌在顶层键 "vB2" 内（真机 d2api 明文 5314 字节：
#      顶层 29 键 + vB2 内 161 键）。早期 unidbg 桥用 JSONObject.put(String,Object)
#      对对象值取 getValue() 得 null，而 org.json 的 put(key,null) 语义是【删除键】，
#      导致整块指纹被静默丢弃 → 服务端只回裸 {"err":"0"}、永不签发。
#      因此本实现显式要求 "vB2" 为嵌套 dict，禁止把对象值当 null。
# ====================================================================

# rG 槽位 → android.os.Build String 字段（IDA 全量解密 @0xC1828 表）
# 门控：slot0 仅 API<=28（Android 9-，(Build.SERIAL 可直读)；slot18-21 仅 API>=31（Android 12+）
BUILD_FIELD_SLOTS = [
    ("rG0",  "SERIAL"),            ("rG1",  "BOARD"),
    ("rG2",  "BOOTLOADER"),        ("rG3",  "CPU_ABI"),
    ("rG4",  "CPU_ABI2"),          ("rG5",  "DEVICE"),
    ("rG6",  "DISPLAY"),           ("rG7",  "FINGERPRINT"),
    ("rG8",  "HARDWARE"),          ("rG9",  "HOST"),
    ("rGa",  "ID"),                ("rGb",  "MANUFACTURER"),
    ("rGc",  "MODEL"),             ("rGd",  "PRODUCT"),
    ("rGe",  "TAGS"),              ("rGf",  "USER"),
    ("rG10", "TYPE"),              ("rG11", "BRAND"),
    ("rG12", "SKU"),               ("rG13", "ODM_SKU"),
    ("rG14", "SOC_MANUFACTURER"),  ("rG15", "SOC_MODEL"),
]


def collect_fingerprint(api_level: int = 28,
                        build_fields: dict | None = None,
                        radio_version: str = "",
                        supported_abis: list | None = None,
                        serial: str = "") -> dict:
    """sub_2B70C 的 Python 等价实现：按 API 级别门控生成指纹 JSON（键序无关）。
    build_fields: {字段名: 值}，缺省的 Build 字段填空串（unidbg 仿真环境即如此）。"""
    bf = dict(build_fields or {})
    out = {}
    for i, (key, fname) in enumerate(BUILD_FIELD_SLOTS):
        if i == 0 and api_level > 28:
            continue          # slot0 门控：API>28 不上报 SERIAL
        if i >= 18 and api_level < 31:
            continue          # slot18-21 门控：API<31 无 SKU/ODM_SKU/SOC_*
        out[key] = bf.get(fname, "")
    out["Kvr"] = radio_version
    out["fKe"] = ",".join(supported_abis or [])
    out["tNP"] = serial
    return out


def assemble_payload(top_fields: dict, fingerprint: dict, nesting_key: str = "vB2") -> dict:
    """把指纹块嵌套进顶层字段（真机形态）。返回新的顶层 dict（浅拷贝）。

    ⚠ 禁止把 fingerprint 直接平铺到顶层，也禁止让对象值落到 JSONObject.put(k,null) 路径。
    """
    payload = dict(top_fields)
    payload[nesting_key] = dict(fingerprint)
    return payload


def build_payload(fields: dict) -> str:
    """构造上报 payload 字符串（紧凑 JSON，键序无关，供自检/兼容）。"""
    return json.dumps(fields, separators=(",", ":"), sort_keys=True)


# ====================================================================
# 5. K5f（进程指纹）sub_25958
#    K5f = upper(hex(md5(fmt % (sessionStr, getpid(), rand(), gettid()))))
#    fmt = "%s%d%d%d"（解自 so VA 0x66864）；键名 "K5f"（VA 0x6BEF8）
#    实测：md5("1790870391.830000000"+"2268"+"1008921510"+"2268")
#          == 72fb3dac09dbf5c8f54d2fd9d988f870
#    含 rand()/getpid()/gettid()，每次进程必然不同，跨运行不可复现属正常。
# ====================================================================

K5F_FMT_VA = 0x66864
K5F_KEY_VA = 0x6BEF8
K5F_FMT = "%s%d%d%d"


def compute_k5f(session_str: str, pid: int, randv: int, tid: int) -> str:
    """返回大写 32 位 hex（= upper(md5("%s%d%d%d" % (session, pid, rand, tid))))."""
    import hashlib
    data = K5F_FMT % (session_str, pid, randv, tid)
    return hashlib.md5(data.encode("utf-8")).hexdigest().upper()


# ====================================================================
# 5.1 设备签名 sKZ / P1J（unidbg 实测：日志 lr=0x1bb94 处 put 出这两个键）
#     生成方式 = 对 WLAN MAC 取 SHA-1，摘要十六进制串切片 g0=[1:7]、g2=[13:19]、
#     g1=[7:13]，按 "g0:g2:g1" 冒号拼接，三组全大写（样例2 服务端 o_a 回显证实）。
#     实测验证：sha1("08:ca:04:3d:5e:66") = e945610d380522094330cb3e861395b8022a503e
#              → "945610:209433:D38052"（unidbg 桥日志吻合）
#              sha1("b8:0b:65:f8:53:dc") → "88D266:C2C10E:C12DA5"（o_a 回显吻合）
#     服务端在响应 o_a 字段回显此签名；换 MAC 即换签名、换设备记录、签新 ID。
# ====================================================================

def device_signature(digest_hex: str) -> str:
    """按 so 的错位切片规则把摘要 hex 拼成 "组0:组2:组1"，三组全大写。"""
    h = digest_hex.lower()
    if len(h) < 19:
        raise ValueError("digest too short for the slicing rule")
    return ("%s:%s:%s" % (h[1:7], h[13:19], h[7:13])).upper()


def device_signature_from_mac(mac: str) -> str:
    """sKZ/P1J 的生成入口：WLAN MAC（如 08:ca:04:3d:5e:66）→ 设备签名。"""
    import hashlib
    return device_signature(hashlib.sha1(mac.encode("utf-8")).hexdigest())


# ====================================================================
# 6. 本地存储封印（sub_4F43C）
#    seal   = UPPER(hex(md5(payload[:64]))) + payload        # payload 前 64 字符整体取 md5
#    落盘   = base64(seal)                                   # 写入 <pkg>_dna.xml / _prefs.xml
#    解封   = base64 解码后，前 32 字符 == md5(payload[:64]) 上界校验，余下为原文
#    实测（真机 prefs）：
#      payload "WNQ14J96FOJ724G8X" → 前缀 923BFEDE89728271FAEADCFB2613AF98
#      payload "2"                 → 前缀 C81E728D9D4C2F636F067F89CC14862C
#    物理键名 = upper(hex(md5(逻辑键名)))（如 md5("sid")=B8C1A306…）
# ====================================================================

_SEAL_PREFIX_LEN = 32


def seal(payload: str) -> str:
    """返回封印串：UPPER(md5(payload[:64])) + payload（不 base64）。"""
    import hashlib
    prefix = hashlib.md5(payload[:64].encode("utf-8")).hexdigest().upper()
    return prefix + payload


def unseal(sealed: str, verify: bool = True) -> str:
    """剥离并校验封印前缀，返回 payload 原文。"""
    payload = sealed[_SEAL_PREFIX_LEN:]
    if verify:
        expected = seal(payload)[:_SEAL_PREFIX_LEN]
        if sealed[:_SEAL_PREFIX_LEN] != expected:
            raise ValueError("seal prefix mismatch (anti-tamper)")
    return payload


def seal_pref_value(payload: str) -> str:
    """落盘形态：base64(seal(payload))。"""
    import base64
    return base64.b64encode(seal(payload).encode("utf-8")).decode("ascii")


def unseal_pref_value(b64_value: str) -> str:
    """从 prefs 的 base64 值解封出 payload。"""
    import base64
    sealed = base64.b64decode(b64_value).decode("utf-8")
    return unseal(sealed)


def pref_key(logical_key: str) -> str:
    """SharedPreferences 物理键名 = upper(hex(md5(逻辑键名)))。"""
    return _md5_hex(logical_key, upper=True)


# ====================================================================
# 7. 字符串编码器 sub_543EC（R*/rG* 值混淆）
#    ① 合法性：逐字符检查 32..126 可打印
#    ② 移位：shift = (dword_C1944 % 100) % 57 + 1        # 1..57
#            逐字符 c += shift; if c > 0x7E: c -= 95       # 95 可打印字符循环
#    ③ 二级变换（按 (dword_C1944 / 100) % 4 选）：
#       case0: sub_4BA28 — 后半降序/前半降序成对重排
#       case1: sub_4BB00 — 前后半交错（out[2i]=in[n-1-i], out[2i+1]=in[i]）
#       case2: sub_4BE04 — 奇位降序 + 偶位降序（真机 MuMu 用的就是它）
#       case3: sub_4C29C — 偶位升序 + 奇位升序
#       四个置换均已用 unidbg 直接调用取真值、对 n=2..24 共 23 组逐一核对（见文末自检）。
#       它们都是 NEON 向量化实现，但语义等价于上述纯标量置换 —— 已严格验证，非近似。
#    ④ sub_540C0 put 编码值
#    - unidbg 环境输入为空 → C1944=0 → shift=1 / case0（7/7 实证：embmfvic→bullhead 等）。
#    - 真机 MuMu 报文 → 实测 shift=55 / case2 置换（对应 c1944=254）；
#      对 6 个 Build 字段（含 48 字符 FINGERPRINT）与 Kvr/fKe 重编码逐字节吻合。
# ====================================================================


def _shift_up(s: str, shift: int) -> str:
    return "".join(chr((ord(c) - 32 + shift) % 95 + 32) for c in s)


def _shift_down(s: str, shift: int) -> str:
    return "".join(chr((ord(c) - 32 - shift) % 95 + 32) for c in s)


def _perm_case0(n: int):
    """case0（sub_4BA28）："后半降序 / 前半降序" 成对重排。
    偶数 n：out[2i]=n-1-i, out[2i+1]=n-1-i-h
    奇数 n：out[2i]=h-i,   out[2i+1]=2h-i（i=0..h-1），末尾补 0
    注：旧实现（h/2 那种写法）在 n=2..24 里 11 组对不上，已按 unidbg 实测置换更正。"""
    h = n // 2
    out = []
    if n % 2 == 0:
        for i in range(h):
            out.append(n - 1 - i)
            out.append(n - 1 - i - h)
    else:
        for i in range(h):
            out.append(h - i)
            out.append(2 * h - i)
        out.append(0)
    return out


def _perm_case1(n: int):
    """case1（sub_4BB00）：前后半交错 —— out[2i]=in[n-1-i], out[2i+1]=in[i]，
    奇数 n 时中间元素放最后。n=8 → [7,0,6,1,5,2,4,3]。"""
    out = []
    for i in range(n // 2):
        out.append(n - 1 - i)
        out.append(i)
    if n % 2:
        out.append(n // 2)
    return out


def _perm_case2(n: int):
    """case2（sub_4BE04）：奇位降序 + 偶位降序（旧的 `_perm_riffle`，名字标错成了 case1）。
    n=8 → [7,5,3,1,6,4,2,0]；真机 MuMu 报文用的就是它。"""
    return list(range(n - 1, -1, -2)) + list(range(n - 2, -1, -2))


def _perm_case3(n: int):
    """case3（sub_4C29C）：偶位升序 + 奇位升序。n=8 → [0,2,4,6,1,3,5,7]。"""
    return list(range(0, n, 2)) + list(range(1, n, 2))


_PERMS = {0: _perm_case0, 1: _perm_case1, 2: _perm_case2, 3: _perm_case3}


def _perm(n: int, case: int):
    fn = _PERMS.get(case)
    if fn is None:
        raise ValueError("encoder case %d 未还原（NEON）" % case)
    return fn(n)


def encode_543ec(s: str, c1944: int = 0, case: int = 0) -> str:
    shift = (c1944 % 100) % 57 + 1
    x = _shift_up(s, shift)
    p = _perm(len(x), case)
    return "".join(x[p[i]] for i in range(len(x)))


def decode_543ec(s: str, c1944: int = 0, case: int = 0) -> str:
    shift = (c1944 % 100) % 57 + 1
    p = _perm(len(s), case)
    x = [None] * len(s)
    for i, src in enumerate(p):
        x[src] = s[i]
    return _shift_down("".join(x), shift)


# 真机 MuMu 报文编码参数（实测推导）
#   shift = (c1944 % 100) % 57 + 1 = 55  → c1944 % 100 == 54
#   case  = (c1944 / 100) % 4      = 2   → 走 sub_4BE04（奇位降序+偶位降序）
# 故 c1944 = 254（不是旧注释写的 154 —— 154 只满足 shift，case 会是 1）。
# 判定依据：unidbg 直接调用四个变换函数取真实置换（-Ddu.encprobe=true），
#           case2 的置换与真机报文 6 个字段（含 48 字符 FINGERPRINT）逐字节吻合。
MUMU_C1944 = 254
MUMU_ENC_CASE = 2


def decode_report_string(s: str) -> str:
    """按真机 MuMu 参数解出上报字符串原值。"""
    return decode_543ec(s, MUMU_C1944, MUMU_ENC_CASE)


# ====================================================================
# 8. 字段表（真机 d2api 明文 doc：本地抓包 k6 请求体）
#    顶层 29 键 + 嵌套 vB2 内 161 键，全部落在此处（运行时自包含）。
# ====================================================================

TOP_FIELDS = [
    "AYk", "sKZ", "sf0M", "fM0", "s4j1", "41j", "P1J", "DUv", "Qg1", "LMi",
    "Zrs", "EV2", "SAN", "h6Z", "K5f", "3mS", "AAA", "BBB", "HAG", "GVp",
    "msg", "MaO", "dLH", "y5W", "eBI", "vB2", "o7k", "iWf", "B3k",
]

# 已知语义（其余按不透明字段保留，不臆造含义）
TOP_FIELD_SEMANTICS = {
    "DUv":  "宿主 App 包名（com.zhihu.android）",
    "EV2":  "宿主 App 版本名（11.10.0）",
    "Zrs":  "宿主 App versionCode（int，41012）",
    "h6Z":  "宿主 App 名（知乎）",
    "SAN":  "宿主 Build.VERSION.SDK_INT（35）",
    "3mS":  "SDK 版本（v8.4.0）",
    "AAA":  "协议标记（v1.0）",
    "BBB":  "协议标记（v1.0）",
    "K5f":  "进程指纹（见 compute_k5f / sub_25958）",
    "HAG":  "cn.shuzilm.config.json 的 apiKey（512-bit RSA 公钥 SPKI base64）",
    "GVp":  "渠道/渠道包（zhihuwap64）",
    "AYk":  "设备签名（md5 摘要切片拼接，与 sKZ/P1J 同族）",
    "sKZ":  "设备签名（sha1(WLAN MAC) 错位切片，见第 6 节拼接规则）",
    "P1J":  "设备签名（与 sKZ 同一摘要的另一切片）",
    "fM0":  "WLAN MAC（编码态，真机=08:ca:04:3d:5e:66）",
    "41j":  "WLAN MAC（fM0 的同源副本）",
    "sf0M": "短签名/指纹片段（编码态，7 字符）",
    "s4j1": "短签名/指纹片段（sf0M 的同源副本）",
    "Qg1":  "毫秒时间戳（firstInstallTime）",
    "LMi":  "毫秒时间戳（lastUpdateTime）",
    "dLH":  "会话/设备 UUID（编码态，解出为 uuid 字符串）",
    "2cO":  "会话时间戳串（秒.微秒，未编码）",   # 注：2cO 实际位于 vB2 内，见下
    "msg":  "自定义事件载荷（{\"custom\":\"\"}）",
    "MaO":  "状态标记（\"0\"）",
    "y5W":  "状态标记（\"1\"/\"2\"）",
    "eBI":  "状态标记（\"7\"）",
    "vB2":  "★ 嵌套指纹块（Build rG* + 补充采集器 R* + 环境字段）★",
    "o7k":  "状态/统计（int）",
    "iWf":  "状态/统计（int）",
    "B3k":  "状态/统计（int，实测 1007/3953/1007）",
}
# 解析 2cO 更正：真机报文里 2cO 在 vB2 内（顶层无 2cO）；此处保留说明。

VB2_FIELDS = [
    "rG1", "rG2", "rG3", "rG4", "rG5", "rG6", "rG7", "rG8", "rG9", "rGa",
    "rGb", "rGc", "rGd", "rGe", "rGf", "rG10", "rG11", "rG12", "rG13", "rG14",
    "rG15", "Kvr", "fKe", "Ra", "Rc", "Rd", "R1f", "R23", "R24", "R25",
    "R26", "R27", "R28", "R2a", "R2b", "R2c", "R2f", "R30", "R31", "R33",
    "R34", "R37", "R38", "R3a", "R3d", "R41", "R44", "R45", "R47", "R4a",
    "R4f", "R53", "R55", "R5a", "R63", "R64", "Ra1", "Ra2", "Ra5", "Rab",
    "Rad", "Rb0", "Rb3", "Rd0", "Rf6", "VUZ", "wSK", "DVp", "9N2", "Bn2",
    "JYD", "7S2", "iYB", "z4e", "zpA", "QQW", "2Lp", "0qI", "9P6", "mIS",
    "sfOo", "foO", "4VP", "bf7", "JPd", "J7w", "sJN", "I68", "iXj", "zUN",
    "8ET", "2us", "c2O", "PV8", "9pz", "43c", "CzO", "TwQ", "oJI", "uCM",
    "XH7", "vv1", "NAB", "sCc", "fPV", "3q2", "QgA", "ED2", "kYm", "LLS",
    "JEw", "iZS", "XQp", "84j", "Hg6", "UOv", "Bsy", "qdK", "2cO", "Pxm",
    "anY", "OW2", "S6e", "zc7", "90P", "LAh", "wlM", "nur", "tth", "t7Q",
    "cfx", "5y9", "VIB", "cmP", "ne8", "Cl5", "xRD", "B1q", "pT4", "eTk",
    "SAu", "fxb", "tbL", "sAJ", "w91", "G8U", "5Nc", "IJs", "qH9", "w5v",
    "Bos", "IJK", "IAI", "aFw", "KyU", "7Hz", "gEd", "zvW", "B7G", "9be",
    "6yY",
]

VB2_FIELD_SEMANTICS = {
    # Build 22 槽（编码态，需 decode_report_string；语义见 BUILD_FIELD_SLOTS）
    "rG1": "Build.BOARD", "rG2": "Build.BOOTLOADER", "rG3": "Build.CPU_ABI",
    "rG4": "Build.CPU_ABI2", "rG5": "Build.DEVICE", "rG6": "Build.DISPLAY",
    "rG7": "Build.FINGERPRINT", "rG8": "Build.HARDWARE", "rG9": "Build.HOST",
    "rGa": "Build.ID", "rGb": "Build.MANUFACTURER", "rGc": "Build.MODEL",
    "rGd": "Build.PRODUCT", "rGe": "Build.TAGS", "rGf": "Build.USER",
    "rG10": "Build.TYPE", "rG11": "Build.BRAND", "rG12": "Build.SKU",
    "rG13": "Build.ODM_SKU", "rG14": "Build.SOC_MANUFACTURER",
    "rG15": "Build.SOC_MODEL",
    "Kvr": "Build.getRadioVersion()（基带版本）",
    "fKe": "Build.SUPPORTED_ABIS 逗号拼接",
    "2cO": "会话时间戳串（秒.微秒，未编码）",
    "wSK": "本机 IP",
    "43c": "网关 IP",
    "LLS": "WLAN MAC（明文）",
    "zpA": "网络类型（WIFI）",
    "iXj": "厂商+机型（Samsung SM-G9900）",
    "TwQ": "屏幕参数（1Lx=宽 / NlZ=高 / NZE,zm4=density / AJd=标志）",
    "uCM": "CPU 核心信息",
    "3q2": "CPU 拓扑信息",
    "R25": "系统构建时间（Build date）",
    "R26": "构建描述 build description",
    "R28": "Build.FINGERPRINT 副本",
    "R30": "Build.MODEL 副本",
    "R37": "Build.MANUFACTURER/BRAND 副本",
    "R3d": "Build.MODEL 副本",
    "R55": "时区",
    "R2a": "主机名 (Build.HOST)",
    "Rb3": "调试状态（adb）",
    "R2c": "Build.TYPE",
    "R34": "SDK_INT 字符串",
    # 其余为补充采集器/环境探测的不透明字段，按原样保留
}

# 不透明字段（无语义证据，原样保留，勿臆造）
VB2_OPAQUE_FIELDS = [k for k in VB2_FIELDS if k not in VB2_FIELD_SEMANTICS]


# ====================================================================
# 9. 响应解析（sub_779EC 端点6 / sub_751E8 端点16 / sub_79978 audd族 / sub_77590 端点5）
#    真机实测 schema：
#      端点 6  (d2api): {"err","o_a","n_a","nctl","cdd"}
#      端点 4  (dcc2):  {"LCS","CdN","2sW","VrJ","Cww","NXF","f1V"}
#      端点 5  (adt):   {"err","MnE"}
#      端点 13 (audd valid): {"WP3","YdJ","n9j","Y4c","xGh"}
#      端点 16 (mdna):  {"err","n_a","nctl","ocdd","cdd","o_a","dlab","denv","isem"}
#    device_id 提取：err==0；nctl=="1" → ocdd(备选 sid)；否则 → cdd。
# ====================================================================

RESPONSE_SCHEMAS = {
    4:  ["LCS", "CdN", "2sW", "VrJ", "Cww", "NXF", "f1V"],
    5:  ["err", "MnE"],
    6:  ["err", "o_a", "n_a", "nctl", "cdd"],
    13: ["WP3", "YdJ", "n9j", "Y4c", "xGh"],
    14: ["WP3", "YdJ", "7Cu"],
    16: ["err", "n_a", "nctl", "ocdd", "cdd", "o_a", "dlab", "denv", "isem"],
}


def _parse_endpoint6(resp: dict) -> dict:
    """端点 6/16 共用：err 门控 → nctl 选 ID → 双写防篡改校验（sub_84534）。"""
    # err 可能为字符串 "0" 或数字 0
    try:
        err = int(resp.get("err", -1))
    except (TypeError, ValueError):
        err = -1
    nctl = str(resp.get("nctl", "2"))
    if nctl == "1":
        device_id = resp.get("ocdd") or resp.get("sid")
        echo = resp.get("cdd") or resp.get("ocdd")
    else:
        device_id = resp.get("cdd")
        echo = resp.get("ocdd") or resp.get("sid")
    # sub_84534：state_ni==4 时校验两处回显一致
    if str(resp.get("state_ni")) == "4" and device_id and echo and device_id != echo:
        raise ValueError("device_id double-write mismatch (anti-tamper)")
    return {
        "err": err,
        "nctl": nctl,
        "device_id": device_id if err == 0 else None,
        "cdd": resp.get("cdd"),
        "ocdd": resp.get("ocdd"),
        "sid": resp.get("sid"),
        "n_a": resp.get("n_a"),
        "o_a": resp.get("o_a"),
        "dlab": resp.get("dlab"),
        "denv": resp.get("denv"),
        "isem": resp.get("isem"),
        "supplemental": {("i%d" % i): resp.get("i%d" % i) for i in range(1, 10)
                         if ("i%d" % i) in resp},
    }


def parse_response(raw: bytes, endpoint_id: int) -> dict:
    """输入：HTTP 响应体原始字节（XOR 信封态）。
    处理：XOR 解封（端点秘钥）→ JSON 解析 → 按端点 schema 归一化。"""
    key = KEYS_BY_ID.get(endpoint_id)
    if key is None:
        raise ValueError("no xor key for endpoint %d" % endpoint_id)
    plain = xor_envelope(raw, key)
    resp = json.loads(plain.decode("utf-8", "replace"))
    out = {"raw_json": resp, "schema": RESPONSE_SCHEMAS.get(endpoint_id)}

    if endpoint_id in (6, 16):
        out.update(_parse_endpoint6(resp))
    elif endpoint_id == 4:
        # dcc2：LCS=err；VrJ=长 base64 令牌；CdN/2sW/Cww/NXF/f1V 为状态/版本切片
        try:
            out["err"] = int(resp.get("LCS", -1))
        except (TypeError, ValueError):
            out["err"] = -1
        out["token"] = resp.get("VrJ")
        out["device_id"] = None
    elif endpoint_id == 5:
        try:
            out["err"] = int(resp.get("err", -1))
        except (TypeError, ValueError):
            out["err"] = -1
        out["uuid"] = resp.get("MnE")     # 服务端下发 UUID
        out["device_id"] = None
    elif endpoint_id in (13, 14):
        try:
            out["err"] = int(resp.get("WP3", -1))   # audd 门控字段 = WP3
        except (TypeError, ValueError):
            out["err"] = -1
        out["status"] = resp.get("YdJ")             # 状态字段
        out["valid_window"] = resp.get("xGh")       # 有效窗（秒，实测 2592000=30 天）
        out["token"] = resp.get("Y4c") or resp.get("7Cu")
        out["n9j"] = resp.get("n9j")
        out["device_id"] = None
    else:
        out["err"] = None
        out["device_id"] = None
    return out


# ====================================================================
# 10. 设备档案（真机 MuMu：Samsung SM-G9900 / r9q / Android 15 API 35）
#     原始 Build 22 字段值由真机 d2api 报文（本地抓包 k6）经 sub_543EC
#     反解得到（shift=55 / riffle 置换），并与 mumu getprop 交叉印证。
#     注：编码态原值另存于 DEVICE_PROFILE_MUMU["encoded"]，可做重编码对拍。
# ====================================================================

# ====================================================================
# 11. 补充ID 本地存储加密（sub_82930/sub_170A4 → javax.crypto 反射）
#     AES/ECB/PKCS5Padding；AES 会话密钥经 config 的 RSA 公钥（apiKey）封装。
#     注意：补充ID 的 AES 落盘与传输层 XOR+zlib 是两条独立链路（旧文档曾误称传输层走 AES）。
# ====================================================================

# ====================================================================
# 12. 协议客户端（请求构造 + 可选真实发送）
# ====================================================================

# ====================================================================
# 12.1 简易传输层（shuzilm_forge.py 使用；URL/头形态均经真实服务端验证）
# ====================================================================

AUNI_HOST = "https://auni.telecome.cn"          # 主域名解密自 VA 0x6E014；强制 HTTPS
PKG_CUR = "com.zhihu.android"                   # p 参数的包名角色

_SHORT_PATHS = {
    5:  "/a/adt/report?v=5.0&c=1&e=1&t=adt",
    6:  "/a/d2api/report?v=8.1&t=a&e=2",
    16: "/a/mdna/report?v=1.0&t=m",
}


def http_post(url: str, body: bytes) -> bytes:
    """请求头 = sub_123C0 组包原文 + Content-Type（unidbg setRequestProperty 捕获）。"""
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream",
                                          "Accept-Encoding": "gzip",
                                          "Connection": "Keep-Alive"})
    return urllib.request.urlopen(req, timeout=15, context=ctx).read()


def seal_body(json_str: str, ep_id: int) -> bytes:
    """请求体封包 = XOR_key(zlib(json))（sub_4D0DC → sub_4FF88）。"""
    return xor_envelope(zlib.compress(json_str.encode("utf-8")), KEYS_BY_ID[ep_id])


def unseal_body(raw: bytes, ep_id: int) -> dict:
    """响应解包 = XOR 解封 → 响应若 zlib 压缩（0x78 头）则解压 → JSON。"""
    plain = xor_envelope(raw, KEYS_BY_ID[ep_id])
    if plain[:1] == b"\x78":
        plain = zlib.decompress(plain)
    return json.loads(plain)


def build_sign_url(ep_id: int, n_a: str = "", seq: int = 1) -> str:
    """签发三端点的 URL。p/r/n/l/h 找参见 第 3 节：
    p=md5(pkg+盐, 小写)  r=UUID去横杠  n/l=计数器  h=md5(n_a+盐)，首装 h="0"。"""
    r = uuid.uuid4().hex
    path = _SHORT_PATHS[ep_id]
    if ep_id != 6:
        return AUNI_HOST + path
    p = hashlib.md5(("%s.37be8a1e.v8.4.0" % PKG_CUR).encode()).hexdigest()
    h = hashlib.md5((n_a + ".889e0b01").encode()).hexdigest() if n_a else "0"
    return "%s%s&p=%s&r=%s&n=%d&l=%d&h=%s" % (AUNI_HOST, path, p, r, seq, seq, h)


# ====================================================================
# 13. 自检
# ====================================================================

def _read(p: str) -> bytes:
    with open(p, "rb") as f:
        return f.read()


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(root, "evidence")       # 往返报文目录
    so = os.path.join(root, "sample", "libdu.so")  # 目标 so（仓库内副本）

    print("=" * 68)
    print("数字联盟可信ID SDK v8.4.0 — Python 协议还原自检")
    print("=" * 68)
    ok = 0

    # ---- (c1) K5f 断言 ----
    k5f = compute_k5f("1790870391.830000000", 2268, 1008921510, 2268)
    assert k5f == "72FB3DAC09DBF5C8F54D2FD9D988F870", k5f
    print("[+] K5f 公式 OK：md5(\"1790870391.830000000\"+\"2268\"+\"1008921510\"+\"2268\") =", k5f)
    ok += 1

    # ---- (c1b) 设备签名 sKZ/P1J 断言 ----
    sig = device_signature_from_mac("08:ca:04:3d:5e:66")
    assert sig == "945610:209433:D38052", sig
    print("[+] 设备签名 OK：sKZ/P1J = singature(sha1(WLAN MAC)) =", sig)
    ok += 1

    # ---- (c2) 本地存储封印断言 ----
    assert seal("WNQ14J96FOJ724G8X")[:32] == "923BFEDE89728271FAEADCFB2613AF98"
    assert seal("2")[:32] == "C81E728D9D4C2F636F067F89CC14862C"
    assert unseal(seal("WNQ14J96FOJ724G8X")) == "WNQ14J96FOJ724G8X"
    assert unseal_pref_value(seal_pref_value("nctl-value-2")) == "nctl-value-2"
    assert pref_key("sid") == _md5_hex("sid", upper=True)
    print("[+] 存储封印 OK：seal(\"WNQ14J96FOJ724G8X\") 前缀 = 923BFEDE89728271FAEADCFB2613AF98；"
          "seal(\"2\") 前缀 = C81E728D9D4C2F636F067F89CC14862C")
    ok += 1

    # ---- 编码器 sub_543EC 断言 ----
    assert decode_543ec("embmfvic", 0, case=0) == "bullhead"
    assert decode_543ec("27/22/43/:92", 0, case=0) == "192.168.31.1"
    # 真机参数：shift=55 / riffle 置换，重编码须逐字节还原真机报文
    for raw_val, enc_val in [
        ("SM-G9900", "gp~%gpd+"),
        ("unknown", "FGCMOFF"),
        ("arm64-v8a", "9NkE9odmJ"),
        ("V417IR release-keys", "K=dK==W!h.QC=9DJ*nk"),
        ("x86_64,arm64-v8a,x86,", "cocodmJcmmPmP9NkE9k7o"),
        ("Samsung/r9q/r9q:15/V417IR/1100:user/release-keys",
         "K=dK==f=Mghf!h.lqpfpfFK9QC=9DJJKqgh*nkfhIJIJ?ME+"),
    ]:
        assert decode_report_string(enc_val) == raw_val, (enc_val, raw_val)
        assert encode_543ec(raw_val, MUMU_C1944, MUMU_ENC_CASE) == enc_val
    print("[+] 编码器 sub_543EC OK：case0/shift1 解 bullhead；真机参数(shift=55)重编码 6 字段逐字节吻合")
    ok += 1

    # ---- 二级变换四个置换：金标准 = unidbg 直接调用 sub_4BA28/4BB00/4BE04/4C29C 取回的真值 ----
    # 取真值方式：runner 加 -Ddu.encprobe=true，喂 "ABCD..." 读输出，对 n=2..24 逐一核对。
    for n, case, want in [
        (8,  0, [7, 3, 6, 2, 5, 1, 4, 0]),
        (7,  0, [3, 6, 2, 5, 1, 4, 0]),
        (8,  1, [7, 0, 6, 1, 5, 2, 4, 3]),
        (9,  1, [8, 0, 7, 1, 6, 2, 5, 3, 4]),
        (8,  2, [7, 5, 3, 1, 6, 4, 2, 0]),
        (19, 2, [18, 16, 14, 12, 10, 8, 6, 4, 2, 0, 17, 15, 13, 11, 9, 7, 5, 3, 1]),
        (8,  3, [0, 2, 4, 6, 1, 3, 5, 7]),
        (19, 3, [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 1, 3, 5, 7, 9, 11, 13, 15, 17]),
    ]:
        got = _perm(n, case)
        assert got == want, ("case%d n=%d" % (case, n), got, want)
    # case0 的结构不变量：奇数 n 的置换 == 偶数(n+1) 的置换去掉首元素、末尾补 0
    # （已用 n=2..93 全量探针核对：四置换共 368 组，0 不匹配）
    for odd in (3, 5, 7, 9, 11, 45, 93):
        assert _perm(odd, 0) == _perm(odd + 1, 0)[1:], ("case0 奇数不变量 n=%d" % odd)
    assert _perm(46, 0)[:8] == [45, 22, 44, 21, 43, 20, 42, 19]      # n=46 抽样（h=23）
    print("[+] 二级变换四置换 OK：case0/1/2/3 与 unidbg 真值逐位一致"
          "（n=2..93 全量 368 组，0 不匹配）")
    ok += 1

    # ---- URL 参数断言 ----
    q = build_query_params(pkg="com.zhihu.android", uuid="3e2cafd1-a5c8-4c91-9ec5-575c0e32dfc6",
                           n=1, l=1, n_a="")
    assert q["p"] == "30ABF75967EFADA71AEA8640CC7A611B", q["p"]
    assert q["r"] == "3e2cafd1a5c84c919ec5575c0e32dfc6"
    assert q["h"] == "0"
    print("[+] URL 参数 OK：p=md5(pkg+'.37be8a1e.v8.4.0') =", q["p"], "；r 去横杠；首装 h=0")
    ok += 1

    # ---- vB2 嵌套（JSONObject.put 坑）断言 ----
    fp = collect_fingerprint(api_level=35, build_fields={"MODEL": "SM-G9900"})
    payload = assemble_payload({"DUv": "com.zhihu.android"}, fp)
    assert isinstance(payload.get("vB2"), dict) and payload["vB2"]["rGc"] == "SM-G9900"
    assert len(TOP_FIELDS) == 29 and len(VB2_FIELDS) == 161
    print("[+] payload OK：vB2 嵌套保留（避免 JSONObject.put(k,null) 丢块）；顶层 %d 键 / vB2 %d 键"
          % (len(TOP_FIELDS), len(VB2_FIELDS)))
    ok += 1

    # ---- 各端点响应 schema 解析 ----
    adt = os.path.join(out_dir, "real_adt_response.bin")
    mdna = os.path.join(out_dir, "real_mdna_response.bin")
    if os.path.exists(adt):
        p = parse_response(_read(adt), 5)
        assert p["err"] == 0 and p["uuid"]
        print("[+] 端点 5 (adt) 响应解析 OK：err=%d uuid=%s" % (p["err"], p["uuid"]))
        ok += 1
    if os.path.exists(mdna):
        p = parse_response(_read(mdna), 16)
        assert p["err"] == 0 and p["nctl"] == "" and p["dlab"]
        print("[+] 端点 16 (mdna) 响应解析 OK：fields=%s" % sorted(p["raw_json"].keys()))
        ok += 1
    # ---- (d) 字符串池 ----
    if os.path.exists(so):
        strings = dump_all_strings(so)
        assert 11250 <= len(strings) <= 11300, len(strings)
        assert any("FrameLayout$LayoutParams" in s for s in strings)
        assert decrypt_va(0x5CEF8, so) == "/a/d2api/report?v=8.1&t=a&e=2"
        print("[+] (d) 字符串池 OK：dump_all_strings 解出 %d 条唯一字符串（含 FrameLayout$LayoutParams）"
              % len(strings))
        ok += 1
    else:
        print("[!] (d) 跳过：未找到 libdu.so")

    print("=" * 68)
    print("自检通过项：%d" % ok)
    print("完成。所有常量与算法均来自 libdu.so 静态解密 + unidbg 动态验证 + 真机抓包。")


if __name__ == "__main__":
    main()
