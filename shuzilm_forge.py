#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
数字联盟可信 ID —— 全新设备 forge（不读任何捕获 .bin，逐键构造请求）
=====================================================================
随机一台全新设备，从零构造 adt(5)/d2api(6)/mdna(16) 三个请求体并签发全新 ms_id。
键建模规则、找参出处、校验方法见《数字联盟可信ID逆向分析》与《数字联盟设备ID还原》。

用法：
  python shuzilm_forge.py                # forge 三步链路，签发全新 ms_id
  python shuzilm_forge.py --dump         # 只打印构造的请求体（不联网）
"""

import sys, os, json, hashlib, uuid, time, random, string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shuzilm_protocol import (encode_543ec, compute_k5f,
                              http_post, seal_body, unseal_body, build_sign_url, PKG_CUR)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
PKG = PKG_CUR

# 已知历史 ms_id（签出其中任何一个都说明随机化没生效，要报警）
KNOWN_IDS = {
    "DU2ovjZ1Tnj5Ks-nZjJp6wLbRtQCvT-1MldaRFUyb3ZqWjFUbmo1S3MtblpqSnA2d0xiUnRRQ3ZULTFNbGRhc2h1": "旧 MuMu / unidbg 默认仿真身份",
    "DUk8KSE2EIMCLk4O5K-DlYvRSefnPTwWIG1cRFVrOEtTRTJFSU1DTGs0TzVLLURsWXZSU2VmblBUd1dJRzFjc2h1": "新模拟器 7555 (Xiaomi cupid)",
    "DUJDRqzzn5GU7G0HlM9KSKNdFA12Hibite46RFVKRFJxenpuNUdVN0cwSGxNOUtTS05kRkExMkhpYml0ZTQ2c2h1": "unidbg randdev#1 (OnePlus)",
    "DU4CMB7W2CWsij7x2YdULQdnCXUNDUyfQd73RFU0Q01CN1cyQ1dzaWo3eDJZZFVMUWRuQ1hVTkRVeWZRZDczc2h1": "unidbg randdev#2 (Google)",
}

# ── 随机设备档案 ──────────────────────────────────────────────
# 品牌族（model/device/fingerprint 生成器按各家真实格式建模）
def _dev_profile(r: random.Random) -> dict:
    fam = r.choice([
        {"br": "Xiaomi",  "hw": "qcom",   "mk": "qualcomm", "mdl": lambda: f"2{r.randint(10,25)}0{r.randint(10,99)}{r.choice('ABCX')}",
         "dv": lambda: f"missi_{r.choice(['phone','pad'])}" },
        {"br": "OPPO",    "hw": "qcom",   "mk": "QTI",      "mdl": lambda: f"P{r.choice('DEFHK')}M{r.randint(10,99)}",
         "dv": lambda: f"OP{r.randint(4,5)}{r.choice('ABC')}{r.randint(1,9)}{r.choice('L')}" },
        {"br": "vivo",    "hw": "qcom",   "mk": "qualcomm", "mdl": lambda: f"V{r.randint(21,30)}{r.choice('ABC')}A",
         "dv": lambda: f"PD{r.randint(21,32)}{r.randint(10,99)}" },
        {"br": "HONOR",   "hw": "kirin900", "mk": "HISI",   "mdl": lambda: f"HON-{r.randint(100,999)}",
         "dv": lambda: f"HNY{r.choice('ABCX')}-{''.join(r.choices(string.digits, k=2))}" },
        {"br": "Samsung", "hw": "exynos", "mk": "samsung",  "mdl": lambda: f"SM-S{r.randint(90,94)}{r.choice('BEUN')}{r.randint(0,9)}",
         "dv": lambda: f"r{r.choice('abcde')}{r.choice('qs')}" },
        {"br": "Google",  "hw": "tensor", "mk": "google",   "mdl": lambda: f"Pixel {r.randint(6,9)}",
         "dv": lambda: r.choice(["raven", "oriole", "panther", "cheetah", "lynx"]) },
    ])
    brand   = fam["br"]
    model   = fam["mdl"]()
    device  = fam["dv"]()
    product = device
    mfr     = {"Xiaomi": "Xiaomi", "OPPO": "OPPO", "vivo": "vivo", "HONOR": "HONOR",
               "Samsung": "Samsung", "Google": "Google"}[brand]
    api     = r.choice([31, 32, 33, 34, 35])
    blid    = "".join(r.choices(string.ascii_uppercase + string.digits, k=6))   # rGa/R2b ID
    offset  = str(r.randint(1000, 9999))                                       # 构建偏移
    host    = f"bld{r.randint(100000, 999999)}"                                # rG9/R2a 构建主机
    user    = f"builder{r.randint(10, 99)}"                                    # rGf
    dl      = f"{blid} release-keys"                                           # rG6/R27 DISPLAY
    fp      = f"{brand}/{device}/{device}:{api-20}/{blid}/{offset}:user/release-keys"   # rG7/R28
    desc    = f"{device}-{model}-user {api} {blid} {offset} release-keys"       # R26 构建描述
    mac1    = ":".join(f"{b:02x}" for b in [r.randint(0,255) for _ in range(6)])  # WLAN MAC
    mac2    = ":".join(f"{b:02x}" for b in [r.randint(0,255) for _ in range(6)])  # 第二网卡（LLS/AYk）
    aid     = "".join(r.choices("0123456789abcdef", k=16))                     # ANDROID_ID
    boot_id = str(uuid.UUID(int=r.getrandbits(128), version=4))                # ED2/mIS
    return {
        "brand": brand, "mfr": mfr, "model": model, "device": device, "product": product,
        "board": device, "hardware": fam["hw"], "soc_mfr": fam["mk"],
        "soc_model": fam["mk"].upper(), "api": api, "blid": blid, "offset": offset,
        "host": host, "user": user, "display": dl, "fp": fp, "desc": desc,
        "mac1": mac1, "mac2": mac2, "aid": aid, "boot_id": boot_id,
        "radio": f"1.0.{r.randint(10000,99999)}.0", "baseband": f"M{r.randint(8000,9999)}F-{r.randint(1,3)}.{r.randint(10,60)}.{r.randint(10,99)}.0.{r.randint(10,99)}",
        "serial": "0x" + "".join(r.choices("0123456789abcdef", k=66)),
        "sku": str(r.randint(1000,9999)), "odm_sku": str(r.randint(1000,9999)),
        "carrier": r.choice(["China Mobile GSM", "China Unicom 3G", "China Telecom 4G", "CHINA MOBILE"]),
        "tz": r.choice(["Asia/Shanghai", "Asia/Shanghai", "Asia/Urumqi"]),
        "ringtone": r.choice(["Alarm_Classic.ogg", "Argon.ogg", "Helium.ogg", "Krypton.ogg"]),
        "color": r.choice(["orange", "black", "white", "blue", "mint"]),
        "abis": "arm64-v8a,armeabi-v7a,armeabi",
        "apk_path": f"/data/app/~~{uuid.uuid4().hex[:22]}==/{PKG}-{uuid.uuid4().hex[:22]}==/base.apk",
        "ip4": f"192.168.{r.randint(0,31)}.{r.randint(2,254)}",
        "gps": f"{r.uniform(-90,90):.6f},{r.uniform(-180,180):.6f}",
    }

def _sig(mac: str) -> str:
    """sKZ/P1J/AYk 设备签名：sha1(MAC) 切片 g0=d[1:7], g2=d[13:19], g1=d[7:13]，全大写。"""
    d = hashlib.sha1(mac.encode()).hexdigest()
    return f"{d[1:7]}:{d[13:19]}:{d[7:13]}".upper()

_E = lambda s: encode_543ec(s, 0, 0)   # C1944=0（unidbg 捕获同参数，服务端已验证可解）

_MONTH = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
_WDAY  = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

def _build_date(r: random.Random) -> str:
    """R25 构建时间：'Tue Sep 29 13:28:26 UTC 2026'（asctime 风格，解密实证）。"""
    t = int(time.time()) - r.randint(30, 400) * 86400
    tt = time.gmtime(t)
    return f"{_WDAY[tt.tm_wday]} {_MONTH[tt.tm_mon-1]} {tt.tm_mday:2d} {tt.tm_hour:02d}:{tt.tm_min:02d}:{tt.tm_sec:02d} UTC {tt.tm_year}"

# ── 请求体构造 ────────────────────────────────────────────────
def forge_bodies(verbose=False, seed=None):
    """返回 (bodies, prof, meta)。bodies = {"adt": dict, "d2api": dict, "mdna": dict}。
    所有键按捕获 schema 逐键构造；设备标识字段全部随机全新。"""
    r = random.Random(seed)
    now_ms = int(time.time() * 1000)
    p = _dev_profile(r)
    sig1, sig2 = _sig(p["mac1"]), _sig(p["mac2"])
    k5f = compute_k5f(f"{time.time():.9f}", r.randint(2000, 9999), r.getrandbits(31), r.randint(2000, 9999))
    jfn = uuid.uuid4().hex    # 无 adt 会话时 so 回填 boot_id 去横杠；forge 先占位，签名后由 adt MnE 覆盖

    # ---- vB2 指纹块（144 键，编码性逐键判定）----
    vb2 = {
        # ── rG*：android.os.Build 22 槽（组装器 sub_2B70C / 键名 snprintf("rG%x",i)）──
        "rG1": _E(p["board"]),          # BOARD
        "rG2": _E("unknown"),           # BOOTLOADER
        "rG3": _E("arm64-v8a"),         # CPU_ABI
        "rG5": _E(p["device"]),         # DEVICE
        "rG6": _E(p["display"]),        # DISPLAY
        "rG7": _E(p["fp"]),             # FINGERPRINT
        "rG8": _E(p["hardware"]),       # HARDWARE
        "rG9": _E(p["host"]),           # HOST
        "rGa": _E(p["blid"]),           # ID
        "rGb": _E(p["mfr"]),            # MANUFACTURER
        "rGc": _E(p["model"]),          # MODEL
        "rGd": _E(p["product"]),        # PRODUCT
        "rGe": _E("release-keys"),      # TAGS
        "rGf": _E(p["user"]),           # USER
        "rG10": _E("user"),             # TYPE
        "rG11": _E(p["brand"]),         # BRAND
        "rG12": _E(p["sku"]),           # SKU（API≥31 才采）
        "rG13": _E(p["odm_sku"]),       # ODM_SKU
        "rG14": _E(p["soc_mfr"]),       # SOC_MANUFACTURER
        "rG15": _E(p["model"]),         # SOC_MODEL
        "Kvr": _E(p["radio"]),          # Build.getRadioVersion()
        "fKe": _E(p["abis"]),           # SUPPORTED_ABIS 逗号拼接
        # ── R*：系统属性/环境族（采集后必经 543EC）──
        "R1e": _E("android-" + p["aid"]),   # ANDROID_ID 串
        "R1f": _E(p["brand"].lower()),      # 品牌（小写）
        "R20": _E("BHZ10i"),                # 基带模块 id（族字面量）
        "R23": _E("default"),               # net 策略?
        "R24": _E(str(int(time.time()) - r.randint(30, 400) * 86400)),  # 构建时间戳
        "R25": _E(_build_date(r)),          # 构建日期串
        "R26": _E(p["desc"]),               # ro.build.description
        "R27": _E(p["display"]),            # display 副本
        "R28": _E(p["fp"]),                 # fingerprint 副本
        "R2a": _E(p["host"]),               # 构建主机副本
        "R2b": _E(p["blid"]),               # ID 副本
        "R2c": _E("user"),                  # type
        "R2f": _E("196610"),                # 版本号字面量（捕获同族）
        "R30": _E(p["model"]),              # model 副本
        "R31": _E(p["brand"]),              # brand 副本
        "R33": _E("arm64-v8a"),             # ABI 副本
        "R34": _E(str(p["api"] - 3)),       # SDK 串（捕获: SAN=35/R34='32'）
        "R37": _E(p["brand"]),              # brand 副本
        "R38": _E("1"),                     # 布尔标志（捕获 '2'↔'1'）
        "R3a": _E("HSPA"),                  # 网络类型
        "R3d": _E(p["model"]),              # model 副本
        "R41": _E("13"),                    # 版本族字面量
        "R43": _E("android-" + p["brand"].lower()),
        "R44": _E(p["device"]),             # device 副本
        "R45": _E("false"),
        "R47": _E("1"),
        "R4a": _E("unknown"),
        "R4f": _E("1"),
        "R53": _E("0"),                     # 捕获 '1'↔'0'
        "R55": _E(p["tz"]),                 # 时区
        "R59": _E("true"),
        "R5a": _E(r.choice(["46000", "46001", "46002", "46007"])),  # MCC+MNC
        "R63": _E("running"),               # 采集状态
        "R64": _E(p["brand"].lower()),
        "R68": _E(p["serial"]),             # 序列号 0x+66hex
        "R8":  _E("wlan0"),                 # 网卡名
        "Ra":  _E("LOADED"),                # 电池状态
        "Ra1": _E(p["abis"]),               # ABIS 副本
        "Ra2": _E("31"),                    # API 字面量（捕获同族）
        "Ra5": _E(p["carrier"]),            # 运营商
        "Ra9": _E(p["baseband"]),           # 基带版本
        "Raa": _E("BHZ10i"),
        "Rab": _E(p["ringtone"]),           # 铃声文件
        "Rad": _E(f"{p['device']}-{p['model']}-user"),  # 构建描述短版
        "Rb0": _E("REL"),                   # VERSION.RELEASE codename
        "Rb3": _E("adb"),                   # sys.usb.config
        "Rbd": _E("1"),
        "Rc":  _E("1.0.0.0"),               # radio 副本
        "Rd":  _E("android reference-ril 1.0"),
        "Rd0": _E(p["mfr"]),                # 厂商显示名
        "Rd2": _E("1"),
        "Ree": _E(p["color"]),              # 机身颜色
        "Rf6": _E("1"),
        # ── 环境串（解码实证：UUID/路径/IP/GPS/位标志）──
        "ED2": _E(p["boot_id"]),            # boot_id UUID
        "mIS": _E(p["boot_id"]),            # boot_id 副本
        "VUZ": _E(str(uuid.UUID(int=r.getrandbits(128), version=4))),  # 第二 UUID（媒体/DRM id 族）
        "Cl5": _E(p["apk_path"]),           # APK 安装路径
        "foO": _E("".join(r.choices("0123456789abcdef", k=16))),  # 16hex 设备 id 变体
        "UOv": _E(f"{time.time():.9f}"),    # epoch 纳秒精度
        "LAh": _E("11111111"),              # 位标志（捕获 '22222222'↔'11111111'）
        "90P": _E("00"),
        "9N2": _E("0,0"),                   # 传感器极值对
        "Bn2": _E("0,0"),
        "VIB": _E("2,1"),
        "w5v": _E("1"),
        "iYB.MCN": _E(f"[fd17:{uuid.uuid4().hex[:4]}:{uuid.uuid4().hex[:4]}::3, {p['ip4']}]"),  # 本机 IP 列表
        "iYB.txo": _E("wlan0"),
        "iYB.AWo": _E("0000000010"),        # 位标志串
        "G8U.H4S": _E(p["gps"]),            # GPS 坐标
        # ── 裸值（decode 得垃圾：时间戳/MAC/哈希/统计）──
        "2cO": f"{time.time():.8f}",        # epoch 秒（8 位小数，字符串）
        "6yY": "0" * 32,                    # 位图
        "LLS": p["mac2"].upper(),           # 第二网卡 MAC（裸）
        "ne8": hashlib.md5((p["aid"] + p["boot_id"]).encode()).hexdigest(),  # 32hex 设备哈希
        "xRD": ",".join(str(r.randint(100, 999999)) for _ in range(10)) + ",",  # 统计 CSV
        "9pz": "100483",
        "sfOo": "".join(r.choices("0123456789ABCDEF", k=7)),
        "anY": "1000000",
        "zc7": "0001",
        "JPd": "0", "bf7": "0", "qH9": "0",
        "zpA": "WIFI",                      # 网络类型（d2api 里在 vB2 内）
        "9P6": "",                          # 空串（捕获同）
        "qdK": _E(str(r.randint(2200, 5000))),  # 电池容量 mAh（捕获 dec='3161'）
        # ── 整型/字面量（非设备标识，保持捕获族值）──
        "JIi": 0, "wlM": 0, "B1q": 1196, "cmP": r.randint(1, 2**31 - 1),
        "0qI": 0, "sCc": 0, "QQW": 0, "9be": -1, "XH7": 0, "2Lp": 0,
        "iZS": 0, "t7Q": 0, "vv1": 0, "cfx": 0, "LkB": 0, "S6e": 0,
        "nur": 1, "XQp": 18564, "z4e": 0, "eTk": 0, "qUM": 0, "I68": 0,
        "QgA": 0, "fxb": 368, "JYD": 0, "5y9": 1, "tth": 1, "J7w": 0,
        "4VP": 0, "NAB": 0, "84j": 18564, "sJN": 0,
        # ── 嵌套子对象 ──
        "TwQ": {"zm4": 402, "NZE": 403, "AJd": 0, "1Lx": 2340, "NlZ": 1080},  # 屏幕密度/分辨率
        "kKW": {"P9K": 0, "6sB": 0, "LjE": 0, "Fuv": 0, "2dz": 0, "5Uy": 0,
                "7Df": 25, "YQ3": 0, "AMZ": 0, "IpF": 1, "Lwi": 0},
        "0qN": {"j3i": 0, "09L": 0, "X7y": 0, "teO": "0", "Zpd": 0},
        "iYB": {},   # 占位，下面填充（MCN/txo/AWo 编码值引用 prof）
        "2us": {"DHU": "0", "jIO": "0", "7Gf": "0", "WJr": "0", "EIS": "0"},
        "uCM": {"I2Y": 0, "LzC": 0, "pnb": 0, "nF5": 0, "fgm": 0, "YXM": 0},
        "G8U": {},   # 占位
        "B7G": {}, "7S2": {}, "oJI": {},
    }
    vb2["iYB"] = {"8tS": 60000, "MCN": vb2.pop("iYB.MCN"), "AWo": vb2.pop("iYB.AWo"),
                  "txo": vb2.pop("iYB.txo"), "Hsz": 12000}
    vb2["G8U"] = {"H4S": vb2.pop("G8U.H4S")}

    # ---- 顶层 ----
    # 三端点顶层键集不同（对拍捕获 schema 实测）：
    #   adt/d2api/mdna 共同：SAN/BBB/DUV/h8h/Zrs/tth/EV2/GVp/AAA/3mS/DUv/P1J/sKZ/AYk
    #   仅 adt：ZZA/LkB/S6e/QgA/nur/XQp/wlM/iZS/z4e/J7w/4VP/zpA
    #   仅 d2api：2CP/3k2/9mU/E7R/hd7/41j/fM0/eBI/s4j1/sf0M/K5f/LMi/Qg1/B3k/vB2
    #   仅 mdna：cHo/Db2/QVn/mIS/ne8/foO/R1e/sfOo/6yY/LMi/Qg1/B3k/K5f
    sensors = "e6;74;6c;19;g9;c"   # 传感器族字面量（裸值）
    common = {
        "SAN": p["api"], "BBB": "v1.0", "DUv": PKG, "h8h": 0, "Zrs": 0,
        "tth": 1, "EV2": "11.10.0", "GVp": "DefaultChannel", "AAA": "v1.0",
        "3mS": "v8.4.0", "P1J": sig1, "sKZ": sig1, "AYk": sig2,
    }
    # adt+mdna 共有的整型/标志组（d2api 没有；mdna 无 z4e）
    adt_mdna_ints = {"ZZA": 0, "LkB": 0, "S6e": 0, "QgA": 0, "nur": 1,
                     "wlM": 0, "iZS": 0, "J7w": 0, "4VP": 0}
    adt = dict(common)
    adt.update(adt_mdna_ints)
    adt.update({
        "XQp": 18564, "zpA": "WIFI", "z4e": 0,
        "JFN": jfn,
        "R41": _E("13"), "R63": _E("running"), "Ra": _E("LOADED"),
        "LAh": _E("11111111"), "w5v": _E("1"), "90P": _E("00"),
        "UOv": _E(f"{time.time():.9f}"), "R5a": _E("46000"),
        "JPd": "0", "qH9": "0", "zc7": "0001", "R53": _E("0"), "bf7": "0",
        "R3d": _E(p["model"]), "R37": _E(p["brand"]), "7Gf": "0",
        "ED2": _E(p["boot_id"]),
        "iYB": vb2["iYB"], "7S2": {},
        "2cO": f"{time.time():.8f}",
    })
    d2 = {
        "SAN": p["api"], "BBB": "v1.0", "DUv": PKG, "h8h": 0, "Zrs": 0,
        "EV2": "11.10.0", "GVp": "DefaultChannel", "AAA": "v1.0",
        "3mS": "v8.4.0", "P1J": sig1, "sKZ": sig1, "AYk": sig2,
        "JFN": jfn, "LMi": now_ms, "Qg1": now_ms - 2, "K5f": k5f,
        "2CP": "0.004000", "3k2": "0.002000", "9mU": "0.001000",
        "E7R": "0.002000", "hd7": "0.025000",
        "41j": sensors, "fM0": sensors,
        "eBI": "5", "s4j1": "0C048B3", "sf0M": "0C048B3",
        "B3k": r.randint(1000, 2000),
        "vB2": vb2,
    }
    mdna = dict(common)
    mdna.update(adt_mdna_ints)
    mdna.update({
        "JFN": jfn, "LMi": now_ms, "Qg1": now_ms - 2, "K5f": k5f,
        "cHo": 0, "Db2": 101, "QVn": 31, "zpA": "WIFI",
        "R63": _E("running"), "LAh": _E("11111111"), "90P": _E("00"),
        "UOv": _E(f"{time.time():.9f}"), "qH9": "0", "JPd": "0",
        "R53": _E("0"), "bf7": "0",
        "sfOo": vb2["sfOo"], "R1e": vb2["R1e"], "foO": vb2["foO"],
        "R41": _E("13"), "Ra": _E("LOADED"),
        "iYB": vb2["iYB"], "7S2": {}, "6yY": "0" * 32,
        "B3k": r.randint(1000, 2000),
        "mIS": _E(p["boot_id"]), "ne8": vb2["ne8"],
        "R3d": _E(p["model"]), "R37": _E(p["brand"]),
        "2cO": f"{time.time():.8f}",
    })
    return {"adt": adt, "d2api": d2, "mdna": mdna}, p, {"sig1": sig1, "sig2": sig2, "k5f": k5f}

# ── 链路 ──────────────────────────────────────────────────────
def run_forge(verbose=True, dump_only=False):
    log = (lambda *a: print(*a)) if verbose else (lambda *a: None)
    bodies, prof, meta = forge_bodies()
    log(f"随机设备: {prof['brand']} {prof['model']} dev={prof['device']} api={prof['api']}")
    log(f"  MAC1={prof['mac1']} MAC2={prof['mac2']}")
    log(f"  android_id={prof['aid']} boot_id={prof['boot_id']}")
    log(f"  fp={prof['fp']}")
    log(f"  sKZ={meta['sig1']}  AYk={meta['sig2']}")

    if dump_only:
        for name, b in bodies.items():
            path = os.path.join(OUT_DIR, f"forge_{name}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(b, f, ensure_ascii=False, indent=1)
            log(f"  {name}: {len(json.dumps(b, separators=(',',':')))}B → {path}")
        return None, bodies

    results = {}
    # ① adt → MnE
    log("── [1/3] adt (端点 5) ──")
    raw5 = http_post(build_sign_url(5), seal_body(json.dumps(bodies["adt"], separators=(",", ":")), 5))
    resp5 = unseal_body(raw5, 5)
    results["adt"] = resp5
    mne = resp5.get("MnE", "")
    log(f"    MnE = {mne}  ({len(raw5)}B)")
    if mne:
        jfn = mne.replace("-", "")
        bodies["d2api"]["JFN"] = jfn
        bodies["mdna"]["JFN"] = jfn

    # ② d2api → 签发
    log("── [2/3] d2api (端点 6) ──")
    body6 = json.dumps(bodies["d2api"], separators=(",", ":"))
    url6 = build_sign_url(6, n_a="", seq=1)
    raw6 = http_post(url6, seal_body(body6, 6))
    resp6 = unseal_body(raw6, 6)
    results["d2api"] = resp6
    log(f"    响应 {len(raw6)}B")
    ms_id = resp6.get("cdd") or resp6.get("ocdd") or ""
    log(f"    err={resp6.get('err')} nctl={resp6.get('nctl')} n_a={resp6.get('n_a')}")
    if ms_id:
        if ms_id in KNOWN_IDS:
            log(f"    ✗✗ 返回了已知历史 ID（{KNOWN_IDS[ms_id]}）—— 随机化失效！")
        else:
            log(f"    ✓ 全新 ms_id = {ms_id}")

    # ③ mdna
    log("── [3/3] mdna (端点 16) ──")
    try:
        raw16 = http_post(build_sign_url(16), seal_body(json.dumps(bodies["mdna"], separators=(",", ":")), 16))
        resp16 = unseal_body(raw16, 16)
        results["mdna"] = resp16
        log(f"    响应 {len(raw16)}B")
    except Exception as e:
        log(f"    mdna 跳过（非必需）: {e}")
        results["mdna"] = {"skipped": True}

    with open(os.path.join(OUT_DIR, "forge_result.json"), "w", encoding="utf-8") as f:
        json.dump({"ms_id": ms_id, "profile": prof, "meta": meta, "results": results},
                  f, ensure_ascii=False, indent=2, default=str)
    log("结果已保存: out/forge_result.json")
    return ms_id, results

if __name__ == "__main__":
    print("=" * 60)
    print("数字联盟可信 ID —— 全新设备 forge（零捕获依赖）")
    print("=" * 60)
    if "--dump" in sys.argv:
        run_forge(dump_only=True)
        sys.exit(0)
    ms_id, _ = run_forge()
    sys.exit(0 if ms_id else 1)
