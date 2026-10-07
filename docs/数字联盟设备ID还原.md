# 数字联盟"可信 ID"（shuzilm）SDK v8.4.0 —— 完整还原文档

> 目标样本：知乎 Android 11.10.0 内嵌 `libdu.so`（arm64-v8a，`apk/lib/arm64-v8a/libdu.so`，v8.4.0，728KB，OLLVM）。
> 状态（2026-10）：**客户端全链路已跑通并拿到服务端签发**；本文给出 so 逻辑、协议、字段、算法、服务端行为。
> 已被推翻的旧结论在 第 12 节 集中列出并标注原因。
>
> 证据标注规则：`VA 0x…` = so 内虚拟地址；`sub_XXXXX` = so 内函数；`tools/…` = 仓库内证据文件；`out/…` = 本地工作产物（不入库）；日志行直接给行文。

---

## 1. 总体结论

1. **device_id（可信 ID / ms_id）由服务端签发**，客户端二进制内不存在 ID 生成算法。客户端职责 = 采集指纹 → 组包 → 编码/压缩/XOR 加密 → 上报 → 解析响应 → 落盘。
2. **客户端全链路已在 unidbg 上跑通，当前代码零注入**：不注入会话、不注入 device_id、不 patch 任何校验门；SDK 自己发出 `adt`（端点 5）/ `d2api`（端点 6）/ `mdna`（端点 16）的真实往返，服务端应答形如
   `{"err":"0","o_a":"…","n_a":"…","nctl":"2","cdd":"<ms_id>"}`（176 字节级）。
   证据：`out/du_run_real*.log`、`evidence/real_d2api_request.bin`、`evidence/real_d2api_response.bin`、`evidence/real_adt_request.bin/response.bin`、`evidence/real_mdna_*.bin`。
3. **服务端按设备稳定标识索引设备记录**：命中已有记录 → 回发原 `cdd`；未命中 → 签发新 ID。改 App 标识（URL 的 `p`）不影响结果（索引键是设备不是 App）；更换设备身份（指纹/MAC/boot_id 等）即得全新 ID。四组对照见第 15 节坑 A2。

- 样本 md5：`libdu.so = 536e303d11e1a44ad1c0fd6da4c94d45`；导出符号仅 `JNI_OnLoad` / `JNI_UnOnload`。
- JNI 注册表：`sub_7BCC4` → `RegisterNatives`，14 个方法注册到 `cn/shuzilm/core/DUHelper`（动态 dump 与静态分析逐项吻合，见 `evidence/natives_map.txt`）。

---

## 2. 字符串加密（sub_717C0，已完全恢复）

```
plain[k] = (enc[2k+1] - 1) ^ k      // 以 enc[2k+1] == 0 结尾
```

- blob 4 字节对齐内嵌 `.text`，**偶数位填充常为 0**，但它是数据的一部分，遍历/过滤**不能**用 `data[off]==0` 跳过，否则漏解（曾因此漏掉 `android/widget/FrameLayout$LayoutParams`）。
- 按 `enc[2k+1]==0` 正确判尾、穷举全 blob → **11272 条唯一字符串**（早期按错误过滤得到的 2097 条只是子集，该表可由 `tools/decrypt_strings.py` 现场生成）。
- 参考实现：`shuzilm_protocol.decrypt_blob / decrypt_va`；命令行工具 `tools/decrypt_strings.py`；IDA 脚本 `tools/ida/decrypt_request.py`。

---

## 3. 指纹采集

### 3.1 Build 常量 22 槽表

组装器 `sub_2B70C`（主构建器 `sub_27A0C` 状态 `0x348` 处调用）：函数指针表 `off_C1828`（表长函数 `sub_71908` 返回 22），每槽返回一个**解密后的 Build 字段名**，`sub_3A370` 用 `FindClass("android/os/Build")` + `GetStaticFieldID(name,"Ljava/lang/String;")` 取值，键名 `snprintf(buf,10,"rG%x",i)`（格式串 `rG%x` @VA `0x6C174`，索引十六进制格式化）。

| 槽 | 键 | Build 字段 | 门控 |
|---|---|---|---|
| 0 | rG0 | `SERIAL` | 仅 API ≤ 28 |
| 1 | rG1 | `BOARD` | — |
| 2 | rG2 | `BOOTLOADER` | — |
| 3 | rG3 | `CPU_ABI` | — |
| 4 | rG4 | `CPU_ABI2` | — |
| 5 | rG5 | `DEVICE` | — |
| 6 | rG6 | `DISPLAY` | — |
| 7 | rG7 | `FINGERPRINT` | — |
| 8 | rG8 | `HARDWARE` | — |
| 9 | rG9 | `HOST` | — |
| 10 | rGa | `ID` | — |
| 11 | rGb | `MANUFACTURER` | — |
| 12 | rGc | `MODEL` | — |
| 13 | rGd | `PRODUCT` | — |
| 14 | rGe | `TAGS` | — |
| 15 | rGf | `USER` | — |
| 16 | rG10 | `TYPE` | — |
| 17 | rG11 | `BRAND` | — |
| 18 | rG12 | `SKU` | 仅 API ≥ 31 |
| 19 | rG13 | `ODM_SKU` | 仅 API ≥ 31 |
| 20 | rG14 | `SOC_MANUFACTURER` | 仅 API ≥ 31 |
| 21 | rG15 | `SOC_MODEL` | 仅 API ≥ 31 |

门控实现在槽位函数内联比较 API 级别（`sub_8403C`），不满足则返回 0，组装器跳过该键。

附加键（表循环后追加）：

| 键 | 采集函数 | 语义 |
|---|---|---|
| `Kvr` | `sub_3A424` | `Build.getRadioVersion()`（基带版本） |
| `fKe` | `sub_3A550` | `Build.SUPPORTED_ABIS` 逐项逗号拼接（分隔符 `,` @`0x6BF88`） |
| `tNP` | `sub_3A4AC` | `Build.getSerial()`；内部错误码 `sub_85AF4()==10002` 时置空 |

Python 等价实现（含 API 门控）：`shuzilm_protocol.collect_fingerprint()`。

### 3.2 补充采集器族（载荷其它字段的数据源）

Java API 簇（`0x3xxxx`，各自 1-hit 特征串）：

| 函数 | 特征串 | 目标 |
|---|---|---|
| 0x35F1C / 0x360F4 / 0x36384 | `getImei` | IMEI（多版本分支） |
| 0x36FDC / 0x371D8 | `getSimSerialNumber` | SIM 序列号 |
| 0x3B1CC | `android_id` | ANDROID_ID |
| 0x3DD28 | `getMacAddress` | MAC |
| 0x3D7E4 | `android.intent.action.BATTERY_CHANGED` | 电池状态 |
| 0x3AE3C | `getSensorList` | 传感器清单 |
| 0x3BC60 | `ad_aaid` | 广告 ID（OAID 系） |
| 0x44E44 | `/sys/devices/system/cpu/present` | CPU 拓扑 |

系统属性簇（`0x7xxxx`，`__system_property_get` 封装）：0x72AE4 序列号多路回退（`ro.serialno`/`gsm.serial`/`ro.boot.ap_serial`/厂商定制 30+ 条）；0x72824 IMEI 属性回退；0x72460 蓝牙/WLAN MAC 属性回退；0x71F00 `xdpi/ydpi`；0x71F1C `ro.product.cpu.abi`。

条件回退采集器 `sub_417EC`：读 `Build.MANUFACTURER` 与两解密常量（`0x6C548`/`0x5CADC`）比对，命中跳过，否则 API≥20 走备选反射采集（降级路径）。

### 3.3 检测套件（环境对抗清单）

- **13 个改机包名黑名单**（`sub_477A0`，直接作为上报字段）：`com.soft.apk008v`、`com.sollyu.xposed.hook.model`、`com.android1500.androidfaker` 等。
- **6 文件探针**：`libnoxspeedum` / `Superuser.apk` / `microvirt-prop` / `libreference-ril` / `libnemuVMprop` / `ldinit`。
- `loadClass` 类探针（`sub_7B270`）；蓝牙配对计数（`sub_41D30`）；`ip neigh`（`sub_43AE0`）；数美共存（`sub_3B2E0`）。
- 字符串层还含：`frida-agent`、Xposed/Magisk/LSPosed 路径、Root 路径、模拟器特征（`vbox86p`/Nox/Andy/droid4x/KVM/`qemu.sf.lcd_density`）、自动化工具包名、假 MAC `11:22:33:44:55:66`、`__system_property_read_callback` hook 检测、`popen`（如 `cat /proc/meminfo`）。

> `android/widget/FrameLayout$LayoutParams`（VA `0x6e894`）**不是检测项**：完整跑通的一轮里 `sub_717C0` 实际只解密 1267 条字符串，view 相关仅 `()Landroid/view/Display;`（取屏幕分辨率，调用点 `lr=0x2e59c`）等 3 条，FrameLayout / View / WebView / findViewById / addView 均未被用到；该串无代码 xref、无指针引用，属 SDK 内未走到的残留。

---

## 4. 编码器 sub_543EC（字符串值混淆）

所有上报字符串值 put 进 JSON 前经 `sub_543EC(env,key,value,env2,type)`：

```
① 合法性：逐字符检查 32..126 可打印
② 移位：shift = (dword_C1944 % 100) % 57 + 1        # 1..57
        逐字符 c += shift; if (c > 0x7E) c -= 95      # 95 可打印字符循环
③ 二级变换（按 (dword_C1944 / 100) % 4 选）—— 四个都已还原为纯标量置换：
   case 0: sub_4BA28 — 「尾部降序 / 前半降序」交错
           偶 n：out[2i]=in[n-1-i], out[2i+1]=in[h-1-i]   (h=n/2)
           奇 n：out = 偶(n+1) 的置换去掉首元素，即 out[2i]=in[h-i], out[2i+1]=in[2h-i]，末尾补 in[0]
   case 1: sub_4BB00 — 前后半交错：out[2i]=in[n-1-i], out[2i+1]=in[i]，奇 n 中间元素放最后（n=8→[7,0,6,1,5,2,4,3]）
   case 2: sub_4BE04 — 奇位降序 + 偶位降序（n=8→[7,5,3,1,6,4,2,0]），**真机 MuMu 走的就是它**
   case 3: sub_4C29C — 偶位升序 + 奇位升序（n=8→[0,2,4,6,1,3,5,7]）
④ sub_540C0 put 编码值
```

**等价性已严格验证（非抽样、非近似）**：runner 加 `-Ddu.encprobe=true` 直接用 unidbg 调用
`sub_4BA28/4BB00/4BE04/4C29C`（黑盒，不靠反汇编 NEON 猜），输入用 33..126 的**互不相同**字节
（不能用 `A-Z` 循环，n>26 会重复导致无法唯一反推），读输出缓冲 `byte_C31C0`。
覆盖 **n = 2..93**（真机最长字段 46 字符的两倍余量），**四个置换合计 368 组，0 不匹配**。

- 状态源 `dword_C1944`（getter `sub_85DC4`）= `atoi(点分字符串末段≤4字符)`，输入串 ≥12 字符且带点。**unidbg 环境输入为空 → C1944=0 → shift=1 / 变换=case0**。
- **真机 MuMu 的 C1944 = 254**（不是 154）：`(254%100)%57+1 = 55` 给出 shift=55，`(254/100)%4 = 2` 给出 case2；
  若取 154 则 shift 对但 case 会算成 1（走 sub_4BB00），与真机报文矛盾。判定依据：真机 6 个字段
  （含 48 字符 FINGERPRINT）用 shift=55 + case2 重编码逐字节吻合。
- 解码实证 7/7：`R30="embmfvic"→"bullhead"`、`R3d→"Nexus 5X"`、`R25→"Wed Sep 30 19:53:14 UTC 2015"`、`R2a→"vpef12.mtv.corp.google.com"`、`R55→"America/New_York"`、`R97→"192.168.31.1"`、`R2d→"0157b34321c72505"`。

---

## 5. 请求构建 sub_27A0C 与字段 schema

主请求构建器 `sub_27A0C`（OLLVM 扁平化状态机 `dword_C1030/C1034`），状态 `0x348` 调用 `sub_2B70C`（rG 清单）、`sub_2B8AC`（附加装配）、`sub_275D4`（收尾）。

### 5.1 密钥结构：vB2 必须嵌套承载整个指纹块

**签发请求体必须以 `vB2` 嵌套对象承载整个指纹块**。真机 d2api 请求 5314 字节明文，顶层 29 键，`vB2` 内约 150 键。
证据：`evidence/real_d2api_request.bin`、`out/payload_1_0x5a5.bin`（本地留存）。

> ❌ 早期失败形态：模拟 JNI 的 `JSONObject.put(String,Object)` 对对象值取 `getValue()` 得 null，而 org.json 的 `put(key,null)` 语义是**删除键** → 整块指纹被静默丢弃 → 服务端只回裸 `{"err":"0"}`。修好 `put` 桥后才拿到签发。

### 5.2 顶层其它字段（全量字段名词表）

| 键 | 语义 | 值来源 |
|---|---|---|
| `2CP` / `vB2` / `pr2` / `iWf` | 配置与上报参数 | `sub_85F1C`/`0x8601C`/`0x85EDC`/`0x85F5C`/`0x85FDC` 配置族 |
| `v1X` / `B7G` / `ubF` / `hd7` | 补充采集字段 | `sub_1CBDC/1D0DC/1D3EC/1DF9C/2058C/23048/25EB8/25288` 族 |
| `My2` / `B3k` / `eBI` / `kz6` | 补充采集字段 | `sub_30F00+sub_54688`、`sub_3137C`、`sub_2BB54` 族 |
| `9mU` / `3k2` / `E7R` / `o7k` | 会话/统计字段 | 同上配置/状态族 |
| `ni` | 通知/标志位（int，`%d` @`0x69988`） | 内部状态 |
| `na_seq_ni` / `na_rseq_ni` | 请求/响应序列号（单调递增，防重放） | `sub_55708` |
| `cdd` | 既有 device_id（首装为空） | 本地存储 |
| `o_a` | 服务端旧回执（客户端校验长度 ≥11） | 本地存储 |


### 5.3 K5f 公式（实测验证）

```
K5f = upper( hex( md5( fmt % (sessionStr, getpid(), rand(), gettid()) ) ) )
fmt = "%s%d%d%d"        # 解自 so VA 0x66864
键名 "K5f"              # VA 0x6BEF8
逻辑在 sub_25958
```

样例：`md5("1790870391.830000000" + "2268" + "1008921510" + "2268") == 72fb3dac09dbf5c8f54d2fd9d988f870`。
含 `rand()/getpid()/gettid()`，**每次进程必然不同**，与真机值不可比（真机值也不可复现，属正常）。

---

## 6. 设备签名 sKZ / P1J

**来源：sKZ = f(hash(WLAN MAC))**，实测日志链：

```
[md5] update([BII) ascii=08:ca:04:3d:5e:66
[md5] digest -> e945610d380522094330cb3e861395b8022a503e
put sKZ = 945610:209433:D38052
```

**拼接规则**（从摘要 bit 偏移 4 起，每 24bit 切一组，按 `组0:组2:组1` 顺序冒号拼接，第三段大写）：

- 组0 = 摘要[1:7] = `945610`
- 组1 = 摘要[7:13] 大写 = `380522` → `D38052`
- 组2 = 摘要[13:19] = `209433`
- 输出 = `组0:组2:组1` = `945610:209433:D38052` ✓

`P1J` 同族（同一 md5 摘要的不同切片/编码，日志中与 `sKZ` 一同 put）。

---

## 7. 传输协议

### 7.1 端点与 XOR 密钥表

来源：`sub_848B8`（端点选择器）+ `sub_847F0`（密钥选择）+ `sub_4FF88`（`data[i]^=key[i%len]` 对称信封）+ 解密字符串。完整表见 `shuzilm_protocol.ENDPOINTS` / `KEYS_BY_ID`：

| 端点 | URL 路径（解密原文） | XOR 密钥（KEYS_BY_ID） |
|---|---|---|
| 1 | `/a/dai/report?v=2.2&c=1&e=1` | `@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!` |
| 2 | `/a/daa/report?v=1.1&c=1&e=1` | `li~jl#etu98v2f!edv3o5$%^&+=90`-)tqw$jqu@7v6.a1` |
| 3 | `/a/ldc/report?v=1.0&c=1&e=1` | `69tr_ew+>:oi}12q{k40#$%<as)78dfghuyj5l;][p3^&*(` |
| 4 | `/a/dcc2/request?v=2.0&c=1&e=1` | `$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb` |
| 5 | `/a/adt/report?v=5.0&c=1&e=1&t=adt` | `Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W` |
| 6 | `/a/d2api/report?v=8.1&t=a&e=2`（主通道） | `9+=%^8>:oi}12q5l;]q|{2f8v>?:[ss%^&fq5$baf7fq+=d-0` |
| 8 | `/siieuu93pasidovna/shuzilm/tra_file`（配置/文件下发） | — |
| 9 | `/a/aads/request?v=1.0&t=ads` | `.}pmn];1tsb^x*,-09+=87f4TWq&/56%o,<v2$%>?:['|` |
| 13 | `/a/audd/valid?v=1.0&t=uid1` | `7.f498yu<>?:['|TWq&/57fqu@7v6.ajl#etu{.jqv2fs` |
| 14 | `/a/audd/token?v=1.0&t=uid2` | 同 13 |
| 16 | `/a/mdna/report?v=1.0&t=m` | `ts!ed%$bt&/57+=n];18u{.j=90f9`-)qu@7|.}pm^&+v2` |

真机主机：`auni.telecome.cn` / `optn.shuzilm.cn` / `ipv4|ipv6.shuzilm.cn` / `cbsipv4.shuzilm.cn` / `auni.unioncom.cc` / `global-auni.checktrustworthiness.com`，端口 **18447**。
so 内另存 `api.shuzilm.cn`、`daa.shuzilm.cn`、`d2api-test.shuzilm.cn`、`download.shuzilm.cn` 及旧版本协议串（`v=5.0`/`v=7.2`/`v=2.2`）。

### 7.2 主通道（端点 6）报文形态

```
POST https://<host>/a/d2api/report?v=8.1&t=a&e=2
     &p=md5(getPackageName + ".37be8a1e.v8.4.0")   # 盐值 37be8a1e
     &r=UUID.randomUUID().toString() 去横杠
     &n=<dword_C1934>&l=<dword_C1938>
     &h=md5(n_a + ".889e0b01")                      # 盐值 889e0b01；首装 n_a 空 → 字面量 "0"
Body   = XOR_key6( zlib( 编码后的指纹 JSON ) )          # 大包压缩，阈值内小包可不压缩
Header = Accept-Encoding: gzip / Host / Connection: Keep-Alive
```

- 传输层是 **XOR 信封 + zlib**（`sub_4FF88` + `sub_4D0DC`），**不是 AES**；AES/ECB/PKCS5 只用于**补充 ID 的本地落盘**（`sub_4F9CC`/`sub_4FCB4`），见 第 9 节。
- so 用 `java.net.URL` + `HttpURLConnection` 反射发起传输（TLS 由 Java 层承担）。

### 7.3 响应 schema（so 侧解析）

解析器：`sub_779EC`（端点 6）/ `sub_751E8`（端点 16）/ `sub_79978`（audd 族）。

```json
{
  "err": "0",        // 门控：atoi==0 才继续
  "nctl": "1",       // 1 → 新 ID 在 ocdd / sid；2 → 新 ID 在 cdd
  "ocdd": "<ms_id>", // nctl=1 时的签发 ID → 存 "sid"+"device_id"
  "cdd":  "<ms_id>", // nctl=2 时的签发 ID → 存 "cdd"+"device_id"
  "state_ni": "4",   // 双写校验（sub_84534）
  "n_a": "…",        // 会话值；=="000000" 视为无效（服务端也用全 0 标无效）
  "o_a": "…",        // 会话票据，长度≥11 才收，下次请求回带
  "aid": "…",        // → 存储 + 暗备 /e2dfcfaa
  "sci": "…",        // → 存为配置键 "duscid"
  "nsci": "…",       // → 存为配置键 "ZHVzY2Lk"
  "ueJ": "1",        // =1 时删除 nhst/ncht（主机重定向令牌失效）
  "nhst": "…", "ncht": "…",   // 服务器可下发新 Host 重定向
  "denv": "…", "dlab": "…",   // dlab → device_label
  "isem": "…", "itime": …, "mdrt": …,
  "oaid": "…", "ioaid": "…",
  "i1".."i9": "…"    // 补充 ID
}
```

**签发实测响应**（零注入实测）：`{"err":"0","o_a":"…","n_a":"…","nctl":"2","cdd":"<ms_id>"}`。即 nctl=2，新 ID 落在 `cdd`。

- **audd 挑战-应答链**（端点 13/14，实测存活）：`/a/audd/valid` 回 `{"WP3":"0","YdJ":"0","xGh":"2592000"}`（err=WP3、状态=YdJ、3 天有效窗）；`/a/audd/token` 回 `{"WP3":"0","YdJ":"0","7Cu":""}`（令牌槽 `7Cu`）。请求体 `sub_7AEC0`：`sub_2CD9C` JSON + `yQD` + `n9j(dword_C191C)` + `dN0` + `Y4c(byte_113DAC 回环)` + `TV5` + `xD5`；token 的 `Y4c/n9j` 来自前次响应回填。

---

## 8. 服务端行为

1. **签发响应**：`err=0` + `o_a/n_a/nctl/cdd`（见 第 7.3 节）。
2. **按设备稳定标识索引**：同一设备身份重复上报 → 回发同一 `cdd`（不重新签发）；换新设备身份（Build/属性/boot_id/MAC 全换）→ 签发全新 `cdd`。`o_a` 始终回显上报的设备签名（`sha1(WLAN MAC)` 切片），可用于验证签名计算是否正确。
   → 结论：要拿新 ID 就换设备身份；`shuzilm_forge.py` 即按此每次生成全新设备并签发。
3. `HAG` 是固定值：即 APK 内置 `assets/cn.shuzilm.config.json` 的 `apiKey`（512-bit RSA 公钥），按 App 构建固定，服务端不下发也不回显，且**不参与签发门控**（不带它照样拿到签发）。

---

## 9. 本地存储

- **文件路由** `sub_55848(env,ctx,type)`（被 `55A70`/`558F4` 调用）：`FMT='%s%s'`，type1 后缀 `_prefs` → `<pkg>_prefs.xml`（全部会话状态）；type2 后缀 `_dna` → `<pkg>_dna.xml`（**device_id / ms_id 封印体**）。
- **物理键名** = `md5(逻辑键名)` 的大写 hex（如 `md5("sid")=B8C1A306…`）。
- **值封印格式** = `UPPER(hex(md5(payload[:64]))) + payload`（前 64 字符精确校验，内存写断点实证，重编码逐字节吻合）。
- **dna 提取公式**（对任意真机 dna.xml 可用）：

```python
import base64
raw = base64.b64decode(xml值["device_id"])
ms_id = raw[32:].decode()     # 前 32 字符 = md5(ms_id[:64]) 完整性封印，可本地校验
```

> 真机 dna.xml 也可能直接存 RAW sid（88 字符 DU 形态），两种形态都见过：真机=RAW，unidbg 封印测试=带 32 字符前缀包装。

- **两个文件的写入点**：`sub_1884C`（→ sid0/device_id 落盘）、`sub_84534`（sid/cdd/state_ni 双写校验，worker `7C14C` 直调 3 处）；取值器 `sub_762E0`（经常量表按 nctl 选键 `sid`/`cdd`）。
- **补充 ID（i0..i9）**：AES/ECB/PKCS5 加密落盘（`sub_82930` 写 / `sub_170A4` 读），AES 会话密钥经 config 的 RSA 公钥（`X509EncodedKeySpec`+`KeyFactory`）协商。
- **so 自有 sqlite**：`zx.db` / `zx_table`，列名为 3 字符不透明键。
- **本地回环 HTTP 服务**（"ID 导出"）：native 自带 HTTP/1.1 实现，绑定 `0.0.0.0`，端口 `mPort`（muMu 实测 `bind 0.0.0.0:19910`；Java 层 `mPort` 为 `hash(pkg+Build.MODEL)%5000 + ~60000 + firstInstallTime%10000`，失败回退 17835），存在 `duid` 端点（VA `0x681b4`，引用 `sub_1B474`）。

---

## 10. unidbg 动态复现（把 so 整个跑起来）

静态还原之外，`libdu.so` 已在 unidbg 里**完整跑通**：SDK 自己发出 `adt`/`d2api`/`mdna` 真实请求，
服务端返回完整签发应答。这是判定"协议还原是否正确"的最终依据。

### 10.1 目录与依赖

| 项 | 位置 | 说明 |
|---|---|---|
| runner 源码 | `unidbg/runner/` | `DuRunner.java` + `pom.xml`（仓库内，自包含） |
| unidbg 源码 | 自行 `git clone https://github.com/zhkl0228/unidbg` | 按 `unidbg/patch/` 打补丁后 `mvn install` |
| 目标 so | `sample/libdu.so` | v8.4.0 / arm64 / OLLVM |
| 工作目录输入 | `tools/mumu_props.txt`、`tools/rootfs/` | runner 从 outDir 读取（739 条属性 + 伪文件系统） |
| 工具链 | JDK 21 + Maven | unidbg 依赖 class 65，须 JDK 21 |

unidbg 侧必要改动（否则跑不起来，共 5 文件）：上游大量"未实现即抛异常"的分支正好被
libdu.so 的风控探测踩中，异常从 syscall handler 抛出会**打断整个 emulation**。关键三处：

1. `UnixSyscallHandler.resolve()` —— `stat("/proc/self/fd/")` 切出空串，`parseInt("")` 抛 `NumberFormatException`。
2. `ARM64SyscallHandler` —— `socket(AF_NETLINK, SOCK_RAW)` / `socket(AF_INET, SOCK_RAW)` 抛 `UnsupportedOperationException`；
   `openat` 的 pathname 为 null 或 normalize 后为 null 时 NPE。
3. `NetLinkSocket` —— 11 个方法由 `throw` 改为 benign no-op。

**完整补丁与逐条改动说明见 `unidbg/patch/`**：

| 补丁 | 规模 | 内容 |
|---|---|---|
| `unidbg-libdu.patch` | 5 文件 | 跑通必需的改动（上列三类 + `DalvikVM64` + `pom.xml`） |

改完在 `unidbg-src\unidbg-api` 跑（只改 api 时）：

```
mvn -o -DskipTests "-Dgpg.skip=true" install
```

### 10.2 运行

**必须带 `compile` 目标** —— `mvn exec:java` 是单目标、不触发编译，改了 Java 源码会跑旧 class
（坑过多轮，见坑档 C1）：

```bash
# 1) 准备工作目录（runner 从中读 mumu_props.txt / rootfs，并写出报文与日志）
mkdir -p work && cp tools/mumu_props.txt work/ && cp -r tools/rootfs work/

# 2) 跑 runner（参数：<libdu.so> <outDir>）
cd unidbg/runner
mvn -o compile exec:java "-Dexec.args=../sample/libdu.so ../work"
```

### 10.3 开关

| 开关 | 默认 | 作用 |
|---|---|---|
| `-Ddu.verbose=true` | false | JNI 逐调用日志（`[jni-obj]`/`[put]`/`[md5]`/`[enc]`） |
| `-Ddu.strtrace=true` | false | 打印运行期**实际被解密**的每个字符串 + 调用点（一轮约 1200 条） |
| `-Ddu.encprobe=true` | false | 编码器探针：直接调 `sub_4BA28/4BB00/4BE04/4C29C` 取真实置换后即退出 |
| `-Ddu.randdev=true` | false | 随机化设备属性（Build/属性/boot_id/WLAN MAC）→ 服务端按设备索引，每次都签新 ID |
| `-Ddu.norop=true` | false | 连设备属性也不伪装（对照实验） |
| `-Ddu.queryType=N` | 2 | `query()` 第 4 参 → 落到 `sub_82FBC` / `dword_C1938` |
| `-Ddu.syscall=true` | false | syscall 直方图（看死循环卡在哪个 syscall） |

### 10.4 怎么判定跑通

只看两行：

```
[fwd] -> http://auni.telecome.cn/a/d2api/report?v=8.1&t=a&e=2 (≈1.9KB)
[fwd] <- 200 174B
```

174 字节且能解出 `nctl`/`cdd` 即为**服务端已签发**：

```json
{"err":"0","o_a":"945610:209433:D38052","n_a":"WNQ14J96FOJ724G8X","nctl":"2","cdd":"DU2ovjZ…c2h1"}
```

若只回 `{"err":"0"}`（11 字节）→ 指纹块没进请求体，多半是 `vB2` 嵌套丢了（坑档 A1）。

### 10.5 产物

| 路径 | 说明 |
|---|---|
| `evidence/real_{adt,d2api,mdna}_request.bin` | 三端点真实请求体（zlib+XOR 后） |
| `evidence/real_{adt,d2api,mdna}_response.bin` | 对应真实应答 |
| `out/json_req_*.json` | 每次 `put` 后的 payload 快照（本地留存） |
| `out/sp_writes.log` | SDK 写 SharedPreferences 的记录（本地留存） |
| `evidence/natives_map.txt` | `JNI_OnLoad` 后 DUHelper 注册的 native 方法表 |
| `out/run_*.log` | 各次运行日志（本地留存；`run_encprobe2.log` = 编码器探针 368 组真值） |
| `out/so_url.txt` / `out/so_body.bin` | so 自产的 URL 与请求体（本地留存） |

### 10.6 姿态与既有环境要点

默认即"**只伪装设备属性**"：注入 `SYS_PROPS`/`mumu_props.txt`/Build 字段/rootfs 伪文件
（否则全空 Build 会被 SDK 判成"环境不通过"），**不注入真机会话、不注入 device_id、
不 patch 任何门控/校验函数、不伪造摘要结果**。仅保留两条**管道修补**（非校验伪装）：
`sub_56F84→RET`（清理函数在 unidbg 上会读未映射内存）、`sub_85484→port`
（Windows 上 :80 被 http.sys 占用，故把 so 的出网端口改到本地转发端口）。

其余环境要点：

- so 传输链：`openConnection → setRequestMethod(POST) → setProperty → setDoOutput → connect → getOutputStream → new DataOutputStream(os) → DataOutputStream.write([B) → close → getResponseCode(200) → NewByteArray(1024) → getInputStream → read([B)`
  - 写走的是 `DataOutputStream.write([B)`，**不是** `OutputStream.write`；响应注入点 = `java/io/InputStream->read(` 的 `callIntMethodV`。
- 指纹采集崩溃根因（已修）：`sub_49220` 经 `qword_C3010` 派发函数指针，该表只由 `sub_4A134()` 写入；
  未初始化时 `ldr x0,[x8,w0,sxtw#3]` 读地址 0 → `UC_ERR_READ_UNMAPPED`，采集在建完 Build 字段后即死。
- worker `0x7C018` 是永不退出的守护循环（sigaction 心跳），`0x760E4/0x75F84` 是 rtnetlink 永驻监听 —— 同步驱动一律跳过。
- 状态机路径非确定性：patch 组合变化会翻转 `27A0C` 的字段集（R* 86 字段 ↔ 替代字段组），跨运行差分不可靠。

---

## 11. 证据与产物索引

仓库内文件（均可复现）：

| 路径 | 说明 |
|---|---|
| `sample/libdu.so` | 目标 so（v8.4.0，arm64，OLLVM 加固） |
| `tools/ida/*.py`、`ida/ask_addrs.json` | IDA 批处理脚本（字符串解密、定向反编译、槽位/编码器 dump） |
| `tools/decrypt_strings.py` | 字符串池全量解密（11272 条） |
| `evidence/real_{adt,d2api,mdna}_{request,response}.bin` | 三端点真实往返报文 |
| `tools/mumu_props.txt`、`tools/rootfs/` | unidbg 复现所需的模拟器属性与伪文件系统 |
| `evidence/natives_map.txt` | `JNI_OnLoad` 后 DUHelper 注册的 native 方法表 |
| `unidbg/patch/` | unidbg 跑通补丁（必需 5 文件） |
| `docs/` | 本档案、技术文档、探索记录 |

其余运行日志、抓包、payload 快照、反编译转储均为本地工作产物（`out/`），不入库。

---

## 12. 已被推翻的旧结论

早期若干判断（unidbg 无法签发、服务端固定签发、传输层 AES+RSA、请求体必须字节级保真、sKZ 用 md5、HAG 参与门控等）已由实测推翻，以正文各节结论为准。

---

## 13. 纯 Python 签发链路（shuzilm_forge.py）

传输助手（`http_post`/`seal_body`/`unseal_body`/`build_sign_url`）在 `shuzilm_protocol.py`
第 12.1 节。三步流程：`adt(5) → d2api(6) → mdna(16)`，adt 返回 `MnE` → d2api 的 `JFN` →
d2api 返回 `nctl`+`cdd`（ms_id）。

零捕获依赖：不读任何捕获文件，逐键构造 adt/d2api/mdna 三个请求体。

```bash
python shuzilm_forge.py          # 随机全新设备 → 三步链路 → 全新 ms_id
python shuzilm_forge.py --dump   # 只构造+落盘 out/forge_*.json，不联网
```

要点（详见坑 A7 新版与文件头注释）：

1. **键集对拍零差异**：三端点键集与捕获 schema 完全一致（adt 46 / d2api 210 含 vB2 / mdna 52）后才联网。
2. **编码性逐键判定**（500 的真凶）：`decode_543ec(捕获值)` 得干净语义值 = 编码键（R*/rG*/Kvr/fKe、UUID ED2/mIS/VUZ、APK 路径 Cl5、IP 列表 iYB.MCN、GPS G8U.H4S、位标志 LAh/90P 等），走 `encode_543ec(明文,0,0)`；解码得垃圾 = 裸值（时间戳、MAC LLS、md5 ne8、统计 xRD、传感器 41j/fM0）。
3. **一致性绑定**：sKZ=P1J=sig(sha1(MAC1))、AYk=sig(sha1(MAC2))、ED2=mIS=boot_id、R1e=`android-`+android_id、JFN=adt 回传 MnE。
4. **`2cO` 必须保持字符串**（`%.8f`），转 float 曾致 mdna 400。
5. 随机设备档：6 品牌族 × model/device/fingerprint + MAC×2 + android_id + boot_id + serial + 运营商 + 时区 + GPS + IP。

实测（2026-10-07）：两连发两台设备两个全新 ID（`DU7gEeve...` / `DUGYDh1x...`），均不在历史 ID 集。所谓"JSON 重序列化→500、必须字节级保真"已推翻——服务端不在乎键序，只在乎每键编码性与值格式正确。

---

## 14. checkid 校验方法

`checkid.py` 是校验壳：抓包后把 URL 与请求头填入其中的空占位，然后起服务：

```bash
python checkid.py
curl "http://127.0.0.1:5000/checkid?ms_id=<待验证ID>"
```

候选 `ms_id` 会被填入 `x-ms-id` 头后重放：返回 200 且带搜索结果 = 通过；403 = 不通过。

会话头约 5 天过期，过期后连原 ID 也会 403，重新抓包填入即可。

校验实测（2026-10-07）：抓包原 ID 200；构造签发的两个全新 ID 均 200；拼凑的垃圾 ID 403。

---

## 15. 坑清单（已合并原《坑与注意事项》，文中"见坑 A2"等引用均指本节）

| # | 坑 | 根因 → 修法 |
|---|---|---|
| A1 | 指纹整块被静默丢弃，只回裸 `{"err":"0"}` | 签发体必须 `vB2` 嵌套承载指纹；JNI 桥 `put(key,null)` 触发 org.json 删键 → 桥必须正确序列化对象值 |
| A2 | 误判"服务端固定签发" | 服务端**按设备稳定标识索引**（命中回发原 ID/未命中签新 ID）；四组对照：unidbg 仿真/旧MuMu `a543208bbf9cf92a`→`DU2ovjZ1`，新模拟器 `199daa693856d3ed`→`DUk8KSE2`，randdev#1→`DUJDRqzz`，#2→`DU4CMB7W` |
| A3 | HAG 参与签发门控 | APK 内置 RSA 公钥，不带照样签发 |
| A4 | adt/mdna 400/500 判为服务端缺陷 | 报文格式错误；正确 vB2 报文三端点正常 |
| A5 | K5f 与真机不一致 | 含 rand/pid/tid 必然每次不同，只验公式自洽 |
| A6 | 传输层误判 AES+RSA | 实为 XOR 信封+zlib；AES-ECB 仅补充 ID 本地落盘 |
| A7 | 500 误判"必须字节级保真" | 真因=编码性错标+case0 奇 n bug；JSON 键序无所谓；`2cO` 保持字符串 `%.8f`；随机化在 unidbg 仿真层或 forge 构造层做 |
| B1 | Build 采集后崩溃 UC_ERR_READ_UNMAPPED | `qword_C3010` 函数指针表未初始化 → 显式调 `sub_4A134()` |
| B2 | R* 误判"第三层加密配置系统" | 就是 unidbg 自带 Android 6.0 镜像真实指纹；改镜像即可 |
| B3 | 字符串解密漏解（2097 vs 11272） | 判尾=`enc[2k+1]==0`，偶数位是填充不能当结束符 |
| B4 | FrameLayout$LayoutParams 误判检测项 | 无 xref 的残留 |
| B5 | MessageDigest.update 被吞，摘要恒空 | receiver 必须用方法入参 dvmObject（VaList 不含 this） |
| B6 | sKZ 拼接规则错 | `sha1(MAC带冒号)`（非 md5）→ `d[1:7]:d[13:19]:d[7:13]` **三组全大写** |
| B7 | 编码器置换猜错 | 用 unidbg 直接调用四变换实测（encprobe，n=2..93）；探针输入须互不相同字节 |
| C1 | `mvn exec:java` 跑旧 class | 必须带 `compile` |
| C2 | javac 编译"成功"运行旧类 | 必须 `-d classes` |
| C3 | 改 target/classes 无效 | classpath 里 JAR 内旧资源优先 → classes 放前或同步改 JAR |
| C4 | IDA 二次打开 .i64 报 error 4 | 换名全新分析（约 90s） |
| C5 | MSYS 路径转换 | `MSYS_NO_PATHCONV=1`；openssl `-subj` 用 `//CN=`；**`-Dexec.args` 必须 Windows 风格路径**，否则 outDir 失效 → mumu_props.txt 静默不加载 → query 返回 null 无上报 |
| C6 | `StringObject(vm, null)` NPE | 仿真层返回空串替代 null |
| C7 | compress 内嵌 emulateFunction CME | 用 Java 原生 Deflater 替代 |
| C8 | `Settings$Secure.getString` 拦截不到 | 它是静态方法，须在 `callStaticObjectMethodV` 中处理 |
| D1 | 钩 OutputStream.write 抓不到请求体 | so 走 `DataOutputStream.write([B)`；响应注入点 `InputStream.read` 的 `callIntMethodV` |
| D2 | worker 守护循环永不退出 | 0x7C018=心跳守护、0x760E4/0x75F84=rtnetlink 监听 → 跳过 jobs 直接调目标通道 |
| D3 | SDK 不启动 | 隐私弹窗必须点同意（MuMu 900×1600 上"同意并继续"在 450,1421） |
| D4 | MuMu adb 连不上 | `MuMuManager.exe adb -v 0` 查端口；`adb kill-server` 清 offline |
| D5 | checkid 老 ID 也 403 | 会话头约 5 天过期 → 先传抓包原 ID 自证会话再验候选（第 14 节） |
| D6 | 跨 patch 组合差分不可靠 | 状态机路径非确定性 → 固定 patch 组合再比较 |
| E1 | 手造结构完美 ID 直发 checkid | 403（签发记录校验） |
| E2 | P34 密文反推 | 228 种客户端变换全阴性，25B 为服务端密码学输出 |
| E3 | 合成会话值注入 | 早期无 vB2 嵌套所致（见 A1） |
| E4 | 修改 R* 找"第三层配置" | 见 B2 |
