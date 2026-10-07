# AGENTS.md

本仓库是数字联盟（Shuzilm）可信 ID SDK `libdu.so` v8.4.0 的协议还原与 Python 复现。

## 布局

| 路径 | 内容 |
|---|---|
| `shuzilm_protocol.py` | 协议库：字符串解密、端点/XOR 秘钥、编码器 `sub_543EC`、指纹表、K5f/设备签名、响应解析、传输助手 |
| `shuzilm_forge.py` | 签发：随机设备 → 逐键构造 adt/d2api/mdna 请求 → 全新 `ms_id` |
| `checkid.py` | 校验：候选 `ms_id` 填入 `x-ms-id` 头，重放抓包请求 |
| `docs/` | 发布稿、探索记录、技术档案（找参出处与坑清单） |
| `sample/libdu.so` | 分析目标（arm64，OLLVM 加固） |
| `tools/` | 解密器、IDA 脚本、unidbg 复现输入（`mumu_props.txt`、`rootfs/`） |
| `evidence/` | 三端点真实往返报文、JNI 方法表 |
| `unidbg/runner/`、`unidbg/patch/` | 动态复现入口与 unidbg 补丁 |

`out/` 为本地工作目录（日志、抓包、payload 快照），不入库。

## 关键事实

1. `ms_id` 由服务端签发，端侧只有协议：采集指纹 → 组包 → 编码/压缩/XOR → 上报 → 解析响应。
2. 服务端按设备稳定标识索引设备记录：同一身份重复上报回发原 `cdd`，换新身份签发新 ID；URL 的 `p`（App 标识）不影响结果。
3. 传输层 = 每端点独立 XOR 秘钥 + zlib；AES-ECB 仅用于补充 ID 本地落盘。

## 报文硬约束

- 指纹块嵌在顶层 `vB2` 对象内（顶层 28 键 + `vB2` 内 144 键）；缺嵌套则服务端只回 `{"err":"0"}`。
- 编码/裸值逐键判定：`R*`/`rG*`/`Kvr`/`fKe`、UUID（`ED2`/`mIS`/`VUZ`）、`Cl5`、`iYB.MCN`、`G8U.H4S`、位标志经 `sub_543EC` 编码；时间戳、`LLS`、`ne8`、`xRD` 为裸值。判据：`decode_543ec(值, 0, 0)` 能解出干净语义值即为编码键。
- 编码统一用 `encode_543ec(明文, 0, 0)`（C1944=0 → shift=1 / case0）。
- `2cO` 保持字符串（`%.8f`）。
- 绑定关系：`sKZ = P1J = sha1(MAC1)` 切片（三组全大写）、`AYk = sha1(MAC2)`、`ED2 = mIS = boot_id`、`R1e = "android-" + android_id`、`JFN` = adt 回显的 `MnE` 去横杠。
- 键序无关，无需字节级序列化一致。

## 命令

```bash
pip install requests flask

python shuzilm_protocol.py        # 离线自检（10 项）
python shuzilm_forge.py           # 随机新设备签发 → 全新 ms_id
python shuzilm_forge.py --dump    # 只构造请求体落盘 out/，不联网
python checkid.py                 # 校验服务（0.0.0.0:5000），再 curl /checkid?ms_id=<ID>
```

## 提交规则

- 不提交凭据：`checkid.py` 只留空占位，抓包内容填本地副本 `checkid.local.py`（已 gitignore）。
- 不入库：`apk/`、`out/`、`*.apk`、`*.i64`、`unidbg-src/`、`unidbg/runner/target/`。
- 保持单提交历史（`--amend` + `--force`）。
