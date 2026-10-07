# 数字联盟可信 ID 逆向（libdu.so v8.4.0）

逆向知乎 Android 客户端内嵌的数字联盟（Shuzilm）「可信 ID」SDK，还原设备 ID（`ms_id`）签发协议，
并用纯 Python 从零构造请求向真实服务端签发全新 ID，最后通过知乎真实接口校验其有效性。

> 本项目由 AI（ZCode / GLM）辅助完成分析与实现。仅供技术研究，请勿用于非法用途。

## 仓库结构

```
├── shuzilm_protocol.py     # 协议库：字符串解密 / XOR 信封 / 编码器 / 指纹 / 传输助手
├── shuzilm_forge.py        # 签发：随机全新设备，逐键构造 adt→d2api→mdna 三步请求
├── checkid.py              # 校验：ms_id 填入 x-ms-id 头打知乎真实接口（200 有效 / 403 拒绝）
├── docs/
│   ├── 数字联盟可信ID逆向分析.md   # 技术文档（精简发布稿）
│   ├── 探索记录.md                 # 探索时间线：误判与推翻过程
│   └── 数字联盟设备ID还原.md       # 完整技术档案：找参出处、坑清单（第 15 节）
├── sample/libdu.so         # 目标样本（v8.4.0 / arm64 / OLLVM）
├── tools/
│   ├── decrypt_strings.py  # 字符串池全量解密器
│   ├── ida/                # IDA 脚本（字段解密 / 批反编译 / 编码器与槽位 dump）
│   ├── mumu_props.txt      # unidbg 复现用模拟器属性（739 条）
│   └── rootfs/             # unidbg 复现用伪文件系统
├── evidence/               # 三端点真实往返报文 + JNI 方法表
└── unidbg/
    ├── runner/             # DuRunner.java + pom.xml（动态复现入口）
    └── patch/              # unidbg 跑通补丁（5 文件）
```

## 快速开始

```bash
pip install requests flask

# 1. 签发一个全新 ms_id（每次运行 = 一台随机新设备）
python shuzilm_forge.py

# 2. 校验 ms_id 在知乎侧是否有效（需先按 docs 第 14 节抓包真机搜索请求写入 HEADERS）
python checkid.py
curl "http://127.0.0.1:5000/checkid?ms_id=<待验证ID>"

# 3. 协议库离线自检（字符串解密 / 信封 / 编码器往返）
python shuzilm_protocol.py
```

## 核心结论速览

| 项 | 结论 |
|---|---|
| ID 来源 | 服务端签发，端侧无本地算法 |
| 传输 | 每端点独立 XOR 秘钥 + zlib（非 AES/RSA） |
| 报文 | 顶层 28 键 + `vB2` 嵌套指纹块（144 键），字符串经 `sub_543EC` 混淆 |
| 服务端行为 | 按设备稳定标识索引：命中回发原 ID，未命中签发新 ID |
| 构造签发 | 键集/编码性逐键对拍后全量构造，可稳定获得全新 ID |
| 有效性 | 构造签发的 ID 通过知乎 `search_v3` 真实接口校验（`x-ms-id` 头） |

详见 [docs/数字联盟可信ID逆向分析.md](docs/数字联盟可信ID逆向分析.md)。

## 环境说明

- Python 3.10+（`requests`、`flask`）即可跑通签发与校验链路。
- unidbg 动态环境（JDK21 + Maven）为可选的对照验证手段：把 `unidbg/patch/unidbg-libdu.patch`
  应用到 unidbg 源码树后运行 `DuRunner`，命令与参数见 docs/数字联盟设备ID还原.md 第 10 节。
- `out/` 为本地工作目录（运行日志、抓包、临时产物），整体不入库（见 `.gitignore`）。
