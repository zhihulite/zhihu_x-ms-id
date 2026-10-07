# unidbg 复现补丁（libdu.so 跑通所需）

本目录让 `数字联盟设备ID还原.md` 第 10 节 的 unidbg 复现**自包含**：只要有 upstream unidbg + 本补丁即可重建，无需任何被就地改过的源码树。

## 1. 基线

| 项 | 值 |
|---|---|
| upstream | `https://github.com/zhkl0228/unidbg` |
| 基线 commit | `2ded0545d4ae053055f469ef4a4c49e3f15196a7`（2026-09-28） |
| 版本 | `0.9.10-SNAPSHOT` |
| 我们源树的来源 | 更早的上游快照（约 2026-09-08），故补丁里含少量"回退新版配置"的行 |

## 2. 应用方式

| 补丁 | 文件数 | 内容 | 是否必打 |
|---|---|---|---|
| `unidbg-libdu.patch` | 5 | 跑通 libdu.so 必需的改动 | **必打** |

```
git clone --depth 1 https://github.com/zhkl0228/unidbg.git unidbg
cd unidbg
git apply /path/to/unidbg-libdu.patch
```

补丁已通过 `git apply --check`，应用后与源树比对 **5/5 文件一致**。

> **行尾提示**：源树为 LF；Windows + `core.autocrlf=true` 下打完工作区是 CRLF，语义完全一致。

## 3. 改动清单

| # | 文件 | 改动 | 必需性 |
|---|---|---|---|
| 1 | `unidbg-api/.../unix/UnixSyscallHandler.java` | `resolve()` 里 `/proc/<pid>/fd/`、`/proc/self/fd/` 的 fd 解析加空串保护 | **必需** |
| 2 | `unidbg-android/.../linux/ARM64SyscallHandler.java` | `openat`：pathname 为 null 或 normalize 后为 null → 返回 `-ENOENT`（原为 NPE） | **必需** |
| 2 | 同上 | `socket()`：`SOCK_RAW` → 建 `TcpSocket`（原为 `UnsupportedOperationException`） | **必需** |
| 2 | 同上 | `socket()`：`AF_NETLINK` 的 `SOCK_RAW`/default → 建 `NetLinkSocket`（原为抛异常） | **必需** |
| 2 | 同上 | `case 134`（sigaction）：worker 守护循环计数有界化，仅当 `-Ddu.phase=jobs` 时生效 | 调试辅助（默认惰性） |
| 3 | `unidbg-android/.../linux/file/NetLinkSocket.java` | 11 个方法由 `throw UnsupportedOperationException` 改为 benign no-op（`read`→0、`getTcpNoDelay`→0、各 setter 空实现、`getLocalSocketAddress`→`InetSocketAddress(0)`、`connect_ipv4/6`→0） | **必需** |
| 4 | `unidbg-android/.../linux/android/dvm/DalvikVM64.java` | 一个 JNI 桩返回 `0`（double 0.0）而非抛异常 | **必需** |
| 5 | `pom.xml` | javadoc 插件加 `<skip>true</skip>` | **必需**，见 第 4 节 |

> 第 2 项里的 `case 134` 那条惰性调试 hunk 仍留在必需补丁中（它和必需 hunk 同处一个文件，
> 拆开会牺牲补丁的可应用性；它只在显式传 `-Ddu.phase=jobs` 时才有行为，默认完全惰性）。

### 为什么 1/2/3 项是必需的

libdu.so 一启动就会做风控与环境探测，这些探测正好踩在 unidbg 的"未实现即抛异常"分支上，
异常会从 syscall handler 抛出并**打断整个 emulation**（表现为采集到一半就死、或 query 卡死）：

- `stat("/proc/self/fd/")` → 空串 `parseInt` → `NumberFormatException`
- `socket(AF_NETLINK, SOCK_RAW, ...)`（rtnetlink 监听）→ `UnsupportedOperationException`
- `socket(AF_INET, SOCK_RAW, ...)` → 同上
- `openat` 传 null / 非常规路径 → `NullPointerException`
- NetLinkSocket 上的 `setTcpNoDelay` / `getLocalSocketAddress` 等 → 同上

## 4. 两处需要留意


**(b) `pom.xml` 的 hunk 顺带回退了 upstream 新版 javadoc 配置**：因为我们源树基于更早的上游，
该 hunk 把 upstream 新增的 `<executions><goal>jar</goal></executions>` 一并去掉了。
只要最小改动的话，保留 `executions`、仅加一行 `<skip>true</skip>` 即可。

## 5. 构建与安装

改完源树后**必须**重新安装到本地 Maven 仓库，`DuRunner` 依赖的就是这份本地快照：

```
cd unidbg
mvn -o -DskipTests "-Dgpg.skip=true" install
```

只改了 `unidbg-api` 时可只装该模块：

```
cd unidbg/unidbg-api
mvn -o -DskipTests "-Dgpg.skip=true" install
```

然后按 `数字联盟设备ID还原.md` 第 10.2 节 跑 runner（注意必须带 `compile` 目标）。

## 6. 本补丁的验证结论

| 检查 | 结果 |
|---|---|
| `git apply --check` 于基线 commit `2ded0545` | **通过（exit 0）** |
| 补丁应用后与源树比对（5 个文件，忽略行尾） | **5/5 完全一致** |
| 行尾差异 | 仅 CRLF/LF（本机 `autocrlf`），内容无差异 |
| 补丁规模 | 201 行 / 5 文件 |

改动的定位过程：上游树无 `.git`，无法直接 diff，因此按 mtime 圈出"检出时间之后被动过"的源码文件，
再用 `git diff --no-index` 与 upstream 逐文件比对，逐个 hunk 判定是"我们的修改"还是"上游漂移"。
两个纯 import 顺带改动（`AndroidElfLoader.java` / `AbstractARMDebugger.java`）已如实保留，可忽略。
