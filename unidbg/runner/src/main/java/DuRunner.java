import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.XHookImpl;
import unicorn.Arm64Const;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.SystemPropertyProvider;

import com.sun.jna.Pointer;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Dynamic verification runner for 数字联盟 libdu.so (v8.4.0).
 *
 *  1. load libdu.so, run JNI_OnLoad, dump DvmClass.nativesMap (name -> fnPtr)
 *  2. call native query() with a stub Context and capture verbose JNI trace
 *  3. (best effort) let the worker build its fingerprint payload
 *
 * Usage: java DuRunner <path-to-libdu.so> [outDir]
 */
public class DuRunner extends AbstractJni {

    private static final String PKG = "com.zhihu.android";

    // xhook 的第一个参数是 pathname 正则。原先写死 "libdu.so"：一旦换个文件名加载
    // （比如 IDA 的工作副本 libdu_b.so），正则匹配不上，而 xhook_refresh() 仍然返回成功，
    // 于是所有钩子静默失效 —— 表现为 sem_wait 等不到 worker 线程、query() 卡死在 futex 轮询。
    // 这里改成匹配任意 libdu*.so，任何加载路径都能挂上。
    private static final String HOOK_MODULE = "libdu.*\\.so";

    // ---- 唯一的"伪装"：把 unidbg 这台模拟机呈现成一台具体设备 ----
    // SYS_PROPS / mumu_props.txt / Build 字段 / rootfs 伪文件 = 设备属性。这是环境采集
    // 有数据可收的前提（全空的 Build 会被 SDK 判成"环境不通过"）。
    // 除此之外不再向 SDK 注入任何东西：不喂真机会话、不喂 device_id、不 patch 任何
    // 门控/校验函数、不伪造摘要结果 —— SDK 采集到什么就是什么。
    //   -Ddu.norop=true : 连设备属性也不伪装（对照实验用）
    private static boolean prop(String key, boolean def) {
        String v = System.getProperty(key);
        return v == null ? def : Boolean.parseBoolean(v);
    }

    private static final boolean NOROP = prop("du.norop", false);
    // query() 的第 4 个参数会被 worker 拿去调 sub_82FBC()，即设置 dword_C1938。
    private static final int QUERY_TYPE = Integer.getInteger("du.queryType", 2);
    // -Ddu.randdev=true：把设备属性整体随机成一台"全新设备"（含 boot_id），
    // 用来验证服务端会不会为它签发一个新 ID，而不是复用同一设备的记录。
    private static final boolean RANDDEV = prop("du.randdev", false);
    private static final String RAND_BOOT_ID = RANDDEV ? java.util.UUID.randomUUID().toString() : null;

    private final AndroidEmulator emulator;
    private final VM vm;
    private final File soFile;
    private final File outDir;
    private long envPtr;
    private long ctxObj;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: DuRunner <libdu.so> [outDir]");
            System.exit(1);
        }
        File so = new File(args[0]);
        File out = new File(args.length > 1 ? args[1] : ".");
        if (!out.exists()) {
            out.mkdirs();
        }
        DuRunner r = new DuRunner(so, out);
        r.run();
    }

    public DuRunner(File soFile, File outDir) {
        this.soFile = soFile;
        this.outDir = outDir;
        // unidbg resolves guest paths against this rootDir, so seed the pseudo-files
        // the so probes with the MuMu device's real values. Without them every read
        // came back ENOENT and the SDK's environment branch collected nothing.
        File rootFs = new File(outDir, "rootfs");
        if (!NOROP) {
            seedRootFs(rootFs);
        } else {
            System.out.println("[nomock] norop: rootfs 伪文件不再注入");
        }
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName(PKG)
                .setRootDir(rootFs)
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setVerbose(Boolean.getBoolean("du.verbose"));
        vm.setJni(this);
        new AndroidModule(emulator, vm).register(memory);

        // PATCHED: fill system properties so environment collectors get data
        // (empty collections -> zero hashes -> "environment not passed" state)
        SystemPropertyHook sph = new SystemPropertyHook(emulator);
        final Map<String, UnidbgPointer> propInfoCache = new java.util.HashMap<>();
        if (NOROP) {
            System.out.println("[nomock] norop: 不接管系统属性，SDK 读 unidbg 自带 property 区");
        }
        sph.setPropertyProvider(new SystemPropertyProvider() {
            @Override
            public String getProperty(String key) {
                String v = NOROP ? null : SYS_PROPS.get(key);
                System.out.println("[prop] " + key + " -> " + (v == null ? "<EMPTY>" : v));
                return v;
            }
            @Override
            public Pointer __system_property_find(String key) {
                // PATCHED: modern API must also return our values, else the so reads
                // the bundled bullhead property area and ignores MuMu's identity
                String v = NOROP ? null : SYS_PROPS.get(key);
                System.out.println("[find] " + key + " -> " + (v == null ? "<null>" : v));
                if (v == null) return null;
                return propInfoCache.computeIfAbsent(key, k -> {
                    UnidbgPointer pi = emulator.getMemory().malloc(0x200, true).getPointer();
                    byte[] vb = v.getBytes(StandardCharsets.UTF_8);
                    byte[] kb = k.getBytes(StandardCharsets.UTF_8);
                    pi.setInt(0, 1);                       // prop serial
                    pi.write(4, vb, 0, vb.length);          // value @ +4
                    pi.setByte(4 + vb.length, (byte) 0);
                    pi.write(96, kb, 0, kb.length);         // name @ +96
                    pi.setByte(96 + kb.length, (byte) 0);
                    return pi;
                });
            }
        });
        memory.addHookListener(sph);

        // Optional syscall histogram (-Ddu.syscall=true). When the so spins at 100% CPU
        // inside one native call this shows which syscall number it is hammering, which is
        // the fastest way to tell a risk-control probe from a blocked wait. Read-only.
        if (Boolean.getBoolean("du.syscall")) {
            final java.util.Map<Integer, long[]> tally = new java.util.concurrent.ConcurrentHashMap<>();
            final long[] total = {0};
            final long[] futexSeen = {0};
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.InterruptHook() {
                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) { }
                @Override
                public void detach() { }
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, int intno, int swi, Object user) {
                    try {
                        int nr = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
                        tally.computeIfAbsent(nr, k -> new long[1])[0]++;
                        // syscall 98 = futex: dump the first few so we can see which lock the
                        // so parks on (op/val/current word) instead of only counting them.
                        if (nr == 98 && futexSeen[0]++ < 40) {
                            long uaddr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                            int op = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                            int val = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                            int cur = 0;
                            try {
                                cur = UnidbgPointer.pointer(emulator, uaddr).getInt(0);
                            } catch (Throwable ignore) { }
                            System.out.println("[futex] uaddr=0x" + Long.toHexString(uaddr)
                                    + " op=0x" + Integer.toHexString(op)
                                    + " val=0x" + Integer.toHexString(val)
                                    + " cur=0x" + Integer.toHexString(cur)
                                    + " lr=" + emulator.getContext().getLRPointer());
                        }
                        if (++total[0] % 200000 == 0) {
                            StringBuilder sb = new StringBuilder("[sys] total=" + total[0] + " top:");
                            tally.entrySet().stream()
                                    .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                                    .limit(8)
                                    .forEach(e -> sb.append(' ').append(e.getKey()).append('=').append(e.getValue()[0]));
                            System.out.println(sb);
                        }
                    } catch (Throwable ignore) { }
                }
            }, null);
            System.out.println("[sys] syscall histogram enabled");
        }
    }

    private void run() throws Exception {
        // pre-resolve the class the lib registers natives on, so FindClass succeeds
        DvmClass duHelper = vm.resolveClass("cn/shuzilm/core/DUHelper");
        DvmClass listener = vm.resolveClass("cn/shuzilm/core/DUListener");
        vm.resolveClass("cn/shuzilm/core/IDUService");

        DalvikModule dm = vm.loadLibrary(soFile, false);
        Module module = dm.getModule();
        System.out.println("[+] libdu.so loaded at 0x" + Long.toHexString(module.base));

        // --- unblock pthread sync primitives that deadlock the worker thread ---
        IxHook xhook = XHookImpl.getInstance(emulator);
        ReplaceCallback passReturnZero = new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0);
            }
        };
        xhook.register(HOOK_MODULE, "sem_wait", passReturnZero);
        xhook.register(HOOK_MODULE, "sem_timedwait", passReturnZero);
        xhook.register(HOOK_MODULE, "sem_init", passReturnZero);
        // capture plaintext payload right before zlib compression
        final java.util.List<long[]> jobs = new java.util.ArrayList<>();
        xhook.register(HOOK_MODULE, "pthread_create", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                long routine = ctx.getLongArg(2);
                long arg = ctx.getLongArg(3);
                synchronized (jobs) {
                    jobs.add(new long[]{routine, arg});
                }
                System.out.println("[pthread_create] queued routine=0x" + Long.toHexString(routine - module.base)
                        + " arg=0x" + Long.toHexString(arg));
                return HookStatus.LR(emulator, 0); // pretend success, run synchronously later
            }
        });
        // ---- native I/O visibility hooks (pass-through + log) ----
        ReplaceCallback connectLog = new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                UnidbgPointer sa = ctx.getPointerArg(1);
                String desc = "?";
                try {
                    byte[] d = sa.getByteArray(0, 16);
                    int family = d[0] | (d[1] << 8);
                    int port = ((d[2] & 0xFF) << 8) | (d[3] & 0xFF);
                    if (family == 2) {
                        desc = port + "@" + (d[4]&0xFF) + "." + (d[5]&0xFF) + "." + (d[6]&0xFF) + "." + (d[7]&0xFF);
                    } else {
                        desc = "family" + family;
                    }
                } catch (Throwable ignore) { }
                System.out.println("[io] connect fd=" + ctx.getIntArg(0) + " -> " + desc);
                ctx.push(emulator.getContext().getLongArg(0), emulator.getContext().getLongArg(1),
                        emulator.getContext().getLongArg(2), emulator.getContext().getLongArg(3));
                Number ret = Module.emulateFunction(emulator, originFunction,
                        ctx.getLongArg(0), ctx.getLongArg(1), ctx.getLongArg(2), ctx.getLongArg(3));
                ctx.pop();
                return HookStatus.LR(emulator, ret.intValue());
            }
        };
        ReplaceCallback writeLog = new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                UnidbgPointer buf = ctx.getPointerArg(1);
                int len = ctx.getIntArg(2);
                if (buf != null && len > 8 && len < 8192) {
                    byte[] d = buf.getByteArray(0, len);
                    String head = new String(d, 0, Math.min(48, len), StandardCharsets.ISO_8859_1);
                    if (head.contains("HTTP") || head.contains("POST") || head.contains("GET")) {
                        String show = head.replace('\r', '|').replace('\n', '|');
                        System.out.println("[io] write fd=" + ctx.getIntArg(0) + " len=" + len + " : " + show);
                    }
                }
                ctx.push(emulator.getContext().getLongArg(0), emulator.getContext().getLongArg(1),
                        emulator.getContext().getLongArg(2), emulator.getContext().getLongArg(3));
                Number ret = Module.emulateFunction(emulator, originFunction,
                        ctx.getLongArg(0), ctx.getLongArg(1), ctx.getLongArg(2), ctx.getLongArg(3));
                ctx.pop();
                return HookStatus.LR(emulator, ret.intValue());
            }
        };
        ReplaceCallback sendtoLog = new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                UnidbgPointer buf = ctx.getPointerArg(1);
                int len = ctx.getIntArg(2);
                if (buf != null && len > 8) {
                    byte[] d = buf.getByteArray(0, Math.min(len, 80));
                    String show = new String(d, StandardCharsets.ISO_8859_1).replace('\r', '|').replace('\n', '|');
                    System.out.println("[io] sendto fd=" + ctx.getIntArg(0) + " len=" + len + " : " + show);
                }
                ctx.push(emulator.getContext().getLongArg(0), emulator.getContext().getLongArg(1),
                        emulator.getContext().getLongArg(2), emulator.getContext().getLongArg(3),
                        emulator.getContext().getLongArg(4), emulator.getContext().getLongArg(5));
                Number ret = Module.emulateFunction(emulator, originFunction,
                        ctx.getLongArg(0), ctx.getLongArg(1), ctx.getLongArg(2), ctx.getLongArg(3),
                        ctx.getLongArg(4), ctx.getLongArg(5));
                ctx.pop();
                return HookStatus.LR(emulator, ret.intValue());
            }
        };
        xhook.register(HOOK_MODULE, "connect", connectLog);
        xhook.register(HOOK_MODULE, "write", writeLog);
        xhook.register(HOOK_MODULE, "sendto", sendtoLog);
        // recvmsg：libdu.so 自己导入了 recvmsg/sendmsg，但 unidbg 的 ARM64SyscallHandler
        // 既没有 case 212(recvmsg) 也没有任何 recvmsg 实现，调用会落到 handleUnknownSyscall
        // 的失败分支，什么都不做就返回，于是 SO 无限重试（实测 740 万次，卡死 0x779EC）。
        // 注意：这里绝不能再用 Module.emulateFunction 去转调 libc 的 recvfrom —— 本回调
        // 已经在 emu_start 里，嵌套调用会让 AbstractEmulator.emulate 抛
        // "IllegalStateException: running"，蹦床拿到 jump=0，表现为 debugger break at
        // 0xfffe1974 并让通道异常退出。改成直接用 unidbg 的 FileIO 读进宾客内存。
        xhook.register(HOOK_MODULE, "recvmsg", new ReplaceCallback() {
            private int n;
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                int fd = ctx.getIntArg(0);
                UnidbgPointer msg = ctx.getPointerArg(1);
                int flags = ctx.getIntArg(2);
                if (msg == null) {
                    return HookStatus.LR(emulator, -1);
                }
                // struct msghdr (LP64): +0 msg_name, +8 msg_namelen(u32), +16 msg_iov,
                // +24 msg_iovlen, +32 msg_control, +40 msg_controllen, +48 msg_flags
                UnidbgPointer iov = msg.getPointer(16);
                long iovLen = msg.getLong(24);
                UnidbgPointer base = iov == null ? null : iov.getPointer(0);
                long blen = iov == null ? 0 : iov.getLong(8);
                int got = -1;
                if (iovLen >= 1 && base != null && blen > 0) {
                    try {
                        com.github.unidbg.file.FileIO io = fileIO(emulator, fd);
                        if (io != null) {
                            got = io.read(emulator.getBackend(), base,
                                    (int) Math.min(blen, Integer.MAX_VALUE));
                        }
                    } catch (Throwable t) {
                        System.out.println("[recvmsg] read failed: " + t);
                    }
                    // 收包时内核会回填 msg_namelen / msg_flags
                    msg.setInt(8, 0);
                    msg.setInt(48, 0);
                }
                if (n++ < 10) {
                    System.out.println("[recvmsg] fd=" + fd + " iovlen=" + iovLen
                            + " base=0x" + (base == null ? "null" : Long.toHexString(base.peer))
                            + " len=" + blen + " flags=0x" + Integer.toHexString(flags)
                            + " -> " + got);
                }
                return HookStatus.LR(emulator, got);
            }
        });
        xhook.register(HOOK_MODULE, "pthread_exit", passReturnZero);
        xhook.register(HOOK_MODULE, "pthread_detach", passReturnZero);
        xhook.register(HOOK_MODULE, "pthread_join", passReturnZero);
        // ---- risk-control surface: every file probe + process-identity query ----
        // libdu.so imports open/fopen/access/stat/lstat/readlink/opendir/popen and
        // getpid/gettid/getppid/prctl - the classic anti-emulator inputs. Log them so we
        // can see which pseudo-files the SDK reads. Observation only: onCall forwards to
        // the original libc body (HookStatus.RET), so no result is altered - nothing mocked.
        final class Probe extends ReplaceCallback {
            private final String sym;
            private final boolean path;
            Probe(String sym, boolean path) { this.sym = sym; this.path = path; }
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                StringBuilder sb = new StringBuilder("[probe] ").append(sym);
                if (path) {
                    String a = "<null>";
                    try {
                        UnidbgPointer p = ctx.getPointerArg(0);
                        if (p != null) a = p.getString(0);
                    } catch (Throwable ignore) { }
                    sb.append("(\"").append(a).append("\")");
                } else if ("prctl".equals(sym)) {
                    sb.append("(op=").append(ctx.getIntArg(0)).append(")");
                } else {
                    sb.append("()");
                }
                System.out.println(sb);
                return super.onCall(emulator, originFunction);
            }
        }
        // OFF by default: add 12 extra GOT hooks and the so can stall, so this must be
        // opted into with -Ddu.probe=true while investigating.
        if (Boolean.getBoolean("du.probe")) {
            for (String sym : new String[]{"open", "fopen", "access", "stat", "lstat", "readlink", "opendir", "popen"}) {
                xhook.register(HOOK_MODULE, sym, new Probe(sym, true));
            }
            for (String sym : new String[]{"getpid", "gettid", "getppid", "prctl"}) {
                xhook.register(HOOK_MODULE, sym, new Probe(sym, false));
            }
            System.out.println("[probe] probes enabled");
        }
        xhook.register(HOOK_MODULE, "compress", new ReplaceCallback() {
            private int n;
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                UnidbgPointer dest = ctx.getPointerArg(0);
                UnidbgPointer destLenP = ctx.getPointerArg(1);
                UnidbgPointer src = ctx.getPointerArg(2);
                int srcLen = ctx.getIntArg(3);
                if (src == null || srcLen <= 0 || dest == null || destLenP == null) {
                    return HookStatus.LR(emulator, -5);
                }
                byte[] data = src.getByteArray(0, srcLen);
                java.util.zip.Deflater def = new java.util.zip.Deflater();
                def.setInput(data);
                def.finish();
                byte[] out = new byte[srcLen + 64];
                int len = def.deflate(out);
                def.end();
                dest.write(0, out, 0, len);
                destLenP.setLong(0, len);
                File f = new File(outDir, "payload_" + (++n) + "_0x" + Integer.toHexString(srcLen) + ".bin");
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    fos.write(data);
                } catch (IOException ignore) {
                }
                System.out.println("[compress] java-deflate " + srcLen + " -> " + len + " bytes, captured -> " + f.getName());
                return HookStatus.LR(emulator, 0); // Z_OK
            }
        });

        // prctl emulation for the SDK's seccomp / no_new_privs probes.
        // unidbg's arm64 syscall handler has no case for PR_GET_SECCOMP(21) or
        // PR_GET_NO_NEW_PRIVS(39), so a call falls into its default branch and throws
        // UnsupportedOperationException, which emu_stop()s and unwinds out of the syscall
        // handler. sub_48E40 is exactly such a caller: it builds "%d,%d" from both and
        // sub_22C34 stores it as the mdna body field "VIB" - the last field it writes.
        // Our captured so_built_body.json has no "VIB", i.e. the build dies right there.
        // A normal Android app reports SECCOMP_MODE_FILTER(2) and no_new_privs(1);
        // override with -Ddu.prctl.seccomp / -Ddu.prctl.nnp while comparing with the server.
        xhook.register(HOOK_MODULE, "prctl", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext ctx, long originFunction) {
                int option = ctx.getIntArg(0);
                if (option == 21 || option == 39) {
                    int v = option == 21
                            ? Integer.getInteger("du.prctl.seccomp", 2)
                            : Integer.getInteger("du.prctl.nnp", 1);
                    System.out.println("[prctl] option=" + option + " -> " + v);
                    return HookStatus.LR(emulator, v);
                }
                return super.onCall(emulator, originFunction);
            }
        });

        xhook.refresh();
        System.out.println("[+] hooks installed");
        initOutput();
        if (!NOROP) {
            loadMumuProps();
        } else {
            System.out.println("[norop] 不加载 mumu_props.txt，SDK 读 unidbg 自带 property 区");
        }
        if (RANDDEV) {
            randomizeDevice();
        }

        // 不 patch 任何门控/校验函数，so 自己判。
        // 下面两条是跑通 unidbg 必需的管道修补，不是校验伪装，始终生效：
        // sub_56F84 cleanup helper (DeleteGlobalRef + ExceptionClear pair) crashes on stale
        // refs (UC_ERR_READ_UNMAPPED at 0x56fb0-0x56fc0). Pure cleanup -> patch to RET.
        emulator.getBackend().mem_write(module.base + 0x56F84L, new byte[]{
                (byte) 0xC0, 0x03, 0x5F, (byte) 0xD6});
        // sub_85484(endpoint) -> TCP port. Force 18443: unidbg forces outbound TCP to
        // loopback, but Windows http.sys (pid 4) holds :80 on all interfaces, so the
        // so's own HTTP to auni.telecome.cn:80 can never be served. = mov w0,#18443;ret
        emulator.getBackend().mem_write(module.base + 0x85484L, new byte[]{
                (byte) 0xE0, 0x01, (byte) 0x89, 0x52, (byte) 0xC0, 0x03, 0x5F, (byte) 0xD6});
        System.out.println("[+] 管道修补完成（56F84->RET, 85484->port），校验门未 patch");
        emulator.getSyscallHandler().setVerbose(true);   // syscall 级追踪

        // backend-level code hooks (unicorn-native, always effective) to observe flow
        com.github.unidbg.arm.backend.CodeHook watcher = new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                long rel = address - module.base;
                if (rel == 0x4CCF4 || rel == 0x4C9D0) {
                    long a0 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    long a1 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    long a2 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue();
                    long a3 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X3).longValue();
                    StringBuilder sb = new StringBuilder("[watch-md5] " + Long.toHexString(rel)
                            + " x0=0x" + Long.toHexString(a0) + " x1=0x" + Long.toHexString(a1)
                            + " x2=0x" + Long.toHexString(a2) + " x3=0x" + Long.toHexString(a3));
                    for (long p : new long[]{a0, a1, a2}) {
                        if (p > 0x10000 && p < 0x7fff_ffff_0000L) {
                            try {
                                UnidbgPointer ptr = UnidbgPointer.pointer(emulator, p);
                                byte[] d = ptr.getByteArray(0, 48);
                                StringBuilder txt = new StringBuilder(" | [").append(Long.toHexString(p)).append("]=");
                                for (byte b : d) {
                                    txt.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                                }
                                sb.append(txt);
                            } catch (Throwable ignore) {
                            }
                        }
                    }
                    System.out.println(sb);
                }
                if (rel == 0x543EC) {
                    // encoder entry sub_543EC(env, key, value, env2, type): x1 is the JSON
                    // key and x2 is the plaintext BEFORE encoding, so this dump shows the
                    // real value the so collected for every uploaded field.
                    try {
                        long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                        StringBuilder sb = new StringBuilder("[enc] lr=0x")
                                .append(Long.toHexString(lr - 0x12000000L));
                        for (long p : new long[]{
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue(),
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue()}) {
                            String s = "<null>";
                            if (p > 0x10000 && p < 0x7fff_ffff_0000L) {
                                try {
                                    UnidbgPointer ptr = UnidbgPointer.pointer(emulator, p);
                                    byte[] d = ptr.getByteArray(0, 96);
                                    int z = 0;
                                    while (z < d.length && d[z] >= 0x20 && d[z] < 0x7F) z++;
                                    s = z > 0 ? new String(d, 0, z, StandardCharsets.ISO_8859_1) : "<non-ascii>";
                                } catch (Throwable ignore) { }
                            }
                            sb.append(" | ").append(s);
                        }
                        System.out.println(sb);
                    } catch (Throwable ignore) { }
                }                if (rel == 0x540C0 || rel == 0x54688) {
                    // JSON put-string boundary: dump key/value strings + call site
                    try {
                        long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                        StringBuilder sb = new StringBuilder("[put] lr=0x")
                                .append(Long.toHexString(lr - 0x12000000L));
                        for (int ri = 1; ri <= 3; ri++) {
                            long rv = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + ri).longValue();
                            UnidbgPointer pp = UnidbgPointer.pointer(emulator, rv);
                            if (pp != null) {
                                byte[] d = pp.getByteArray(0, 48);
                                int z = 0;
                                while (z < d.length && d[z] >= 0x20 && d[z] < 0x7F) z++;
                                if (z > 0) {
                                    sb.append(" x").append(ri).append("='")
                                      .append(new String(d, 0, z, StandardCharsets.ISO_8859_1)).append("'");
                                }
                            }
                        }
                        System.out.println(sb);
                    } catch (Throwable ignore) {
                    }
                }
                if (rel == 0x828E4) {
                    // query entry: x0=JNIEnv*, x1=clazz, x2=ctx jobject
                    envPtr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    ctxObj = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue();
                    System.out.println("[watch] query entry, env=0x" + Long.toHexString(envPtr)
                            + " ctx=0x" + Long.toHexString(ctxObj));
                }
                System.out.println("[watch] hit rel 0x" + Long.toHexString(rel));
            }
            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) { }
            @Override
            public void detach() { }
        };
        try {
            java.io.File watchFile = new File(outDir, "watch_addrs.json");
            if (watchFile.exists()) {
                String txt = new String(Files.readAllBytes(watchFile.toPath()), StandardCharsets.UTF_8);
                for (String a : txt.replace("[", "").replace("]", "").replace("\"", "").split(",")) {
                    String s = a.trim();
                    if (!s.isEmpty()) {
                        emulator.getBackend().hook_add_new(watcher, module.base + Long.decode(s), module.base + Long.decode(s), null);
                    }
                }
            }
            emulator.getBackend().hook_add_new(watcher, module.base + 0x13F3CL, module.base + 0x13F3CL, null);
            emulator.getBackend().hook_add_new(watcher, module.base + 0x4CCF4L, module.base + 0x4CCF4L, null);
            // memory-write watchpoint on the encoder state word C1944
            try {
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, long value, Object user) {
                        long pc = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
                        long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                        System.out.println("[C1944-WRITE] pc=0x" + Long.toHexString(pc - 0x12000000L)
                                + " lr=0x" + Long.toHexString(lr - 0x12000000L)
                                + " value=0x" + Long.toHexString(value) + " size=" + size);
                    }
                    @Override public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) { }
                    @Override public void detach() { }
                }, module.base + 0xC1944L, module.base + 0xC1947L, null);
                System.out.println("[+] C1944 write watchpoint installed");
            } catch (Throwable t) {
                System.out.println("[!] C1944 watchpoint failed: " + t);
            }
            // memory-write watchpoint on the report-host global qword_1149F8.
            // Whoever stores here is the code that decides which shuzilm.cn host the
            // report goes to; the string is empty when nothing ever set it.
            try {
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, long value, Object user) {
                        long pc = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
                        long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                        String s = "";
                        try {
                            UnidbgPointer wp = UnidbgPointer.pointer(emulator, value);
                            if (wp != null) {
                                byte[] wd = wp.getByteArray(0, 64);
                                int wz = 0;
                                while (wz < wd.length && wd[wz] != 0) wz++;
                                s = new String(wd, 0, wz, StandardCharsets.ISO_8859_1);
                            }
                        } catch (Throwable ignore) { }
                        System.out.println("[HOST-WRITE] pc=0x" + Long.toHexString(pc - 0x12000000L)
                                + " lr=0x" + Long.toHexString(lr - 0x12000000L)
                                + " addr=0x" + Long.toHexString(address - 0x12000000L)
                                + " value=0x" + Long.toHexString(value) + " size=" + size
                                + (s.isEmpty() ? "" : " str='" + s + "'"));
                    }
                    @Override public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) { }
                    @Override public void detach() { }
                }, module.base + 0x1149F0L, module.base + 0x114A08L, null);
                System.out.println("[+] host globals (0x1149F0-0x114A08) write watchpoint installed");
            } catch (Throwable t) {
                System.out.println("[!] host watchpoint failed: " + t);
            }
            emulator.getBackend().hook_add_new(watcher, module.base + 0x540C0L, module.base + 0x540C0L, null);
            emulator.getBackend().hook_add_new(watcher, module.base + 0x54688L, module.base + 0x54688L, null);
            emulator.getBackend().hook_add_new(watcher, module.base + 0x4C9D0L, module.base + 0x4C9D0L, null);
            emulator.getBackend().hook_add_new(watcher, module.base + 0x4D0DCL, module.base + 0x4D0DCL, null);

            // 字符串解密器 sub_717C0 的运行时观测（-Ddu.strtrace=true 才开）：打印**实际被解密**
            // 的每个串及其调用点，去重。只读诊断，用来回答"so 里某个字符串到底有没有被用到、
            // 在哪儿用"（一次完整运行约 1200+ 条，默认关掉避免刷屏）。
            if (prop("du.strtrace", false)) {
                final java.util.Set<String> seenStrs =
                        java.util.Collections.synchronizedSet(new java.util.HashSet<>());
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                        try {
                            long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                            long va = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            UnidbgPointer p = UnidbgPointer.pointer(emulator, va & ~3L);
                            if (p == null) {
                                return;
                            }
                            StringBuilder sb = new StringBuilder();
                            for (int k = 0; k < 200; k++) {
                                int e = p.getByte(2L * k + 1) & 0xFF;
                                if (e == 0) {
                                    break;
                                }
                                char c = (char) (((e - 1) & 0xFF) ^ k);
                                if (c < 0x20 || c > 0x7E) {
                                    return;              // 不像字符串，丢弃
                                }
                                sb.append(c);
                            }
                            if (sb.length() < 3) {
                                return;
                            }
                            String s = sb.toString();
                            if (seenStrs.add(s)) {
                                System.out.println("[str] lr=0x" + Long.toHexString(lr - module.base) + " " + s);
                            }
                        } catch (Throwable ignore) {
                        }
                    }
                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) { }
                    @Override
                    public void detach() { }
                }, module.base + 0x717C0L, module.base + 0x717C0L, null);
                System.out.println("[+] sub_717C0 字符串解密观测已开启（strtrace）");
            }
            System.out.println("[+] watchers added");
        } catch (Throwable t) {
            System.out.println("[!] watcher add failed: " + t);
        }

        try {
            dm.callJNI_OnLoad(emulator);
        } catch (Throwable t) {
            System.out.println("[!] JNI_OnLoad exception: " + t);
        }
        // qword_C19F8 holds the address of the 22-entry Build-field-name thunk array
        // (off_C1828 @0xC1828) that sub_3A360 indexes. It is installed only by
        // sub_3A6D4, reached via sub_8036C -> sub_2DE9C - an init path the surgical
        // flow never runs. Left unset it keeps the file filler 0xFFFFFFFFFFFFFFFF, so
        // sub_3A360(0) dies with UC_ERR_READ_UNMAPPED and all 22 rG* Build slots are
        // skipped. Install it so the so collects its own device attributes.
        try {
            Number initRet = Module.emulateFunction(emulator, module.base + 0x3A6D4L);
            long tblVal = UnidbgPointer.pointer(emulator, module.base + 0xC19F8L).getLong(0);
            System.out.println("[+] C19F8 init ret=" + initRet + " table=0x" + Long.toHexString(tblVal)
                    + " (expect 0x" + Long.toHexString(module.base + 0xC1828L) + ")");
        } catch (Throwable t) {
            System.out.println("[!] C19F8 init failed: " + t);
        }
        // qword_C3010 只在 sub_4A134() 里赋值，值是 &off_C1050 —— 一张 251 项的 property
        // stub 函数指针表（表长来自 sub_718F4() 的 0xFB）。不调它 qword_C3010 恒为 0，
        // sub_49220(i) 就是 "br 0"：sub_2B8AC 构造 R%x 属性块时会直接撞 BRK 中止——
        // 这正是端点 6(d2api) 通道发不出去的原因。和 qword_C19F8 一样，这条 init 路径
        // 手术模式不会走到，显式补上。
        try {
            Number c3010Ret = Module.emulateFunction(emulator, module.base + 0x4A134L);
            long c3010Tbl = UnidbgPointer.pointer(emulator, module.base + 0xC3010L).getLong(0);
            System.out.println("[+] C3010 init ret=" + c3010Ret + " table=0x" + Long.toHexString(c3010Tbl)
                    + " (expect 0x" + Long.toHexString(module.base + 0xC1050L) + ")");
        } catch (Throwable t) {
            System.out.println("[!] C3010 init failed: " + t);
        }
        dumpNativesMap(duHelper);

        // -Ddu.encprobe=true：编码器探针。直接调用 sub_543EC 的四个二级变换函数，
        // 用 "ABCD..." 这种可辨识输入反推真实置换，跑完即退出（不跑业务链路）。
        if (prop("du.encprobe", false)) {
            runEncoderProbe(module);
            System.exit(0);
        }

        // ---- call query() ----
        try {
            DvmObject<?> ctx = vm.resolveClass("android/content/Context").newObject(null);
            vm.addGlobalObject(ctx);   // worker/channel 复用 ctx：必须全局引用，否则局部引用过期
            StringObject ret = (StringObject) duHelper.callStaticJniMethodObject(
                    emulator,
                    "query(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;",
                    ctx,
                    new StringObject(vm, "{\"store\":\"DUTest\",\"apiKey\":\"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANc7lrAPh8Vki2+Gf9KQxUbWzTqMvwIe+y9VuHfUPWHlTovg3JwUJnkoTHLCTH2BTMHHRe/lkEFCn7wAXmrisjsCAwEAAQ==\"}"),
                    new StringObject(vm, "{\"custom\":\"test\"}"),
                    QUERY_TYPE);
            System.out.println("[+] query#1 returned: " + (ret == null ? "null" : ret.getValue()));
        } catch (Throwable t) {
            System.out.println("[!] query#1 exception: " + t);
        }
        try {
            DvmObject<?> ctx2 = vm.resolveClass("android/content/Context").newObject(null);
            vm.addGlobalObject(ctx2);
            StringObject ret2 = (StringObject) duHelper.callStaticJniMethodObject(
                    emulator,
                    "query(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;",
                    ctx2,
                    new StringObject(vm, "{\"store\":\"DUTest\",\"apiKey\":\"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANc7lrAPh8Vki2+Gf9KQxUbWzTqMvwIe+y9VuHfUPWHlTovg3JwUJnkoTHLCTH2BTMHHRe/lkEFCn7wAXmrisjsCAwEAAQ==\"}"),
                    new StringObject(vm, "{\"custom\":\"test\"}"),
                    QUERY_TYPE);
            System.out.println("[+] query#2 returned: " + (ret2 == null ? "null" : ret2.getValue()));
        } catch (Throwable t) {
            System.out.println("[!] query#2 exception: " + t);
        }

        // mode-0 "run" worker is the fire-and-forget report cycle
        try {
            DvmObject<?> ctx3 = vm.resolveClass("android/content/Context").newObject(null);
            vm.addGlobalObject(ctx3);
            StringObject ret3 = (StringObject) duHelper.callStaticJniMethodObject(
                    emulator,
                    "run(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    ctx3,
                    new StringObject(vm, "{\"store\":\"DUTest\",\"apiKey\":\"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANc7lrAPh8Vki2+Gf9KQxUbWzTqMvwIe+y9VuHfUPWHlTovg3JwUJnkoTHLCTH2BTMHHRe/lkEFCn7wAXmrisjsCAwEAAQ==\"}"),
                    new StringObject(vm, "{\"custom\":\"test\"}"));
            System.out.println("[+] run returned: " + (ret3 == null ? "null" : ret3.getValue()));
        } catch (Throwable t) {
            System.out.println("[!] run exception: " + t);
        }

        // run queued worker jobs synchronously (sub_7C018 etc.)
        // The worker is a daemon loop; du.phase=jobs + sigaction tick bound (60)
        // terminates it after warm-up so the synchronous channels can run.
        System.setProperty("du.phase", "jobs");
        for (int round = 0; round < 0; round++) { // surgical mode: daemon skipped
            long[] job;
            synchronized (jobs) {
                job = jobs.isEmpty() ? null : jobs.remove(0);
            }
            if (job == null) {
                break;
            }
            System.out.println("[jobs] running routine 0x" + Long.toHexString(job[0] - module.base)
                    + " arg=0x" + Long.toHexString(job[1]));
            try {
                Module.emulateFunction(emulator, job[0], job[1]);
                System.out.println("[jobs] routine finished");
            } catch (Throwable t) {
                System.out.println("[!] job exception: " + t);
            }
        }

        // directly emulate the report channels now that gates are patched open
        if (envPtr != 0 && ctxObj != 0) {
            long[][] chans = {
                {0x77590, 2}, // config sync (env, ctx)
                // 0x760E4/0x75F84 removed: rtnetlink monitor daemon bodies - block forever
                {0x79548, 3}, // ip query (env, ctx, 1)
            };
            for (long[] ch : chans) {
                System.out.println("[chan] calling 0x" + Long.toHexString(ch[0]));
                try {
                    if (ch[1] == 2) {
                        Module.emulateFunction(emulator, module.base + ch[0], envPtr, ctxObj);
                    } else if (ch[0] == 0x75F84) {
                        Module.emulateFunction(emulator, module.base + ch[0], envPtr, ctxObj, 2);
                    } else {
                        Module.emulateFunction(emulator, module.base + ch[0], envPtr, ctxObj, 1);
                    }
                    System.out.println("[chan] 0x" + Long.toHexString(ch[0]) + " done");
                } catch (Throwable t) {
                    System.out.println("[!] chan 0x" + Long.toHexString(ch[0]) + " exception: " + t);
                }
            }
        }

        // ---- drive the report channel 0x779EC directly (sync, global ctx) ----
        System.setProperty("du.phase", "chan");
        if (envPtr != 0) {
            System.out.println("[chan] calling 0x779EC (report, sync)");
            long ctxHash = 0;
            try {
                DvmObject<?> gctx = vm.resolveClass("android/content/Context").newObject(null);
                ctxHash = vm.addGlobalObject(gctx) & 0xFFFFFFFFL;
                System.out.println("[chan] global ctx hash=0x" + Long.toHexString(ctxHash));
                Module.emulateFunction(emulator, module.base + 0x779ECL, envPtr, ctxHash, 6);
                System.out.println("[chan] 0x779EC done");
            } catch (Throwable t) {
                System.out.println("[!] chan 0x779EC exception: " + t);
            }

            // ---- surgical mode: call the so's own network/decode/store functions ----
            try {
                // SO-BUILT-BODY: do not feed a canned/hand-built request body. Ask the
                // so's own builder sub_26000(env, ctx) for the JSONObject - it collects
                // the live device attributes - then serialise it exactly the way the so
                // does (JSONObject.toString()). Nothing is mocked here.
                byte[] body;
                Number soJn = Module.emulateFunction(emulator, module.base + 0x26000L, envPtr, ctxHash);
                org.json.JSONObject soJo = null;
                if (soJn != null) {
                    DvmObject<?> soObj = vm.getObject(soJn.intValue());
                    soJo = soObj == null ? null : jsonObjs.get(soObj);
                }
                if (soJo == null) {
                    System.out.println("[!] sub_26000 returned no JSONObject (env=0x"
                            + Long.toHexString(envPtr) + ")");
                    body = new byte[0];
                } else {
                    body = soJo.toString().getBytes(StandardCharsets.UTF_8);
                    System.out.println("[surg] so-built mdna body: " + body.length + " bytes");
                    Files.write(new File(outDir, "so_built_body.json").toPath(), body);
                }
                com.github.unidbg.memory.MemoryBlock bodyBlk =
                        emulator.getMemory().malloc(body.length + 1, true);
                UnidbgPointer bodyPtr = bodyBlk.getPointer();
                bodyPtr.write(0, body, 0, body.length);
                bodyPtr.setByte(body.length, (byte) 0);

                com.github.unidbg.memory.MemoryBlock outBlk =
                        emulator.getMemory().malloc(32, true);
                UnidbgPointer outPtr = outBlk.getPointer();
                outPtr.write(0, new byte[32], 0, 32);

                // sub_84DB8(env, ctx, endpointId) assembles the full URL the so would
                // POST to: snprintf("%s%s", host, sub_848B8(endpointId)).
                // The fallback host sub_84DB8 uses when qword_1149F8 is null comes from
                // the encrypted blob at 0x6DBC0 (sub_717C0 is the string decryptor).
                Number hn = Module.emulateFunction(emulator, module.base + 0x717C0L,
                        module.base + 0x6DBC0L);
                long hAddr = hn.longValue();
                if (hAddr != 0) {
                    UnidbgPointer hp = UnidbgPointer.pointer(emulator, hAddr);
                    byte[] hd = hp.getByteArray(0, 128);
                    int hz = 0;
                    while (hz < hd.length && hd[hz] != 0) hz++;
                    System.out.println("[surg] default host blob 0x6DBC0 = '"
                            + new String(hd, 0, hz, StandardCharsets.ISO_8859_1) + "'");
                } else {
                    System.out.println("[surg] default host blob 0x6DBC0 = <null>");
                }
                // ---- CORRECTION: qword_1149F8 is NOT the host. It is the config
                // "path" prefix (set in sub_864C8 from the config-sync response field
                // "path" when it starts with '/' and does not end with '/'). The real
                // hostname for an endpoint is returned by sub_853A4(env,ctx,type,flag);
                // sub_13F3C then gethostbyname()/getaddrinfo()s it and dials via
                // sub_123C0 (plain) / sub_12F6C (TLS).
                try {
                    String[] bNames = {"auni.telecome.cn@6E014", "global-auni@6C1B4", "optn@6AAA8", "ipv4@6D65C", "cbsipv4@69BDC", "auni.unioncom@65E44"};
                    long[] bAddrs = {0x6E014L, 0x6C1B4L, 0x6AAA8L, 0x6D65CL, 0x69BDCL, 0x65E44L};
                    for (int bi = 0; bi < bAddrs.length; bi++) {
                        Number bn = Module.emulateFunction(emulator, module.base + 0x717C0L, module.base + bAddrs[bi]);
                        long ba = bn.longValue();
                        String bs = "<null>";
                        if (ba != 0) {
                            UnidbgPointer bp = UnidbgPointer.pointer(emulator, ba);
                            byte[] bd = bp.getByteArray(0, 128);
                            int bz = 0;
                            while (bz < bd.length && bd[bz] != 0) bz++;
                            bs = new String(bd, 0, bz, StandardCharsets.ISO_8859_1);
                        }
                        System.out.println("[surg] hostblob " + bNames[bi] + " = '" + bs + "'");
                    }
                    int[] eTypes = {16, 6, 4, 8, 11, 12, 17};
                    for (int ei = 0; ei < eTypes.length; ei++) {
                        int et = eTypes[ei];
                        Number hn2 = Module.emulateFunction(emulator, module.base + 0x853A4L, envPtr, ctxHash, et, 1L);
                        long ha2 = hn2.longValue();
                        String hs = "<null>";
                        if (ha2 != 0) {
                            UnidbgPointer hp2 = UnidbgPointer.pointer(emulator, ha2);
                            byte[] hd2 = hp2.getByteArray(0, 256);
                            int hz2 = 0;
                            while (hz2 < hd2.length && hd2[hz2] != 0) hz2++;
                            hs = new String(hd2, 0, hz2, StandardCharsets.ISO_8859_1);
                        }
                        String portStr = "?";
                        try {
                            portStr = String.valueOf(Module.emulateFunction(emulator, module.base + 0x85484L, et));
                        } catch (Throwable ignore) { }
                        System.out.println("[surg] HOST endpoint " + et + " = '" + hs + "' port=" + portStr);
                    }
                } catch (Throwable t) {
                    System.out.println("[!] host diag failed: " + t);
                }
                Number urlN = Module.emulateFunction(emulator, module.base + 0x84DB8L,
                        envPtr, ctxHash, 16);
                long urlAddr = urlN.longValue();
                if (urlAddr != 0) {
                    UnidbgPointer uptr = UnidbgPointer.pointer(emulator, urlAddr);
                    byte[] uraw = uptr.getByteArray(0, 1024);
                    int uz = 0;
                    while (uz < uraw.length && uraw[uz] != 0) uz++;
                    System.out.println("[surg] endpoint 16 URL = "
                            + new String(uraw, 0, uz, StandardCharsets.ISO_8859_1));
                } else {
                    System.out.println("[surg] endpoint 16 URL = <null>");
                }
                // Endpoint 6 is the only one whose branch does
                // "qword_1149F0 = strdup(sub_84C00(a1))" inside sub_84DB8, so building
                // its URL tells us what that global would hold (and the host watchpoint
                // catches the store).
                Number url6N = Module.emulateFunction(emulator, module.base + 0x84DB8L,
                        envPtr, ctxHash, 6);
                long url6Addr = url6N.longValue();
                if (url6Addr != 0) {
                    UnidbgPointer u6 = UnidbgPointer.pointer(emulator, url6Addr);
                    byte[] u6raw = u6.getByteArray(0, 1024);
                    int u6z = 0;
                    while (u6z < u6raw.length && u6raw[u6z] != 0) u6z++;
                    System.out.println("[surg] endpoint 6 URL = "
                            + new String(u6raw, 0, u6z, StandardCharsets.ISO_8859_1));
                } else {
                    System.out.println("[surg] endpoint 6 URL = <null>");
                }
                // The old canned local HTTP listener on 127.0.0.1:18447 is gone: the so's
                // request is forwarded to the real host and the genuine reply is injected
                // through the URLConnection mock (forwardToRealServer).
                // DIRECT-IDGEN: call the so's own ID-generation function and let it run
                // the entire cycle internally - sub_751E8 collects the device state,
                // builds the mdna body with sub_26000, posts it through sub_13F3C and
                // parses/stores the reply. We no longer hand-feed a request body and no
                // longer trigger the server ourselves.
                System.out.println("[surg] calling ID generator 751E8 (build + send + parse)");
                Number r751 = Module.emulateFunction(emulator, module.base + 0x751E8L,
                        envPtr, ctxHash, 0);
                System.out.println("[surg] 751E8 returned " + r751);
                // the manual response plumbing below is now inert: 751E8 handled the reply
                long respAddr = 0;
                int respLen = 0;

                if (respAddr != 0 && respLen > 0) {
                    // key for endpoint 16 (sub_847F0)
                    Number keyPtrN = Module.emulateFunction(emulator, module.base + 0x847F0L, 16);
                    long keyAddr = keyPtrN.longValue();
                    System.out.println("[surg] 847F0(16) key @0x" + Long.toHexString(keyAddr));
                    // XOR decode (sub_4FF88)
                    Number decPtrN = Module.emulateFunction(emulator, module.base + 0x4FF88L,
                            envPtr, respAddr, respLen, keyAddr);
                    long decAddr = decPtrN.longValue();
                    UnidbgPointer decPtr = UnidbgPointer.pointer(emulator, decAddr);
                    byte[] dec = decPtr.getByteArray(0, Math.min(respLen, 2048));
                    String plain = new String(dec, StandardCharsets.ISO_8859_1);
                    System.out.println("[surg] decoded response head: "
                            + plain.substring(0, Math.min(200, plain.length())));

                    // extract "sid" via sub_54E34(env, json, keyStr, 0)
                    com.github.unidbg.memory.MemoryBlock keyBlk =
                            emulator.getMemory().malloc(8, true);
                    UnidbgPointer sidKeyPtr = keyBlk.getPointer();
                    byte[] sk = "sid".getBytes(StandardCharsets.ISO_8859_1);
                    byte[] skn = new byte[sk.length + 1];
                    System.arraycopy(sk, 0, skn, 0, sk.length);
                    sidKeyPtr.write(0, skn, 0, skn.length);
                    Number sidPtrN = Module.emulateFunction(emulator, module.base + 0x54E34L,
                            envPtr, decAddr, sidKeyPtr.peer, 0);
                    long sidAddr = sidPtrN.longValue();
                    String sidVal = "";
                    if (sidAddr != 0) {
                        UnidbgPointer sidPtr = UnidbgPointer.pointer(emulator, sidAddr);
                        byte[] raw = sidPtr.getByteArray(0, 256);
                        int z = 0;
                        while (z < raw.length && raw[z] != 0) z++;
                        sidVal = new String(raw, 0, z, StandardCharsets.ISO_8859_1);
                    }
                    System.out.println("[surg] 54E34 sid = " + sidVal);

                    if (!sidVal.isEmpty()) {
                        // store: sub_55A70(env, ctx, "sid", value, 1) — the so's own setter
                        com.github.unidbg.memory.MemoryBlock vBlk =
                                emulator.getMemory().malloc(sidVal.length() + 1, true);
                        UnidbgPointer vPtr = vBlk.getPointer();
                        byte[] vb = sidVal.getBytes(StandardCharsets.ISO_8859_1);
                        byte[] vbn = new byte[vb.length + 1];
                        System.arraycopy(vb, 0, vbn, 0, vb.length);
                        vPtr.write(0, vbn, 0, vbn.length);
                        Module.emulateFunction(emulator, module.base + 0x55A70L,
                                envPtr, ctxHash, sidKeyPtr.peer, vPtr.peer, 1);
                        System.out.println("[surg] 55A70 sid stored; calling 1884C (dna writer)");
                        // 0x1884C reads 'sid' and writes sid0 + device_id through the so
                        Module.emulateFunction(emulator, module.base + 0x1884CL, envPtr, ctxHash);
                        System.out.println("[surg] 1884C done — see sp_writes.log");
                    }
                }
            } catch (Throwable t) {
                System.out.println("[!] surgical exception: " + t);
                t.printStackTrace(System.out);
            }
        }

        File payloadDir = outDir;
        File[] p = payloadDir.listFiles((d, name) -> name.startsWith("payload_"));
        System.out.println("[+] payload files: " + (p == null ? 0 : p.length));
        System.out.println("[+] done - forcing exit (emulator.close() blocks on live socket threads)");
        System.out.flush();
        Runtime.getRuntime().halt(0);
        if (spLog != null && spLog != System.out) {
            spLog.close();
        }
        emulator.close();
    }

    /** reflectively dump DvmClass.nativesMap : "name(sig)" -> UnidbgPointer(fnPtr) */
    @SuppressWarnings("unchecked")
    private void dumpNativesMap(DvmClass clazz) {
        try {
            Field f = DvmClass.class.getDeclaredField("nativesMap");
            f.setAccessible(true);
            Map<String, Object> m = (Map<String, Object>) f.get(clazz);
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Object> e : m.entrySet()) {
                long fnPtr = -1;
                Object v = e.getValue();
                if (v instanceof Number) {
                    fnPtr = ((Number) v).longValue();
                } else {
                    try {
                        Field pf = v.getClass().getField("peer");
                        pf.setAccessible(true);
                        fnPtr = pf.getLong(v);
                    } catch (Throwable ignore) {
                    }
                }
                long rel = fnPtr >= 0 && moduleBase() > 0 ? fnPtr - moduleBase() : -1;
                String line = String.format("  %-64s -> 0x%x (rel 0x%x)", e.getKey(), fnPtr, rel);
                System.out.println("[ natives ]" + line);
                sb.append(line).append('\n');
            }
            Files.write(Paths.get(outDir.getAbsolutePath(), "natives_map.txt"),
                    sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            System.out.println("[!] nativesMap dump failed: " + t);
        }
    }

    private long moduleBase() {
        Module m = emulator.getMemory().findModule("libdu.so");
        if (m == null) {
            // 同一个坑：findModule 是精确名字匹配，加载成 libdu_b.so 时就查不到，
            // 于是转移表偏移全被算成 -1。退化成按名字包含 libdu 找。
            for (Module mod : emulator.getMemory().getLoadedModules()) {
                if (mod.name != null && mod.name.contains("libdu")) {
                    m = mod;
                    break;
                }
            }
        }
        return m == null ? 0 : m.base;
    }

    /** 从 URL 取端点名：.../a/adt/report?... -> "adt"，用于按端点分文件落盘。 */
    private static String endpointSlug(String url) {
        int a = url.indexOf("/a/");
        if (a < 0) {
            return "unknown";
        }
        int s = a + 3;
        int e = url.indexOf('/', s);
        if (e < 0) {
            e = url.length();
        }
        String slug = url.substring(s, e).replaceAll("[^A-Za-z0-9_-]", "_");
        return slug.isEmpty() ? "unknown" : slug;
    }

    private static void dump(File dir, String name, byte[] data) throws IOException {
        java.io.FileOutputStream fos = new java.io.FileOutputStream(new java.io.File(dir, name));
        try {
            fos.write(data);
        } finally {
            fos.close();
        }
    }

    // 取 fd 对应的 FileIO（unidbg 的 UnixSyscallHandler.getFileIO）。SDK 的原生 socket
    // 读写都要靠它，不用它就只能嵌套 emu_start —— 那会抛 IllegalStateException: running。
    private static com.github.unidbg.file.FileIO fileIO(Emulator<?> emulator, int fd) {
        com.github.unidbg.spi.SyscallHandler<?> sh = emulator.getSyscallHandler();
        if (sh instanceof com.github.unidbg.unix.UnixSyscallHandler) {
            return ((com.github.unidbg.unix.UnixSyscallHandler) sh).getFileIO(fd);
        }
        return null;
    }

    // ---- signature-dispatched catch-all JNI stubs ----

    private final Map<DvmObject<?>, org.json.JSONObject> jsonObjs =
            java.util.Collections.synchronizedMap(new java.util.IdentityHashMap<>());
    private int jsonReqCounter;

    // 真机服务端返回的应答（由转发器回调原样回灌给 so），不再有任何离线 canned 数据
    private volatile byte[] pendingResponse;

    // ---- SharedPreferences write capture ----
    private final Map<DvmObject<?>, String> prefNames = new java.util.IdentityHashMap<>();
    private final Map<DvmObject<?>, Map<String, String>> prefData = new java.util.IdentityHashMap<>();
    private final Map<DvmObject<?>, DvmObject<?>> editorOwner = new java.util.IdentityHashMap<>();
    private java.io.PrintStream spLog;
    private final Map<DvmObject<?>, java.security.MessageDigest> digestMap =
            new java.util.IdentityHashMap<>();

    private static byte[] md5raw(byte[] input) {
        try {
            return java.security.MessageDigest.getInstance("MD5").digest(
                    input == null ? new byte[0] : input);
        } catch (Exception e) {
            return new byte[16];
        }
    }

    /**
     * Real seal format of the session values in _prefs/_dna, reverse-engineered from
     * real_prefs.xml (verified: n_a payload "WNQ14J96FOJ724G8X" -> prefix
     * "923BFEDE89728271FAEADCFB2613AF98"; nctl "1" -> "C4CA4238A0B923820DCC509A6F75849B"):
     *
     *   seal = UPPER(hex(md5(payload[0..63]))) + payload
     *
     * A bogus "0"*32 prefix fails this check, so the so treats the variable as
     * unset/invalid - which is exactly the "000000" (environment not passed) marker.
     */
    /**
     * Mirror the emulator's whole property space: read the getprop dump taken from
     * the MuMu instance (out/mumu_props.txt, lines of the form [key]: [value]) and
     * put every entry into the property table, instead of only the ~40 hardcoded
     * ones. This is what makes the emulated environment look like that emulator.
     */
    private void loadMumuProps() {
        File f = new File(outDir, "mumu_props.txt");
        if (!f.exists()) {
            System.out.println("[props] no mumu_props.txt, keeping built-in props");
            return;
        }
        int n = 0;
        try {
            java.util.regex.Pattern pat =
                    java.util.regex.Pattern.compile("^\\[(.+?)\\]: \\[(.*)\\]$");
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                java.util.regex.Matcher m = pat.matcher(line);
                if (m.matches()) {
                    SYS_PROPS.put(m.group(1), m.group(2));
                    n++;
                }
            }
        } catch (Throwable t) {
            System.out.println("[props] load failed: " + t);
        }
        System.out.println("[props] loaded " + n + " emulator props from mumu_props.txt, total="
                + SYS_PROPS.size());
    }

    /**
     * 编码器二级变换探针：对 case0..case3 的实现函数喂 "ABCDEF..." 形状的输入，
     * 打印输出，从而反推每个 case 的真实置换表（避免靠反汇编 NEON 猜）。
     */
    private void runEncoderProbe(com.github.unidbg.Module module) {
        long[] fns = {0x4BA28L, 0x4BB00L, 0x4BE04L, 0x4C29CL};
        String[] names = {"case0(4BA28)", "case1(4BB00)", "case2(4BE04)", "case3(4C29C)"};
        // 输入用 33..126 的**互不相同**字节（不能用 A-Z 循环，n>26 时会重复、无法唯一反推置换）。
        // 输出打 hex，Python 侧按 (byte-33) 还原下标序列。
        for (int fi = 0; fi < fns.length; fi++) {
            for (int n = 2; n <= 93; n++) {
                byte[] in = new byte[n];
                for (int i = 0; i < n; i++) {
                    in[i] = (byte) (33 + i);
                }
                UnidbgPointer p = emulator.getMemory().malloc(n + 1, true).getPointer();
                p.write(0, in, 0, n);
                p.setByte(n, (byte) 0);
                try {
                    Number ret = Module.emulateFunction(emulator, module.base + fns[fi], p);
                    long rp = ret == null ? 0 : ret.longValue();
                    UnidbgPointer out = UnidbgPointer.pointer(emulator, rp != 0 ? rp : module.base + 0xC31C0L);
                    byte[] ob = out.getByteArray(0, n);
                    StringBuilder os = new StringBuilder();
                    for (byte b : ob) {
                        os.append(String.format("%02x", b & 0xFF));
                    }
                    System.out.println("[encprobe] " + names[fi] + " n=" + n + " out=" + os);
                } catch (Throwable t) {
                    System.out.println("[encprobe] " + names[fi] + " n=" + n + " FAILED: " + t);
                }
            }
        }
    }

    /**
     * -Ddu.randdev=true：把设备属性（系统属性 + Build 字段 + boot_id）整体随机成一台
     * "全新设备"，用来验证服务端是否会为它签发一个新 ID，而不是复用同一设备的记录。
     * 只随机"设备身份"相关项；SDK/包名/屏幕等宿主侧参数保持不变，避免引入无关变量。
     */
    private static void randomizeDevice() {
        java.util.Random r = new java.util.Random();
        String[] brands = {"Xiaomi", "OPPO", "vivo", "OnePlus", "realme", "HONOR", "Google", "Sony"};
        String brand = brands[r.nextInt(brands.length)];
        String model = brand.substring(0, Math.min(3, brand.length())).toUpperCase()
                + "-" + (1000 + r.nextInt(9000));
        String device = "dvc" + Integer.toHexString(r.nextInt(0xFFFF));
        int sdk = 31 + r.nextInt(5);                  // 31..35：保证 rG12~rG15(SKU/SOC_*) 上报
        String release = String.valueOf(sdk - 19);    // 31→12 … 35→16
        String buildId = "R" + r.nextInt(99) + "." + (10 + r.nextInt(90)) + "." + r.nextInt(9);
        String host = "bld" + Integer.toHexString(r.nextInt(0xFFFFFF));
        String user = "builder" + r.nextInt(99);
        String fp = brand + "/" + device + "/" + device + ":" + release + "/" + buildId + "/"
                + (1000 + r.nextInt(9000)) + ":user/release-keys";
        String abilist = "arm64-v8a,armeabi-v7a,armeabi";

        SYS_PROPS.put("ro.product.brand", brand);
        SYS_PROPS.put("ro.product.manufacturer", brand);
        SYS_PROPS.put("ro.product.model", model);
        SYS_PROPS.put("ro.product.device", device);
        SYS_PROPS.put("ro.product.name", device);
        SYS_PROPS.put("ro.product.board", model);
        SYS_PROPS.put("ro.build.version.sdk", String.valueOf(sdk));
        SYS_PROPS.put("ro.build.version.release", release);
        SYS_PROPS.put("ro.build.fingerprint", fp);
        SYS_PROPS.put("ro.build.display.id", buildId + " release-keys");
        SYS_PROPS.put("ro.build.id", buildId);
        SYS_PROPS.put("ro.build.host", host);
        SYS_PROPS.put("ro.build.user", user);
        SYS_PROPS.put("ro.bootloader", "unknown");
        SYS_PROPS.put("ro.hardware", brand.toLowerCase());
        SYS_PROPS.put("ro.board.platform", brand.toLowerCase());
        SYS_PROPS.put("ro.product.cpu.abi", "arm64-v8a");
        SYS_PROPS.put("ro.product.cpu.abilist", abilist);

        BUILD_VALUES.put("BOARD", model);
        BUILD_VALUES.put("BOOTLOADER", "unknown");
        BUILD_VALUES.put("BRAND", brand);
        BUILD_VALUES.put("CPU_ABI", "arm64-v8a");
        BUILD_VALUES.put("CPU_ABI2", "");
        BUILD_VALUES.put("DEVICE", device);
        BUILD_VALUES.put("DISPLAY", buildId + " release-keys");
        BUILD_VALUES.put("FINGERPRINT", fp);
        BUILD_VALUES.put("HARDWARE", brand.toLowerCase());
        BUILD_VALUES.put("HOST", host);
        BUILD_VALUES.put("ID", buildId);
        BUILD_VALUES.put("MANUFACTURER", brand);
        BUILD_VALUES.put("MODEL", model);
        BUILD_VALUES.put("PRODUCT", device);
        BUILD_VALUES.put("TAGS", "release-keys");
        BUILD_VALUES.put("TYPE", "user");
        BUILD_VALUES.put("USER", user);
        BUILD_VALUES.put("SKU", String.valueOf(1000 + r.nextInt(9000)));
        BUILD_VALUES.put("ODM_SKU", String.valueOf(1000 + r.nextInt(9000)));
        BUILD_VALUES.put("SOC_MANUFACTURER", brand);
        BUILD_VALUES.put("SOC_MODEL", model);

        // 设备签名的真正来源：sKZ/P1J = hash(WLAN MAC) 的错位切片（日志实测 lr=0x1bb94）。
        // 不换 MAC 的话，Build/属性怎么随机服务端都认成同一台设备。
        DEV_WLAN_MAC = String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                r.nextInt(256) & 0xFE, r.nextInt(256), r.nextInt(256),
                r.nextInt(256), r.nextInt(256), r.nextInt(256));
        DEV_ANDROID_ID = String.format("%016x", r.nextLong() & 0xFFFFFFFFFFFFFFFFL);
        System.out.println("[randdev] android_id = " + DEV_ANDROID_ID);

        System.out.println("[randdev] 随机设备: " + brand + " " + model + " dev=" + device
                + " sdk=" + sdk + " mac=" + DEV_WLAN_MAC + " boot_id=" + RAND_BOOT_ID);
        System.out.println("[randdev] fingerprint = " + fp);
    }

    /**
     * Materialise the /proc and /sys pseudo-files the SDK reads, using the values the
     * MuMu device actually reports (captured with `adb shell cat`). unidbg's default
     * rootDir holds none of them, so every read returned ENOENT and the environment
     * branch of the fingerprint collection stayed empty.
     */
    private static void seedRootFs(File rootFs) {
        // stable per-boot identity - used as an environment fingerprint
        String bootId = RAND_BOOT_ID != null ? RAND_BOOT_ID : "d0b1c6d9-8535-4443-9c50-869a8007da93";
        writeFs(rootFs, "proc/sys/kernel/random/boot_id", bootId + "\n");
        writeFs(rootFs, "proc/sys/kernel/random/uuid", bootId + "\n");
        // MuMu runs permissive
        writeFs(rootFs, "sys/fs/selinux/enforce", "0\n");
        writeFs(rootFs, "proc/self/status",
                "Name:\tcom.zhihu.android\n"
                        + "Umask:\t0077\n"
                        + "State:\tS (sleeping)\n"
                        + "Tgid:\t20154\n"
                        + "Pid:\t20154\n"
                        + "PPid:\t1\n"
                        + "TracerPid:\t0\n"
                        + "Uid:\tu0_a54\tu0_a54\tu0_a54\tu0_a54\n"
                        + "Gid:\tu0_a54\tu0_a54\tu0_a54\tu0_a54\n"
                        + "FDSize:\t256\n"
                        + "Groups:\t3003 9997 20154 50154\n"
                        + "VmPeak:\t 4096000 kB\n"
                        + "VmSize:\t 3812544 kB\n"
                        + "VmLck:\t       0 kB\n"
                        + "VmRSS:\t  184320 kB\n"
                        + "Threads:\t42\n"
                        + "SigQ:\t0/9400\n"
                        + "SigPnd:\t0000000000000000\n"
                        + "ShdPnd:\t0000000000000000\n"
                        + "SigBlk:\t0000000000001204\n"
                        + "SigIgn:\t0000000000001000\n"
                        + "SigCgt:\t00000001800044e8\n"
                        + "CapInh:\t0000000000000000\n"
                        + "CapPrm:\t0000000000000000\n"
                        + "CapEff:\t0000000000000000\n"
                        + "CapBnd:\t0000000000000000\n"
                        + "Seccomp:\t0\n");
    }

    private static void writeFs(File rootFs, String rel, String content) {
        try {
            File f = new File(rootFs, rel);
            File dir = f.getParentFile();
            if (dir != null && !dir.exists()) {
                dir.mkdirs();
            }
            Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            System.out.println("[!] rootfs seed failed " + rel + ": " + t);
        }
    }

    private static String sealValue(String payload) {
        String head = payload.length() > 64 ? payload.substring(0, 64) : payload;
        byte[] d = md5raw(head.getBytes(StandardCharsets.ISO_8859_1));
        StringBuilder sb = new StringBuilder(32 + payload.length());
        for (byte b : d) {
            sb.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)));
            sb.append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
        }
        return sb.append(payload).toString();
    }
    /** 只负责打开输出流。不加载任何离线数据。 */
    private void initOutput() {
        try {
            spLog = new java.io.PrintStream(new FileOutputStream(
                    new File(outDir, "sp_writes.log"), false), true, "UTF-8");
        } catch (Throwable t) {
            spLog = System.out;
        }
    }

    /** XOR/JSON/zlib endpoint detection on a captured request body; arms pendingResponse */
    private void detectEndpointAndPrepare(byte[] req) {
        if (req == null || req.length == 0) {
            return;
        }
        String text = new String(req, StandardCharsets.ISO_8859_1);
        boolean plainJson = text.trim().startsWith("{");
        System.out.println("[http] captured request " + req.length + " bytes, "
                + (plainJson ? "plain-json head=" + text.substring(0, Math.min(160, text.length()))
                             : "encrypted/opaque（正文由 [json] put 日志与端点 URL 交叉确认）"));
        // 应答一律来自真机服务端（转发器回调），这里不准备任何东西。
    }

    private void spWrite(DvmObject<?> editor, String key, String value) {
        DvmObject<?> sp = editorOwner.get(editor);
        String pref = sp == null ? "?" : prefNames.get(sp);
        String line = "[sp-write] " + pref + ".xml  " + key + " = " + value;
        System.out.println(line);
        spLog.println(line);
        Map<String, String> d = prefData.get(sp);
        if (d == null) {
            d = new java.util.HashMap<>();
            prefData.put(sp, d);
        }
        d.put(key, value);
    }

    private void logJson(String tag, org.json.JSONObject jo) {
        System.out.println("[json] " + tag + " " + jo);
        String s = jo.toString();
        if (s.length() > 40) {
            try {
                Files.write(Paths.get(outDir.getAbsolutePath(),
                        "json_req_" + (++jsonReqCounter) + ".json"), s.getBytes(StandardCharsets.UTF_8));
            } catch (IOException ignore) {
            }
        }
    }

    private DvmObject<?> jsonDispatch(BaseVM vm, DvmObject<?> obj, String signature, VaList vaList) {
        org.json.JSONObject jo = jsonObjs.get(obj);
        if (jo == null) {
            return null;
        }
        String m = signature.substring(signature.indexOf("->") + 2);
        if (m.startsWith("put(Ljava/lang/String;Ljava/lang/Object;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            DvmObject<?> val = vaList.getObjectArg(1);
            // PATCHED: 对象值必须走 jsonObjs 取回被模拟的嵌套 JSONObject。
            // 旧代码对非 StringObject 一律 val.getValue() -> null，而 org.json 的
            // put(key, null) 语义是 **删除该键**，于是 put("vB2", 指纹对象) 与
            // put("msg", {...}) 全被静默丢弃 —— 发出去的报文因此缺整个指纹块。
            Object v = null;
            if (val instanceof StringObject) {
                v = ((StringObject) val).getValue();
            } else if (val != null && jsonObjs.containsKey(val)) {
                v = jsonObjs.get(val);          // 嵌套 JSONObject，交给 org.json 递归序列化
            } else if (val != null) {
                v = val.getValue();             // 数字/布尔等 boxed 值
            }
            if (v != null) {
                try { jo.put(key, v); } catch (Exception ignore) { }
            }
            logJson("put", jo);
            return obj;
        }
        if (m.startsWith("put(Ljava/lang/String;D)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            // 注意：D 是 double。用 getLongArg 会抛 ClassCastException(Double->Long)，
            // 异常会打断整个 payload 组装（实测把端点 6 的发送整个吞掉）。
            double d = 0;
            try {
                d = vaList.getDoubleArg(1);
            } catch (Throwable ignore) {
            }
            try { jo.put(key, d); } catch (Exception ignore) { }
            logJson("put", jo);
            return obj;
        }
        if (m.startsWith("put(Ljava/lang/String;I)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            try { jo.put(key, vaList.getIntArg(1)); } catch (Exception ignore) { }
            logJson("put", jo);
            return obj;
        }
        if (m.startsWith("put(Ljava/lang/String;J)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            try { jo.put(key, vaList.getLongArg(1)); } catch (Exception ignore) { }
            logJson("put", jo);
            return obj;
        }
        if (m.startsWith("put(Ljava/lang/String;Z)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            try { jo.put(key, vaList.getIntArg(1) != 0); } catch (Exception ignore) { }
            logJson("put", jo);
            return obj;
        }
        if (m.startsWith("toString()")) {
            return new StringObject((VM) vm, jo.toString());
        }
        if (m.startsWith("optString(Ljava/lang/String;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            String def = "";
            try {
                def = jo.optString(key, m.contains(";Ljava/lang/String;I") || m.contains("Ljava/lang/String;Ljava/lang/String;")
                        ? (vaList.getObjectArg(1) instanceof StringObject ? ((StringObject) vaList.getObjectArg(1)).getValue() : "")
                        : "");
            } catch (Exception ignore) { }
            return new StringObject((VM) vm, def);
        }
        if (m.startsWith("getString(Ljava/lang/String;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            return new StringObject((VM) vm, jo.optString(key, ""));
        }
        if (m.startsWith("optInt(Ljava/lang/String;)") || m.startsWith("getInt(Ljava/lang/String;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            return DvmInteger.valueOf((VM) vm, jo.optInt(key));
        }
        if (m.startsWith("has(Ljava/lang/String;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            // boolean-returning path is handled by callBooleanMethodV; placeholder
            return new StringObject((VM) vm, String.valueOf(jo.has(key)));
        }
        if (m.startsWith("remove(Ljava/lang/String;)")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            jo.remove(key);
            return obj;
        }
        if (m.startsWith("length()")) {
            return DvmInteger.valueOf((VM) vm, jo.length());
        }
        return null;
    }

    private DvmObject<?> mock(String cls) {
        DvmObject<?> obj = vm.resolveClass(cls).newObject(null);
        vm.addGlobalObject(obj);
        return obj;
    }

    // The List handed back by LinkProperties.getDnsServers() - identity-tracked so the
    // generic java/util/List handlers can tell it apart from the sensor list.
    private final java.util.Set<DvmObject<?>> dnsListObjs =
            java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DvmObject<?>, Boolean>());

    // ---- values read straight off the MuMu device (adb), used below ----
    // 非 final：允许 -Ddu.randdev 整体换设备时一并改写（sKZ/P1J 设备签名就是由它派生）
    private static String DEV_WLAN_MAC = "08:ca:04:3d:5e:66";            // /sys/class/net/wlan0/address
    private static String DEV_ANDROID_ID = "a543208bbf9cf92a";           // Settings.Secure.ANDROID_ID
    private static final String DEV_IFACE = "wlan0";                     // active network interface
    private static final String DEV_DNS_1 = "fd17:625c:f037:2::3";       // dumpsys connectivity
    private static final String DEV_DNS_2 = "192.168.31.1";
    // 真机 d2api 报文实证：EV2="11.10.0"、h6Z="知乎"；APK 路径取自设备
    // /proc/<pid>/maps 里已加载 libdu.so 的目录。
    private static final String APP_VERSION = "11.10.0";
    private static final String APP_LABEL = "知乎";
    private static final String APP_DATA_DIR = "/data/user/0/com.zhihu.android";
    private static final String APP_SOURCE_DIR =
            "/data/app/~~WWlqcIv5wLe3-sNzYfid9g==/com.zhihu.android-xfizW9tCiPv5D5y45-VOHA==/base.apk";
    private static final int DEV_UID = 10054;                            // u0_a54
    private static final long BOOT_NANOS = System.nanoTime();

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-obj] " + signature);
        }
        // Real MuMu network stack values, keyed on the receiver's class. Only what the
        // emulator actually reports is filled in: MuMu has no IMEI / serial / SIM
        // operator / proxy, so those stay empty rather than being invented.
        // NB: unidbg signs instance calls "android/net/LinkProperties->getInterfaceName()...",
        // so these must match with contains(), not startsWith().
        // These getters exist on exactly one Android class each, so matching on the
        // method name alone is unambiguous (recvCls() proved unreliable for the mocks).
        if (signature.contains("getInterfaceName")) {
            return new StringObject((VM) vm, DEV_IFACE);
        }
        if (signature.contains("getDnsServers")) {
            DvmObject<?> dns = mock("java/util/List");
            dnsListObjs.add(dns);
            return dns;
        }
        if (signature.contains("getHttpProxy")) {
            return null;   // no proxy configured on MuMu
        }
        if (signature.contains("getTypeName")) {
            return new StringObject((VM) vm, "WIFI");   // Active default network: WIFI CONNECTED
        }
        if (signature.contains("toString") && dnsListObjs.contains(dvmObject)) {
            return new StringObject((VM) vm, "[" + DEV_DNS_1 + ", " + DEV_DNS_2 + "]");
        }
        // STRING-GETBYTES: sub_56CAC converts a Java String to a native char* exactly
        // as String.getBytes("UTF-8") -> byte[] -> GetArrayLength -> GetByteArrayElements.
        // The generic fallback returned a 16-byte zero array, so every collected Build
        // slot became an empty native string (first byte 0) and all rG* stayed "".
        if (signature.startsWith("java/lang/String->getBytes")) {
            try {
                String s = dvmObject instanceof StringObject
                        ? ((StringObject) dvmObject).getValue() : String.valueOf(dvmObject);
                return new ByteArray((VM) vm, s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8));
            } catch (Throwable t) {
                return new ByteArray((VM) vm, new byte[0]);
            }
        }

        if (signature.endsWith("getPackageName()Ljava/lang/String;")) {
            return new StringObject((VM) vm, PKG);
        }
        if (signature.endsWith("()Landroid/content/Context;")) {
            return dvmObject;
        }
        if (signature.startsWith("org/json/JSONObject->")) {
            DvmObject<?> r = jsonDispatch(vm, dvmObject, signature, vaList);
            if (r != null) {
                return r;
            }
        }
        if (signature.startsWith("java/security/MessageDigest->digest([B)")) {
            // one-shot digest: hash the input array directly
            DvmObject<?> arg0 = vaList.getObjectArg(0);
            byte[] input = arg0 instanceof com.github.unidbg.linux.android.dvm.array.ByteArray
                    ? ((com.github.unidbg.linux.android.dvm.array.ByteArray) arg0).getValue()
                    : new byte[0];
            StringBuilder sb = new StringBuilder("[md5] digest([B) input len=");
            sb.append(input.length).append(" ascii=");
            for (byte b : input) {
                sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
            }
            System.out.println(sb);
            return new ByteArray((VM) vm, md5raw(input));
        }
        if (signature.startsWith("java/security/MessageDigest->digest()")) {
            java.security.MessageDigest md = digestMap.get(dvmObject);
            // 只反映真实累计状态（getInstance/update 都按 JNI 语义实现），不做任何结果伪造。
            byte[] d = md != null ? md.digest() : new byte[16];
            System.out.println("[md5] digest() stateful -> " + java.util.HexFormat.of().formatHex(d));
            return new ByteArray((VM) vm, d);
        }
        if (signature.contains("java/util/List->get(I)")) {
            String[] sl = sensorLists.get(dvmObject);
            int idx = vaList.getIntArg(1);
            DvmObject<?> sen = mock("android/hardware/Sensor");
            if (sl != null && idx < sl.length) {
                sensorIdx.put(sen, idx);
            }
            return sen;
        }
        // PATCHED: clean-environment answers for the detection suite
        // (blacklisted hook classes must NOT resolve -> "class not found" = clean)
        if (signature.contains("ClassLoader->loadClass")) {
            return null;
        }
        // (foreign/cheat packages must NOT resolve -> "not installed" = clean)
        if (signature.contains("PackageManager->getApplicationLabel")) {
            // h6Z 的来源（真机报文 h6Z="知乎"）
            return new StringObject((VM) vm, APP_LABEL);
        }
        if (signature.contains("PackageManager->getPackageInfo")
                || signature.contains("PackageManager->getApplicationInfo")) {
            String pkgArg = vaList.getObjectArg(0) instanceof StringObject
                    ? ((StringObject) vaList.getObjectArg(0)).getValue() : "";
            if (!PKG.equals(pkgArg)) {
                return null;
            }
            return mock("android/content/pm/PackageInfo");
        }
        // PATCHED: real sensor list for the R* collector (0x3AE3C)
        if (signature.contains("SensorManager->getSensorList")) {
            DvmObject<?> listObj = mock("java/util/List");
            sensorLists.put(listObj, MUMU_SENSORS);
            return listObj;
        }
        if (signature.contains("Sensor->getName()")) {
            Integer idx = sensorIdx.get(dvmObject);
            String nm = idx != null && idx < MUMU_SENSORS.length ? MUMU_SENSORS[idx] : "Sensor";
            return new StringObject((VM) vm, nm);
        }
        if (signature.contains("Settings$Secure->getString(")
                || signature.contains("Settings.Secure->getString(")) {
            String key = vaList.getObjectArg(1) instanceof StringObject
                    ? ((StringObject) vaList.getObjectArg(1)).getValue() : "";
            if (key.equals("android_id")) {
                return new StringObject((VM) vm, DEV_ANDROID_ID);   // randomized by randdev
            }
            return new StringObject((VM) vm, "");
        }
        // Cursor access (media store scans). Return empty rather than invented values -
        // "ctf-media" / "_id" were fabricated and would poison the fingerprint.
        if (signature.contains("Cursor->getString")) {
            return new StringObject((VM) vm, "");
        }
        if (signature.contains("Cursor->getColumnName")) {
            return new StringObject((VM) vm, "");
        }
        if (signature.startsWith("android/content/Context->getSharedPreferences")) {
            String name = ((StringObject) vaList.getObjectArg(0)).getValue();
            DvmObject<?> sp = mock("android/content/SharedPreferences");
            prefNames.put(sp, name);
            prefData.put(sp, new java.util.HashMap<String, String>());
            System.out.println("[sp] open prefs: " + name);
            return sp;
        }
        if (signature.startsWith("android/content/SharedPreferences->edit()")) {
            DvmObject<?> ed = mock("android/content/SharedPreferences$Editor");
            editorOwner.put(ed, dvmObject);
            return ed;
        }
        if (signature.startsWith("android/content/SharedPreferences->getString(")) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            String def = vaList.getObjectArg(1) instanceof StringObject
                    ? ((StringObject) vaList.getObjectArg(1)).getValue() : "";
            Map<String, String> d = prefData.get(dvmObject);
            String v = (d == null || !d.containsKey(key)) ? def : d.get(key);
            // 不回灌任何外部数据：prefs 里有什么就是什么（初始为空），SDK 只能拿到自己的内存态。
            System.out.println("[sp] read " + prefNames.get(dvmObject) + "." + key + " -> " + v);
            return new StringObject((VM) vm, v);
        }
        if (signature.startsWith("android/content/SharedPreferences$Editor->put")) {
            // putString/putInt/putLong/putBoolean(String, X) — all return the Editor
            String key = vaList.getObjectArg(0) instanceof StringObject
                    ? ((StringObject) vaList.getObjectArg(0)).getValue() : String.valueOf(vaList.getObjectArg(0));
            Object a1 = vaList.getObjectArg(1);
            String val = a1 instanceof StringObject ? ((StringObject) a1).getValue() : String.valueOf(a1);
            spWrite(dvmObject, key, val);
            return dvmObject;
        }
        if (signature.endsWith("getSystemService(Ljava/lang/String;)Ljava/lang/Object;")
                || signature.endsWith("getSystemService(Ljava/lang/String;)Ljava/lang/String;")) {
            return mock("android/app/SystemService");
        }
        // generic: parse return type from the signature and mock it
        int rparen = signature.lastIndexOf(')');
        if (rparen >= 0) {
            String ret = signature.substring(rparen + 1);
            if (ret.equals("Ljava/lang/String;")) {
                return new StringObject((VM) vm, "");
            }
            if (ret.equals("[B")) {
                return new ByteArray((VM) vm, new byte[16]);
            }
            // ARRAY-AND-SAFE-FALLBACK: object-array returns (e.g.
            // ConnectivityManager.getAllNetworks() -> [Landroid/net/Network;) previously
            // reached super, which throws UnsupportedOperationException. That exception
            // aborts the SDK mid-cycle, so sub_751E8 bailed out before it ever sent the
            // mdna report. Hand back a concrete empty array instead.
            if (ret.startsWith("[")) {
                if (ret.equals("[Ljava/lang/String;")) {
                    return new com.github.unidbg.linux.android.dvm.array.ArrayObject();
                }
                return new com.github.unidbg.linux.android.dvm.array.ArrayObject();
            }            if (ret.startsWith("L") && ret.endsWith(";")) {
                String cls = ret.substring(1, ret.length() - 1);
                if (!cls.equals("java/lang/Object")) {
                    return mock(cls);
                }
                return null;
            }
        }
        try {
            return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        } catch (Throwable t) {
            System.out.println("[jni-miss] " + signature + " -> null (" + t.getClass().getSimpleName() + ")");
            return null;
        }
    }

    private volatile String pendingUrl;

    /** HTTP status returned by the real server on the last forwarded request (-1 = none yet) */
    private volatile int lastHttpCode = -1;

    private byte[] forwardToRealServer(byte[] body) {
        try {
            // The so dials auni.telecome.cn:18447, which does not exist on the real
            // internet. Rewrite to our loopback listener and strip TLS so the so's
            // own request reaches the canned response instead of timing out.
            String url;
            if (pendingUrl != null && pendingUrl.contains("://")) {
                int sc = pendingUrl.indexOf('/', pendingUrl.indexOf("://") + 3);
                String pth = sc > 0 ? pendingUrl.substring(sc) : "/";
                url = "http://auni.telecome.cn" + pth;   // real server, standard port 80
            } else {
                url = "http://auni.telecome.cn/a/d2api/report?v=8.1&t=a&e=2";
            }
            System.out.println("[fwd] real " + pendingUrl + " -> " + url);
            // 每次转发都会覆盖 real_request.bin / real_response.bin，多端点连发时只剩最后一个
            // （dt/d2api 的应答就是这么被 mdna 那次盖掉的）。这里按端点再存一份
            // real_<endpoint>_request/response.bin，让三条应答都能留档。
            String slug = endpointSlug(url);
            try {
                dump(outDir, "real_request.bin", body);
                dump(outDir, "real_" + slug + "_request.bin", body);
                System.out.println("[dump] request " + body.length + "B -> real_" + slug + "_request.bin");
            } catch (Throwable ignore) { }
            System.out.println("[fwd] -> " + url + " (" + body.length + "B)");
            javax.net.ssl.SSLContext c = javax.net.ssl.SSLContext.getInstance("TLS");
            c.init(null, new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        public void checkClientTrusted(java.security.cert.X509Certificate[] ch, String a) { }
                        public void checkServerTrusted(java.security.cert.X509Certificate[] ch, String a) { }
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                    }
            }, new java.security.SecureRandom());
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(c.getSocketFactory());
            javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((h, s2) -> true);
            java.net.URL u = new java.net.URL(url);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) u.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setRequestProperty("User-Agent",
                    "Dalvik/2.1.0 (Linux; U; Android 9; SM-G9900 Build/PPR1.180610.011)");
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            lastHttpCode = conn.getResponseCode();
            java.io.InputStream is = lastHttpCode < 400 ? conn.getInputStream()
                    : conn.getErrorStream();
            byte[] resp = is != null ? is.readAllBytes() : new byte[0];
            System.out.println("[fwd] <- " + lastHttpCode + " " + resp.length + "B");
            try {
                dump(outDir, "real_response.bin", resp);
                dump(outDir, "real_" + slug + "_response.bin", resp);
                System.out.println("[dump] response " + resp.length + "B -> real_" + slug + "_response.bin");
            } catch (Throwable ignore) { }
            return resp;
        } catch (Throwable t) {
            System.out.println("[fwd] fail: " + t);
            return new byte[0];
        }
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.startsWith("java/net/URL-><init>")) {
            DvmObject<?> o = dvmClass.newObject(null);
            vm.addGlobalObject(o);
            try {
                Object a0 = vaList.getObjectArg(0);
                if (a0 instanceof StringObject) {
                    pendingUrl = ((StringObject) a0).getValue();
                    System.out.println("[url] " + pendingUrl);
                }
            } catch (Throwable ignore) { }
            return o;
        }
        if (signature.startsWith("org/json/JSONObject-><init>")) {
            DvmObject<?> obj = dvmClass.newObject(null);
            vm.addGlobalObject(obj);
            if (signature.startsWith("org/json/JSONObject-><init>(Ljava/lang/String;)")) {
                StringObject so = vaList.getObjectArg(0) instanceof StringObject
                        ? (StringObject) vaList.getObjectArg(0) : null;
                try {
                    jsonObjs.put(obj, new org.json.JSONObject(so == null ? "{}" : so.getValue()));
                    System.out.println("[json] init-from-string " + jsonObjs.get(obj));
                } catch (Exception e) {
                    jsonObjs.put(obj, new org.json.JSONObject());
                }
            } else {
                jsonObjs.put(obj, new org.json.JSONObject());
            }
            return obj;
        }
        return dvmClass.newObject(null);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (signature.startsWith("org/json/JSONObject-><init>")) {
            DvmObject<?> obj = dvmClass.newObject(null);
            vm.addGlobalObject(obj);
            jsonObjs.put(obj, new org.json.JSONObject());
            return obj;
        }
        DvmObject<?> obj = dvmClass.newObject(null);
        vm.addGlobalObject(obj);
        return obj;
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        // 基类 callStaticBooleanMethodV 直接 throw UnsupportedOperationException（没有任何已知
        // 分支），SDK 用它查 ActivityManager.isUserAMonkey()（"是否在 Monkey 自动化测试下运行"）
        // 时就会把端点 6 通道的 emulation 打断。正常设备恒为 false，这里统一兜 false，
        // 顺便把签名打出来，方便发现后面还有哪些静态布尔方法被调用。
        System.out.println("[jni-static-bool] " + signature + " -> false");
        return false;
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.startsWith("org/json/JSONObject->has(") && jsonObjs.containsKey(dvmObject)) {
            String key = ((StringObject) vaList.getObjectArg(0)).getValue();
            return jsonObjs.get(dvmObject).has(key);
        }
        // NetworkCapabilities.hasTransport(I): MuMu's default network is WIFI CONNECTED,
        // so TRANSPORT_WIFI(1) is the only transport that reports true.
        if (signature.contains("hasTransport")) {
            return vaList.getIntArg(0) == 1;
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-bool] " + signature);
        }
        // connectivity gates must report "online" or the worker skips reporting
        if (signature.contains("isConnected") || signature.contains("isAvailable")
                || signature.contains("isConnectedOrConnecting")) {
            return true;
        }
        if (signature.contains("Cursor->moveToFirst") || signature.contains("Cursor->moveToNext")) {
            return true;
        }
        if (signature.startsWith("android/content/SharedPreferences$Editor->commit()")) {
            System.out.println("[sp] commit");
            return true;
        }
        return false;
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (signature.startsWith("java/security/MessageDigest->update([BII)")) {
            java.security.MessageDigest md = digestMap.get(dvmObject);
            if (md != null && varArg.getObjectArg(0) instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                com.github.unidbg.linux.android.dvm.array.ByteArray ba =
                        (com.github.unidbg.linux.android.dvm.array.ByteArray) varArg.getObjectArg(0);
                int off = varArg.getIntArg(1);
                int len = varArg.getIntArg(2);
                byte[] seg = new byte[Math.max(0, Math.min(len, ba.getValue().length - off))];
                System.arraycopy(ba.getValue(), off, seg, 0, seg.length);
                md.update(seg);
                StringBuilder sb = new StringBuilder("[md5] update VarArg([BII) len=").append(len).append(" ascii=");
                for (byte b : seg) {
                    sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                }
                System.out.println(sb);
            }
            return;
        }
        if (signature.startsWith("java/security/MessageDigest->update([B)")) {
            java.security.MessageDigest md = digestMap.get(dvmObject);
            if (md != null && varArg.getObjectArg(0) instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                byte[] data = ((com.github.unidbg.linux.android.dvm.array.ByteArray) varArg.getObjectArg(0)).getValue();
                md.update(data);
                System.out.println("[md5] update VarArg([B) len=" + data.length);
            }
            return;
        }
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.contains("getAccuracy")) {
            return 25.0f;   // plausible GPS accuracy
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-float] " + signature);
        }
        return 0.0f;
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        // Binder.getCallingUid() inside the app process is the app's own uid, so it must
        // agree with Process.myUid(). The old hardcoded 10085 contradicted 10054 - an
        // internally inconsistent value the server's consistency check can spot.
        if (signature.contains("getCallingUid")) {
            return DEV_UID;
        }
        // android.os.Process.myUid() - MuMu runs com.zhihu.android as u0_a54
        if (signature.contains("myUid")) {
            return DEV_UID;
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-static-int] " + signature);
        }
        return 0;
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.contains("currentTimeMillis")) {
            return System.currentTimeMillis();
        }
        // SystemClock.elapsedRealtime() is milliseconds since boot; a frozen 0 would
        // look wrong to the SDK's timing logic, so return a monotonic uptime.
        if (signature.contains("elapsedRealtime")) {
            return (System.nanoTime() - BOOT_NANOS) / 1_000_000L;
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-static-long] " + signature);
        }
        return 0L;
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (signature.contains("lastUpdateTime") || signature.contains("firstInstallTime")
                || signature.contains("Time")) {
            return System.currentTimeMillis();
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-longfield] " + signature);
        }
        return 0L;
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        // URLConnection.getResponseCode(): report the status the REAL server returned
        // (recorded by forwardToRealServer) instead of a blanket 200.
        if (signature.contains("getResponseCode")) {
            return lastHttpCode >= 0 ? lastHttpCode : 200;
        }
        if (signature.contains("Cursor->getCount")) {
            return 1;
        }
        // DNS list from LinkProperties.getDnsServers() - MuMu resolves via these two
        if (signature.contains("size") && dnsListObjs.contains(dvmObject)) {
            return 2;
        }
        // NetworkCapabilities bandwidths: MuMu reports >=12000Kbps up / >=60000Kbps down
        if (signature.contains("getLinkUpstreamBandwidthKbps")) {
            return 12000;
        }
        if (signature.contains("getLinkDownstreamBandwidthKbps")) {
            return 60000;
        }
        if (signature.contains("java/util/List->size()")) {
            Integer[] names = {0};
            String[] sl = sensorLists.get(dvmObject);
            return sl != null ? sl.length : 0;
        }
        // Cursor column index/int: 0 rather than the old invented 42
        if (signature.contains("Cursor->getInt") || signature.contains("Cursor->getColumnIndex")) {
            return 0;
        }
        if (signature.startsWith("java/io/InputStream->read(")) {
            DvmObject<?> arg0 = vaList.getObjectArg(0);
            if (arg0 instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                com.github.unidbg.linux.android.dvm.array.ByteArray ba =
                        (com.github.unidbg.linux.android.dvm.array.ByteArray) arg0;
                byte[] resp = pendingResponse;
                if (resp == null) {
                    return -1; // EOF
                }
                byte[] chunk = resp;
                if (signature.startsWith("java/io/InputStream->read([BII)")) {
                    int off = vaList.getIntArg(1);
                    int len = vaList.getIntArg(2);
                    chunk = new byte[Math.max(0, Math.min(len, resp.length))];
                    System.arraycopy(resp, 0, chunk, 0, chunk.length);
                }
                ba.setValue(chunk);
                pendingResponse = null;
                System.out.println("[http] injected response " + chunk.length + " bytes");
                return chunk.length;
            }
            return -1;
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-int] " + signature);
        }
        return 0;
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-long] " + signature);
        }
        return 0L;
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-void] " + signature);
        }
        if (signature.startsWith("java/security/MessageDigest->update([BII)")) {
            // unidbg 的 VaList 只装方法实参（不含 this），receiver 就是入参 dvmObject。
            // 旧代码把 arg0 当 receiver、arg1 当 byte[]，于是永远查不到 MessageDigest 实例，
            // update 被静默吞掉 —— digest() 最终返回 md5("")，K5f 变成空串摘要。
            java.security.MessageDigest md = digestMap.get(dvmObject);
            if (md != null && vaList.getObjectArg(0) instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                com.github.unidbg.linux.android.dvm.array.ByteArray ba =
                        (com.github.unidbg.linux.android.dvm.array.ByteArray) vaList.getObjectArg(0);
                int off = vaList.getIntArg(1);
                int len = vaList.getIntArg(2);
                byte[] seg = new byte[Math.max(0, Math.min(len, ba.getValue().length - off))];
                System.arraycopy(ba.getValue(), off, seg, 0, seg.length);
                md.update(seg);
                StringBuilder sb = new StringBuilder("[md5] update([BII) len=").append(len).append(" ascii=");
                for (byte b : seg) {
                    sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                }
                System.out.println(sb);
            }
            return;
        }
        if (signature.startsWith("java/security/MessageDigest->update([B)")) {
            java.security.MessageDigest md = digestMap.get(dvmObject);
            if (md != null && vaList.getObjectArg(0) instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                byte[] data = ((com.github.unidbg.linux.android.dvm.array.ByteArray) vaList.getObjectArg(0)).getValue();
                md.update(data);
                StringBuilder sb = new StringBuilder("[md5] update([B) len=").append(data.length).append(" ascii=");
                for (byte b : data) {
                    sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                }
                System.out.println(sb);
            }
            return;
        }
        if (signature.startsWith("java/io/DataOutputStream->write([B")) {
            // PATCHED: the so wraps the stream in DataOutputStream — capture the body
            DvmObject<?> arg0 = vaList.getObjectArg(0);
            if (arg0 instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                byte[] body = ((com.github.unidbg.linux.android.dvm.array.ByteArray) arg0).getValue();
                System.out.println("[fwd-cap] DataOutputStream.write " + body.length + "B");
                detectEndpointAndPrepare(body);
                if (pendingUrl != null && pendingUrl.startsWith("http")) {
                    byte[] real = forwardToRealServer(body);
                    if (real.length > 0) {
                        pendingResponse = real;
                        System.out.println("[fwd] real response armed " + real.length + "B");
                    }
                }
            }
            return;
        }
        if (signature.startsWith("java/io/OutputStream->write([B")) {
            DvmObject<?> arg0 = vaList.getObjectArg(0);
            if (arg0 instanceof com.github.unidbg.linux.android.dvm.array.ByteArray) {
                byte[] body = ((com.github.unidbg.linux.android.dvm.array.ByteArray) arg0).getValue();
                if (signature.startsWith("java/io/OutputStream->write([BII)")) {
                    int off = vaList.getIntArg(1);
                    int len = vaList.getIntArg(2);
                    byte[] slice = new byte[Math.max(0, Math.min(len, body.length - off))];
                    System.arraycopy(body, off, slice, 0, slice.length);
                    body = slice;
                }
                detectEndpointAndPrepare(body);
                if (pendingUrl != null && pendingUrl.startsWith("http")) {
                    byte[] real = forwardToRealServer(body);
                    if (real.length > 0) {
                        pendingResponse = real;
                        System.out.println("[fwd] real response armed " + real.length + "B");
                    }
                }
            }
            return;
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-objfield] " + signature);
        }
        // WifiInfo.mMacAddress - the real wlan0 MAC reported by MuMu
        if (signature.contains("mMacAddress")) {
            return new StringObject((VM) vm, DEV_WLAN_MAC);
        }
        // EV2/h6Z 的来源：真机 d2api 报文里 EV2="11.10.0"、h6Z="知乎"。旧实现把所有
        // String 字段一律返回空串，so 判空后干脆不 put 这两个键。
        if (signature.startsWith("android/content/pm/PackageInfo->versionName")) {
            return new StringObject((VM) vm, APP_VERSION);
        }
        if (signature.startsWith("android/content/pm/ApplicationInfo->dataDir")) {
            return new StringObject((VM) vm, APP_DATA_DIR);
        }
        if (signature.startsWith("android/content/pm/ApplicationInfo->publicSourceDir")) {
            return new StringObject((VM) vm, APP_SOURCE_DIR);
        }
        if (signature.startsWith("android/content/pm/ApplicationInfo->sourceDir")) {
            return new StringObject((VM) vm, APP_SOURCE_DIR);
        }
        if (signature.endsWith("Ljava/lang/String;")) {
            return new StringObject((VM) vm, "");
        }
        return null;
    }

    // DisplayMetrics：SDK 会读这些字段做屏幕指纹。基类 AbstractJni.getFloatField 是直接
    // throw UnsupportedOperationException（日志里那条 android/util/DisplayMetrics->xdpi:F），
    // 一抛就让端点 6 通道的 emulation 中断。这里按真机 SM-G9900（1080x2340, 420dpi）给值。
    private static final String DM_PREFIX = "android/util/DisplayMetrics->";
    private static final Map<String, Float> DM_FLOATS = new java.util.HashMap<>();
    static {
        DM_FLOATS.put("density", 2.625f);          // 420dpi / 160
        DM_FLOATS.put("scaledDensity", 2.625f);
        DM_FLOATS.put("xdpi", 403.42f);
        DM_FLOATS.put("ydpi", 402.55f);
    }

    /** 从 "android/util/DisplayMetrics->xdpi:F" 取出 "xdpi"，不是该类的字段则返回 null。 */
    private static String dmField(String signature) {
        if (!signature.startsWith(DM_PREFIX)) {
            return null;
        }
        String f = signature.substring(DM_PREFIX.length());
        int c = f.indexOf(':');
        return c > 0 ? f.substring(0, c) : f;
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        String name = dmField(signature);
        if (name != null) {
            Float v = DM_FLOATS.get(name);
            if (v != null) {
                if (Boolean.getBoolean("du.verbose")) {
                    System.out.println("[jni-get-float] " + signature + " = " + v);
                }
                return v;
            }
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-float] " + signature);
        }
        return 0f;
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        String name = dmField(signature);
        if (name != null) {
            if ("widthPixels".equals(name)) {
                return 1080;
            }
            if ("heightPixels".equals(name)) {
                return 2340;
            }
            if ("densityDpi".equals(name)) {
                return 420;
            }
        }
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-intfield] " + signature);
        }
        return 0;
    }

    // ---- minimal JNI stubs: make every callback return benign defaults ----

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        // DUHelper static counters (mPopu/mPort/mMeic/mSplt) — Java layer owns them
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-int] " + signature);
        }
        // Real MuMu device is API 35. Returning 0 made the so believe it runs on a
        // pre-API-1 platform, which flips its version-gated collection branches
        // (e.g. rG0/SERIAL is only collected when SDK_INT <= 28).
        if (signature.startsWith("android/os/Build$VERSION->SDK_INT")) {
            return 35;
        }
        return 0;
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-set-int] " + signature + " = " + value);
        }
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-long] " + signature);
        }
        return 0L;
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-set-long] " + signature + " = " + value);
        }
    }

    @Override
    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature, DvmObject<?> value) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-set-obj] " + signature);
        }
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-get-obj] " + signature);
        }
        // array-typed static fields (e.g. Build.SUPPORTED_ABIS [Ljava/lang/String;)
        // must return a real array or GetArrayLength throws ClassCastException
        if (signature.endsWith("[Ljava/lang/String;") || signature.contains("SUPPORTED_ABIS")) {
            DvmClass strCls = vm.resolveClass("java/lang/String");
            // fKe = Build.SUPPORTED_ABIS joined with ',' - MuMu's real abilist is
            // ro.product.cpu.abilist = x86_64,arm64-v8a,x86
            return new com.github.unidbg.linux.android.dvm.array.ArrayObject(
                    new StringObject((VM) vm, "x86_64"),
                    new StringObject((VM) vm, "arm64-v8a"),
                    new StringObject((VM) vm, "x86"));
        }
        if (signature.endsWith("[B")) {
            return new ByteArray((VM) vm, new byte[16]);
        }
        // PATCHED: consistent non-empty synthetic device (all-empty Build fields is an
        // "environment invalid" signal for a device-ID SDK)
        if (signature.startsWith("android/os/Build->")) {
            String field = signature.substring("android/os/Build->".length());
            int sp = field.indexOf(':');   // unidbg signs it "android/os/Build->DEVICE:Ljava/lang/String;" - splitting on a space never matched any slot, so every rG* stayed empty
            String fname = sp > 0 ? field.substring(0, sp) : field;
            String v = NOROP ? null : BUILD_VALUES.get(fname);
            if (Boolean.getBoolean("du.verbose")) {
                System.out.println("[build] sig=" + signature + " fname=" + fname + " v=" + v);
            }
            if (v != null) {
                return new StringObject((VM) vm, v);
            }
        }
        return new StringObject((VM) vm, "");
    }

    private static final Map<String, String> SYS_PROPS = new java.util.HashMap<>();
    static {
        // ONLY-REAL-DEVICE-PROPS: every entry below was verified to exist on the MuMu
        // device via `adb shell getprop`. The previous table also injected fabricated
        // serial / IMEI / MAC / cpuid keys plus oppo|oneplus aliases and
        // ro.product.cpu.abi2 - none of which exist on the device - so the emulated
        // fingerprint diverged from the device that actually received the real ms_id.
        SYS_PROPS.put("ro.product.model", "SM-G9900");
        SYS_PROPS.put("ro.product.brand", "Samsung");
        SYS_PROPS.put("ro.product.manufacturer", "Samsung");
        SYS_PROPS.put("ro.product.device", "r9q");
        SYS_PROPS.put("ro.product.name", "r9q");
        SYS_PROPS.put("ro.product.board", "SM-G9900");
        SYS_PROPS.put("ro.build.version.sdk", "35");
        SYS_PROPS.put("ro.build.version.release", "15");
        SYS_PROPS.put("ro.build.fingerprint", "Samsung/r9q/r9q:15/V417IR/1100:user/release-keys");
        SYS_PROPS.put("ro.build.display.id", "V417IR release-keys");
        SYS_PROPS.put("ro.build.id", "V417IR");
        SYS_PROPS.put("ro.build.host", "6b29a8384f29");
        SYS_PROPS.put("ro.build.tags", "release-keys");
        SYS_PROPS.put("ro.build.type", "user");
        SYS_PROPS.put("ro.build.user", "abc");
        SYS_PROPS.put("ro.build.date.utc", "1790688506");
        SYS_PROPS.put("ro.bootloader", "unknown");
        SYS_PROPS.put("ro.hardware", "Samsung");
        SYS_PROPS.put("ro.board.platform", "Samsung");
        SYS_PROPS.put("ro.boot.hardware", "kona");
        SYS_PROPS.put("ro.product.cpu.abi", "x86_64");
        SYS_PROPS.put("ro.product.cpu.abilist", "x86_64,arm64-v8a,x86");
    }

    // MuMu real sensor names (dumpsys sensorservice) — for getSensorList mocking
    private static final String[] MUMU_SENSORS = {
        "3-axis Accelerometer", "3-axis Gyroscope", "3-axis Magnetic field sensor",
        "Orientation sensor", "Ambient Temperature sensor", "Proximity sensor",
        "Light sensor", "Pressure sensor", "Corrected Gyroscope Sensor",
        "Game Rotation Vector Sensor", "Gyroscope Bias (debug)",
        "GeoMag Rotation Vector Sensor", "Gravity Sensor", "Linear Acceleration Sensor",
        "Rotation Vector Sensor", "Orientation Sensor"
    };
    private final Map<DvmObject<?>, String[]> sensorLists = new java.util.IdentityHashMap<>();
    private final Map<DvmObject<?>, Integer> sensorIdx = new java.util.IdentityHashMap<>();
    private int sensorCursor = 0;

    private static final Map<String, String> BUILD_VALUES = new java.util.HashMap<>();
    static {
        // Values read straight off the MuMu device (getprop). Slots the device leaves
        // empty (SERIAL / SKU / ODM_SKU / SOC_*) are kept empty on purpose - fabricating
        // them is exactly what made the fingerprint stop matching.
        BUILD_VALUES.put("BOARD", "SM-G9900");
        BUILD_VALUES.put("BOOTLOADER", "unknown");
        BUILD_VALUES.put("BRAND", "Samsung");
        BUILD_VALUES.put("CPU_ABI", "x86_64");
        BUILD_VALUES.put("CPU_ABI2", "");
        BUILD_VALUES.put("DEVICE", "r9q");
        BUILD_VALUES.put("DISPLAY", "V417IR release-keys");
        BUILD_VALUES.put("FINGERPRINT", "Samsung/r9q/r9q:15/V417IR/1100:user/release-keys");
        BUILD_VALUES.put("HARDWARE", "Samsung");
        BUILD_VALUES.put("HOST", "6b29a8384f29");
        BUILD_VALUES.put("ID", "V417IR");
        BUILD_VALUES.put("MANUFACTURER", "Samsung");
        BUILD_VALUES.put("MODEL", "SM-G9900");
        BUILD_VALUES.put("PRODUCT", "r9q");
        BUILD_VALUES.put("SERIAL", "");
        BUILD_VALUES.put("TAGS", "release-keys");
        BUILD_VALUES.put("TYPE", "user");
        BUILD_VALUES.put("USER", "abc");
        BUILD_VALUES.put("SKU", "");
        BUILD_VALUES.put("ODM_SKU", "");
        BUILD_VALUES.put("SOC_MANUFACTURER", "");
        BUILD_VALUES.put("SOC_MODEL", "");
    }    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (Boolean.getBoolean("du.verbose")) {
            System.out.println("[jni-static-obj] " + signature);
        }
        // Kvr: sub_3A424 -> android.os.Build.getRadioVersion(). MuMu reports
        // gsm.version.baseband = 1.0.0.0.
        if (signature.startsWith("android/os/Build->getRadioVersion()")) {
            return new StringObject((VM) vm, "1.0.0.0");
        }
        // tNP: sub_3A4AC -> android.os.Build.getSerial(). ro.serialno is unset on MuMu,
        // which is exactly the case AOSP maps to the UNKNOWN constant. (The SDK also
        // skips the field outright when its serial error code is 10002.)
        if (signature.startsWith("android/os/Build->getSerial()")) {
            // ro.serialno is unset on MuMu (verified via adb), so hand back the raw
            // property value instead of substituting the AOSP "unknown" constant.
            return new StringObject((VM) vm, "");
        }
        if (signature.endsWith("getProperty(Ljava/lang/String;)Ljava/lang/String;")
                || signature.endsWith("getenv(Ljava/lang/String;)Ljava/lang/String;")) {
            return new StringObject((VM) vm, "");   // PATCHED: null crashes StringObject ctor
        }
        if (signature.contains("Settings$Secure->getString")) {
            String key = vaList.getObjectArg(1) instanceof StringObject
                    ? ((StringObject) vaList.getObjectArg(1)).getValue() : "";
            if (key.equals("android_id")) {
                return new StringObject((VM) vm, DEV_ANDROID_ID);   // randomized by randdev
            }
            return new StringObject((VM) vm, "");
        }
        if (signature.startsWith("java/security/MessageDigest->getInstance")) {
            DvmObject<?> mdObj = dvmClass.newObject(null);
            vm.addGlobalObject(mdObj);
            try {
                String algo = ((StringObject) vaList.getObjectArg(0)).getValue();
                digestMap.put(mdObj, java.security.MessageDigest.getInstance(algo));
            } catch (Exception ignore) {
            }
            return mdObj;
        }
        int rparen = signature.lastIndexOf(')');
        if (rparen >= 0) {
            String ret = signature.substring(rparen + 1);
            try {
                if (ret.equals("Ljava/lang/String;")) {
                    return new StringObject((VM) vm, "");
                }
                if (ret.equals("[B")) {
                    return new ByteArray((VM) vm, new byte[16]);
                }
                // ARRAY-AND-SAFE-FALLBACK: object-array returns (e.g.
            // ConnectivityManager.getAllNetworks() -> [Landroid/net/Network;) previously
            // reached super, which throws UnsupportedOperationException. That exception
            // aborts the SDK mid-cycle, so sub_751E8 bailed out before it ever sent the
            // mdna report. Hand back a concrete empty array instead.
            if (ret.startsWith("[")) {
                if (ret.equals("[Ljava/lang/String;")) {
                    return new com.github.unidbg.linux.android.dvm.array.ArrayObject();
                }
                return new com.github.unidbg.linux.android.dvm.array.ArrayObject();
            }            if (ret.startsWith("L") && ret.endsWith(";")) {
                    String cls = ret.substring(1, ret.length() - 1);
                    if (!cls.equals("java/lang/Object")) {
                        return mock(cls);
                    }
                    return null;
                }
            } catch (Throwable t) {
                System.out.println("[!] static-obj " + signature + " -> " + t);
                return new StringObject((VM) vm, "");
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }
}
