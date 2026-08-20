// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.bridge;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class NativeBridge {
    public static native int getJvmtiVersion0();
    public static native boolean addToBootstrapSearch0(String path);
    public static native boolean addToSystemSearch0(String path);
    public static native int getLoadedClassCount0();

    // Phase 2: install memory guard (inline-hook VirtualProtect etc.)
    public static native void installMemoryGuard0();
    // Phase 2: start hook scanner background thread
    public static native void startHookScanner0();
    // Phase 2: stop hook scanner
    public static native void stopHookScanner0();
    // Phase 2: get memory guard block count
    public static native long getMemoryGuardBlockCount0();
    // Phase 2: get hook scanner repair count
    public static native long getHookScannerRepairCount0();
    // Phase 2: manually trigger a full scan + repair cycle
    public static native int scanAndRepairNow0();
    // Phase 2: get jvm.dll base address (native-side, reliable)
    public static native long getJvmBaseAddress0();
    // Phase 2: check if a function at address looks hooked
    public static native boolean isFunctionHooked0(long addr, int size);

    // ── Method replacement (no JVMTI, no bytecode modification) ──
    // These use direct Method* entry-point redirection.
    // Bytecodes stay pristine — JVMTI GetBytecodes sees the original.

    // Find a method by class + name + signature. Returns a handle.
    public static native long methodFind0(Class<?> clazz, String name, String sig);
    // Redirect a method's entry to a native function pointer.
    // Forces interpreter mode (deoptimizes JIT). Returns true on success.
    public static native boolean methodRedirect0(long handle, long funcPtr);
    // Restore original entry point.
    public static native boolean methodRestore0(long handle);
    // Detect Method* field offsets at runtime (call once early).
    public static native void methodDetectOffsets0();
    // Verify redirect is still in place; re-apply if overwritten
    // by JIT recompilation / link_method / clear_code / RetransformClasses.
    public static native boolean methodVerify0(long handle, long funcPtr);
    // Get replacement function pointer by index
    // 0 = getHealth returning FLT_MAX, 1 = getHealth returning 0
    public static native long getReplacementFuncByIndex0(int index);

    // ── Interpreter hook (constMethod swap — runs target's Java bytecodes) ──
    // Initialize: find interpreter dispatch table in jvm.dll
    public static native boolean interpHookInit0();

    // Resolve a java.lang.reflect.Method to its raw Method* address (long).
    // Convenience for passing src to interpHookFreturn0.
    public static native long methodPtrOf0(java.lang.reflect.Method m);

    // Make src execute target's Java bytecodes.
    //   srcMethodPtr : resolved Method* of the method to override
    //                  (get it via methodPtrOf0(srcMethod))
    //   targetMethod : a java.lang.reflect.Method whose bytecodes src will run.
    // Requires src and target to share the same descriptor (same args/return)
    // so the shared interpreter frame (this + args) stays valid.
    // Forces src into interpreter mode + anti-inline; Tier-2 best-effort
    // deoptimizes nmethods that already inlined src.
    public static native boolean interpHookFreturn0(long srcMethodPtr, java.lang.reflect.Method targetMethod);

    // Remove hook: restore src's original constMethod + entry points.
    public static native boolean interpHookFreturnRemove0(long srcMethodPtr);

    // Start/stop the fast guard thread (auto-started in JNI_OnLoad; re-applies
    // every hook every ~1ms so adversary direct Method* writes are reverted).
    public static native void interpHookStartGuard0();
    public static native void interpHookStopGuard0();

    // Self-test: trigger a JVMTI RetransformClasses on `clazz` via our env.
    // The patched shared JVMTI table routes it through our filter, which
    // re-applies hooks after — proving adversary retransform can't revert us.
    // Returns the jvmtiError code (0 = success).
    public static native int selfRetransform0(Class<?> clazz);

    // Test helper: simulate an adversary reverting src._constMethod to its
    // original. The guard thread should re-apply within ~1ms.
    public static native boolean testTamperConstMethod0(long srcMethodPtr);

    // Deoptimize method (force interpreter mode)
    public static native void interpHookDeoptimize0(long methodPtr, int codeOffset);
    // Get raw Method* pointer from a methodFind0 handle
    public static native long methodGetRawPtr0(long handle);

    // ── TRUE interpreter hook (dispatch-table level, Method*-independent) ──
    // Patches the interpreter's bytecode dispatch table so that at src's
    // freturn, if rbx==src, control re-dispatches target's bytecodes in the
    // shared frame (this -> target's first param). src's Method* is NEVER
    // written, so an adversary changing src's Method* cannot affect the
    // interpreted return path. No guard thread needed.
    public static native boolean dispatchHookInit0();
    public static native boolean dispatchHookFreturn0(long srcMethodPtr, java.lang.reflect.Method targetMethod);
    public static native boolean dispatchHookFreturnRemove0(long srcMethodPtr);

    // ── Stub-based interpreter hook (no constMethod swap) ──────────────
    // Allocates a tiny executable stub that returns a captured constant and
    // redirects src's _from_interpreted_entry / _from_compiled_entry to it.
    // This is the SAFE successor to the constMethod-swap approach — the JIT
    // compiler's metadata chain stays intact (no C1/C2 crash).
    //   retType: 0 = float, 1 = double, 2 = int, 3 = long, 4 = object(null), 5 = void
    //   retValueBits: raw bits of the return value (float bits, double bits, int, long)
    public static native boolean interpHookStub0(long srcMethodPtr, int retType, long retValueBits);

    // ── Complete method replacement (entry-point copy, supports params) ──
    // Copies target's _from_interpreted_entry / _from_compiled_entry to src.
    // src executes target's Java bytecodes (this + args shared via the
    // interpreter frame). Supports methods with ANY signature (parameters,
    // any return type). No constMethod swap — JIT metadata stays intact.
    public static native boolean interpHookReplace0(long srcMethodPtr, java.lang.reflect.Method targetMethod);

    // ── Class protection (pure native, no JVMTI) ──────────────────────
    // Marks a class as hidden (JVM_ACC_IS_HIDDEN_CLASS), unlinks it from the
    // ClassLoaderData's class list (invisible to JVMTI GetLoadedClasses /
    // ClassFileLoadHook / RetransformClasses), and VirtualProtect-locks its
    // InstanceKlass memory pages to PAGE_READONLY.
    public static native boolean protectClass0(Class<?> clazz);
    public static native boolean unprotectClass0(Class<?> clazz);
    public static native String debugCheckProtection0(Class<?> clazz);

    // ── Ghost class: inject bytecodes as a hidden class (bypass ClassLoader) ──
    // Creates a class in Metaspace that is NOT in SystemDictionary,
    // NOT in any ClassLoader's class list, NOT visible to JVMTI.
    // Uses defineHiddenClass + full protect_class defense layer.
    // hostClass: provides package/nest access context
    // bytecodes: raw .class file bytes

    /**
     * 滚木类生成方法 注： 常量池项不能超过 4096 个，方法数量不要超过 64 个
     * @param bytecodes 要注入的字节码
     * @param hostClass 宿主类，绕过为null则强行在jvm中生成一个这个类
     * @return 生成的类
     */
    public static native Class<?> defineGhostClass0(byte[] bytecodes, Class<?> hostClass);

    // ── Unified Framework API (src, target) ──────────────────
    // Framework 1: Method* entry-point replacement
    // Copies target's _i2i_entry, _from_interpreted_entry, _from_compiled_entry
    // to src. Forces src into interpreter mode (deoptimize + anti-inline).
    // this is naturally available via interpreter frame Locals[0].
    public static native boolean replaceMethod0(java.lang.reflect.Method src, java.lang.reflect.Method target);

    // Framework 2: Interpreter-level hook
    // Same mechanism as replaceMethod0 but tracked separately for
    // guard/re-apply. Removes old replacementBits/assembly stub approach.
    public static native boolean hookInterpreterMethod0(java.lang.reflect.Method src, java.lang.reflect.Method target);

    // Remove interpreter hook by src Method
    public static native boolean removeInterpreterHook0(java.lang.reflect.Method src);

    // Initialize jvm_deopt (detect Method* offsets)
    public static native void jvmDeoptInit0();

    // ── 进程保护 (PPL via BYOVD) ──────────────────────────────────
    // 详见 docs/PPL_RESEARCH.md。强制启用 PPL 保护:
    //   纯用户态无法设置 PPL (EPROCESS.Protection 是内核字段, 仅内核可写)。
    //   此方法通过 BYOVD (Bring Your Own Vulnerable Driver) 加载一个有
    //   内核 R/W 原语的已签名驱动, 直接 patch EPROCESS.Protection = 0xC1
    //   (WinTcb ProtectedLight), 使本进程获得 PPL 级保护 —— 调试器和
    //   外部进程 (含管理员) 都无法 OpenProcess / ReadProcessMemory /
    //   WriteProcessMemory / DebugActiveProcess。
    //
    //   driverPath : .sys 驱动文件绝对路径; null=仅查询状态
    //   driverType : 0=NONE(仅查询), 1=RTCore64协议, 2=GENERIC(自定义IOCTL),
    //                3=CUSTOM(tzd_ppl_drv.sys, 见 native/driver/)
    //   targetPpl  : 目标 PPL 字节
    //                0xC1 = WinTcb ProtectedLight (最高级, 仅 WinTcb 进程能访问)
    //                0xA1 = Windows ProtectedLight
    //                0x61 = Antimalware ProtectedLight
    //   返回: 0=成功, 负数=错误码
    //         -1=需管理员, -2=驱动加载失败, -3=设备打开失败,
    //         -4=找不到ntoskrnl, -5=偏移解析失败, -6=找不到EPROCESS,
    //         -7=内核写入失败, -8=验证失败, -9=未提供驱动
    public static native int processProtect0(String driverPath, int driverType, int targetPpl);

    // 查询当前进程 PPL 保护字节
    // 返回: 0=无保护, 0xC1=WinTcb PPL, 0xA1=Windows PPL... 或 -1=查询失败
    public static native int getProcessProtectionByte0();

    // 获取保护状态 JSON 字串 (含驱动/内核基址/EPROCESS地址/保护字节等)
    public static native String getProcessProtectionStatus0();

    // 设置通用驱动 IOCTL 协议参数 (driverType=GENERIC 时使用)
    //   deviceName : 如 "\\\\.\\MyDriver"
    //   readIoctl  : 读内存 IOCTL 码 (如 0x80002050)
    //   writeIoctl : 写内存 IOCTL 码 (如 0x80002048)
    public static native boolean setGenericDriverIoctl0(String deviceName, int readIoctl, int writeIoctl);

    // 设置 KernCoreLib64 (driverType=5) 物理扫描的 hole-free RAM 物理范围
    //   CSV: "base,len;base,len;..."  base/len 字节, 可十进制或 0x 十六进制
    //   仅扫描这些范围 → 绝不盲扫 → 不会卡死 (读 MMIO 会让总线挂死且不触发 #PF)
    //   空串/未调用 → kerncore 拒绝扫描 (返回 -10 TZD_PP_ERR_NO_RAMMAP), 不映射不读取
    public static native boolean setRamRanges0(String rangesCsv);

    // 卸载已加载的 BYOVD 驱动服务
    public static native void unloadProtectDriver0();

    // ════════════════════════════════════════════════════════════════
    // ─── 反 shellcode / ETW-TI / systrace / 进程保护 ──────────────────
    //   调用前需先 processProtect0() 成功加载 TZD_DRIVER_CUSTOM 驱动。
    // ════════════════════════════════════════════════════════════════

    // 设置 syscall 扫描监控目标 PID (scanSyscalls0 扫描此 PID)
    public static native boolean setMonitorPid0(int pid);

    // 扫描监控进程的直接/间接 syscall stub → 命中页中和
    //   返回 long[]{hits, nxBlocked}
    public static native long[] scanSyscalls0();

    // 事件驱动进程保护 (ObRegisterCallbacks) — 裁剪他人句柄危险权限
    public static native boolean protectPid0(int pid);
    public static native boolean unprotectPid0();

    // 反 shellcode 防御武装 (线程/镜像通知 + 500ms 扫描 + ETW-TI best-effort)
    //   成功后自动启动告警轮询线程 (compromised=1 → kill 0x5C)
    public static native boolean armScDefense0(int pid);
    //   自动停止告警轮询线程
    public static native boolean disarmScDefense0();

    // 查询反 shellcode 累计统计
    //   返回 long[]{scans, pagesNx, threadsSeen, imagesSeen,
    //               unsignedImgs, filelessPe, etwTiEnabled}
    public static native long[] queryScStats0();

    // ETW Threat-Intelligence 主方案 — 强制 ThreatInt provider 发射
    public static native boolean armEtwTi0();
    public static native boolean disarmEtwTi0();

    // 系统调用追踪 (KiDynamicTraceMask gate; 检测不阻断)
    public static native boolean armSystrace0();
    public static native boolean disarmSystrace0();

    // 查询告警 — 扫描发现 shellcode 时 compromised=1
    //   返回 long[]{compromised, childBlocked, lastShellcodeType,
    //               creatorThreadId, lastShellcodeVa}
    public static native long[] queryAlert0();

    // 告警轮询线程 (500ms poll → compromised=1 → TerminateProcess 0x5C)
    //   armScDefense0 成功后自动调用; 也可独立调用
    public static native boolean startAlertPolling0();
    public static native boolean stopAlertPolling0();

    // ETW ThreatIntelligence consumer — 开 trace session 消费 ThreatInt 事件
    //   pid : 被武装进程 PID (只关心此 PID 的事件)
    //   setPpl : true=自动设 PPL Antimalware Light (ThreatInt 订阅需要)
    //   失败 (ACCESS_DENIED) 说明 PPL 不足 → 回退告警轮询
    public static native boolean startEtwConsumer0(int pid, boolean setPpl);
    public static native boolean stopEtwConsumer0();

    // Thin Hypervisor (VMX + EPT) — Phase 1: VMXON + EPT identity map
    public static native boolean armHypervisor0();
    public static native void disarmHypervisor0();

    // ═══════════════════════════════════════════════════════════════════════
    // ─── JIT 代码缓存写保护 (EPT-based + 周期扫描内容校验) ──────────────────
    //   区分 JIT 合法写 (set_int_at 等, RIP ∈ jvm.dll) vs 恶意篡改 (shellcode /
    //   Unsafe.putByte, RIP ∉ jvm.dll 或内容非 JIT)。调用前需先 armHypervisor0()。
    //
    //   典型使用流程:
    //     1. NativeBridge.armHypervisor0();                     // 武装 hypervisor
    //     2. NativeBridge.setJvmWriter0(jvmDllBase, jvmDllSize); // 设置合法写者范围
    //     3. NativeBridge.registerJitRange0(pid, ccBase, ccSize); // 注册代码缓存范围
    //     4. 轮询 queryJitAlert0() → tampered=1 则 kill
    // ═══════════════════════════════════════════════════════════════════════

    // 注册 JIT 代码缓存 GVA 范围 (JDK20 有 3 个代码堆, 各调一次)
    //   pid  : 目标 Java 进程 PID
    //   base : JIT 代码缓存堆 GVA 基址
    //   size : JIT 代码缓存堆 GVA 大小
    public static native boolean registerJitRange0(int pid, long base, long size);

    // 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段; 合法 JIT 补丁的写者 RIP 必在此内)
    public static native boolean setJvmWriter0(long jvmBase, long jvmSize);

    // 查询 JIT 篡改告警 — 返回 long[6]:
    //   [0] tampered    : 1 = 检测到非 JVM 写 JIT (应 kill)
    //   [1] blocks      : 累计阻止写次数
    //   [2] allows      : 累计允许 JVM 写次数
    //   [3] rangeCount  : 已注册 JIT 范围数
    //   [4] tamperRip   : 最近被阻止写者的 RIP
    //   [5] tamperVa    : 最近被写的 JIT GVA
    public static native long[] queryJitAlert0();

    // 清除所有 JIT 范围 + 恢复 restricted EPT 为 RWX
    public static native boolean clearJitRanges0();

    public static boolean isReady() {
        try {
            return getJvmBaseAddress0() != 0L;
        } catch (Throwable t) {
            return false;
        }
    }

    public static String getOurJarPath() {
        try {
            URL url = NativeBridge.class.getProtectionDomain().getCodeSource().getLocation();
            if (url == null) return null;
            Path p = Paths.get(url.toURI());
            return p.toAbsolutePath().toString();
        } catch (Throwable t) {
            try {
                URL url = NativeBridge.class.getResource("NativeBridge.class");
                if (url != null && url.toString().startsWith("jar:file:")) {
                    String s = url.toString().substring(9, url.toString().indexOf(33));
                    return Paths.get(URI.create(s)).toAbsolutePath().toString();
                }
            } catch (Throwable t2) {}
            return null;
        }
    }
}
