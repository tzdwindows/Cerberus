package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import sun.misc.Unsafe;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 测试驱动 ETW-TI / SC defense / 告警轮询 + bypass 验证。
 *
 * 流程:
 *  1. 加载 DLL → 加载驱动 → 武装 SC defense (自动 ETW-TI + 扫描 + 告警轮询)
 *  2. 打印初始统计
 *  3. 尝试 bypass (syscall shellcode 注入 JIT 代码缓存)
 *  4. 等待扫描周期 → 打印最终统计 + 告警
 */
public class TestMain {

    public static class SecretClass {
        public static String test() { return "Original Secret Code"; }
    }

    public static class TargetClass {
        public static String testHook() { return "Intercepted by dispatchHookFreturn0!"; }
    }

    public static long syscallBypass() { return 10; }

    private static final int OFF_FROM_COMPILED_ENTRY = 0x40;
    private static final int OFF_FROM_INTERP_ENTRY = 0x50;

    private static void printStats(String label) {
        long[] stats = NativeBridge.queryScStats0();
        if (stats != null && stats.length >= 7) {
            System.out.printf("  [%s] scans=%d  pagesNx=%d  threads=%d  imgs=%d  unsigned=%d  fileless=%d  etwTi=%d%n",
                    label, stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[6]);
        } else {
            System.out.println("  [" + label + "] queryScStats0 returned null/short");
        }
        long[] alert = NativeBridge.queryAlert0();
        if (alert != null && alert.length >= 5) {
            System.out.printf("  [%s] compromised=%d  childBlocked=%d  type=%d  tid=%d  va=0x%x%n",
                    label, alert[0], alert[1], alert[2], alert[3], alert[4]);
        } else {
            System.out.println("  [" + label + "] queryAlert0 returned null/short");
        }
    }

    public static void main(String[] args) throws Exception {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));
        long pid = ProcessHandle.current().pid();
        System.out.println("=== TZD Driver API Test ===");
        System.out.println("PID: " + pid);
        System.out.println("按回车继续...");
        System.in.read();

        // ── Step 0: 加载 DLL (必须在 processProtect0 之前) ──────────────
        System.out.println("\n[*] Step 0: 加载 seckill_native.dll...");
        System.load("F:\\秒杀\\aitest\\seckill_mod\\native\\seckill_native.dll");
        System.out.println("    DLL loaded. isReady=" + NativeBridge.isReady());

        // ── Step 1: 加载驱动 (processProtect0 = BYOVD SCM 加载 + 开设备) ──
        System.out.println("\n[*] Step 1: 加载驱动 (processProtect0)...");
        int ppRet = NativeBridge.processProtect0(
                "C:\\Temp\\tzd_ppl_drv.sys",
                3,     // TZD_DRIVER_CUSTOM
                0      // 不设 PPL (0=不改; 只加载驱动开设备)
        );
        System.out.println("    processProtect0 ret=" + ppRet + (ppRet == 0 ? " (OK)" : " (ERR)"));
        if (ppRet != 0) {
            System.out.println("[!] 驱动加载失败, 无法继续测试驱动 API");
            System.out.println("[!] 需要管理员权限 + test-signing 模式");
            return;
        }

        // ── Step 2: 初始化 interp_hook (必须在 armScDefense0 之前!) ──────
        //   interpHookInit0 → jvm_deoptimize_method → patch nmethod verified entry
        //   (VirtualProtect PAGE_READWRITE 临时去掉执行权限)。若扫描器线程已在跑,
        //   CPU 负载撑开 race window → JVM 线程执行到该 nmethod 时 DEP violation → 崩。
        //   先完成 patching, 再启动扫描器 → 无 race。
        System.out.println("\n[*] Step 2: methodDetectOffsets0 + interpHookInit0 (before scanner)...");
        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();
        System.out.println("    interp_hook initialized");

        // ── Step 3: 单独测试 ETW-TI ──────────────────────────────────────
        System.out.println("\n[*] Step 3: armEtwTi0...");
        boolean etwOk = NativeBridge.armEtwTi0();
        System.out.println("    armEtwTi0=" + etwOk);

        // ── Step 4: 设置监控 PID + 扫描 ──────────────────────────────────
        System.out.println("\n[*] Step 4: setMonitorPid0 + scanSyscalls0...");
        boolean monOk = NativeBridge.setMonitorPid0((int) pid);
        System.out.println("    setMonitorPid0=" + monOk);
        long[] scan = NativeBridge.scanSyscalls0();
        if (scan != null) {
            System.out.printf("    scanSyscalls0: hits=%d  nxBlocked=%d%n", scan[0], scan[1]);
        }

        // ── Step 5: 武装 SC defense + Hypervisor ────────────────────────
        System.out.println("\n[*] Step 5: armHypervisor0 (VMXON + EPT)...");
        boolean hvOk = NativeBridge.armHypervisor0();
        System.out.println("    armHypervisor0=" + hvOk);

        System.out.println("\n[*] Step 5b: armScDefense0 (auto-starts alert polling)...");
        boolean armOk = NativeBridge.armScDefense0((int) pid);
        System.out.println("    armScDefense0=" + armOk);

        // ── Step 5b: 启动 ETW ThreatInt consumer (自动设 PPL Antimalware Light) ──
        //   ThreatInt 订阅需要 PPL; setPpl=true 自动通过驱动 SET_PPL 设 0x61+0x0F
        //   consumer 后台线程消费事件 → 可疑事件直接 TerminateProcess(0x5C)
        System.out.println("\n[*] Step 5b: startEtwConsumer0 (setPpl=true)...");
        boolean consumerOk = NativeBridge.startEtwConsumer0((int) pid, true);
        System.out.println("    startEtwConsumer0=" + consumerOk);
        if (!consumerOk) {
            System.out.println("    [!] ETW consumer 启动失败 — ThreatInt 订阅需 PPL Antimalware Light");
            System.out.println("    [!] 回退: 仅靠扫描器 500ms 轮询 + 告警轮询");
        }

        // ── Step 6: 打印初始统计 ────────────────────────────────────────
        System.out.println("\n[*] Step 6: 初始统计:");
        printStats("BEFORE");

        // ── Step 7: bypass 尝试 ──────────────────────────────────────────
        System.out.println("\n[*] Step 7: bypass 尝试 (syscall shellcode 注入 JIT 代码缓存)...");
        System.out.println("Before: " + SecretClass.test());

        Method srcM = SecretClass.class.getDeclaredMethod("test");
        long srcMP = NativeBridge.methodPtrOf0(srcM);
        Method tgtM = TargetClass.class.getDeclaredMethod("testHook");
        long tgtMP = NativeBridge.methodPtrOf0(tgtM);
        System.out.println("srcMP: 0x" + Long.toHexString(srcMP));
        System.out.println("tgtMP: 0x" + Long.toHexString(tgtMP));

        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe u = (Unsafe) f.get(null);

        // JIT 编译辅助方法
        Method helperM = TestMain.class.getDeclaredMethod("syscallBypass");
        long helperMP = NativeBridge.methodPtrOf0(helperM);
        for (int i = 0; i < 30000; i++) syscallBypass();
        long helperEntry = u.getLong(helperMP + OFF_FROM_COMPILED_ENTRY);
        if (helperEntry == 0 || helperEntry < 0x10000) {
            for (int i = 0; i < 30000; i++) TargetClass.testHook();
            helperEntry = u.getLong(tgtMP + OFF_FROM_COMPILED_ENTRY);
        }
        System.out.println("    helperEntry: 0x" + Long.toHexString(helperEntry));
        if (helperEntry == 0 || helperEntry < 0x10000) {
            System.out.println("[!] 无 JIT entry, 跳过 bypass");
        } else {
            // 备份原始代码
            byte[] origCode = new byte[128];
            for (int i = 0; i < 128; i++) origCode[i] = u.getByte(helperEntry + i);

            // 构建 syscall shellcode
            long targetPage = srcMP & ~0xFFFL;
            byte[] sc = buildSyscallOnlyShellcode(targetPage, 0x1000, 0x04);
            System.out.println("    Shellcode: " + sc.length + " bytes");

            // 写入并执行 shellcode
            System.out.println("    写入 shellcode 到 JIT 代码缓存...");
            for (int i = 0; i < sc.length; i++) u.putByte(helperEntry + i, sc[i]);
            long status = syscallBypass();
            System.out.println("    NTSTATUS: 0x" + Long.toHexString(status)
                    + (status >= 0 ? " (SUCCESS)" : " (FAILED)"));
            // 恢复原始代码
            for (int i = 0; i < origCode.length; i++) u.putByte(helperEntry + i, origCode[i]);
            System.out.println("    已恢复原始 JIT 代码");

            // 从新线程写入 Method*
            long tgtFC = u.getLong(tgtMP + OFF_FROM_COMPILED_ENTRY);
            long tgtFI = u.getLong(tgtMP + OFF_FROM_INTERP_ENTRY);
            final long srcMP_f = srcMP, tgtFC_f = tgtFC, tgtFI_f = tgtFI;
            AtomicBoolean done = new AtomicBoolean(false), ok = new AtomicBoolean(false);
            Thread wt = new Thread(() -> {
                try {
                    Field f2 = Unsafe.class.getDeclaredField("theUnsafe");
                    f2.setAccessible(true);
                    Unsafe u2 = (Unsafe) f2.get(null);
                    u2.putLong(srcMP_f + OFF_FROM_COMPILED_ENTRY, tgtFC_f);
                    u2.putLong(srcMP_f + OFF_FROM_INTERP_ENTRY, tgtFI_f);
                    long v = u2.getLong(srcMP_f + OFF_FROM_COMPILED_ENTRY);
                    ok.set(v == tgtFC_f);
                    done.set(true);
                    System.out.println("    [子线程] 写入: 0x" + Long.toHexString(v)
                            + " (" + (v == tgtFC_f ? "SUCCESS" : "BLOCKED") + ")");
                } catch (Throwable t) {
                    System.out.println("    [子线程] 异常: " + t);
                    done.set(true);
                }
            });
            wt.start(); wt.join(5000);
            System.out.println("    Method* 写入: " + (ok.get() ? "SUCCESS" : "FAILED"));
        }

        // ── Step 8: 验证 hook 是否生效 ──────────────────────────────────
        System.out.println("\n=== 验证 ===");
        for (int i = 0; i < 5; i++) {
            String result = SecretClass.test();
            boolean hooked = "Intercepted by dispatchHookFreturn0!".equals(result);
            System.out.println("  [" + i + "] " + result + (hooked ? " ← HOOKED!!!" : ""));
            if (hooked) break;
            Thread.sleep(50);
        }

        // ── Step 9: 等待扫描周期 → 打印最终统计 ──────────────────────────
        System.out.println("\n[*] Step 9: 等待 2s 让扫描周期跑几拍...");
        Thread.sleep(2000);
        printStats("AFTER");

        // ── Step 10: 测试 systrace ────────────────────────────────────────
        System.out.println("\n[*] Step 10: armSystrace0...");
        boolean stOk = NativeBridge.armSystrace0();
        System.out.println("    armSystrace0=" + stOk);

        // ── Step 11: 清理 ───────────────────────────────────────────────
        System.out.println("\n[*] Step 11: 清理...");
        NativeBridge.stopEtwConsumer0();     // 停 ETW consumer + 恢复 PPL
        NativeBridge.disarmHypervisor0();     // VMXOFF + 释放 EPT
        NativeBridge.disarmSystrace0();
        NativeBridge.disarmScDefense0();  // 停告警轮询 + 清 PID
        NativeBridge.unprotectPid0();
        printStats("FINAL");
        System.out.println("\n=== 测试完成 ===");
    }

    private static byte[] buildSyscallOnlyShellcode(long pageAddr, long regionSize, int newProtect) {
        byte[] code = new byte[256];
        int p = 0;
        code[p++] = (byte)0x48; code[p++] = (byte)0x83; code[p++] = (byte)0xEC; code[p++] = 0x48;
        code[p++] = (byte)0x48; code[p++] = (byte)0xB8;
        write64(code, p, pageAddr); p += 8;
        code[p++] = (byte)0x48; code[p++] = (byte)0x89; code[p++] = (byte)0x44; code[p++] = (byte)0x24; code[p++] = 0x30;
        code[p++] = (byte)0x48; code[p++] = (byte)0xB8;
        write64(code, p, regionSize); p += 8;
        code[p++] = (byte)0x48; code[p++] = (byte)0x89; code[p++] = (byte)0x44; code[p++] = (byte)0x24; code[p++] = 0x38;
        code[p++] = (byte)0x48; code[p++] = (byte)0x8D; code[p++] = (byte)0x44; code[p++] = (byte)0x24; code[p++] = 0x40;
        code[p++] = (byte)0x48; code[p++] = (byte)0x89; code[p++] = (byte)0x44; code[p++] = (byte)0x24; code[p++] = 0x28;
        code[p++] = (byte)0x48; code[p++] = (byte)0xC7; code[p++] = (byte)0xC1;
        code[p++] = (byte)0xFF; code[p++] = (byte)0xFF; code[p++] = (byte)0xFF; code[p++] = (byte)0xFF;
        code[p++] = (byte)0x48; code[p++] = (byte)0x8D; code[p++] = (byte)0x54; code[p++] = (byte)0x24; code[p++] = 0x30;
        code[p++] = (byte)0x4C; code[p++] = (byte)0x8D; code[p++] = (byte)0x44; code[p++] = (byte)0x24; code[p++] = 0x38;
        code[p++] = (byte)0x49; code[p++] = (byte)0xC7; code[p++] = (byte)0xC1;
        write32(code, p, newProtect); p += 4;
        code[p++] = (byte)0x4C; code[p++] = (byte)0x8B; code[p++] = (byte)0xD1;
        code[p++] = (byte)0xB8; code[p++] = 0x50; code[p++] = 0x00; code[p++] = 0x00; code[p++] = 0x00;
        code[p++] = (byte)0x0F; code[p++] = (byte)0x05;
        code[p++] = (byte)0x48; code[p++] = (byte)0x83; code[p++] = (byte)0xC4; code[p++] = 0x48;
        code[p++] = (byte)0xC3;
        byte[] result = new byte[p];
        System.arraycopy(code, 0, result, 0, p);
        return result;
    }

    private static void write64(byte[] b, int o, long v) { for (int i=0;i<8;i++) b[o+i]=(byte)(v>>(i*8)); }
    private static void write32(byte[] b, int o, int v) { for (int i=0;i<4;i++) b[o+i]=(byte)(v>>(i*8)); }
}
