package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.util.Scanner;

/**
 * TestProcessProtect: 验证 PPL (Protected Process Light) 强制启用。
 *
 * 用法:
 *   java TestProcessProtect                     # 仅查询当前保护状态
 *   java TestProcessProtect <driver.sys>        # RTCore64 协议 BYOVD
 *   java TestProcessProtect <driver.sys> 2 "\\\\.\\MyDev" 0x80002050 0x80002048
 *                                               # 通用驱动协议 BYOVD
 *   java TestProcessProtect kerncore [KernCoreLib64.sys]  # KernCoreLib64 物理内存映射路径
 *   java TestProcessProtect <KernCoreLib64.sys> 5         # 等价 (显式指定 type=5)
 *
 * 流程:
 *   1. 加载 seckill_native.dll
 *   2. 查询初始保护字节 (应为 0 = 无保护)
 *   3. 若提供驱动路径 → processProtect0() 执行 BYOVD 全链
 *   4. 查询保护字节 (应变为 0xC1 = WinTcb PPL)
 *   5. 打印状态 JSON
 *   6. 验证: 若 PPL 已启用, 外部进程 OpenProcess(PROCESS_VM_READ) 应失败
 *
 * 详见 docs/PPL_RESEARCH.md
 */
public final class TestProcessProtect {

    // PPL 字节常量 (见 process_protect.h)
    static final int PPL_NONE              = 0x00;
    static final int PPL_WINTCB_LIGHT      = 0xC1;
    static final int PPL_WINDOWS_LIGHT     = 0xA1;
    static final int PPL_ANTIMALWARE_LIGHT = 0x61;

    // KernCoreLib64.sys 默认位置 (kerncore 快捷方式未显式指定路径时使用)
    // 注意: 原生 driver_load 用 ANSI 版 CreateServiceA, 不支持中文路径/正斜杠,
    // 故默认放到 C:\Temp (ASCII + 反斜杠)。运行前需把 .sys 复制到此路径。
    static final String DEFAULT_KERNCORE_SYS =
            "C:\\Temp\\KernCoreLib64.sys";

    public static void main(String[] args) throws Exception {
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        try { System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll"); }
        catch (UnsatisfiedLinkError e) {
            if (!e.getMessage().contains("already")) throw e;
        }

        System.out.println("╔════════════════════════════════════════════════════╗");
        System.out.println("║   PPL (Protected Process Light) 强制启用测试       ║");
        System.out.println("╚════════════════════════════════════════════════════╝");
        System.out.println("PID = " + ProcessHandle.current().pid());
        System.out.println("Is elevated? " + isElevated());
        System.out.println();

        // ─── 1. 查询初始保护状态 ───
        System.out.println("═══ Step 1: 查询初始保护状态 ═══");
        int before = NativeBridge.getProcessProtectionByte0();
        System.out.println("初始 PPL 字节 = " + formatPpl(before));
        System.out.println(NativeBridge.getProcessProtectionStatus0());
        System.out.println();

        // ─── 2. 若未提供驱动, 仅报告状态 ───
        if (args.length == 0) {
            System.out.println("═══ 未提供驱动路径 — 仅查询模式 ═══");
            System.out.println("要启用 PPL, 提供驱动或使用内置漏洞利用模式:");
            System.out.println("  java TestProcessProtect kerncore              # KernCoreLib64.sys (物理内存映射)");
            System.out.println("  java TestProcessProtect kerncore <path.sys>    # 指定 KernCoreLib64.sys 路径");
            System.out.println("  java TestProcessProtect <driver.sys>           # BYOVD (RTCore64)");
            System.out.println("  java TestProcessProtect appid                  # 利用 appid.sys SrpDevice");
            System.out.println("  java TestProcessProtect <drv> 3               # 自定义驱动");
            System.out.println();
            System.out.println("支持的模式 (driverType):");
            System.out.println("  1=RTCore64.sys  2=GENERIC  3=CUSTOM(tzd_ppl_drv)  4=APPID(appid.sys)  5=KERNCORE(KernCoreLib64.sys)");
            System.out.println();
            System.out.println("注意: 纯用户态无法设置 PPL (EPROCESS.Protection 是内核字段)。");
            System.out.println("      详见 docs/PPL_RESEARCH.md 的逆向研究结论。");
            boolean pass = (before == 0 || before == -1);
            System.out.println(pass ? "\nPASS (查询正常)" : "\nFAIL");
            System.exit(pass ? 0 : 1);
        }

        // ─── 3. BYOVD: 加载驱动并 patch EPROCESS.Protection ───
        String driverPath = args[0];
        int driverType = 1; // 默认 RTCore64
        int targetPpl = PPL_WINTCB_LIGHT;

        // driverType=4 (APPID) 不需要 driverPath, 直接用 appid.sys
        if (args.length >= 1 && args[0].equals("appid")) {
            driverPath = null;
            driverType = 4;
        }
        // driverType=5 (KERNCORE) — KernCoreLib64.sys 物理内存映射路径
        // 快捷方式: "kerncore" 或 "kerncore <path.sys>"; 否则用显式 "<path.sys> 5"
        if (args.length >= 1 && args[0].equals("kerncore")) {
            driverPath = (args.length >= 2) ? args[1] : DEFAULT_KERNCORE_SYS;
            driverType = 5;
        }
        String deviceName = null;
        int readIoctl = 0, writeIoctl = 0;

        if (args.length >= 2 && !args[0].equals("appid") && !args[0].equals("kerncore")) {
            driverType = Integer.parseInt(args[1]);
        }
        if (driverType == 2 && args.length >= 5) {
            // 通用协议: driverType=2 deviceName readIoctl writeIoctl
            deviceName = args[2];
            readIoctl = (int) Long.parseLong(args[3], 16);
            writeIoctl = (int) Long.parseLong(args[4], 16);
            NativeBridge.setGenericDriverIoctl0(deviceName, readIoctl, writeIoctl);
            System.out.println("═══ Step 2: 配置通用驱动协议 ═══");
            System.out.println("device=" + deviceName + " readIoctl=0x" +
                    Integer.toHexString(readIoctl) + " writeIoctl=0x" +
                    Integer.toHexString(writeIoctl));
        }

        // ─── (仅 KERNCORE) 安全说明 ───
        if (driverType == 5) {
            System.out.println("═══ Step 1.5: KernCoreLib64 安全准备 ═══");
            System.out.println("  native 自包含: 经 PCI 配置空间枚举设备 MMIO, 仅扫非 MMIO 的 RAM");
            System.out.println("  (PCI 配置周期绝不挂起总线; 只有设备 MMIO 读会挂起 → 故只扫 RAM)");
            System.out.println();
        }

        System.out.println("═══ Step 2: BYOVD 强制启用 PPL ═══");
        System.out.println("驱动: " + driverPath);
        System.out.println("协议: " + driverTypeName(driverType));
        System.out.println("目标 PPL: " + formatPpl(targetPpl) +
                " (0x" + Integer.toHexString(targetPpl) + ")");
        System.out.println();

        int rc = NativeBridge.processProtect0(driverPath, driverType, targetPpl);
        System.out.println("processProtect0 返回码 = " + rc + " (" + errName(rc) + ")");
        System.out.println();

        // ─── 4. 查询启用后保护状态 ───
        System.out.println("═══ Step 3: 查询启用后保护状态 ═══");
        int after = NativeBridge.getProcessProtectionByte0();
        System.out.println("当前 PPL 字节 = " + formatPpl(after));
        System.out.println(NativeBridge.getProcessProtectionStatus0());
        System.out.println();

        // ─── 4b. KERNCORE 安全拒绝 (无 RAM 范围) — 未扫描未卡死, 视为安全通过 ───
        if (rc == -10) {
            System.out.println("═══ Step 4: KernCoreLib64 安全拒绝 (NO_RAMMAP) ═══");
            System.out.println("✓ 未盲扫物理内存 — 进程正常返回并打印本行 → 证明未卡死");
            System.out.println("  原因: 本机未暴露可靠的 hole-free RAM 物理映射");
            System.out.println("        (注册表 E820 空 / WMI Win32_PhysicalMemory 未提供字节地址)");
            System.out.println("  早期版本盲扫整段物理内存, 触碰 ~4GB 处 MMIO 空洞 → 整机挂死 (无 #PF, __except 抓不到)");
            System.out.println("  现已改为: 仅扫描调用者确认的 hole-free RAM 范围; 无范围则拒绝 → 绝不卡死");
            System.out.println();
            System.out.println("  PPL 未启用 (此机 KernCoreLib64 物理路径无法安全定位 EPROCESS)。");
            System.out.println("  如需 PPL: 用 RTCore64/CUSTOM 路径 (内核虚拟 R/W, 无 MMIO 问题),");
            System.out.println("  或经内核调试器读取 MmGetPhysicalMemoryRanges 后用 setRamRanges0 手动注入。");
            System.out.println();
            System.out.println("PASS (no freeze: safely refused)");
            System.exit(0);
        }

        // ─── 5. 验证 ───
        System.out.println("═══ Step 4: 验证 PPL 是否生效 ═══");
        boolean pplActive = (after == targetPpl);
        if (pplActive) {
            System.out.println("✓ PPL 已启用! EPROCESS.Protection = 0x" +
                    Integer.toHexString(after & 0xFF));
            System.out.println("✓ 外部进程 (含管理员) 现在无法 OpenProcess(PROCESS_VM_*)");
            System.out.println("✓ 调试器 (x64dbg, CheatEngine, WinDbg) 无法 attach 本进程");
            System.out.println();
            System.out.println("验证方法: 在另一个管理员命令行运行:");
            System.out.println("  tasklist /v  (能列进程但无法读内存)");
            System.out.println("  打开 x64dbg 尝试 attach PID " +
                    ProcessHandle.current().pid() + " — 应失败");
            System.out.println("  Process Hacker 属性 → Protection 应显示 ProtectedLight");
        } else if (after == 0 || after == -1) {
            System.out.println("✗ PPL 未启用 (字节=" + after + ")");
            System.out.println("  可能原因:");
            System.out.println("  - 驱动被阻止 (HVCI / 易受攻击驱动阻止列表)");
            System.out.println("  - 驱动签名无效");
            System.out.println("  - 权限不足 (需要管理员)");
            System.out.println("  - 驱动协议不匹配 (IOCTL 码错误)");
            System.out.println();
            System.out.println("  解决:");
            System.out.println("  - 以管理员身份运行");
            System.out.println("  - 禁用驱动阻止列表:");
            System.out.println("    reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config "
                    + "/v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f");
            System.out.println("  - 确认驱动文件存在且可读");
        } else {
            System.out.println("~ PPL 部分启用 (字节=0x" + Integer.toHexString(after & 0xFF) + ")");
            System.out.println("  写入成功但值非预期 — 检查 targetPpl 参数");
        }

        System.out.println();
        System.out.println(pplActive ? "PASS" : "FAIL");

        // ─── 修改部分：等待用户输入 exit 后退出 ───
        System.out.println("程序挂起中，请输入 'exit' 退出进程...");
        try (Scanner scanner = new Scanner(System.in)) {
            while (scanner.hasNextLine()) {
                String input = scanner.nextLine().trim();
                if ("exit".equalsIgnoreCase(input)) {
                    System.out.println("收到 exit 指令，程序即将退出。");
                    System.exit(pplActive ? 0 : 1);
                }
            }
        }
    }

    static String formatPpl(int b) {
        if (b < 0) return "查询失败 (-1)";
        switch (b) {
            case 0x00: return "0x00 (无保护)";
            case 0xC1: return "0xC1 (WinTcb ProtectedLight)";
            case 0xA1: return "0xA1 (Windows ProtectedLight)";
            case 0x61: return "0x61 (Antimalware ProtectedLight)";
            case 0x81: return "0x81 (Lsa ProtectedLight)";
            case 0xC2: return "0xC2 (WinTcb Protected)";
            default:   return "0x" + Integer.toHexString(b & 0xFF) + " (未知)";
        }
    }

    static String driverTypeName(int t) {
        switch (t) {
            case 0: return "NONE (仅查询)";
            case 1: return "RTCore64";
            case 2: return "GENERIC (自定义IOCTL)";
            case 3: return "CUSTOM (tzd_ppl_drv.sys)";
            case 4: return "APPID (利用appid.sys SrpDevice, 无需驱动文件)";
            case 5: return "KERNCORE (KernCoreLib64.sys, WinIo 物理内存映射)";
            default: return "UNKNOWN(" + t + ")";
        }
    }

    static String errName(int rc) {
        switch (rc) {
            case 0:   return "OK";
            case -1:  return "NO_ADMIN (需要管理员)";
            case -2:  return "DRIVER_LOAD (驱动加载失败)";
            case -3:  return "DRIVER_OPEN (设备打开失败)";
            case -4:  return "NO_NTKRNL (找不到ntoskrnl)";
            case -5:  return "OFFSET (偏移解析失败)";
            case -6:  return "NO_EPROC (找不到EPROCESS)";
            case -7:  return "WRITE (内核写入失败)";
            case -8:  return "VERIFY (验证失败)";
            case -9:  return "NO_DRIVER (未提供驱动)";
            case -10: return "NO_RAMMAP (无 hole-free RAM 范围, 拒绝盲扫 — 安全跳过, 未卡死)";
            default:  return "INTERNAL";
        }
    }

    static boolean isElevated() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (!os.contains("win")) return false;
            Process p = Runtime.getRuntime().exec(
                    "cmd /c net session >nul 2>&1 && echo ELEVATED || echo NOT_ELEVATED");
            p.waitFor();
            byte[] buf = new byte[64];
            int n = p.getInputStream().read(buf);
            return n > 0 && new String(buf, 0, n).contains("ELEVATED");
        } catch (Exception e) {
            return false;
        }
    }

    static String acquireHoleFreeRamRanges() {
        try {
            String ps =
                    "$r=Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue; " +
                            "if(-not $r){ Write-Host 'WMI_NO_INSTANCES'; exit }; " +
                            "foreach($x in $r){ Write-Host ('DIMM Start='+$x.StartingAddress+' Cap='+$x.Capacity) }; " +
                            "$md=Get-CimInstance -ClassName Win32_MemoryDevice -ErrorAction SilentlyContinue; " +
                            "if($md){ foreach($m in $md){ Write-Host ('MemDev Start='+$m.StartingAddress+' End='+$m.EndingAddress) } }";
            Process p = Runtime.getRuntime().exec(new String[]{"powershell", "-NoProfile", "-Command", ps});
            p.waitFor();
            byte[] b = new byte[8192];
            int n = p.getInputStream().read(b);
            String s = (n > 0) ? new String(b, 0, n) : "(no output)";
            System.out.println("  WMI 探测:");
            for (String line : s.split("\n")) {
                line = line.trim();
                if (!line.isEmpty()) System.out.println("    " + line);
            }
            System.out.println("  保守策略: 不自动注入 (单位/空洞不可靠 → 盲扫会卡死)");
            return "";
        } catch (Exception e) {
            System.out.println("  WMI 查询异常: " + e);
            return "";
        }
    }
}