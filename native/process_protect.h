// Architect: tzdwindows 7
// process_protect: 强制启用 PPL (Protected Process Light) via BYOVD
//
// 逆向工程结论 (见 docs/PPL_RESEARCH.md):
//   - EPROCESS.Protection @ +0x87A (PsGetProcessProtection: 8A 81 7A 08 00 00 C3)
//   - EPROCESS.UniqueProcessId @ +0x440 (PsGetProcessId: 48 8B 81 40 04 00 00 C3)
//   - EPROCESS.ActiveProcessLinks @ +0x448 (UniqueProcessId + 8)
//   - PsInitialSystemProcess @ ntoskrnl+0xD1EA60 (指向 System EPROCESS, PID=4)
//
// 纯用户态无法设置 PPL —— EPROCESS.Protection 是内核字段, 仅内核可写。
// 唯一可行路径: BYOVD —— 加载一个有内核 R/W 原语的已签名驱动,
// 直接 patch EPROCESS.Protection = 0xC1 (WinTcb ProtectedLight)。
//
// 分层:
//   L3 BYOVD — 加载驱动 → 内核R/W → 找EPROCESS → patch Protection → 验证
//   L4 验证  — NtQueryInformationProcess(ProcessProtectionInformation) 读回保护字节
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─── 驱动类型 ───
// BYOVD: 用户提供的驱动协议。目前内置 RTCore64 协议;
// 其他驱动需要通过 generic 模式 (JNI 调用时提供 IOCTL 码)。
#define TZD_DRIVER_NONE      0   // 不加载驱动 (仅查询状态)
#define TZD_DRIVER_RTCORE64  1   // RTCore64.sys (MSI Afterburner) 协议
#define TZD_DRIVER_GENERIC   2   // 通用 IOCTL 协议 (需配合 process_protect_set_generic_ioctl)
#define TZD_DRIVER_CUSTOM    3   // 自定义 tzd_ppl_drv.sys (见 native/driver/tzd_ppl_drv.c)
#define TZD_DRIVER_APPID     4   // 利用 appid.sys SrpDevice (无需加载驱动, 见 docs/DRIVER_VULN_SCAN.md)
#define TZD_DRIVER_KERNCORE  5   // KernCoreLib64.sys (WinIo 物理内存映射, 参考 readmsr/MSI_FeatureManager_CVE)

// ─── PPL 字节值 ───
#define TZD_PPL_NONE                 0x00  // 无保护
#define TZD_PPL_WINTCB_LIGHT         0xC1  // (6<<6)|1 — 最高级, 仅WinTcb进程能访问
#define TZD_PPL_WINDOWS_LIGHT        0xA1  // (5<<6)|1 — lsass.exe 等
#define TZD_PPL_ANTIMALWARE_LIGHT    0x61  // (3<<6)|1 — 杀软
#define TZD_PPL_LSA_LIGHT            0x81  // (4<<6)|1
#define TZD_PPL_WINTCB_PROTECTED     0xC2  // (6<<6)|2 — PP (非 Light)

// ─── 错误码 ───
#define TZD_PP_OK                 0
#define TZD_PP_ERR_NO_ADMIN      (-1)   // 需要管理员权限
#define TZD_PP_ERR_DRIVER_LOAD   (-2)   // 驱动加载失败
#define TZD_PP_ERR_DRIVER_OPEN   (-3)   // 设备打开失败
#define TZD_PP_ERR_NO_NTKRNL     (-4)   // 找不到 ntoskrnl
#define TZD_PP_ERR_OFFSET        (-5)   // 动态偏移解析失败
#define TZD_PP_ERR_NO_EPROC     (-6)   // 找不到本进程 EPROCESS
#define TZD_PP_ERR_WRITE        (-7)   // 内核写入失败
#define TZD_PP_ERR_VERIFY       (-8)   // 验证失败 (写后读不匹配)
#define TZD_PP_ERR_NO_DRIVER     (-9)   // 未提供驱动路径
#define TZD_PP_ERR_NO_RAMMAP     (-10)  // 无 hole-free RAM 物理范围 — 拒绝盲扫 (避免系统卡死)
#define TZD_PP_ERR_INTERNAL     (-99)

// ─── Public API ───

// 强制启用 PPL (BYOVD)。
//   driverPath : .sys 文件绝对路径 (UTF-8); NULL=不加载驱动
//   driverType : TZD_DRIVER_RTCORE64 / TZD_DRIVER_GENERIC / TZD_DRIVER_NONE
//   targetPpl : 目标 PPL 字节 (TZD_PPL_WINTCB_LIGHT 等)
// 返回 TZD_PP_OK (0) 或负错误码。
int process_protect_byovd(const char* driverPath, int driverType,
                          unsigned char targetPpl);

// 查询当前进程的 PPL 保护字节。
//   尝试 NtQueryInformationProcess(ProcessProtectionInformation)。
//   返回保护字节 (0=无保护, 0xC1=WinTcb PPL, ...) 或 -1 失败。
int process_protect_get_protection_byte(void);

// 获取状态 JSON 字串 (用于调试)。调用者用完后不需要释放。
const char* process_protect_get_status(void);

// 设置通用驱动 IOCTL 协议参数 (driverType=GENERIC 时使用)。
//   deviceName : 如 "\\\\.\\MyDriver"
//   readIoctl  : 读内存 IOCTL 码
//   writeIoctl : 写内存 IOCTL 码
// 返回 true=设置成功。
bool process_protect_set_generic_ioctl(const char* deviceName,
                                       unsigned int readIoctl,
                                       unsigned int writeIoctl);

// 设置 KernCoreLib64 物理扫描使用的 hole-free RAM 物理范围 (CSV: "base,len;base,len;...")。
//   base/len 可十进制或 0x 十六进制 (字节)。
//   安全要求: 必须是确认无 MMIO 空洞的真实 RAM 范围。仅扫描这些范围 → 绝不触碰
//   MMIO/PCIe 空洞 → 不会卡死 (读 MMIO 会让总线挂起且不触发 #PF, __except 抓不到)。
//   未设置任何范围 → kerncore 路径拒绝盲扫 (返回 TZD_PP_ERR_NO_RAMMAP), 不映射不读取。
//   返回 true=至少解析到 1 段。
bool process_protect_set_ram_ranges(const char* rangesCsv);

// 卸载并删除已加载的驱动服务 (清理)。
void process_protect_unload_driver(void);

// ═══════════════════════════════════════════════════════════════════════
// ─── 内核直通 API (仅 TZD_DRIVER_CUSTOM 驱动已加载时可用) ────────────────
// 这些函数通过 IOCTL 直接调用驱动内核原语, 绕过用户态 ntoskrnl 导出链。
// 调用前需先 process_protect_byovd() 成功加载驱动并打开设备句柄。
// ═══════════════════════════════════════════════════════════════════════

// 内核强制打开进程句柄 — 绕过所有安全检查 (含 PPL 互访限制)。
//   pid : 目标进程 ID
//   desiredAccess : 请求的访问权限 (如 0x1FFFFF = PROCESS_ALL_ACCESS)
// 返回句柄 (调用者负责 CloseHandle) 或 NULL 失败。
HANDLE process_protect_kernel_open_process(unsigned long pid,
                                           unsigned int desiredAccess);

// 按 PID 直接设置 PPL 保护字节 (内核直通, 无需 ntoskrnl 导出链)。
//   pid : 目标进程 ID
//   protection : PS_PROTECTION 字节 (如 0xC1 = WinTcb-Light)
//   sigLevel : SignatureLevel (0=不改, 0x0E=WinTcb, 0x0F=Antimalware, ...)
//              非 0 时同时设 SignatureLevel + SectionSignatureLevel
// 返回 true=成功。
bool process_protect_kernel_set_ppl(unsigned long pid,
                                   unsigned char protection,
                                   unsigned char sigLevel);

// 按 PID 查询 PPL 保护字节。
// 返回保护字节 (0=无保护) 或 0xFF 失败。
unsigned char process_protect_kernel_query_ppl(unsigned long pid);

// 内核终止任意进程 (即便 PPL 保护 — 先降保护再杀)。
//   pid : 目标进程 ID
//   exitStatus : NTSTATUS 退出码 (如 0 = STATUS_SUCCESS)
// 返回 true=成功。
bool process_protect_kernel_kill(unsigned long pid, int exitStatus);

// Token 窃取 — 复制源进程 Token 注入目标进程 (提权到 SYSTEM)。
//   targetPid : 接收 Token 的目标进程
//   sourcePid : Token 来源 (0 = System PID=4)
// 返回 true=成功。
bool process_protect_kernel_steal_token(unsigned long targetPid,
                                        unsigned long sourcePid);

// ═══════════════════════════════════════════════════════════════════════
// ─── 驱动 IOCTL 直通 API (反 shellcode / ETW-TI / systrace / 进程保护) ──────
//   封装 tzd_ppl_drv.sys 的 IOCTL 0x8000201C..0x80002048。
//   调用前需先 process_protect_byovd() 成功加载 TZD_DRIVER_CUSTOM 驱动。
// ═══════════════════════════════════════════════════════════════════════

// 设置 syscall 扫描监控目标 PID (SCAN_SYSCALLS 用)。
bool process_protect_kernel_set_monitor_pid(unsigned long pid);

// 扫描监控进程的直接/间接 syscall stub → 命中页中和 (代码缓存: ud2 覆写; 其他: NX)。
//   outHits  : 发现的 stub 数
//   outNxBlocked : 已中和页数
// 返回 true=成功 (即使 hits=0 也返回 true)。
bool process_protect_kernel_scan_syscalls(unsigned long* outHits,
                                           unsigned long* outNxBlocked);

// 事件驱动进程保护 (ObRegisterCallbacks) — 裁剪他人对被保护进程的危险句柄权限。
bool process_protect_kernel_protect_pid(unsigned long pid);
bool process_protect_kernel_unprotect_pid(void);

// 反 shellcode 防御 — 武装线程/镜像通知 + 500ms 周期扫描 + ETW-TI best-effort。
//   成功后自动启动告警轮询线程 (compromised=1 → kill 0x5C)。
bool process_protect_kernel_arm_sc_defense(unsigned long pid);
//   自动停止告警轮询线程。
bool process_protect_kernel_disarm_sc_defense(void);

// 查询反 shellcode 累计统计。
//   etwTiEnabled 填 Reserved[0] (ETW-TI 主方案状态)。
bool process_protect_kernel_query_sc_stats(unsigned long* scans,
                                            unsigned long* pagesNx,
                                            unsigned long* threadsSeen,
                                            unsigned long* imagesSeen,
                                            unsigned long* unsignedImgs,
                                            unsigned long* filelessPe,
                                            unsigned long* etwTiEnabled);

// ETW Threat-Intelligence 主方案 — 强制 ThreatInt provider 发射
//   (NtAllocateVirtualMemory/NtProtectVirtualMemory/Map/Context/... 全发射)。
bool process_protect_kernel_arm_etw_ti(void);
bool process_protect_kernel_disarm_etw_ti(void);

// 查询告警 — 扫描发现 shellcode 时 compromised=1 (用户层应 kill 0x5C)。
//   告警轮询线程自动处理此查询。
bool process_protect_kernel_query_alert(unsigned long* compromised,
                                        unsigned long* childBlocked,
                                        unsigned long* lastShellcodeType,
                                        unsigned long* creatorThreadId,
                                        unsigned long long* lastShellcodeVa);

// 系统调用追踪 (KiDynamicTraceMask gate; PG-safe 数据写, 检测不阻断)。
bool process_protect_kernel_arm_systrace(void);
bool process_protect_kernel_disarm_systrace(void);

// 告警轮询线程 — 500ms 周期查询 QUERY_ALERT, compromised=1 即 TerminateProcess(self, 0x5C)。
//   armScDefense 成功后自动调用; 也可独立调用。
bool process_protect_start_alert_polling(void);
bool process_protect_stop_alert_polling(void);

// Thin Hypervisor (VMX + EPT) — Phase 1: VMXON + EPT identity map
bool process_protect_arm_hypervisor(void);
void process_protect_disarm_hypervisor(void);

// ═══════════════════════════════════════════════════════════════════════
// ─── JIT 代码缓存写保护 (EPT-based + 周期扫描内容校验) ────────────────────
//   区分 JIT 合法写 (set_int_at 等, RIP ∈ jvm.dll) vs 恶意篡改 (shellcode /
//   Unsafe.putByte, RIP ∉ jvm.dll 或内容非 JIT)。调用前需先 armHypervisor。
// ═══════════════════════════════════════════════════════════════════════

// 注册 JIT 代码缓存 GVA 范围 — 存 GVA 范围 + 附着进程走页表限制物理页 R-X
//   JDK20 有 3 个代码堆 (NonNMethod/Profiled/NonProfiled), 各调一次
bool process_protect_register_jit_range(unsigned long pid,
                                        unsigned long long base,
                                        unsigned long long size);

// 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段; 合法 JIT 补丁的写者 RIP 必在此内)
bool process_protect_set_jvm_writer(unsigned long long jvmBase,
                                    unsigned long long jvmSize);

// 查询 JIT 篡改告警 — jitTampered=1 → 用户层应 TerminateProcess(0x5C)
bool process_protect_query_jit_alert(unsigned long* jitTampered,
                                     unsigned long* jitBlocks,
                                     unsigned long* jitAllows,
                                     unsigned long* jitRangeCount,
                                     unsigned long long* tamperRip,
                                     unsigned long long* tamperVa);

// 清除所有 JIT 范围 + 恢复 restricted EPT 为 RWX
bool process_protect_clear_jit_ranges(void);

#ifdef __cplusplus
}
#endif
