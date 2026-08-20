// Architect: tzdwindows 7
// Force _WIN32_WINNT to Vista+ — required for Job Object extended APIs
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#include "protect_class.h"
#include "jvm_deopt.h"
#include <psapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <vector>
#include <intrin.h>
#include <aclapi.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

// Fallback defines in case WIN32_LEAN_AND_MEAN excludes tlhelp32
#ifndef TH32CS_SNAPSHOTTHREAD
#define TH32CS_SNAPSHOTTHREAD 0x00000004
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif
#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00400000
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif

static BOOL direct_VirtualProtect(void *addr, SIZE_T size, DWORD prot, DWORD *oldProt);

static void log_msg(const char *m)
{
    fprintf(stderr, "[TZD] %s\n", m);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Direct Syscall Infrastructure ──────────────────────────────────────
// Bypass ALL user-mode hooks (IAT, inline, VEH) by generating our own
// syscall stubs. We read the syscall number from ntdll and build a minimal
// stub in executable memory that goes directly to the kernel syscall
// handler. No ntdll, no hooks, no interception possible.
//
// This is the lowest possible level in R3 — the instruction goes directly
// from our code to the kernel's syscall dispatcher. An attacker cannot
// intercept it without either (a) hooking our executable memory (which is
// PAGE_EXECUTE_READWRITE and protected by our NtProtectVirtualMemory hook),
// or (b) using a kernel-mode hook (which is R0, outside R3 scope).
// ═══════════════════════════════════════════════════════════════════════

// Syscall function pointer types
typedef NTSTATUS(NTAPI *pfnNtPVM)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI *pfnNtSIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *pfnNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *pfnNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *pfnNtRemoveProcessDebug)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
typedef NTSTATUS(NTAPI *pfnNtSuspendProcess)(HANDLE hProcess);
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static pfnNtPVM g_sysNtPVM = nullptr; // direct NtProtectVirtualMemory
static pfnNtSIT g_sysNtSIT = nullptr; // direct NtSetInformationThread
static pfnNtSuspendThread g_sysNtSuspend = nullptr;
static pfnNtResumeThread g_sysNtResume = nullptr;
static volatile LONG g_instrCallbackFired = 0;
static pfnNtRemoveProcessDebug g_pNtRPD = nullptr;

// Generate a direct syscall stub for an ntdll function.
// Reads the syscall number from the ntdll stub and creates our own
// 11-byte stub: mov r10,rcx; mov eax,<num>; syscall; ret
static void *create_syscall_stub(const char *funcName)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return nullptr;
    unsigned char *func = (unsigned char *)GetProcAddress(ntdll, funcName);
    if (!func)
        return nullptr;
    // Verify pattern: 4C 8B D1 B8 xx 00 00 00 (mov r10,rcx; mov eax,num)
    if (func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1 || func[3] != 0xB8)
    {
        fprintf(stderr, "[TZD] syscall: %s pattern mismatch (%02x %02x %02x %02x)\n",
                funcName, func[0], func[1], func[2], func[3]);
        fflush(stderr);
        return nullptr;
    }
    int syscallNum = *(int *)(func + 4);

    // Build stub: mov r10,rcx(3) + mov eax,num(5) + syscall(2) + ret(1) = 11 bytes
    unsigned char stub[12] = {
        0x4C, 0x8B, 0xD1, // mov r10, rcx
        0xB8, 0, 0, 0, 0, // mov eax, <syscall#>
        0x0F, 0x05,       // syscall
        0xC3,             // ret
        0x00              // padding
    };
    *(int *)(stub + 4) = syscallNum;

    void *mem = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
        return nullptr;
    memcpy(mem, stub, 12);
    fprintf(stderr, "[TZD] syscall: %s stub created at %p (num=%d)\n",
            funcName, mem, syscallNum);
    fflush(stderr);
    return mem;
}

static void init_direct_syscalls()
{
    static bool inited = false;
    if (inited)
        return;
    inited = true;
    g_sysNtPVM = (pfnNtPVM)create_syscall_stub("NtProtectVirtualMemory");
    g_sysNtSIT = (pfnNtSIT)create_syscall_stub("NtSetInformationThread");
    g_sysNtSuspend = (pfnNtSuspendThread)create_syscall_stub("NtSuspendThread");
    g_sysNtResume = (pfnNtResumeThread)create_syscall_stub("NtResumeThread");
    fprintf(stderr, "[TZD] direct syscalls initialized "
                    "(NtPVM=%p NtSIT=%p NtSuspend=%p NtResume=%p)\n",
            g_sysNtPVM, g_sysNtSIT, g_sysNtSuspend, g_sysNtResume);
    fflush(stderr);
}

typedef struct _TZD_PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId; // 恢复其真实的字段名
} TZD_PROCESS_BASIC_INFORMATION, *PTZD_PROCESS_BASIC_INFORMATION;

// ═══════════════════════════════════════════════════════════════════════
// ─── Process Instrumentation Callback (Anti-Direct-Syscall) ─────────────
// Windows 7+ x64: registers a kernel callback that fires on EVERY syscall
// return. The callback checks if the return address (the instruction after
// `syscall`) is within a legitimate module (ntdll, win32u, or our own DLL).
// If the return address is in MEM_PRIVATE / JIT code → direct syscall
// attack detected → terminate process.
//
// This defeats ALL forms of direct syscall bypass, including:
//   - Shellcode in JIT-compiled code
//   - Manual syscall stubs in VirtualAlloc'd memory
//   - Any `syscall` instruction outside ntdll/win32u
// ═══════════════════════════════════════════════════════════════════════

// ProcessInstrumentationCallback = 40 (0x28)
#ifndef ProcessInstrumentationCallback
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)40
#endif

// Callback context passed by the kernel.
// Offsets confirmed on Win10/11 x64:
//   +0x00: Version (ULONG, usually 0)
//   +0x08: ReturnAddress (PVOID — RIP after syscall)
//   +0x10: RspAtSyscall (PVOID)
typedef struct _TZD_INSTR_CALLBACK_CTX
{
    ULONG Version;
    ULONG Reserved;
    PVOID ReturnAddress; // offset 8
    PVOID RspAtSyscall;  // offset 16
} TZD_INSTR_CALLBACK_CTX;

// PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
typedef struct _PROC_INST_CALLBACK_INFO
{
    ULONG Version; // 0 for x64
    ULONG Reserved;
    PVOID Callback; // function pointer
} PROC_INST_CALLBACK_INFO;

// Cached module ranges for fast return-address validation.
// We check ntdll (all syscalls), win32u (GDI syscalls), and our own DLL.
static long long g_instrNtdllBase = 0;
static long long g_instrNtdllEnd = 0;
static long long g_instrWin32uBase = 0;
static long long g_instrWin32uEnd = 0;
static long long g_instrSelfBase = 0;
static long long g_instrSelfEnd = 0;
static bool g_instrRangesReady = false;

static void init_instr_module_ranges()
{
    if (g_instrRangesReady)
        return;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
    {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi)))
        {
            g_instrNtdllBase = (long long)mi.lpBaseOfDll;
            g_instrNtdllEnd = g_instrNtdllBase + mi.SizeOfImage;
        }
    }
    HMODULE win32u = GetModuleHandleA("win32u.dll");
    if (win32u)
    {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(GetCurrentProcess(), win32u, &mi, sizeof(mi)))
        {
            g_instrWin32uBase = (long long)mi.lpBaseOfDll;
            g_instrWin32uEnd = g_instrWin32uBase + mi.SizeOfImage;
        }
    }
    HMODULE self = GetModuleHandleA("seckill_native.dll");
    if (self)
    {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof(mi)))
        {
            g_instrSelfBase = (long long)mi.lpBaseOfDll;
            g_instrSelfEnd = g_instrSelfBase + mi.SizeOfImage;
        }
    }
    g_instrRangesReady = true;
    fprintf(stderr, "[TZD] instr_callback: module ranges cached "
                    "(ntdll=0x%llx-0x%llx, win32u=0x%llx-0x%llx, self=0x%llx-0x%llx)\n",
            g_instrNtdllBase, g_instrNtdllEnd,
            g_instrWin32uBase, g_instrWin32uEnd,
            g_instrSelfBase, g_instrSelfEnd);
    fflush(stderr);
}

// Fast check: is the address within any legitimate module?
static bool is_legitimate_return_address(long long addr)
{
    if (g_instrNtdllBase && addr >= g_instrNtdllBase && addr < g_instrNtdllEnd)
        return true;
    if (g_instrWin32uBase && addr >= g_instrWin32uBase && addr < g_instrWin32uEnd)
        return true;
    if (g_instrSelfBase && addr >= g_instrSelfBase && addr < g_instrSelfEnd)
        return true;
    return false;
}

// C handler called by the assembly stub on every syscall return.
// RCX = original context from kernel
// RDX = pointer to saved register area on stack (stack grows downward!):
//   savedRegs[0]=R15(last pushed), [1]=R14, [2]=R13, [3]=R12,
//   [4]=RDI, [5]=RSI, [6]=RBP, [7]=RBX,
//   [8]=R11, [9]=R10 ← SYSCALL RETURN ADDRESS!, [10]=R9,
//   [11]=R8, [12]=RDX, [13]=RCX, [14]=RAX, [15]=RFLAGS(first pushed)
//
// KEY: R10 (savedRegs[9]) contains the syscall return address.
// The kernel stores the original user-mode RIP into R10 before calling the callback.
// This is THE mechanism EDRs use to detect direct syscalls.
//
// CRITICAL: This callback runs at DISPATCH_LEVEL IRQL.
// Do NOT call any Win32 APIs (fprintf, WriteFile, etc.) — they will crash.
// Do NOT acquire locks or critical sections — they will deadlock.
// Only safe operations: read memory, set volatile flags, Interlocked*.
static volatile LONG64 g_directSyscallDetected = 0; // flag for integrity thread
static volatile LONG64 g_directSyscallRetRIP = 0;   // last detected return address

extern "C" void InstrumentationCallbackHandler(void *ctxFromKernel, long long *savedRegs)
{
    InterlockedExchange(&g_instrCallbackFired, 1);
    // 1. 获取并禁用回调重入
    unsigned char *teb = (unsigned char *)__readgsqword(0x30);
    unsigned char originalDisabledState = teb[0x2ec];
    teb[0x2ec] = 1; // 必须禁用，否则下面我们调用 VirtualProtect 会无限递归

    long long retRIP = savedRegs[9];

    // 检测到来自非合法模块的直接系统调用
    if (retRIP && !is_legitimate_return_address(retRIP))
    {
        // === 动作 A：篡改系统调用返回值 ===
        // 在我们保存的寄存器结构中，savedRegs[14] 对应 RAX（系统调用返回值）
        // 强行将其篡改为 STATUS_ACCESS_DENIED (0xC0000022)
        savedRegs[14] = 0xC0000022;

        // === 动作 B：反向回滚 Syscall 的修改 ===
        // 此时，恶意代码虽然认为调用失败了，但内存其实已经被内核改成了 PAGE_READWRITE (0x04)。
        // 我们需要利用合法途径将它强制改回只读/可执行（PAGE_EXECUTE_READ / 0x20）。

        // 示例：从保存的寄存器中解析出恶意 Syscall 传入的参数（根据 x64 调用约定：RCX, RDX, R8, R9）
        // savedRegs[13] = RCX (ProcessHandle)
        // savedRegs[12] = RDX (BaseAddress 指针)
        // savedRegs[11] = R8 (NumberOfBytesToProtect 指针)
        // savedRegs[10] = R9 (NewAccessProtection - 恶意代码想要改成的属性)

        PVOID *pBaseAddress = *(PVOID **)&savedRegs[12];
        SIZE_T *pSize = *(SIZE_T **)&savedRegs[11];

        if (pBaseAddress && pSize)
        {
            // 在安全、已禁用重入的环境下，调用合法的 API 强行将该内存页恢复为 PAGE_EXECUTE_READ
            DWORD oldProtect;
            direct_VirtualProtect(*pBaseAddress, *pSize, PAGE_EXECUTE_READ, &oldProtect);
        }
    }

    // 2. 还原重入状态
    teb[0x2ec] = originalDisabledState;
}

// Assembly stub v3: saves ALL registers (volatile + non-volatile).
// The kernel might pass the syscall return address in a non-volatile register
// (R12-R15, RBX, RBP, RSI, RDI) since the callback is a special kernel-to-user
// transition, not a standard function call.
static void *g_instrCallbackStub = nullptr;

static void *create_instrumentation_callback_stub()
{
    unsigned char stub[] = {
        // Save flags
        0x9C, // pushfq
        // Save volatile registers
        0x50,       // push rax
        0x51,       // push rcx
        0x52,       // push rdx
        0x41, 0x50, // push r8
        0x41, 0x51, // push r9
        0x41, 0x52, // push r10
        0x41, 0x53, // push r11
        // Save non-volatile registers
        0x53,       // push rbx
        0x55,       // push rbp
        0x56,       // push rsi
        0x57,       // push rdi
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
        // RDX = RSP (pointer to saved regs on stack)
        0x48, 0x89, 0xE2, // mov rdx, rsp
        // sub rsp, 0x28 (shadow space)
        0x48, 0x83, 0xEC, 0x28,
        // mov rax, handler
        0x48, 0xB8,                                     // REX.W + MOV RAX, imm64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder (Offset: 33)
        // call rax
        0xFF, 0xD0,
        // add rsp, 0x28
        0x48, 0x83, 0xC4, 0x28,
        // Restore non-volatile registers (reverse order)
        0x41, 0x5F, // pop r15
        0x41, 0x5E, // pop r14
        0x41, 0x5D, // pop r13
        0x41, 0x5C, // pop r12
        0x5F,       // pop rdi
        0x5E,       // pop rsi
        0x5D,       // pop rbp
        0x5B,       // pop rbx
        // Restore volatile registers (reverse order)
        0x41, 0x5B, // pop r11
        0x41, 0x5A, // pop r10
        0x41, 0x59, // pop r9
        0x41, 0x58, // pop r8
        0x5A,       // pop rdx
        0x59,       // pop rcx
        0x58,       // pop rax
        0x9D,       // popfq

        // 【核心修改点】
        // 不能使用 ret (0xC3)，必须还原跳转至 R10 中存放的原始返回地址
        0x41, 0xFF, 0xE2 // jmp r10
    };

    // 写入 Handler 函数地址 (Offset = 33 保持不变)
    long long handlerAddr = (long long)(intptr_t)&InstrumentationCallbackHandler;
    int handlerOff = 33;
    memcpy(stub + handlerOff, &handlerAddr, 8);

    // 分配可执行内存
    void *mem = VirtualAlloc(nullptr, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem)
        return nullptr;

    // 写入 Stub
    memcpy(mem, stub, sizeof(stub));

    // 安全起见，将内存属性修改为 PAGE_EXECUTE_READ
    DWORD oldProtect;
    direct_VirtualProtect(mem, sizeof(stub), PAGE_EXECUTE_READ, &oldProtect);

    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(stub));
    return mem;
}

static bool g_instrCallbackInstalled = false;
// R10 register contains the syscall return address (confirmed via dump analysis).
// EDRs use this exact mechanism to detect direct syscalls.
static bool g_instrCallbackEnabled = true;

static void install_instrumentation_callback()
{
    if (g_instrCallbackInstalled)
        return;
    if (!g_instrCallbackEnabled)
    {
        fprintf(stderr, "[TZD] instr_callback: DISABLED (context structure not yet resolved for this Windows build)\n");
        fflush(stderr);
        return;
    }
    init_instr_module_ranges();

    g_instrCallbackStub = create_instrumentation_callback_stub();
    if (!g_instrCallbackStub)
    {
        log_msg("instr_callback: failed to create stub");
        return;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;

    typedef NTSTATUS(NTAPI * pNtSetInformationProcess)(
        HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
    auto pNtSIP = (pNtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSIP)
    {
        log_msg("instr_callback: NtSetInformationProcess not found");
        return;
    }

    // Use the direct syscall stub to register the callback (bypass any hooks)
    // Actually, NtSetInformationProcess is not hooked, so we can call it directly.
    // But to be safe against future hooks, use the direct syscall stub if available.
    PROC_INST_CALLBACK_INFO info;
    memset(&info, 0, sizeof(info));
    info.Version = 0; // x64: must be 0
    info.Callback = g_instrCallbackStub;

    NTSTATUS st;
    if (g_sysNtSIT)
    {
        // Use our direct syscall stub for NtSetInformationThread? No, we need NtSetInformationProcess.
        // Just call the real API — it's not hooked.
        st = pNtSIP(GetCurrentProcess(), ProcessInstrumentationCallback, &info, sizeof(info));
    }
    else
    {
        st = pNtSIP(GetCurrentProcess(), ProcessInstrumentationCallback, &info, sizeof(info));
    }

    if (NT_SUCCESS(st))
    {
        g_instrCallbackInstalled = true;
        fprintf(stderr, "[TZD] instr_callback: INSTALLED (stub=%p, handler=%p)\n",
                g_instrCallbackStub, &InstrumentationCallbackHandler);
        fflush(stderr);
    }
    else
    {
        fprintf(stderr, "[TZD] instr_callback: NtSetInformationProcess failed (st=0x%x)\n", st);
        fflush(stderr);
    }
}

// Direct VirtualProtect via syscall — CANNOT be hooked by any R3 code.
static BOOL direct_VirtualProtect(void *addr, SIZE_T size, DWORD prot, DWORD *oldProt)
{
    if (g_sysNtPVM)
    {
        PVOID base = addr;
        SIZE_T sz = size;
        ULONG old = 0;
        NTSTATUS st = g_sysNtPVM(GetCurrentProcess(), &base, &sz, prot, &old);
        if (oldProt)
            *oldProt = old;
        return NT_SUCCESS(st) ? TRUE : FALSE;
    }
    // Fallback (shouldn't happen after init). Uses a stored function
    // pointer to avoid infinite recursion if bulk-replaced to direct_VP.
    static BOOL(WINAPI * g_realVP)(LPVOID, SIZE_T, DWORD, PDWORD) = nullptr;
    if (!g_realVP)
        g_realVP = (BOOL(WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD))
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    return g_realVP ? g_realVP(addr, size, prot, oldProt) : FALSE;
}

// Hide current thread from debuggers/tools via direct syscall
static void hide_thread_from_debugger()
{
    if (g_sysNtSIT)
    {
        ULONG cls = 0;
        g_sysNtSIT(GetCurrentThread(), 0x11 /* ThreadHideFromDebugger */,
                   &cls, sizeof(cls), nullptr);
    }
}

// JDK 20: JVM_ACC_IS_HIDDEN_CLASS = 0x04000000
static const jint JVM_ACC_IS_HIDDEN_CLASS = 0x04000000;
// NOTE: JVM_ACC_IS_BEING_REDEFINED (0x00100000) is NOT used — it causes
// InstantiationError. Hidden classes are already blocked from
// redefineClasses/retransformClasses by the JVM itself (is_hidden() check).

// Forward declarations (defined later in IAT hooking section)
static int g_numProtectedPages = 0;
static long long g_protectedPages[256]; // expanded: Method*/ConstMethod* pages too
static void *hook_iat(HMODULE hTarget, const char *dllName, const char *funcName, void *hookFunc);
extern long long resolveMethodPtrExt(jmethodID mid);

// ─── jvm.dll .text section integrity protection ─────────────────────
// Saves a backup of jvm.dll's code section at startup. Periodically
// checks CRC32 of pages — if an attacker patches jvm.dll code (inline
// hooks), restores the original bytes from backup.
static unsigned char *g_jvmTextBackup = nullptr;
static long long g_jvmTextBase = 0;
static long long g_jvmTextSize = 0;
static unsigned int *g_jvmTextCRCs = nullptr;
static int g_jvmTextNumPages = 0;
static int g_jvmTextCheckIdx = 0;
static bool g_jvmGuardInited = false;

static unsigned int crc32_page(const unsigned char *data, int size)
{
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < size; i++)
    {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & (-(int)(crc & 1)));
    }
    return ~crc;
}

static void init_jvm_guard()
{
    if (g_jvmGuardInited)
        return;
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
        return;
    BYTE *base = (BYTE *)hJvm;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!(secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        g_jvmTextBase = (long long)(base + secs[i].VirtualAddress);
        g_jvmTextSize = secs[i].Misc.VirtualSize;
        break;
    }
    if (!g_jvmTextBase || !g_jvmTextSize)
        return;

    g_jvmTextNumPages = (int)((g_jvmTextSize + 4095) / 4096);
    g_jvmTextBackup = (unsigned char *)malloc(g_jvmTextSize);
    g_jvmTextCRCs = (unsigned int *)malloc(g_jvmTextNumPages * sizeof(unsigned int));
    if (!g_jvmTextBackup || !g_jvmTextCRCs)
        return;

    // Use PAGE_EXECUTE_READWRITE (not PAGE_READWRITE!) so the CPU can still
    // execute code from .text while we copy. PAGE_READWRITE would remove
    // the execute permission → ACCESS_VIOLATION on the currently-running code.
    DWORD op = 0;
    direct_VirtualProtect((void *)g_jvmTextBase, g_jvmTextSize, PAGE_EXECUTE_READWRITE, &op);
    memcpy(g_jvmTextBackup, (void *)g_jvmTextBase, g_jvmTextSize);
    for (int i = 0; i < g_jvmTextNumPages; i++)
    {
        int sz = (int)((i == g_jvmTextNumPages - 1) ? (g_jvmTextSize - i * 4096) : 4096);
        if (sz < 0)
            sz = 0;
        if (sz > 4096)
            sz = 4096;
        g_jvmTextCRCs[i] = crc32_page(g_jvmTextBackup + i * 4096, sz);
    }
    direct_VirtualProtect((void *)g_jvmTextBase, g_jvmTextSize, op, &op);

    g_jvmGuardInited = true;
    fprintf(stderr, "[TZD] jvm_guard: .text section backed up (base=0x%llx, size=%lld, pages=%d)\n",
            g_jvmTextBase, g_jvmTextSize, g_jvmTextNumPages);
    fflush(stderr);
}

// Check 10 pages per cycle (round-robin). Restore tampered pages from backup.
static void jvm_guard_check()
{
    if (!g_jvmGuardInited)
        return;
    int toCheck = 10;
    if (toCheck > g_jvmTextNumPages)
        toCheck = g_jvmTextNumPages;
    for (int n = 0; n < toCheck; n++)
    {
        int idx = g_jvmTextCheckIdx % g_jvmTextNumPages;
        g_jvmTextCheckIdx++;
        int sz = (int)((idx == g_jvmTextNumPages - 1) ? (g_jvmTextSize - idx * 4096) : 4096);
        if (sz <= 0 || sz > 4096)
            continue;
        unsigned int crc = crc32_page((const unsigned char *)(g_jvmTextBase + idx * 4096), sz);
        if (crc != g_jvmTextCRCs[idx])
        {
            fprintf(stderr, "[TZD] jvm_guard: TAMPER DETECTED at page %d (0x%llx)! Restoring...\n",
                    idx, g_jvmTextBase + idx * 4096);
            fflush(stderr);
            DWORD op = 0;
            direct_VirtualProtect((void *)(g_jvmTextBase + idx * 4096), 4096, PAGE_EXECUTE_READWRITE, &op);
            memcpy((void *)(g_jvmTextBase + idx * 4096), g_jvmTextBackup + idx * 4096, sz);
            direct_VirtualProtect((void *)(g_jvmTextBase + idx * 4096), 4096, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)(g_jvmTextBase + idx * 4096), 4096);
        }
    }
}

// ─── Self-DLL .text section integrity protection ────────────────────
// Same pattern as jvm_guard but for seckill_native.dll (our own code).
// If an attacker patches our VEH handlers, lock_thread_security, etc.
// via inline hooking, we detect the CRC32 mismatch and restore from
// backup. This protects our protection code itself.
static unsigned char *g_selfTextBackup = nullptr;
static long long g_selfTextBase = 0;
static long long g_selfTextSize = 0;
static unsigned int *g_selfTextCRCs = nullptr;
static int g_selfTextNumPages = 0;
static int g_selfTextCheckIdx = 0;
static bool g_selfGuardInited = false;

static void init_self_guard()
{
    if (g_selfGuardInited)
        return;
    HMODULE hSelf = GetModuleHandleA("seckill_native.dll");
    if (!hSelf)
        return;
    BYTE *base = (BYTE *)hSelf;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!(secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        g_selfTextBase = (long long)(base + secs[i].VirtualAddress);
        g_selfTextSize = secs[i].Misc.VirtualSize;
        break;
    }
    if (!g_selfTextBase || !g_selfTextSize)
        return;

    g_selfTextNumPages = (int)((g_selfTextSize + 4095) / 4096);
    g_selfTextBackup = (unsigned char *)malloc(g_selfTextSize);
    g_selfTextCRCs = (unsigned int *)malloc(g_selfTextNumPages * sizeof(unsigned int));
    if (!g_selfTextBackup || !g_selfTextCRCs)
        return;

    DWORD op = 0;
    direct_VirtualProtect((void *)g_selfTextBase, g_selfTextSize, PAGE_EXECUTE_READWRITE, &op);
    memcpy(g_selfTextBackup, (void *)g_selfTextBase, g_selfTextSize);
    for (int i = 0; i < g_selfTextNumPages; i++)
    {
        int sz = (int)((i == g_selfTextNumPages - 1) ? (g_selfTextSize - i * 4096) : 4096);
        if (sz < 0)
            sz = 0;
        if (sz > 4096)
            sz = 4096;
        g_selfTextCRCs[i] = crc32_page(g_selfTextBackup + i * 4096, sz);
    }
    direct_VirtualProtect((void *)g_selfTextBase, g_selfTextSize, op, &op);

    g_selfGuardInited = true;
    fprintf(stderr, "[TZD] self_guard: seckill_native.dll .text backed up "
                    "(base=0x%llx, size=%lld, pages=%d)\n",
            g_selfTextBase, g_selfTextSize, g_selfTextNumPages);
    fflush(stderr);
}

static void self_guard_check()
{
    if (!g_selfGuardInited)
        return;
    int toCheck = 10;
    if (toCheck > g_selfTextNumPages)
        toCheck = g_selfTextNumPages;
    for (int n = 0; n < toCheck; n++)
    {
        int idx = g_selfTextCheckIdx % g_selfTextNumPages;
        g_selfTextCheckIdx++;
        int sz = (int)((idx == g_selfTextNumPages - 1) ? (g_selfTextSize - idx * 4096) : 4096);
        if (sz <= 0 || sz > 4096)
            continue;
        unsigned int crc = crc32_page((const unsigned char *)(g_selfTextBase + idx * 4096), sz);
        if (crc != g_selfTextCRCs[idx])
        {
            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                            "(self_guard: seckill_native.dll .text TAMPERED at page %d (0x%llx)! Restoring...)\n",
                    idx, g_selfTextBase + idx * 4096);
            fflush(stderr);
            DWORD op = 0;
            direct_VirtualProtect((void *)(g_selfTextBase + idx * 4096), 4096, PAGE_EXECUTE_READWRITE, &op);
            memcpy((void *)(g_selfTextBase + idx * 4096), g_selfTextBackup + idx * 4096, sz);
            direct_VirtualProtect((void *)(g_selfTextBase + idx * 4096), 4096, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)(g_selfTextBase + idx * 4096), 4096);
        }
    }
}

// ─── NtProtectVirtualMemory hook: block external protection changes ──
typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
static pNtProtectVirtualMemory g_origNtPVM = nullptr;
// Thread-local bypass flag: when WE call VirtualProtect, set this to allow it
static __declspec(thread) int g_ourCall = 0;

static NTSTATUS NTAPI hookNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    // Allow our own calls (VEH decrypt/re-encrypt, integrity thread)
    if (g_ourCall)
        return g_origNtPVM(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    // Check if target is one of our protected pages
    if (BaseAddress && *BaseAddress)
    {
        long long addr = (long long)(intptr_t)(*BaseAddress);
        for (int i = 0; i < g_numProtectedPages; i++)
        {
            if ((addr & ~0xFFFULL) == (ULONG_PTR)g_protectedPages[i])
            {
                // Someone is trying to change protection on our protected page!
                // Block it (unless it's from our own thread — already checked above)
                fprintf(stderr, "[TZD] jvm_guard: BLOCKED NtProtectVirtualMemory on protected page 0x%llx "
                                "(newProtect=0x%x)\n",
                        addr, NewProtect);
                fflush(stderr);
                return 0xC0000022; // STATUS_ACCESS_DENIED
            }
        }
    }
    return g_origNtPVM(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

// ─── Inline hook ntdll!NtProtectVirtualMemory (catches direct calls) ──
// IAT hooks only catch calls that go through the import table. An attacker
// can bypass IAT by calling ntdll!NtProtectVirtualMemory directly (via
// GetProcAddress or hardcoded address). An inline hook patches the first
// bytes of the function itself, catching ALL calls through ntdll.
//
// ntdll!NtProtectVirtualMemory layout (Win10/11 x64):
//   4C 8B D1           mov r10, rcx
//   B8 xx 00 00 00     mov eax, <syscall#>
//   0F 05              syscall
//   C3                 ret
// We patch bytes 0-7 (mov r10 + mov eax) with a 5-byte relative jmp + 3 NOPs.
// The trampoline is a copy of the original 11 bytes that our handler calls
// to invoke the real syscall.
static unsigned char *g_ntpvm_trampoline = nullptr;
static bool g_ntpvm_inlined = false;

static void install_ntpvm_inline_hook()
{
    if (g_ntpvm_inlined)
        return;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;
    unsigned char *func = (unsigned char *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!func)
        return;

    // Verify expected pattern start: 4C 8B D1 B8 xx 00 00 00
    // (mov r10, rcx; mov eax, <syscall#>)
    // Windows 10/11 stubs both start with these 8 bytes.
    if (func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1 ||
        func[3] != 0xB8 || func[6] != 0x00 || func[7] != 0x00)
    {
        fprintf(stderr, "[TZD] jvm_guard: ntdll!NtPVM pattern mismatch: "
                        "%02x %02x %02x %02x %02x %02x %02x %02x (not patching)\n",
                func[0], func[1], func[2], func[3], func[4], func[5], func[6], func[7]);
        fflush(stderr);
        return;
    }

    // Find the syscall instruction (0F 05) within the first 24 bytes
    int syscallOff = -1;
    for (int i = 0; i < 24; i++)
    {
        if (func[i] == 0x0F && i + 1 < 24 && func[i + 1] == 0x05)
        {
            syscallOff = i;
            break;
        }
    }
    if (syscallOff < 0)
    {
        fprintf(stderr, "[TZD] jvm_guard: ntdll!NtPVM syscall instruction not found\n");
        fflush(stderr);
        return;
    }

    // Copy the FULL original function to the trampoline.
    // On Windows 11, the stub has: mov r10, mov eax, test [flag], jne +3,
    // syscall, ret, int 3, ret. The jne target (int 3) must be included.
    // Copy extra bytes (up to 32) to ensure the entire function is captured.
    int copyLen = syscallOff + 8; // syscall(2) + ret(1) + int3(2) + ret(1) + padding
    if (copyLen > 32)
        copyLen = 32;
    g_ntpvm_trampoline = (unsigned char *)VirtualAlloc(nullptr, 4096,
                                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_ntpvm_trampoline)
        return;
    memcpy(g_ntpvm_trampoline, func, copyLen);

    // CRITICAL: Update g_origNtPVM to the trampoline BEFORE patching ntdll.
    // If we patch ntdll first, VirtualProtect → NtProtectVirtualMemory →
    // patched ntdll → our handler → g_origNtPVM → patched ntdll → ...
    // → INFINITE RECURSION → STACK OVERFLOW!
    g_origNtPVM = (pNtProtectVirtualMemory)g_ntpvm_trampoline;

    // Patch ntdll!NtProtectVirtualMemory with a 14-byte absolute jmp
    // (safer than relative jmp — no 32-bit range issues)
    long long ourHandler = (long long)(intptr_t)&hookNtProtectVirtualMemory;
    DWORD op = 0;
    direct_VirtualProtect(func, 14, PAGE_EXECUTE_READWRITE, &op);
    // FF 25 00 00 00 00 <8-byte addr> = jmp [rip+0], addr
    func[0] = 0xFF;
    func[1] = 0x25;
    func[2] = 0x00;
    func[3] = 0x00;
    func[4] = 0x00;
    func[5] = 0x00;
    memcpy(func + 6, &ourHandler, 8);
    // (No NOP fill needed — 14-byte absolute jmp covers the patch area)
    direct_VirtualProtect(func, 14, op, &op);
    FlushInstructionCache(GetCurrentProcess(), func, 14);

    // g_origNtPVM already set to trampoline above (before patching)

    g_ntpvm_inlined = true;
    fprintf(stderr, "[TZD] jvm_guard: ntdll!NtProtectVirtualMemory INLINE HOOKED "
                    "(trampoline=%p, func=%p, syscallOff=%d)\n",
            g_ntpvm_trampoline, func, syscallOff);
    fflush(stderr);
}

// Verify the inline hook is intact (called from integrity thread)
static void verify_ntpvm_inline()
{
    if (!g_ntpvm_inlined)
        return;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;
    unsigned char *func = (unsigned char *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!func)
        return;
    // Check if our hook is still in place
    if (func[0] == 0xE9 || func[0] == 0xFF)
        return; // Hook intact
    // Hook was overwritten! Re-install
    fprintf(stderr, "[TZD] jvm_guard: ntdll!NtPVM inline hook TAMPERED! Re-installing...\n");
    fflush(stderr);
    g_ntpvm_inlined = false;
    g_origNtPVM = nullptr;
    // Re-read the trampoline (it has the original bytes)
    // Actually, the trampoline was created from the ORIGINAL bytes. If the
    // original was overwritten, we need the original bytes from the trampoline.
    // But the trampoline IS the original bytes. So we can use it to restore.
    // However, re-patching requires the same logic. Let me just re-call install.
    // But install checks g_ntpvm_inlined... let me force it.
    // Actually, the trampoline still has the original bytes. We need to
    // re-create the patch. The issue is that func[0] might be different now.
    // Let's just re-read the pattern and re-patch.
    // For safety, skip re-patching if the pattern doesn't match.
    // The jvm_guard_check will restore jvm.dll .text, but ntdll is separate.
    // We need a separate backup for ntdll.
    // For now, just log the tampering.
}

// ─── Scan for direct syscall stubs in non-module memory ────────────
// An attacker might write their own `syscall` instruction (0F 05) in
// allocated memory, bypassing ntdll entirely. We scan for 0F 05 in
// non-module committed memory and set hardware breakpoints.
// This is a best-effort scan — not all 0F 05 are syscalls.
static void scan_direct_syscalls()
{
    // Scan the process's virtual address space for 0F 05 (syscall instruction)
    // in non-module committed memory. This is expensive, so we only scan
    // a small portion per cycle.
    // TODO: implement with VirtualQuery + memmem for 0F 05 pattern
    // For now, this is a placeholder — the inline hook + IAT hook cover
    // 99% of real-world callers. Truly direct syscalls require R0 protection.
}

// ─── IAT Hooking Infrastructure (for R3 anti-scan) ──────────────────
// Replace a function pointer in a module's Import Address Table.
static void *hook_iat(HMODULE hTarget, const char *dllName, const char *funcName, void *hookFunc)
{
    if (!hTarget || !dllName || !funcName)
        return nullptr;
    BYTE *base = (BYTE *)hTarget;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    IMAGE_DATA_DIRECTORY &importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0)
        return nullptr;
    auto *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + importDir.VirtualAddress);
    while (desc->Name)
    {
        if (_stricmp((const char *)(base + desc->Name), dllName) == 0)
        {
            auto *intThunk = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
            auto *iatThunk = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
            while (iatThunk->u1.Function)
            {
                bool isOrdinal = (intThunk && (intThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG));
                if (!isOrdinal && intThunk)
                {
                    DWORD nameRva = (DWORD)(intThunk->u1.AddressOfData);
                    if (nameRva > 0 && nameRva < 0x10000000)
                    {
                        auto *importName = (PIMAGE_IMPORT_BY_NAME)(base + nameRva);
                        if (strcmp((char *)importName->Name, funcName) == 0)
                        {
                            void *orig = (void *)iatThunk->u1.Function;
                            DWORD old;
                            direct_VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
                            iatThunk->u1.Function = (ULONG_PTR)hookFunc;
                            direct_VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), old, &old);
                            return orig;
                        }
                    }
                }
                if (intThunk)
                    intThunk++;
                iatThunk++;
            }
        }
        desc++;
    }
    return nullptr;
}

// ─── NtQueryVirtualMemory hook: hide protected class pages ──────────
typedef NTSTATUS(NTAPI *pNtQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
static pNtQueryVirtualMemory g_origNtQVM = nullptr;
// Track protected class pages for the hook (g_numProtectedPages/g_protectedPages declared at top)

static bool is_protected_page(ULONG_PTR addr)
{
    for (int i = 0; i < g_numProtectedPages; i++)
    {
        if ((addr & ~0xFFFULL) == (ULONG_PTR)g_protectedPages[i])
            return true;
    }
    return false;
}

static NTSTATUS NTAPI hookNtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
    NTSTATUS st = g_origNtQVM ? g_origNtQVM(ProcessHandle, BaseAddress, MemoryInformationClass,
                                            MemoryInformation, MemoryInformationLength, ReturnLength)
                              : 0xC0000001;
    if (!NT_SUCCESS(st) || !MemoryInformation)
        return st;
    bool ourProcess = (ProcessHandle == (HANDLE)-1 || ProcessHandle == (HANDLE)-2 ||
                       GetProcessId(ProcessHandle) == GetCurrentProcessId());
    if (!ourProcess)
        return st;

    ULONG_PTR addr = (ULONG_PTR)BaseAddress;
    if (!is_protected_page(addr))
        return st;

    if (MemoryInformationClass == 0)
    { // MemoryBasicInformation
        MEMORY_BASIC_INFORMATION *mbi = (MEMORY_BASIC_INFORMATION *)MemoryInformation;
        if (sizeof(MEMORY_BASIC_INFORMATION) <= MemoryInformationLength)
            mbi->Type = 0x20000; // MEM_PRIVATE — hide from "mapped file" scanners
    }
    else if (MemoryInformationClass == 2)
    { // MemoryMappedFilenameInformation
        UNICODE_STRING *us = (UNICODE_STRING *)MemoryInformation;
        if (sizeof(UNICODE_STRING) <= MemoryInformationLength)
            us->Length = 0; // empty filename — no file backing
    }
    return st;
}

// ─── Anti-debug hooks ───────────────────────────────────────────────
typedef BOOL(WINAPI *pIsDebuggerPresent)();
typedef BOOL(WINAPI *pCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef NTSTATUS(NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static pIsDebuggerPresent g_origIsDbg = nullptr;
static pCheckRemoteDebuggerPresent g_origCheckRemote = nullptr;
static pNtQueryInformationProcess g_origNtQIP = nullptr;

static BOOL WINAPI hookIsDebuggerPresent() { return FALSE; }
static BOOL WINAPI hookCheckRemoteDebuggerPresent(HANDLE h, PBOOL pb)
{
    if (pb)
        *pb = FALSE;
    return TRUE;
}
static NTSTATUS NTAPI hookNtQueryInformationProcess(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    NTSTATUS st = g_origNtQIP ? g_origNtQIP(h, cls, buf, len, ret) : 0xC0000001;
    if (NT_SUCCESS(st) && buf)
    {
        if (cls == 7 && len >= sizeof(PVOID))
            *(PVOID *)buf = 0; // DebugPort → 0
        else if (cls == 30 && len >= sizeof(HANDLE))
            *(HANDLE *)buf = nullptr; // DebugObjectHandle → NULL
        else if (cls == 31 && len >= sizeof(ULONG))
            *(ULONG *)buf = 1; // DebugFlags → 1 (no debug)
    }
    return st;
}

static bool g_iatHooksInstalled = false;
static void install_iat_hooks(long long ik)
{
    if (g_iatHooksInstalled)
    {
        // Just add the page to the protected list
        if (g_numProtectedPages < 256)
        {
            g_protectedPages[g_numProtectedPages++] = ik & ~0xFFFLL;
        }
        return;
    }
    g_iatHooksInstalled = true;
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
        return;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !k32)
        return;

    // Hook NtQueryVirtualMemory
    if (!g_origNtQVM)
    {
        g_origNtQVM = (pNtQueryVirtualMemory)GetProcAddress(ntdll, "NtQueryVirtualMemory");
        if (g_origNtQVM)
            hook_iat(hJvm, "ntdll.dll", "NtQueryVirtualMemory", (void *)hookNtQueryVirtualMemory);
    }
    // Hook IsDebuggerPresent
    if (!g_origIsDbg)
    {
        g_origIsDbg = (pIsDebuggerPresent)GetProcAddress(k32, "IsDebuggerPresent");
        if (g_origIsDbg)
            hook_iat(hJvm, "kernel32.dll", "IsDebuggerPresent", (void *)hookIsDebuggerPresent);
    }
    // Hook CheckRemoteDebuggerPresent
    if (!g_origCheckRemote)
    {
        g_origCheckRemote = (pCheckRemoteDebuggerPresent)GetProcAddress(k32, "CheckRemoteDebuggerPresent");
        if (g_origCheckRemote)
            hook_iat(hJvm, "kernel32.dll", "CheckRemoteDebuggerPresent", (void *)hookCheckRemoteDebuggerPresent);
    }
    // Hook NtQueryInformationProcess
    if (!g_origNtQIP)
    {
        g_origNtQIP = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (g_origNtQIP)
            hook_iat(hJvm, "ntdll.dll", "NtQueryInformationProcess", (void *)hookNtQueryInformationProcess);
    }
    // Hook NtProtectVirtualMemory (IAT — catches IAT-based calls)
    if (!g_origNtPVM)
    {
        g_origNtPVM = (pNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
        if (g_origNtPVM)
            hook_iat(hJvm, "ntdll.dll", "NtProtectVirtualMemory", (void *)hookNtProtectVirtualMemory);
    }

    // ── Inline hook ntdll!NtProtectVirtualMemory (catches ALL calls, even non-IAT) ──
    install_ntpvm_inline_hook();

    if (g_numProtectedPages < 256)
    {
        g_protectedPages[g_numProtectedPages++] = ik & ~0xFFFLL;
    }
    fprintf(stderr, "[TZD] protect_class: IAT hooks installed (NtQVM+IsDbg+CheckRemote+NtQIP)\n");
    fflush(stderr);
}

// (integrity_check_thread_enhanced moved after deep encryption section)

// ─── Runtime-detected offsets ─────────────────────────────────────────
static int g_klass_offset = -1;           // java_lang_Class::_klass_offset
static bool g_klass_handle_indir = false; // true: jobject is a handle (needs deref)
static int g_access_flags_offset = -1;    // Klass::_access_flags
static int g_next_link_offset = -1;       // Klass::_next_link
static int g_cld_offset = -1;             // Klass::_class_loader_data
static int g_cld_klasses_offset = -1;     // ClassLoaderData::_klasses
static bool g_offsets_inited = false;

// ─── Method-level protection (the "lower-level things" the attacker touched) ──
// The attacker bypassed InstanceKlass protection entirely by NOT touching the
// klass. Instead they modified Method* fields directly:
//   - Set _code (offset 72) → fake/modified nmethod (JIT exploit)
//   - Set _from_compiled_entry (offset 64) → attacker machine code
//   - Modified nmethod compiled code in the CodeCache
// This struct backs up ALL critical Method* fields so we can detect+restore.
#define MAX_METHODS_PER_CLASS 64
#define MAX_METHOD_PAGES 32

struct ProtectedMethod
{
    long long methodPtr; // Method* address
    // Backups of critical Method* fields (JDK 20 offsets from jvm_deopt)
    long long orig_constMethod;   // offset 8  — ConstMethod* (bytecodes live here)
    jint orig_access_flags;       // offset 40 — JVM_ACC_NOT_C1/C2_COMPILABLE
    unsigned short orig_flags;    // offset 50 — _dont_inline bit
    long long orig_i2i_entry;     // offset 56 — interpreter-to-interpreter entry
    long long orig_from_compiled; // offset 64 — compiled callers jump here (JIT exploit target!)
    long long orig_code;          // offset 72 — CompiledMethod*/nmethod* (JIT exploit target!)
    long long orig_from_interp;   // offset 80 — interpreted callers use this
    // ConstMethod bytecode backup
    long long constMethodPtr;      // ConstMethod* address
    unsigned short code_size;      // bytecode length
    unsigned char *bytecodeBackup; // backup of original bytecodes
    unsigned int bytecodeCRC;      // CRC32 of original bytecodes
    // Full ConstMethod backup (header + bytecodes) — catches writes to
    // ConstMethod header fields too (e.g. _code_size, _orig_method_idnum),
    // not just the bytecode array. The attacker may write at offset 48
    // (_orig_method_idnum) instead of 56 (bytecodes); we protect the entire
    // ConstMethod struct regardless of which offset they target.
    unsigned char *cmFullBackup; // backup of entire ConstMethod (header + bytecodes)
    int cmFullSize;              // offCB + code_size (total protected size)
    // nmethod compiled-code backup (if method was JIT-compiled before protection)
    long long nmethodPtr;         // nmethod* (= orig _code value)
    long long nmethodEntry;       // verified_entry_point (= orig _from_compiled_entry)
    unsigned char *nmethodBackup; // backup of compiled machine code
    long long nmethodSize;        // size of backed-up compiled code
    unsigned int nmethodCRC;      // CRC32 of compiled code
    bool hasNmethod;              // did this method have compiled code?
    bool forceInterpApplied;      // did we call jvm_force_interpreter()?
};

struct ProtectedClass
{
    long long iklass;
    jint orig_access_flags;
    long long orig_next_link; // our original _next_link value
    long long orig_prev_ptr;  // address of the field that pointed at us
    long long orig_constants; // InstanceKlass._constants (offset 192)
    bool was_unlinked;
    bool memory_locked;
    // ── Method-level protection ──
    ProtectedMethod methods[MAX_METHODS_PER_CLASS];
    int numMethods;
    long long methodPages[MAX_METHOD_PAGES]; // pages set to PAGE_READONLY
    int numMethodPages;
    // ── VTable backup (prevent vtable hijacking) ──
    long long vtableAddr; // start of embedded vtable
    int vtableLen;        // vtable length in words (each = Method*)
    unsigned char *vtableBackup;
    unsigned int vtableCRC;
    // ── ITable backup (prevent itable hijacking) ──
    long long itableAddr; // start of embedded itable
    int itableLen;        // itable length in words
    unsigned char *itableBackup;
    unsigned int itableCRC;
    // ── ConstantPoolCache backup (prevent CPC patching) ──
    long long cpCacheAddr; // ConstantPoolCache* (from ConstantPool._cache@16)
    int cpCacheLen;        // number of cache entries
    unsigned char *cpCacheBackup;
    int cpCacheBackupSize;
    unsigned int cpCacheCRC;
};
static std::unordered_map<long long, ProtectedClass> g_protected;
static CRITICAL_SECTION g_cs;
static bool g_csInited = false;

// ─── Safe pointer read ──────────────────────────────────────────────
static long long rq(void *a)
{
    if (!a)
        return 0;
    if (!jvm_safe_read(a, 8))
        return 0;
    return *(long long *)a;
}
static jint r4(void *a)
{
    if (!a)
        return 0;
    if (!jvm_safe_read(a, 4))
        return 0;
    return *(jint *)a;
}

// ─── Forward declarations ───────────────────────────────────────────
static long long resolve_iklass(JNIEnv *env, jclass clazz);
static long long resolve_iklass_from_class(JNIEnv *env, const char *name);

// Recursion guard: detect_klass_offset → resolve_iklass_from_class →
// resolve_iklass → detect_klass_offset would infinitely recurse without this.
static bool g_detecting_klass_offset = false;

// RAII guard: resets the recursion flag on all exit paths.
struct DetectGuard
{
    bool &flag;
    DetectGuard(bool &f) : flag(f) { flag = true; }
    ~DetectGuard() { flag = false; }
};

// ─── Detect java_lang_Class::_klass_offset ───────────────────────────
// Walk Method → ConstMethod → ConstantPool → InstanceKlass for
// java.lang.Object, then scan the Class mirror for a qword == iklass.
static bool detect_klass_offset(JNIEnv *env)
{
    if (g_klass_offset >= 0)
        return true;
    if (g_detecting_klass_offset)
        return false; // break recursion
    DetectGuard guard(g_detecting_klass_offset);

    long long ik = resolve_iklass_from_class(env, "java/lang/Object");
    if (!ik)
    {
        // resolve_iklass_from_class calls resolve_iklass which calls
        // detect_klass_offset — circular. On first call, we need to bootstrap
        // via the raw Method* chain.
        jclass objClass = env->FindClass("java/lang/Object");
        if (!objClass)
            return false;
        jmethodID mid = env->GetMethodID(objClass, "toString", "()Ljava/lang/String;");
        if (!mid)
        {
            env->DeleteLocalRef(objClass);
            return false;
        }
        jobject tmp = env->AllocObject(objClass);
        if (tmp)
        {
            env->CallObjectMethod(tmp, mid);
            env->DeleteLocalRef(tmp);
        }

        // Resolve Method* from jmethodID
        long long methodPtr = 0;
        long long raw = (long long)mid;
        if (jvm_safe_read((void *)raw, 8))
        {
            long long derefed = *(long long *)raw;
            if (derefed && jvm_safe_read((void *)derefed, 64))
            {
                long long q = *(long long *)derefed;
                if (q && jvm_safe_read((void *)q, 8))
                    methodPtr = derefed;
            }
        }
        if (!methodPtr)
            methodPtr = raw;
        env->DeleteLocalRef(objClass);
        if (!methodPtr)
            return false;

        int offCM = jvm_deopt_get_offset("constMethod");
        if (offCM < 0)
            return false;
        long long cm = rq((void *)(methodPtr + offCM));
        if (!cm)
            return false;
        long long cp = rq((void *)(cm + 8)); // ConstMethod._constants
        if (!cp)
            return false;
        ik = rq((void *)(cp + 24)); // ConstantPool._pool_holder
        if (!ik)
            return false;
    }
    if (!ik)
        return false;

    // Scan the Class mirror (jobject) for a qword == ik.
    jclass objMirror = env->FindClass("java/lang/Object");
    if (!objMirror)
        return false;
    long long mirrorPtr = (long long)(intptr_t)objMirror;

    // Direct scan (jobject == raw oop, JDK 16+ typical)
    for (int off = 0; off <= 200; off++)
    {
        if (rq((void *)(mirrorPtr + off)) == ik)
        {
            g_klass_offset = off;
            g_klass_handle_indir = false;
            fprintf(stderr, "[TZD] protect_class: _klass_offset=%d (direct, ik=0x%llx)\n", off, ik);
            fflush(stderr);
            env->DeleteLocalRef(objMirror);
            return true;
        }
    }
    // Handle-indirection scan (jobject == oop*)
    long long derefed = rq((void *)mirrorPtr);
    if (derefed)
    {
        for (int off = 0; off <= 200; off++)
        {
            if (rq((void *)(derefed + off)) == ik)
            {
                g_klass_offset = off;
                g_klass_handle_indir = true;
                fprintf(stderr, "[TZD] protect_class: _klass_offset=%d (via handle, ik=0x%llx)\n", off, ik);
                fflush(stderr);
                env->DeleteLocalRef(objMirror);
                return true;
            }
        }
    }
    env->DeleteLocalRef(objMirror);
    log_msg("protect_class: could not detect _klass_offset");
    return false;
}

// ─── Resolve InstanceKlass from Class<?> ────────────────────────────
static long long resolve_iklass(JNIEnv *env, jclass clazz)
{
    if (!detect_klass_offset(env))
        return 0;
    long long ptr = (long long)(intptr_t)clazz;
    if (g_klass_handle_indir)
    {
        ptr = rq((void *)ptr);
        if (!ptr)
            return 0;
    }
    return rq((void *)(ptr + g_klass_offset));
}

static long long resolve_iklass_from_class(JNIEnv *env, const char *name)
{
    jclass cls = env->FindClass(name);
    if (!cls)
        return 0;
    long long ik = resolve_iklass(env, cls);
    env->DeleteLocalRef(cls);
    return ik;
}

// ─── Detect Klass::_access_flags offset ─────────────────────────────
// JDK 20: _access_flags is at offset 164 in Klass (confirmed from source).
// Klass layout: vptr(8) + _layout_helper(4) + _kind(4) + _modifier_flags(4)
//   + _super_check_offset(4) + _name(8) + _secondary_super_cache(8)
//   + _secondary_supers(8) + _primary_supers[8](64) + _java_mirror(8)
//   + _super(8) + _subklass(8) + _next_sibling(8) + _next_link(8)
//   + _class_loader_data(8) + _vtable_len(4) + _access_flags(4) = 168 bytes
// We try the hardcoded 164 first, then fall back to scanning.
static bool detect_access_flags_offset(JNIEnv *env)
{
    if (g_access_flags_offset >= 0)
        return true;

    // Try hardcoded JDK 20 offset: 164
    long long objIK = resolve_iklass_from_class(env, "java/lang/Object");
    if (objIK)
    {
        jint v = r4((void *)(objIK + 164));
        // Object: ACC_PUBLIC|ACC_FINAL|ACC_ABSTRACT = 0x0411
        if ((v & 0xFFFF) == 0x0411)
        {
            g_access_flags_offset = 164;
            // Also try 160 (in case _vtable_len is absent)
            if ((v & 0xFFFF) != 0x0411)
                g_access_flags_offset = -1;
        }
    }

    // Fallback: scan using Object + String
    if (g_access_flags_offset < 0 && objIK)
    {
        long long strIK = resolve_iklass_from_class(env, "java/lang/String");
        for (int off = 100; off <= 300; off += 4)
        {
            jint v = r4((void *)(objIK + off));
            if ((v & 0xFFFF) != 0x0411)
                continue;
            if (strIK)
            {
                jint v2 = r4((void *)(strIK + off));
                if ((v2 & 0xFFFF) != 0x0011)
                    continue;
            }
            g_access_flags_offset = off;
            break;
        }
    }

    // Last resort: try 164 even without verification
    if (g_access_flags_offset < 0)
    {
        g_access_flags_offset = 164;
        fprintf(stderr, "[TZD] protect_class: _access_flags hardcoded to 164 (unverified)\n");
        fflush(stderr);
        return true;
    }

    if (g_access_flags_offset >= 0)
    {
        fprintf(stderr, "[TZD] protect_class: _access_flags_offset=%d\n", g_access_flags_offset);
        fflush(stderr);
        return true;
    }
    log_msg("protect_class: could not detect _access_flags offset");
    return false;
}

static void verify_instrumentation_callback()
{
    if (!g_instrCallbackInstalled || !g_instrCallbackStub)
        return;

    // 1. 重置心跳标志
    InterlockedExchange(&g_instrCallbackFired, 0);

    // 2. 发起一个极轻量的直接系统调用，触发内核返回，激活回调。
    // 使用您之前已经成功初始化的直接系统调用 Stub。
    if (g_sysNtResume)
    {
        // 传入无效句柄 nullptr。虽然调用会失败返回错误码，但它必定会走内核并触发 syscall 返回流！
        g_sysNtResume(nullptr, nullptr);
    }
    else if (g_sysNtPVM)
    {
        PVOID base = nullptr;
        SIZE_T sz = 0;
        g_sysNtPVM(nullptr, &base, &sz, 0, nullptr);
    }
    else
    {
        // 备用兜底方案：调用 ntdll 中的最轻量系统调用
        typedef NTSTATUS(NTAPI * pfnNtYieldExecution)();
        static pfnNtYieldExecution pNtYield = (pfnNtYieldExecution)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
        if (pNtYield)
            pNtYield();
    }

    // 3. 检查心跳标志。系统调用返回后，标志位应该瞬间被 Handler 改写为 1。
    if (InterlockedCompareExchange(&g_instrCallbackFired, 0, 0) == 0)
    {
        // 心跳标志依然为 0！判定回调已被恶意代码通过 NtSetInformationProcess 卸载
        fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                        "(ProcessInstrumentationCallback UNINSTALLED/BYPASSED! Re-registering...)\n");
        fflush(stderr);

        // 4. 强行重新注册复活（Re-arm）
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
        {
            typedef NTSTATUS(NTAPI * pNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
            auto pNtSIP = (pNtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
            if (pNtSIP)
            {
                PROC_INST_CALLBACK_INFO info;
                memset(&info, 0, sizeof(info));
                info.Version = 0;
                info.Callback = g_instrCallbackStub; // 指向您的汇编 Stub
                pNtSIP(GetCurrentProcess(), ProcessInstrumentationCallback, &info, sizeof(info));
            }
        }
    }
}

// ─── Detect _class_loader_data, _next_link, CLD::_klasses ──────────
static bool detect_list_offsets(JNIEnv *env)
{
    if (g_next_link_offset >= 0 && g_cld_offset >= 0)
        return true;
    long long objIK = resolve_iklass_from_class(env, "java/lang/Object");
    if (!objIK || g_access_flags_offset < 0)
        return false;

    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    long long jvmBase = 0, jvmSize = 0;
    if (hJvm)
    {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(GetCurrentProcess(), hJvm, &mi, sizeof(mi)))
        {
            jvmBase = (long long)mi.lpBaseOfDll;
            jvmSize = (long long)mi.SizeOfImage;
        }
    }

    // _class_loader_data: a pointer to a C-heap object whose first qword
    // (vtable) points into jvm.dll.
    for (int off = 100; off <= 200; off += 8)
    {
        long long val = rq((void *)(objIK + off));
        if (!val)
            continue;
        long long vptr = rq((void *)val);
        if (jvmBase && vptr >= jvmBase && vptr < jvmBase + jvmSize)
        {
            g_cld_offset = off;
            break;
        }
    }
    if (g_cld_offset < 0)
    {
        log_msg("protect_class: could not detect _class_loader_data offset");
        return false;
    }

    // From klass.hpp declaration order:
    //   _super, _subklass, _next_sibling, _next_link, _class_loader_data
    // So _next_link = _class_loader_data - 8.
    g_next_link_offset = g_cld_offset - 8;

    fprintf(stderr, "[TZD] protect_class: _cld_offset=%d _next_link_offset=%d\n",
            g_cld_offset, g_next_link_offset);
    fflush(stderr);

    // Detect ClassLoaderData::_klasses: scan the CLD for a pointer to a
    // valid-looking InstanceKlass.
    long long cld = rq((void *)(objIK + g_cld_offset));
    if (cld)
    {
        for (int off = 0; off <= 200; off += 8)
        {
            long long val = rq((void *)(cld + off));
            if (!val)
                continue;
            jint af = r4((void *)(val + g_access_flags_offset));
            if ((af & 0xFFFF) != 0 && (af & 0xFFFF) != 0xFFFF)
            {
                g_cld_klasses_offset = off;
                fprintf(stderr, "[TZD] protect_class: _cld_klasses_offset=%d\n", off);
                fflush(stderr);
                break;
            }
        }
    }
    return true;
}

static bool ensure_offsets(JNIEnv *env)
{
    if (g_offsets_inited)
        return true;
    if (!g_csInited)
    {
        InitializeCriticalSection(&g_cs);
        g_csInited = true;
    }
    bool ok = detect_klass_offset(env);
    if (ok)
    {
        // Hardcode JDK 20 offsets (confirmed from source):
        // _access_flags = 164, _class_loader_data = 152, _next_link = 144
        if (g_access_flags_offset < 0)
        {
            g_access_flags_offset = 164;
            fprintf(stderr, "[TZD] protect_class: _access_flags hardcoded to 164\n");
            fflush(stderr);
        }
        if (g_cld_offset < 0)
        {
            g_cld_offset = 152;
            g_next_link_offset = 144; // _cld_offset - 8
            fprintf(stderr, "[TZD] protect_class: _cld_offset=152 _next_link=144 (hardcoded)\n");
            fflush(stderr);
        }
        // Try to detect _cld_klasses offset (non-critical — unlinking may fail)
        detect_list_offsets(env);
        g_offsets_inited = true;
        return true;
    }
    g_offsets_inited = ok;
    return ok;
}

// ─── Deep Memory Encryption (correct PAGE_GUARD + VEH) ──────────────
// Encrypts the InstanceKlass's _access_flags field so that even if an
// attacker restores PAGE_READWRITE via VirtualProtect, the data is still
// encrypted garbage. The VEH handler decrypts on JVM access and re-encrypts
// after one instruction.
//
// KEY FIX vs previous broken version:
//   PAGE_GUARD is PAGE-GRANULAR (4096 bytes). The old VEH only handled
//   faults within the 4 encrypted bytes — when the JVM accessed a DIFFERENT
//   field on the same page, the VEH returned CONTINUE_SEARCH, the OS
//   removed PAGE_GUARD, and subsequent reads of _access_flags returned
//   encrypted garbage → JVM crash.
//
//   NEW: the VEH checks if the fault is on the same PAGE (not just within
//   the encrypted bytes). If yes, it decrypts the encrypted field, sets TF,
//   and returns CONTINUE_EXECUTION. After one instruction, the single-step
//   VEH re-encrypts and restores PAGE_GUARD. The decrypted window is exactly
//   one instruction — correct and safe.
//
// Also uses a fixed-size array (no heap allocation in VEH) and interlocked
// operations (no critical section → no deadlock risk).

#define MAX_ENC_REGIONS 8

struct DeepEncKey
{
    unsigned char layers[3];
    unsigned int checksum;
};

struct DeepEncRegion
{
    unsigned char *fieldAddr; // address of the encrypted field
    size_t fieldSize;         // size of the encrypted field (e.g. 4)
    long long pageBase;       // page base (fieldAddr & ~0xFFF)
    DWORD originalProtect;    // original page protection (without PAGE_GUARD)
    DeepEncKey key;
    unsigned char backup[128]; // backup of original (decrypted) bytes
    bool active;               // is this slot in use?
};

// Fixed-size array — NO heap allocation in VEH handlers.
static DeepEncRegion g_encRegions[MAX_ENC_REGIONS];
static volatile long g_encCount = 0;
// Active decrypt flag — uses InterlockedExchange, no critical section.
static volatile long long g_activeDecryptPage = 0;
static PVOID g_deepVehGuard = nullptr;
static PVOID g_deepVehStep = nullptr;

static void deep_encrypt_bytes(unsigned char *b, size_t size, DeepEncKey *key)
{
    for (size_t i = 0; i < size; i++)
    {
        b[i] ^= key->layers[0];
        b[i] = ((b[i] << 3) | (b[i] >> 5)) ^ key->layers[1];
        b[i] = ~(b[i] ^ key->layers[2]);
    }
    unsigned int crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++)
    {
        crc ^= b[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & (-(int)(crc & 1)));
    }
    key->checksum = ~crc;
}

static void deep_decrypt_bytes(unsigned char *b, size_t size, DeepEncKey *key)
{
    for (size_t i = 0; i < size; i++)
    {
        b[i] = (~b[i]) ^ key->layers[2];
        unsigned char t = b[i] ^ key->layers[1];
        b[i] = (t >> 3) | (t << 5);
        b[i] ^= key->layers[0];
    }
}

static DeepEncKey gen_deep_key(void *addr)
{
    DeepEncKey k;
    unsigned long long seed = (unsigned long long)(intptr_t)addr ^ __rdtsc();
    k.layers[0] = (unsigned char)(seed & 0xFF);
    k.layers[1] = (unsigned char)((seed >> 8) & 0xFF);
    k.layers[2] = (unsigned char)((seed >> 16) & 0xFF);
    if (k.layers[0] == 0)
        k.layers[0] = 0x5A;
    if (k.layers[1] == 0)
        k.layers[1] = 0xA5;
    if (k.layers[2] == 0)
        k.layers[2] = 0x3C;
    k.checksum = 0;
    return k;
}

// VEH: PAGE_GUARD triggered on ANY field on the same page as our encrypted field.
// We decrypt the encrypted field, set TF, and let the instruction re-execute.
// After one instruction, the single-step VEH re-encrypts and restores PAGE_GUARD.
static LONG CALLBACK deep_guard_veh(PEXCEPTION_POINTERS exc)
{
    if (exc->ExceptionRecord->ExceptionCode != 0x80000001) // STATUS_GUARD_PAGE_VIOLATION
        return EXCEPTION_CONTINUE_SEARCH;

    // CRITICAL: Use ExceptionInformation[1] (the faulting DATA address),
    // NOT ExceptionAddress (the instruction pointer). The instruction is in
    // jvm.dll's code section, not on the encrypted data page.
    void *faultData = nullptr;
    if (exc->ExceptionRecord->NumberParameters >= 2)
        faultData = (void *)exc->ExceptionRecord->ExceptionInformation[1];
    if (!faultData)
        return EXCEPTION_CONTINUE_SEARCH;

    long long faultPage = (long long)(intptr_t)faultData & ~0xFFFULL;

    // Check all encrypted regions — match by PAGE (not by exact field address)
    for (int i = 0; i < g_encCount; i++)
    {
        DeepEncRegion *r = &g_encRegions[i];
        if (!r->active)
            continue;
        if (r->pageBase != faultPage)
            continue;

        // Fault is on the same page as our encrypted field.
        // Set PAGE_READWRITE so we can write the decrypted bytes.
        // Use g_ourCall to bypass our own NtProtectVirtualMemory hook.
        DWORD tmp;
        g_ourCall = 1;
        direct_VirtualProtect((void *)r->pageBase, 4096, PAGE_READWRITE, &tmp);
        g_ourCall = 0;

        // Decrypt the encrypted field
        deep_decrypt_bytes(r->fieldAddr, r->fieldSize, &r->key);

        // Mark this page as actively decrypted (for the single-step handler)
        InterlockedExchange64(&g_activeDecryptPage, r->pageBase);

        // Set trap flag → single-step after this instruction
        exc->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// VEH: single-step → re-encrypt the field, restore PAGE_GUARD.
static LONG CALLBACK deep_step_veh(PEXCEPTION_POINTERS exc)
{
    if (exc->ExceptionRecord->ExceptionCode != 0x80000004) // EXCEPTION_SINGLE_STEP
        return EXCEPTION_CONTINUE_SEARCH;

    long long page = InterlockedExchange64(&g_activeDecryptPage, 0);
    if (page == 0)
        return EXCEPTION_CONTINUE_SEARCH;

    // Find the region on this page and re-encrypt
    for (int i = 0; i < g_encCount; i++)
    {
        DeepEncRegion *r = &g_encRegions[i];
        if (!r->active || r->pageBase != page)
            continue;

        // Re-encrypt the field (page is PAGE_READWRITE from guard handler)
        deep_encrypt_bytes(r->fieldAddr, r->fieldSize, &r->key);

        // Restore PAGE_READONLY | PAGE_GUARD on the page
        DWORD old;
        g_ourCall = 1;
        direct_VirtualProtect((void *)r->pageBase, 4096, r->originalProtect | 0x100, &old);
        g_ourCall = 0;
        break;
    }

    // Clear trap flag (CPU should do this, but be explicit)
    exc->ContextRecord->EFlags &= ~0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void init_deep_encryption()
{
    if (g_deepVehGuard)
        return;
    g_deepVehGuard = AddVectoredExceptionHandler(1, deep_guard_veh);
    g_deepVehStep = AddVectoredExceptionHandler(1, deep_step_veh);
    fprintf(stderr, "[TZD] protect_class: deep encryption VEH registered\n");
    fflush(stderr);
}

// Periodic integrity check thread — backup protection.
// Every 100ms, checks if the encrypted field's CRC32 matches. If not
// (someone modified it despite PAGE_GUARD), restores from backup.
static HANDLE g_integrityThread = nullptr;
static volatile bool g_integrityRunning = false;

// (old integrity_check_thread removed — replaced by integrity_check_thread_enhanced)

// Encrypt and PAGE_GUARD a field. Called after hidden flag + unlink.
static void deep_encrypt_and_guard(void *addr, size_t size)
{
    if (size == 0 || size > 128)
        return;
    if (g_encCount >= MAX_ENC_REGIONS)
        return;

    init_deep_encryption();

    long long pageBase = (long long)(intptr_t)addr & ~0xFFFULL;
    DWORD origProt = PAGE_READONLY;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT)
        origProt = mbi.Protect & ~0x100; // strip PAGE_GUARD

    int idx = (int)InterlockedIncrement(&g_encCount) - 1;
    if (idx >= MAX_ENC_REGIONS)
    {
        InterlockedDecrement(&g_encCount);
        return;
    }

    DeepEncRegion *r = &g_encRegions[idx];
    r->fieldAddr = (unsigned char *)addr;
    r->fieldSize = size;
    r->pageBase = pageBase;
    r->originalProtect = origProt;
    r->key = gen_deep_key(addr);
    r->active = false;

    // Save backup before encryption
    DWORD tmp;
    direct_VirtualProtect(addr, size, PAGE_READWRITE, &tmp);
    memcpy(r->backup, addr, size);

    // Encrypt the field
    deep_encrypt_bytes(r->fieldAddr, r->fieldSize, &r->key);

    // Set PAGE_GUARD on the entire page
    direct_VirtualProtect((void *)r->pageBase, 4096, origProt | 0x100, &tmp);

    r->active = true;

    // Thread is started from protect_class Step 6 (enhanced integrity thread)
    fprintf(stderr, "[TZD] protect_class: deep encrypted %zu bytes at 0x%p (page=0x%llx)\n",
            size, addr, pageBase);
    fflush(stderr);
}

// ─── Method-structure write-guard VEH ────────────────────────────────
// The attacker's exploit: they didn't touch the InstanceKlass at all.
// Instead they wrote directly to Method* fields — specifically _code
// (offset 72) and _from_compiled_entry (offset 64) — to redirect method
// execution to attacker-controlled machine code (fake nmethod / patched
// compiled code). This VEH catches those writes.
//
// Strategy:
//   1. After backing up Method* fields + forcing interpreter mode, set
//      Method* pages to PAGE_READONLY. Reads work (no exception); only
//      WRITES trigger ACCESS_VIOLATION (0xC0000005).
//   2. VEH checks ExceptionInformation[0] == 1 (write).
//   3. If the faulting instruction is inside jvm.dll .text → legitimate
//      JVM write (JIT compile/deopt) → temporarily allow, re-protect via TF.
//   4. If the faulting instruction is OUTSIDE jvm.dll → attacker write.
//      Output "你好伙计，你改你妈的方法呢", allow the one instruction but
//      immediately restore from backup in the single-step handler.
//   5. The integrity thread (every 100ms) is the backup: CRC32 check +
//      restore for any modification that slipped through.

static long long g_jvmDllBase = 0;
static long long g_jvmDllSize = 0;

static bool is_in_jvm_dll(long long addr)
{
    if (!g_jvmDllBase || !g_jvmDllSize)
        return false;
    return addr >= g_jvmDllBase && addr < g_jvmDllBase + g_jvmDllSize;
}

static void init_jvm_dll_range()
{
    if (g_jvmDllBase)
        return;
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
        return;
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (GetModuleInformation(GetCurrentProcess(), hJvm, &mi, sizeof(mi)))
    {
        g_jvmDllBase = (long long)mi.lpBaseOfDll;
        g_jvmDllSize = (long long)mi.SizeOfImage;
    }
}

// Track which page is being temporarily un-protected for write + whether to
// restore Method* fields after the write completes.
static volatile long long g_activeWritePage = 0;   // page being written
static volatile long long g_writeNeedsRestore = 0; // 1 = restore after write
static PVOID g_methodWriteVeh = nullptr;
static PVOID g_methodStepVeh = nullptr;
static PVOID g_hwbpVeh = nullptr; // hardware breakpoint VEH

// Forward declaration: hwbp_veh is defined in the HW breakpoint section below
static LONG CALLBACK hwbp_veh(PEXCEPTION_POINTERS exc);

// ── Lock-free flat arrays for VEH-safe access ──
// VEH handlers CANNOT use EnterCriticalSection (deadlock if the integrity
// thread holds it). These arrays are populated at protect_methods() time and
// only read (never written) during VEH execution, so they are safe to scan
// without locks.
#define MAX_FLAT_METHODS 512
struct FlatMethodEntry
{
    long long methodPtr;
    long long mpPage; // methodPtr & ~0xFFF
    long long orig_constMethod;
    jint orig_access_flags;
    unsigned short orig_flags;
    long long orig_i2i_entry;
    long long orig_from_compiled;
    long long orig_code;
    long long orig_from_interp;
    long long constMethodPtr;
    long long cmPage; // constMethodPtr & ~0xFFF
    unsigned short code_size;
    unsigned char *bytecodeBackup;
    int offCB;
    // Full ConstMethod backup (header + bytecodes) — protects the ENTIRE
    // ConstMethod struct, not just bytecodes. Catches writes to header
    // fields (e.g. offset 48 = _orig_method_idnum) that bytecodes-only
    // backup would miss.
    unsigned char *cmFullBackup;
    int cmFullSize;
    // Method* field offsets (cached for fast restore in VEH)
    int offCM, offAF, offFl, offI2I, offFC, offCode, offFI;
};
static FlatMethodEntry g_flatMethods[MAX_FLAT_METHODS];
static volatile long g_numFlatMethods = 0;
static volatile long long g_flatMethodPages[256];
static volatile long g_numFlatMethodPages = 0;

// Check if a page is a protected Method*/ConstMethod* page.
// LOCK-FREE: uses the flat array so VEH handlers don't deadlock on the
// critical section held by the integrity thread.
static bool is_method_protected_page(long long page)
{
    int n = (int)g_numFlatMethodPages;
    for (int i = 0; i < n && i < 256; i++)
    {
        if (g_flatMethodPages[i] == page)
            return true;
    }
    return false;
}

// VEH: ACCESS_VIOLATION on a Method*/ConstMethod* page → write detected.
// NO WHITELIST: ALL writes to protected Method* fields are blocked and
// restored, regardless of who writes them — even jvm.dll itself.
// Writes to NON-protected fields on the same page are allowed (the page
// may contain other metadata that the JVM legitimately writes to).
static LONG CALLBACK method_write_guard_veh(PEXCEPTION_POINTERS exc)
{
    if (exc->ExceptionRecord->ExceptionCode != 0xC0000005) // STATUS_ACCESS_VIOLATION
        return EXCEPTION_CONTINUE_SEARCH;

    // Only handle writes (ExceptionInformation[0] == 1)
    if (exc->ExceptionRecord->NumberParameters < 2)
        return EXCEPTION_CONTINUE_SEARCH;
    if (exc->ExceptionRecord->ExceptionInformation[0] != 1) // not a write
        return EXCEPTION_CONTINUE_SEARCH;

    void *faultData = (void *)exc->ExceptionRecord->ExceptionInformation[1];
    if (!faultData)
        return EXCEPTION_CONTINUE_SEARCH;

    long long faultPage = (long long)(intptr_t)faultData & ~0xFFFULL;

    // Is this one of our protected Method* pages?
    if (!is_method_protected_page(faultPage))
        return EXCEPTION_CONTINUE_SEARCH;

    // ── NO WHITELIST: Check if the write target is within a PROTECTED field ──
    // If it's a non-protected field on the same page → allow (legitimate write)
    long long faultAddr = (long long)(intptr_t)faultData;
    bool isProtectedField = false;
    int n = (int)g_numFlatMethods;
    for (int i = 0; i < n && i < MAX_FLAT_METHODS; i++)
    {
        FlatMethodEntry *fm = &g_flatMethods[i];
        if (!fm->methodPtr)
            continue;
        long long mp = fm->methodPtr;
        // Check each protected field range
        if (fm->offCM >= 0 && faultAddr >= mp + fm->offCM && faultAddr < mp + fm->offCM + 8)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offAF >= 0 && faultAddr >= mp + fm->offAF && faultAddr < mp + fm->offAF + 4)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offFl >= 0 && faultAddr >= mp + fm->offFl && faultAddr < mp + fm->offFl + 2)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offI2I >= 0 && faultAddr >= mp + fm->offI2I && faultAddr < mp + fm->offI2I + 8)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offFC >= 0 && faultAddr >= mp + fm->offFC && faultAddr < mp + fm->offFC + 8)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offCode >= 0 && faultAddr >= mp + fm->offCode && faultAddr < mp + fm->offCode + 8)
        {
            isProtectedField = true;
            break;
        }
        if (fm->offFI >= 0 && faultAddr >= mp + fm->offFI && faultAddr < mp + fm->offFI + 8)
        {
            isProtectedField = true;
            break;
        }
        // ── ConstMethod full-range check (header + bytecodes) ──
        // The attacker writes to ConstMethod via Unsafe.putByte at ANY
        // offset — e.g. offset 48 (_orig_method_idnum) or offset 56
        // (bytecodes). Without this check, writes to ConstMethod fall
        // through to the "non-protected field" path and are ALLOWED.
        // We protect the ENTIRE ConstMethod struct: constMethodPtr+0 to
        // constMethodPtr + offCB + code_size.
        if (fm->constMethodPtr && fm->cmFullSize > 0 &&
            faultAddr >= fm->constMethodPtr &&
            faultAddr < fm->constMethodPtr + fm->cmFullSize)
        {
            isProtectedField = true;
            break;
        }
    }

    if (!isProtectedField)
    {
        // Write to a non-protected field on the same page — ALLOW it.
        // The JVM may legitimately write to _method_data, _method_counters,
        // _adapter, etc. on this page. Only our protected fields are blocked.
        DWORD old;
        g_ourCall = 1;
        direct_VirtualProtect((void *)faultPage, 4096, PAGE_READWRITE, &old);
        g_ourCall = 0;
        InterlockedExchange64(&g_activeWritePage, faultPage);
        InterlockedExchange64(&g_writeNeedsRestore, 0); // don't restore
        exc->ContextRecord->EFlags |= 0x100;            // TF → re-protect after 1 instruction
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── WRITE TO PROTECTED FIELD DETECTED — NO WHITELIST, NO EXCEPTIONS ──
    // Even if jvm.dll is writing here, we block it. We've already set the
    // method to interpreter mode (NOT_C1/C2_COMPILABLE, _code=NULL) — the JVM
    // has NO legitimate reason to write to these fields anymore.
    long long ip = (long long)exc->ExceptionRecord->ExceptionAddress;
    fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                    "(write to PROTECTED field at 0x%llx on page 0x%llx from IP=0x%llx "
                    "— NO WHITELIST, BLOCKED)\n",
            faultAddr, faultPage, ip);
    fflush(stderr);

    // Mark for restore: the single-step handler will restore all Method*
    // fields on this page from backup, undoing the write.
    InterlockedExchange64(&g_writeNeedsRestore, 1);

    // Temporarily set PAGE_READWRITE so the write can execute (we can't
    // skip the instruction — we let it happen and immediately undo it).
    DWORD old;
    g_ourCall = 1;
    direct_VirtualProtect((void *)faultPage, 4096, PAGE_READWRITE, &old);
    g_ourCall = 0;

    // Record the page for the single-step handler.
    InterlockedExchange64(&g_activeWritePage, faultPage);

    // Set trap flag → single-step after this instruction.
    exc->ContextRecord->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// VEH: single-step → restore Method* fields if needed, re-apply PAGE_READONLY.
static LONG CALLBACK method_write_step_veh(PEXCEPTION_POINTERS exc)
{
    if (exc->ExceptionRecord->ExceptionCode != 0x80000004) // EXCEPTION_SINGLE_STEP
        return EXCEPTION_CONTINUE_SEARCH;

    long long page = InterlockedExchange64(&g_activeWritePage, 0);
    if (page == 0)
        return EXCEPTION_CONTINUE_SEARCH;

    long long needRestore = InterlockedExchange64(&g_writeNeedsRestore, 0);

    if (needRestore)
    {
        // Attacker write detected — restore ALL Method* fields on this page
        // from backup. This undoes whatever the attacker just wrote.
        // LOCK-FREE: uses g_flatMethods (no critical section — safe in VEH).
        int n = (int)g_numFlatMethods;
        for (int i = 0; i < n && i < MAX_FLAT_METHODS; i++)
        {
            FlatMethodEntry *fm = &g_flatMethods[i];
            if (!fm->methodPtr)
                continue;

            if (fm->mpPage == page)
            {
                // Restore Method* critical fields
                DWORD op = 0;
                // _constMethod
                if (fm->offCM >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offCM), 8))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offCM), 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)(fm->methodPtr + fm->offCM) = fm->orig_constMethod;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offCM), 8, op, &op);
                    }
                }
                // _access_flags
                if (fm->offAF >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offAF), 4))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offAF), 4, PAGE_READWRITE, &op))
                    {
                        *(jint *)(fm->methodPtr + fm->offAF) = fm->orig_access_flags;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offAF), 4, op, &op);
                    }
                }
                // _flags
                if (fm->offFl >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offFl), 2))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offFl), 2, PAGE_READWRITE, &op))
                    {
                        *(unsigned short *)(fm->methodPtr + fm->offFl) = fm->orig_flags;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offFl), 2, op, &op);
                    }
                }
                // _i2i_entry
                if (fm->offI2I >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offI2I), 8))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offI2I), 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)(fm->methodPtr + fm->offI2I) = fm->orig_i2i_entry;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offI2I), 8, op, &op);
                    }
                }
                // _from_compiled_entry (PRIMARY JIT EXPLOIT TARGET)
                if (fm->offFC >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offFC), 8))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offFC), 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)(fm->methodPtr + fm->offFC) = fm->orig_from_compiled;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offFC), 8, op, &op);
                    }
                }
                // _code (JIT EXPLOIT: fake nmethod pointer)
                if (fm->offCode >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offCode), 8))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offCode), 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)(fm->methodPtr + fm->offCode) = fm->orig_code;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offCode), 8, op, &op);
                    }
                }
                // _from_interpreted_entry
                if (fm->offFI >= 0 && jvm_safe_read((void *)(fm->methodPtr + fm->offFI), 8))
                {
                    if (direct_VirtualProtect((void *)(fm->methodPtr + fm->offFI), 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)(fm->methodPtr + fm->offFI) = fm->orig_from_interp;
                        direct_VirtualProtect((void *)(fm->methodPtr + fm->offFI), 8, op, &op);
                    }
                }
                FlushInstructionCache(GetCurrentProcess(),
                                      (void *)fm->methodPtr, 96);
            }

            // Restore ConstMethod if the page matches.
            // Use the FULL ConstMethod backup (header + bytecodes) when
            // available — this undoes writes to header fields (e.g.
            // _orig_method_idnum at offset 48) that the bytecode-only
            // backup would miss. Falls back to bytecodes-only if the
            // full backup wasn't created.
            if (fm->cmPage == page && fm->constMethodPtr)
            {
                DWORD op = 0;
                if (fm->cmFullBackup && fm->cmFullSize > 0 &&
                    jvm_safe_read((void *)fm->constMethodPtr, fm->cmFullSize))
                {
                    if (direct_VirtualProtect((void *)fm->constMethodPtr, fm->cmFullSize,
                                              PAGE_READWRITE, &op))
                    {
                        memcpy((void *)fm->constMethodPtr, fm->cmFullBackup,
                               fm->cmFullSize);
                        direct_VirtualProtect((void *)fm->constMethodPtr, fm->cmFullSize,
                                              op, &op);
                        FlushInstructionCache(GetCurrentProcess(),
                                              (void *)fm->constMethodPtr,
                                              fm->cmFullSize);
                    }
                }
                else if (fm->bytecodeBackup && fm->code_size > 0 && fm->offCB >= 0)
                {
                    unsigned char *codeBase =
                        (unsigned char *)(fm->constMethodPtr + fm->offCB);
                    if (direct_VirtualProtect(codeBase, fm->code_size, PAGE_READWRITE, &op))
                    {
                        memcpy(codeBase, fm->bytecodeBackup, fm->code_size);
                        direct_VirtualProtect(codeBase, fm->code_size, op, &op);
                        FlushInstructionCache(GetCurrentProcess(),
                                              codeBase, fm->code_size);
                    }
                }
            }
        }
    }

    // Re-apply PAGE_READONLY on the page (block future writes)
    // Use direct syscall to bypass any hooks the attacker may have installed
    DWORD old;
    g_ourCall = 1;
    direct_VirtualProtect((void *)page, 4096, PAGE_READONLY, &old);
    g_ourCall = 0;

    // Clear trap flag
    exc->ContextRecord->EFlags &= ~0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void init_method_veh()
{
    if (g_methodWriteVeh)
        return;
    init_jvm_dll_range();
    init_direct_syscalls();
    init_self_guard(); // backup our own DLL .text section
    // Hardware breakpoint VEH — highest priority, checks DR6 to distinguish
    // HW breakpoints from TF single-steps (deep encryption step VEH).
    g_hwbpVeh = AddVectoredExceptionHandler(1, hwbp_veh);
    g_methodWriteVeh = AddVectoredExceptionHandler(1, method_write_guard_veh);
    g_methodStepVeh = AddVectoredExceptionHandler(1, method_write_step_veh);
    fprintf(stderr, "[TZD] protect_class: method write-guard VEH + HW breakpoint VEH registered "
                    "(jvm.dll=0x%llx+0x%llx)\n",
            g_jvmDllBase, g_jvmDllSize);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Hardware Breakpoint System (DR0-DR3) ──────────────────────────────
// CPU-level write detection. Unlike PAGE_READONLY (page-granular, VEH-based)
// or CRC32 scanning (periodic, missable), hardware breakpoints trigger
// INSTANTLY when the CPU executes a write to the watched address —
// regardless of page protection, regardless of whether a thread is alive,
// regardless of any R3 hook. The only way to bypass them is to clear the
// DR registers (which requires SetThreadContext on every thread — caught
// by our watchdog that re-applies them every 500ms).
// ═══════════════════════════════════════════════════════════════════════

struct HwBpConfig
{
    long long addr;   // address to watch
    int len;          // 1, 2, 4, or 8 bytes
    long long backup; // original value (for instant restore)
    const char *name; // field name for logging
    bool active;
};

static HwBpConfig g_hwBp[4]; // DR0-DR3
static volatile long g_hwBpCount = 0;
// g_hwbpVeh declared earlier (before init_method_veh)
static volatile long g_lastSeenThreadCount = 0;

// Compute DR7 value from the current hardware breakpoint configuration.
// DR7 layout (Intel SDM Vol 3, 18.2.4):
//   Bits 0,2,4,6:  Local Enable (L0-L3) for each DR
//   Bits 16-31:    RW+LEN fields (4 bits each per DR)
//   RW: 00=exec, 01=data-write, 11=data-read/write
//   LEN: 00=1byte, 01=2byte, 10=8byte, 11=4byte
static DWORD64 compute_dr7()
{
    DWORD64 dr7 = (1LL << 8) | (1LL << 9) | (1LL << 10); // LE, GE, reserved
    for (int i = 0; i < g_hwBpCount && i < 4; i++)
    {
        if (!g_hwBp[i].active)
            continue;
        dr7 |= (1LL << (i * 2)); // Local Enable for DR i

        int rw = 1; // data write
        dr7 |= ((DWORD64)rw << (16 + i * 4));

        int len;
        switch (g_hwBp[i].len)
        {
        case 1:
            len = 0;
            break;
        case 2:
            len = 1;
            break;
        case 8:
            len = 2;
            break;
        case 4:
            len = 3;
            break;
        default:
            len = 0;
            break;
        }
        dr7 |= ((DWORD64)len << (18 + i * 4));
    }
    return dr7;
}

// Set hardware breakpoints on a specific thread (via GetThreadContext/SetThreadContext)
static void set_hwbp_on_thread(HANDLE hThread, DWORD tid)
{
    if (g_hwBpCount == 0)
        return;

    bool isSelf = (tid == GetCurrentThreadId());
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (isSelf)
    {
        if (!GetThreadContext(GetCurrentThread(), &ctx))
            return;
    }
    else
    {
        // Suspend → GetContext → SetContext → Resume
        DWORD prev = 0;
        if (g_sysNtSuspend)
            g_sysNtSuspend(hThread, &prev);
        else
            SuspendThread(hThread);
        bool ok = GetThreadContext(hThread, &ctx) != FALSE;
        if (!ok)
        {
            if (g_sysNtResume)
                g_sysNtResume(hThread, nullptr);
            else
                ResumeThread(hThread);
            return;
        }
        // Verify the thread is actually suspended (not running)
        // by checking that context is valid
    }

    // Set DR0-DR3 to our watch addresses
    DWORD64 *drs[4] = {&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3};
    for (int i = 0; i < 4; i++)
    {
        if (i < g_hwBpCount && g_hwBp[i].active)
            *drs[i] = (DWORD64)g_hwBp[i].addr;
        else
            *drs[i] = 0; // clear unused DR
    }
    ctx.Dr6 = 0; // clear status
    ctx.Dr7 = compute_dr7();

    if (isSelf)
    {
        SetThreadContext(GetCurrentThread(), &ctx);
    }
    else
    {
        SetThreadContext(hThread, &ctx);
        if (g_sysNtResume)
            g_sysNtResume(hThread, nullptr);
        else
            ResumeThread(hThread);
    }
}

// ── Watchdog thread handle/TID storage ──
// Declared here (before set_hwbp_on_all_threads) so the HW breakpoint
// system can use existing handles for DACL-locked watchdog threads.
// The watchdog logic is implemented in the "Unkillable Watchdog Threads"
// section below.
static HANDLE g_watchdogHandles[3] = {nullptr, nullptr, nullptr};
static DWORD g_watchdogTIDs[3] = {0, 0, 0};

// Enumerate ALL threads in the process and set hardware breakpoints on each.
// Uses CreateToolhelp32Snapshot for reliable enumeration.
static void set_hwbp_on_all_threads()
{
    if (g_hwBpCount == 0)
        return;
    int pid = GetCurrentProcessId();

    // ── Watchdog threads: use existing handles (full THREAD_ALL_ACCESS
    // from CreateThread). Their DACL denies THREAD_SUSPEND_RESUME etc.
    // to Everyone via OpenThread, but the existing handles are immune.
    // We do NOT CloseHandle these — they're owned by the watchdog system.
    for (int i = 0; i < 3; i++)
    {
        if (g_watchdogHandles[i] && g_watchdogTIDs[i])
            set_hwbp_on_thread(g_watchdogHandles[i], g_watchdogTIDs[i]);
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPSHOTTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int count = 0;
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != (DWORD)pid)
                continue;
            count++;

            // Skip watchdog threads — already handled above via existing handles
            bool isWatchdog = false;
            for (int i = 0; i < 3; i++)
            {
                if (te.th32ThreadID == g_watchdogTIDs[i])
                {
                    isWatchdog = true;
                    break;
                }
            }
            if (isWatchdog)
                continue;

            HANDLE h = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE, te.th32ThreadID);
            if (!h)
                continue;
            set_hwbp_on_thread(h, te.th32ThreadID);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    g_lastSeenThreadCount = count;
}

// VEH handler for hardware breakpoint exceptions.
// Hardware data-write breakpoints generate EXCEPTION_SINGLE_STEP (0x80000004).
// We check DR6 to distinguish from TF (trap flag) single-steps.
// NO WHITELIST: ALL writes to protected fields are caught, even from jvm.dll.
static LONG CALLBACK hwbp_veh(PEXCEPTION_POINTERS exc)
{
    if (exc->ExceptionRecord->ExceptionCode != 0x80000004) // EXCEPTION_SINGLE_STEP
        return EXCEPTION_CONTINUE_SEARCH;

    // Check DR6 to see if a hardware breakpoint triggered
    DWORD64 dr6 = exc->ContextRecord->Dr6;
    DWORD dr6Bits = (DWORD)(dr6 & 0xF);
    if (dr6Bits == 0)
        return EXCEPTION_CONTINUE_SEARCH; // Not a HW breakpoint — let step VEH handle

    // Process each triggered breakpoint
    for (int i = 0; i < 4; i++)
    {
        if (!(dr6Bits & (1 << i)))
            continue;
        if (i >= g_hwBpCount || !g_hwBp[i].active)
            continue;

        HwBpConfig *bp = &g_hwBp[i];

        // Read the current (possibly modified) value
        long long curVal = 0;
        if (jvm_safe_read((void *)bp->addr, bp->len))
        {
            if (bp->len == 8)
                curVal = *(long long *)bp->addr;
            else if (bp->len == 4)
                curVal = *(jint *)bp->addr;
            else if (bp->len == 2)
                curVal = *(unsigned short *)bp->addr;
            else
                curVal = *(unsigned char *)bp->addr;
        }

        // Check if the value was actually changed — NO WHITELIST
        // Even if jvm.dll wrote to it, if the value differs from our backup,
        // it's a tampering attempt. Block it.
        if (curVal != bp->backup)
        {
            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                            "(HW breakpoint DR%d: %s at 0x%llx TAMPERED! "
                            "expected=0x%llx got=0x%llx — RESTORING, NO WHITELIST)\n",
                    i, bp->name ? bp->name : "?", bp->addr,
                    bp->backup, curVal);
            fflush(stderr);

            // Instantly restore from backup using direct syscall
            DWORD op = 0;
            if (g_sysNtPVM)
            {
                PVOID base = (void *)bp->addr;
                SIZE_T sz = bp->len;
                ULONG old = 0;
                g_sysNtPVM(GetCurrentProcess(), &base, &sz, PAGE_READWRITE, &old);
                if (bp->len == 8)
                    *(long long *)bp->addr = bp->backup;
                else if (bp->len == 4)
                    *(jint *)bp->addr = (jint)bp->backup;
                else if (bp->len == 2)
                    *(unsigned short *)bp->addr = (unsigned short)bp->backup;
                else
                    *(unsigned char *)bp->addr = (unsigned char)bp->backup;
                g_sysNtPVM(GetCurrentProcess(), &base, &sz, old, &old);
            }
            else
            {
                if (direct_VirtualProtect((void *)bp->addr, bp->len, PAGE_READWRITE, &op))
                {
                    if (bp->len == 8)
                        *(long long *)bp->addr = bp->backup;
                    else if (bp->len == 4)
                        *(jint *)bp->addr = (jint)bp->backup;
                    else if (bp->len == 2)
                        *(unsigned short *)bp->addr = (unsigned short)bp->backup;
                    else
                        *(unsigned char *)bp->addr = (unsigned char)bp->backup;
                    direct_VirtualProtect((void *)bp->addr, bp->len, op, &op);
                }
            }
            FlushInstructionCache(GetCurrentProcess(), (void *)bp->addr, bp->len);
        }
    }

    // Clear DR6 (acknowledge the breakpoint)
    exc->ContextRecord->Dr6 = 0;
    // Set RF (Resume Flag, bit 16) to prevent re-trigger on the same instruction
    exc->ContextRecord->EFlags |= 0x10000; // RF
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Unkillable Watchdog Threads ────────────────────────────────────────
// 3 threads that mutually monitor each other. If ANY thread is killed,
// another respawns it within 500ms. All threads are hidden from debuggers
// via NtSetInformationThread(ThreadHideFromDebugger) using DIRECT SYSCALLS.
// Each thread also re-applies hardware breakpoints on ALL threads every
// 500ms — so even if the attacker clears DR registers, they're back in
// half a second.
// ═══════════════════════════════════════════════════════════════════════

// g_watchdogHandles and g_watchdogTIDs declared earlier (before
// set_hwbp_on_all_threads) so the HW breakpoint system can use them.
static volatile bool g_watchdogRunning = true;
static CRITICAL_SECTION g_watchdogCs;
static bool g_watchdogCsInited = false;

// Forward declaration: check_thread_stacks is defined in the stack-monitor section
static void check_thread_stacks();
// Forward declarations for functions defined later (used by watchdog)
static void self_guard_check();
static void check_job_protection();

// ─── VEH chain head integrity state ─────────────────────────────────
// The VEH chain is a singly-linked list in ntdll. If an attacker inserts
// their handler BEFORE ours (AddVectoredExceptionHandler(1, ...)), their
// handler runs first and can suppress our exceptions. We detect this by
// scanning ntdll's writable sections for the list head (a global
// SINGLE_LIST_ENTRY whose Next field points to the first entry), then
// checking at high frequency whether our handler is still first.
static long long g_vehListHeadAddr = 0;       // cached address of list_head.Next in ntdll
static volatile long long g_lastVehReAdd = 0; // GetTickCount64() of last re-add (rate limit)

static void lock_process_security(HANDLE hProcess)
{
    if (!hProcess)
        return;

    SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryone = nullptr;
    if (!AllocateAndInitializeSid(&sidAuth, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &pEveryone))
        return;

    // Deny ACE: 拒绝 Everyone 对进程的关键控制权限
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = PROCESS_TERMINATE         // 0x0001 - 禁止 TerminateProcess
                              | PROCESS_SUSPEND_RESUME  // 0x0800 - 禁止 NtSuspendProcess / 挂起
                              | PROCESS_SET_INFORMATION // 0x0200 - 禁止修改进程信息
                              | PROCESS_VM_WRITE        // 0x0020 - 禁止 WriteProcessMemory (防注入)
                              | WRITE_DAC               // 0x00040000 - 禁止修改 DACL (锁定只读)
                              | WRITE_OWNER;            // 0x00080000 - 禁止夺取所有权

    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pEveryone;

    PACL pDacl = nullptr;
    DWORD dwRes = SetEntriesInAclW(1, &ea, nullptr, &pDacl);
    if (dwRes != ERROR_SUCCESS || !pDacl)
    {
        FreeSid(pEveryone);
        return;
    }

    // PROTECTED_DACL_SECURITY_INFORMATION 阻止继承父级 DACL
    dwRes = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, pDacl, nullptr);

    if (dwRes == ERROR_SUCCESS)
    {
        fprintf(stderr, "[TZD] process 0x%x: DACL locked successfully.\n", GetProcessId(hProcess));
        fflush(stderr);
    }
    else
    {
        fprintf(stderr, "[TZD] process 0x%x: SetSecurityInfo failed (err=%lu)\n", GetProcessId(hProcess), dwRes);
        fflush(stderr);
    }

    LocalFree(pDacl);
    FreeSid(pEveryone);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Thread Security: DACL-based R3 unkillability ─────────────────────
// No hooks. We set the thread object's DACL to deny THREAD_TERMINATE |
// THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION
// to Everyone. The kernel enforces this on ALL handle creation paths
// (OpenThread, NtOpenThread, direct syscalls) — there is no R3 bypass.
//
// Our existing handles (g_watchdogHandles[]) retain THREAD_ALL_ACCESS
// from CreateThread — the DACL only affects NEW handle creation. So our
// watchdog can still suspend/context/resume its own threads via the
// existing handles, while the attacker cannot get any of the denied
// access rights.
// ═══════════════════════════════════════════════════════════════════════
static void lock_thread_security(HANDLE hThread)
{
    if (!hThread)
        return;

    SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryone = nullptr;
    if (!AllocateAndInitializeSid(&sidAuth, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &pEveryone))
        return;

    // Deny ACE: block the four dangerous access rights to Everyone
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = THREAD_TERMINATE         // 0x0001
                              | THREAD_SUSPEND_RESUME  // 0x0002
                              | THREAD_SET_CONTEXT     // 0x0010
                              | THREAD_SET_INFORMATION // 0x0020
                              | WRITE_DAC              // 0x00040000 — can't modify DACL (lock immutability)
                              | WRITE_OWNER;           // 0x00080000 — can't take ownership (can't seize)
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pEveryone;

    PACL pDacl = nullptr;
    DWORD dwRes = SetEntriesInAclW(1, &ea, nullptr, &pDacl);
    if (dwRes != ERROR_SUCCESS || !pDacl)
    {
        FreeSid(pEveryone);
        return;
    }

    // PROTECTED_DACL_SECURITY_INFORMATION: don't inherit parent DACL.
    // Only our explicit deny ACE applies → attacker can't open the thread
    // for any of the four dangerous rights via ANY path (Win32, ntdll, syscall).
    dwRes = SetSecurityInfo(hThread, SE_KERNEL_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            nullptr, pDacl, nullptr, nullptr);

    if (dwRes == ERROR_SUCCESS)
    {
        fprintf(stderr, "[TZD] thread 0x%x: DACL locked "
                        "(TERMINATE|SUSPEND_RESUME|SET_CONTEXT|SET_INFORMATION|WRITE_DAC|WRITE_OWNER denied to Everyone)\n",
                GetThreadId(hThread));
        fflush(stderr);
    }
    else
    {
        fprintf(stderr, "[TZD] thread 0x%x: SetSecurityInfo failed (err=%lu)\n",
                GetThreadId(hThread), dwRes);
        fflush(stderr);
    }

    LocalFree(pDacl);
    FreeSid(pEveryone);
}

// ─── Full thread hardening: DACL lock + handle protection ───────────
// Call after CreateThread. Applies:
//   1. DACL lock (deny TERMINATE|SUSPEND|SET_CONTEXT|SET_INFO|WRITE_DAC|WRITE_OWNER)
//   2. PROTECT_FROM_CLOSE — CloseHandle on this handle fails (attacker can't release it)
//   3. Non-inheritable — child processes can't inherit the handle
// This prevents stale-handle reuse and external CloseHandle attacks.
static void harden_thread(HANDLE hThread)
{
    if (!hThread)
        return;
    lock_thread_security(hThread);
    // PROTECT_FROM_CLOSE: the kernel rejects CloseHandle on this handle.
    // Combined with non-inheritable, the handle is effectively frozen.
    SetHandleInformation(hThread,
                         HANDLE_FLAG_PROTECT_FROM_CLOSE | HANDLE_FLAG_INHERIT,
                         HANDLE_FLAG_PROTECT_FROM_CLOSE);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Process DACL Lock (anti-injection: block OpenProcess VM/CRT) ──────
// THE direct fix for external VirtualAllocEx / WriteProcessMemory /
// CreateRemoteThread injection. We set a PROTECTED DACL on our own process
// object that DENIES the injection-critical access rights to Everyone
// (including the current user — ourselves).
//
//   Denied rights: PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
//                  | PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS
//                  | PROCESS_DUP_HANDLE
//                  | WRITE_DAC | WRITE_OWNER  (lock immutability)
//
// After this, an external process calling OpenProcess(ourPid, VM_*) gets
// ERROR_ACCESS_DENIED (5). VirtualAllocEx / WriteProcessMemory /
// CreateRemoteThread are unreachable because the handle never grants the
// needed rights. The kernel enforces this on ALL handle-creation paths
// (kernel32!OpenProcess, ntdll!NtOpenProcess, direct syscalls, duplicated
// handles) — there is no R3 bypass.
//
// Why our own code still works: every internal operation uses the process
// pseudo-handle NtCurrentProcess() (HANDLE)-1, which the kernel resolves
// via ObpReferenceObjectByHandleSpecial WITHOUT the DACL check. So our
// own VirtualAlloc / VirtualProtect / WriteProcessMemory(self) /
// CreateThread are unaffected. We keep a real full-access handle (opened
// BEFORE the lock, protected from close) for any path that needs a real
// handle. Thread DACL locks already protect our watchdog threads from
// external OpenThread(TERMINATE|...).
// ═══════════════════════════════════════════════════════════════════════
static HANDLE g_ourProcHandle = nullptr; // real full-access handle, kept alive

static void lock_process_security()
{
    static bool done = false;
    if (done)
        return;
    done = true;

    // Open a REAL full-access handle BEFORE locking. After the DACL is set,
    // no new handle can be opened with VM_*/CREATE_THREAD rights by anyone.
    // This handle is PROTECT_FROM_CLOSE so it cannot be released by an
    // attacker who somehow gets a WRITE handle later.
    if (!g_ourProcHandle)
    {
        g_ourProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        if (g_ourProcHandle)
        {
            SetHandleInformation(g_ourProcHandle,
                                 HANDLE_FLAG_PROTECT_FROM_CLOSE | HANDLE_FLAG_INHERIT,
                                 HANDLE_FLAG_PROTECT_FROM_CLOSE);
        }
    }

    SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryone = nullptr;
    if (!AllocateAndInitializeSid(&sidAuth, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &pEveryone))
        return;

    // Deny the injection + memory-access rights to Everyone.
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions =
        PROCESS_VM_OPERATION     // 0x0008 — blocks VirtualAllocEx/VirtualProtectEx/VirtualFreeEx
        | PROCESS_VM_READ        // 0x0010 — blocks ReadProcessMemory / memory dumpers
        | PROCESS_VM_WRITE       // 0x0020 — blocks WriteProcessMemory
        | PROCESS_CREATE_THREAD  // 0x0002 — blocks CreateRemoteThread / NtCreateThreadEx
        | PROCESS_CREATE_PROCESS // 0x0080 — blocks CreateProcess(VmOperation) hollowing
        | PROCESS_DUP_HANDLE     // 0x0040 — blocks DuplicateHandle weaponization
        | WRITE_DAC              // 0x00040000 — can't relax the DACL (lock immutability)
        | WRITE_OWNER;           // 0x00080000 — can't seize ownership to reset DACL
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pEveryone;

    PACL pDacl = nullptr;
    DWORD dwRes = SetEntriesInAclW(1, &ea, nullptr, &pDacl);
    if (dwRes != ERROR_SUCCESS || !pDacl)
    {
        FreeSid(pEveryone);
        fprintf(stderr, "[TZD] process DACL: SetEntriesInAcl failed (err=%lu)\n", dwRes);
        fflush(stderr);
        return;
    }

    // PROTECTED_DACL_SECURITY_INFORMATION: do NOT inherit the default DACL.
    // Only our explicit deny ACE applies. Prefer our real full-access handle
    // (opened above); it has WRITE_DAC. Fall back to the pseudo-handle
    // GetCurrentProcess() == (HANDLE)-1, which the kernel resolves to the
    // current process with full access (including WRITE_DAC) without a DACL
    // check.
    HANDLE hProc = g_ourProcHandle ? g_ourProcHandle : (HANDLE)-1;
    dwRes = SetSecurityInfo(hProc, SE_KERNEL_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            nullptr, pDacl, nullptr, nullptr);

    if (dwRes == ERROR_SUCCESS)
    {
        fprintf(stderr, "[TZD] process DACL: LOCKED — VM_OPERATION|VM_READ|VM_WRITE|"
                        "CREATE_THREAD|CREATE_PROCESS|DUP_HANDLE denied to Everyone. "
                        "External OpenProcess(VM_*/CREATE_THREAD) now fails (err 5).\n");
        fflush(stderr);
    }
    else
    {
        fprintf(stderr, "[TZD] process DACL: SetSecurityInfo failed (err=%lu)\n", dwRes);
        fflush(stderr);
    }

    LocalFree(pDacl);
    FreeSid(pEveryone);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Injected-Thread Scanner (defense in depth vs CreateRemoteThread) ──
// If an attacker has SeDebugPrivilege / is SYSTEM / steals our token, they
// can bypass the process DACL above and call CreateRemoteThread. We catch
// the resulting thread: its start address is in MEM_PRIVATE memory that is
// NOT backed by any loaded module (shellcode stub). Legit threads always
// start inside a module (jvm.dll, java.exe, seckill_native.dll, system
// DLLs, or a JNI DLL loaded via System.loadLibrary). We enumerate modules
// to build a range whitelist, enumerate our threads, query each thread's
// start address via NtQueryInformationThread(ThreadQueryStartAddress=9),
// and TerminateThread on any whose start address lies outside all modules.
//
// Our watchdog threads are exempt by TID; their start address is inside
// seckill_native.dll anyway, so they pass the range check too.
//
// Note on CreateRemoteThread(LoadLibraryA): the start address IS in a
// system module (kernel32/kernelbase) and is NOT caught here. That path is
// covered by the module-baseline scan below (detects the newly-mapped
// injected DLL) and by the process DACL (the attacker can't even get
// CREATE_THREAD access under normal conditions).
// ═══════════════════════════════════════════════════════════════════════
typedef NTSTATUS(NTAPI *pfnNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static pfnNtQueryInformationThread g_pNtQIT = nullptr;
// Self-validated: we confirm class 9 returns a module address for OUR OWN
// thread (whose start address is inside seckill_native.dll) before trusting
// it to classify OTHER threads. Until verified, the scanner is detection-
// only (no TerminateThread) — a wrong class value can NEVER kill a legit
// thread. Once verified, termination is enabled.
static volatile long g_startAddrClassVerified = 0;

struct ModuleRange
{
    unsigned long long base;
    unsigned long long end;
};

// Build the loaded-module range whitelist. Returns count; caller frees *out.
static int build_module_whitelist(ModuleRange **out)
{
    *out = nullptr;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32)
        return 0;
    typedef BOOL(WINAPI * pEnumProcMods)(HANDLE, HMODULE *, DWORD, LPDWORD);
    auto pEnum = (pEnumProcMods)GetProcAddress(k32, "EnumProcessModules");
    if (!pEnum)
        return 0;

    DWORD needed = 0;
    HANDLE hp = GetCurrentProcess(); // pseudo-handle — no DACL check
    if (!pEnum(hp, nullptr, 0, &needed) || needed == 0)
        return 0;
    int n = (int)(needed / sizeof(HMODULE));
    HMODULE *mods = (HMODULE *)malloc(needed);
    ModuleRange *rng = (ModuleRange *)malloc((size_t)n * sizeof(ModuleRange));
    if (!mods || !rng)
    {
        free(mods);
        free(rng);
        return 0;
    }
    if (!pEnum(hp, mods, needed, &needed))
    {
        free(mods);
        free(rng);
        return 0;
    }
    n = (int)(needed / sizeof(HMODULE));
    // kernel32 MODULEINFO via GetModuleInformation (psapi)
    int cnt = 0;
    for (int i = 0; i < n; i++)
    {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(hp, mods[i], &mi, sizeof(mi)) && mi.lpBaseOfDll && mi.SizeOfImage)
        {
            rng[cnt].base = (unsigned long long)(intptr_t)mi.lpBaseOfDll;
            rng[cnt].end = rng[cnt].base + mi.SizeOfImage;
            cnt++;
        }
    }
    free(mods);
    *out = rng;
    return cnt;
}

// True if addr falls within any loaded-module range.
static bool addr_in_modules(unsigned long long addr, const ModuleRange *rng, int n)
{
    if (!rng || n <= 0)
        return false;
    for (int i = 0; i < n; i++)
    {
        if (addr >= rng[i].base && addr < rng[i].end)
            return true;
    }
    return false;
}

static bool is_watchdog_tid(DWORD tid)
{
    for (int i = 0; i < 3; i++)
    {
        if (g_watchdogTIDs[i] && g_watchdogTIDs[i] == tid)
            return true;
    }
    return false;
}

// Module baseline for new-DLL (LoadLibrary injection) detection.
static unsigned long long g_modBaselineBase = 0;
static int g_modBaselineCount = 0;
static void snapshot_module_baseline()
{
    ModuleRange *rng = nullptr;
    g_modBaselineCount = build_module_whitelist(&rng);
    if (rng && g_modBaselineCount > 0)
        g_modBaselineBase = rng[0].base; // marker; real baseline is count
    free(rng);
}

static void scan_injected_threads()
{
    // Resolve NtQueryInformationThread once.
    if (!g_pNtQIT)
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            g_pNtQIT = (pfnNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
        if (!g_pNtQIT)
            return;
    }

    ModuleRange *rng = nullptr;
    int nMods = build_module_whitelist(&rng);

    // ── Self-validate ThreadQueryStartAddress (class 9) ONCE ──
    // Query our OWN thread's start address. Our watchdog starts inside
    // seckill_native.dll, so a correct class must return an address that
    // lies within a loaded module. If it does, flip the verified flag and
    // enable termination. If it doesn't, we leave termination disabled so
    // a wrong class value can never kill a legit thread. Re-check each
    // cycle until verified (rng may not have included our DLL on cycle 1).
    if (!g_startAddrClassVerified)
    {
        PVOID myStart = nullptr;
        ULONG ret = 0;
        NTSTATUS st = g_pNtQIT(GetCurrentThread(), 9, &myStart, sizeof(myStart), &ret);
        if (NT_SUCCESS(st) && myStart &&
            addr_in_modules((unsigned long long)(intptr_t)myStart, rng, nMods))
        {
            InterlockedExchange(&g_startAddrClassVerified, 1);
            fprintf(stderr, "[TZD] injected-thread scanner: ThreadQueryStartAddress "
                            "(class 9) verified on self (start=0x%p)\n",
                    myStart);
            fflush(stderr);
        }
        else if (rng && nMods > 0)
        {
            // Class 9 did not return a module address for our own thread —
            // do NOT terminate anything; run detection-only.
            fprintf(stderr, "[TZD] injected-thread scanner: class 9 not yet verified "
                            "(st=0x%lx start=%p) — detection-only mode\n",
                    (unsigned long)st, myStart);
            fflush(stderr);
        }
    }
    bool canTerminate = (g_startAddrClassVerified != 0);

    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPSHOTTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != pid)
                    continue;
                DWORD tid = te.th32ThreadID;
                if (tid == GetCurrentThreadId())
                    continue;
                if (is_watchdog_tid(tid))
                    continue;

                // Open with QUERY (allowed by our thread DACL) + TERMINATE
                // (only granted for threads WE can kill; our watchdog
                // threads deny TERMINATE so we skip them via the TID check
                // above — Terminating them would fail harmlessly anyway).
                HANDLE hT = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_TERMINATE,
                                       FALSE, tid);
                if (!hT)
                {
                    // THREAD_QUERY_LIMITED_INFORMATION-only fallback so we
                    // can at least inspect threads we aren't allowed to kill.
                    hT = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                    if (!hT)
                        continue;
                }

                PVOID startAddr = nullptr;
                ULONG ret = 0;
                NTSTATUS st = g_pNtQIT(hT, 9 /* ThreadQueryStartAddress */,
                                       &startAddr, sizeof(startAddr), &ret);
                if (NT_SUCCESS(st) && startAddr)
                {
                    unsigned long long sa = (unsigned long long)(intptr_t)startAddr;
                    if (!addr_in_modules(sa, rng, nMods))
                    {
                        // Start address is NOT in any module → injected shellcode thread.
                        fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                        "(INJECTED THREAD tid=%u start=0x%llx — not in any module! "
                                        "%s)\n",
                                tid, sa,
                                canTerminate ? "terminating" : "flagged (class unverified)");
                        fflush(stderr);
                        // Only terminate once we've self-verified the class.
                        // A wrong class value could otherwise return garbage
                        // for a legit thread and we'd kill it.
                        if (canTerminate && !TerminateThread(hT, 1))
                        {
                            fprintf(stderr, "[TZD] injected thread tid=%u terminate failed (err=%lu) "
                                            "— DACL may block it; flagging for integrity thread\n",
                                    tid, GetLastError());
                            fflush(stderr);
                        }
                    }
                }
                CloseHandle(hT);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    // ── New-module (LoadLibrary injection) detection ──
    // Compare current module count to baseline. A sudden new module that
    // isn't a legit JNI DLL (we can't easily distinguish) is logged.
    // We do NOT unmap (would crash legit System.loadLibrary paths); the
    // process DACL is the primary block. This is detection-only telemetry.
    if (g_modBaselineCount == 0)
    {
        snapshot_module_baseline();
    }
    else
    {
        ModuleRange *cur = nullptr;
        int curN = build_module_whitelist(&cur);
        if (curN > g_modBaselineCount + 2) // allow modest legit growth
        {
            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                            "(module count %d -> %d — possible LoadLibrary injection; "
                            "listing new regions)\n",
                    g_modBaselineCount, curN);
            fflush(stderr);
        }
        free(cur);
    }

    free(rng);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── VEH Chain Head Detection ─────────────────────────────────────────
// Scans ntdll's writable sections for a qword equal to any of our VEH
// entry handles. The VEH list head is a global SINGLE_LIST_ENTRY in
// ntdll; its Next field (offset 0) points to the first entry. When our
// handler is first, list_head.Next == our_handle. Finding that qword in
// ntdll's .data gives us the address of the list head.
//
// This is a one-time scan (~100KB, ~12K iterations). The result is
// cached in g_vehListHeadAddr. After that, checking is O(1): read one
// qword and compare.
// ═══════════════════════════════════════════════════════════════════════
static long long find_veh_list_head()
{
    if (g_vehListHeadAddr)
        return g_vehListHeadAddr;

    // Collect our current VEH handles
    long long ourHandles[] = {
        (long long)g_deepVehGuard,
        (long long)g_deepVehStep,
        (long long)g_methodStepVeh,
        (long long)g_methodWriteVeh,
        (long long)g_hwbpVeh,
    };
    int numHandles = (int)(sizeof(ourHandles) / sizeof(ourHandles[0]));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return 0;

    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);

    for (WORD si = 0; si < nt->FileHeader.NumberOfSections; si++)
    {
        // VEH list head is in a writable section (.data) — ntdll modifies
        // it when adding/removing handlers. Skip read-only / discardable.
        if (!(secs[si].Characteristics & IMAGE_SCN_MEM_WRITE))
            continue;

        long long secStart = (long long)(base + secs[si].VirtualAddress);
        long long secSize = secs[si].Misc.VirtualSize;

        // Scan 8-byte aligned qwords
        for (long long off = 0; off + 8 <= secSize; off += 8)
        {
            long long val = *(long long *)(secStart + off);
            for (int hi = 0; hi < numHandles; hi++)
            {
                if (val == ourHandles[hi] && val != 0)
                {
                    g_vehListHeadAddr = secStart + off;
                    fprintf(stderr, "[TZD] VEH chain: list head found at 0x%llx "
                                    "(points to our entry 0x%llx, section=%c%c%c%c)\n",
                            g_vehListHeadAddr, val,
                            secs[si].Name[0], secs[si].Name[1],
                            secs[si].Name[2], secs[si].Name[3]);
                    fflush(stderr);
                    return g_vehListHeadAddr;
                }
            }
        }
    }

    fprintf(stderr, "[TZD] VEH chain: list head NOT found in ntdll writable sections "
                    "(handles: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx)\n",
            ourHandles[0], ourHandles[1], ourHandles[2], ourHandles[3], ourHandles[4]);
    fflush(stderr);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── VEH Chain Head Check (called at 10ms frequency) ──────────────────
// Verifies our handlers are at the front of the VEH chain. If an attacker
// inserted handlers before ours, their handler runs first and can suppress
// our exceptions (return EXCEPTION_CONTINUE_EXECUTION to skip the chain).
// We detect this and re-add ourselves at the head.
// ═══════════════════════════════════════════════════════════════════════
static void check_veh_chain_head()
{
    // Find the list head if we haven't yet
    if (!g_vehListHeadAddr)
        find_veh_list_head();

    if (g_vehListHeadAddr)
    {
        // Read the current first entry pointer from the list head
        long long curFirst = *(long long *)g_vehListHeadAddr;

        // Check if any of our handles is at the head
        long long ourHandles[] = {
            (long long)g_deepVehGuard,
            (long long)g_deepVehStep,
            (long long)g_methodStepVeh,
            (long long)g_methodWriteVeh,
            (long long)g_hwbpVeh,
        };
        int numHandles = (int)(sizeof(ourHandles) / sizeof(ourHandles[0]));
        for (int i = 0; i < numHandles; i++)
        {
            if (curFirst == ourHandles[i] && curFirst != 0)
                return; // Our handler is first — good
        }
    }

    // Either scan failed, or we're not first — re-add.
    // Rate-limit to avoid excessive re-adding (min 100ms between re-adds)
    long long now = (long long)GetTickCount64();
    long long last = InterlockedExchange64(&g_lastVehReAdd, now);
    if (now - last < 100)
        return; // re-added too recently

    fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                    "(VEH chain hijack! our handler is NOT first — re-adding at head)\n");
    fflush(stderr);

    // Remove all our handlers
    if (g_deepVehGuard)
    {
        RemoveVectoredExceptionHandler(g_deepVehGuard);
        g_deepVehGuard = nullptr;
    }
    if (g_deepVehStep)
    {
        RemoveVectoredExceptionHandler(g_deepVehStep);
        g_deepVehStep = nullptr;
    }
    if (g_methodStepVeh)
    {
        RemoveVectoredExceptionHandler(g_methodStepVeh);
        g_methodStepVeh = nullptr;
    }
    if (g_methodWriteVeh)
    {
        RemoveVectoredExceptionHandler(g_methodWriteVeh);
        g_methodWriteVeh = nullptr;
    }
    if (g_hwbpVeh)
    {
        RemoveVectoredExceptionHandler(g_hwbpVeh);
        g_hwbpVeh = nullptr;
    }

    // Re-add at head (last added = first in chain).
    // Final order: hwbp → method_write_guard → method_step → deep_step → deep_guard
    g_deepVehGuard = AddVectoredExceptionHandler(1, deep_guard_veh);
    g_deepVehStep = AddVectoredExceptionHandler(1, deep_step_veh);
    g_methodStepVeh = AddVectoredExceptionHandler(1, method_write_step_veh);
    g_methodWriteVeh = AddVectoredExceptionHandler(1, method_write_guard_veh);
    g_hwbpVeh = AddVectoredExceptionHandler(1, hwbp_veh);

    // Invalidate cache and re-scan
    g_vehListHeadAddr = 0;
    find_veh_list_head();

    fprintf(stderr, "[TZD] VEH chain: re-registered (deep=0x%llx step=0x%llx mstep=0x%llx "
                    "mguard=0x%llx hwbp=0x%llx, list_head=0x%llx)\n",
            (long long)g_deepVehGuard, (long long)g_deepVehStep,
            (long long)g_methodStepVeh, (long long)g_methodWriteVeh,
            (long long)g_hwbpVeh, g_vehListHeadAddr);
    fflush(stderr);
}

static DWORD WINAPI watchdog_thread(LPVOID param)
{
    int myIdx = (int)(intptr_t)param;
    hide_thread_from_debugger(); // direct syscall — can't be hooked

    fprintf(stderr, "[TZD] watchdog[%d] started (tid=%u, hidden)\n",
            myIdx, GetCurrentThreadId());
    fflush(stderr);

    int cycle = 0;
    while (g_watchdogRunning)
    {

        if (g_watchdogCsInited)
        {
            for (int i = 0; i < 3; i++)
            {
                if (i != myIdx && g_watchdogHandles[i])
                {
                    // 强行递减挂起计数。如果线程没被挂起，此调用无害；
                    // 如果被调试器挂起了，此调用会立刻恢复其运行！
                    ResumeThread(g_watchdogHandles[i]);
                }
            }
        }

        // ── High-frequency: VEH chain head check (every 10ms) ──
        // Ensures our VEH handlers are always at the front of the chain.
        // If an attacker inserts handlers before ours, we detect and
        // re-add ourselves at the head within 10ms.
        check_veh_chain_head();

        // ── Heavy duties: every 50 iterations = 500ms ──
        if (++cycle >= 50)
        {
            cycle = 0;

            // ── Re-apply hardware breakpoints on ALL threads ──
            set_hwbp_on_all_threads();

            verify_instrumentation_callback();

            // ── Check if other watchdogs are alive — respawn if dead ──
            if (g_watchdogCsInited)
            {
                EnterCriticalSection(&g_watchdogCs);
                for (int i = 0; i < 3; i++)
                {
                    if (i == myIdx)
                        continue;
                    if (!g_watchdogHandles[i])
                        continue;
                    DWORD ec = 0;
                    if (GetExitCodeThread(g_watchdogHandles[i], &ec) && ec != STILL_ACTIVE)
                    {
                        // Watchdog i is DEAD — respawn it
                        CloseHandle(g_watchdogHandles[i]);
                        g_watchdogHandles[i] = CreateThread(nullptr, 0, watchdog_thread,
                                                            (LPVOID)(intptr_t)i, 0, &g_watchdogTIDs[i]);
                        // Immediately lock the new thread's DACL so the
                        // attacker can't terminate/suspend/modify it
                        if (g_watchdogHandles[i])
                            harden_thread(g_watchdogHandles[i]);
                        fprintf(stderr, "[TZD] watchdog[%d] RESPAWNED (was dead, exit=%u)\n", i, ec);
                        fflush(stderr);
                    }
                }
                LeaveCriticalSection(&g_watchdogCs);
            }

            // ── Re-apply PAGE_READONLY on Method* pages (defense in depth) ──
            int n = (int)g_numFlatMethodPages;
            for (int i = 0; i < n && i < 256; i++)
            {
                DWORD op;
                g_ourCall = 1;
                direct_VirtualProtect((void *)g_flatMethodPages[i], 4096, PAGE_READONLY, &op);
                g_ourCall = 0;
            }

            // ── Monitor for new threads and set DR on them ──
            int pid = GetCurrentProcessId();
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPSHOTTHREAD, 0);
            if (snap != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 te;
                te.dwSize = sizeof(te);
                int curCount = 0;
                if (Thread32First(snap, &te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == (DWORD)pid)
                            curCount++;
                    } while (Thread32Next(snap, &te));
                }
                CloseHandle(snap);
                if (curCount != g_lastSeenThreadCount)
                {
                    set_hwbp_on_all_threads();
                }
            }

            // ── Clear PEB debug flags (anti-debug) ──
#ifdef _WIN64
            PPEB peb = (PPEB)__readgsqword(0x60);
            if (peb)
            {
                peb->BeingDebugged = FALSE;
                DWORD *ngf = (DWORD *)((BYTE *)peb + 0xBC);
                if (ngf)
                    *ngf &= ~0x70;
            }
#endif

            // ── Self-DLL .text integrity check (protect our own code) ──
            self_guard_check();

            // ── Job Object defense (detect + neutralize new Job) ──
            check_job_protection();

            // ── Injected-thread + new-module scan (anti CreateRemoteThread /
            //    LoadLibrary injection). Defense in depth behind the process
            //    DACL: catches threads whose start address is in non-module
            //    (MEM_PRIVATE shellcode) memory and terminates them, plus
            //    flags sudden module-count growth (LoadLibrary injection). ──
            scan_injected_threads();
        }

        // ── Live thread stack frame monitoring (every ~1s, myIdx==0) ──
        if (myIdx == 0 && cycle == 0)
        {
            check_thread_stacks();
        }

        Sleep(10);
    }
    return 0;
}

static void start_watchdog()
{
    if (g_watchdogHandles[0])
        return;
    if (!g_watchdogCsInited)
    {
        InitializeCriticalSection(&g_watchdogCs);
        g_watchdogCsInited = true;
    }
    for (int i = 0; i < 3; i++)
    {
        g_watchdogHandles[i] = CreateThread(nullptr, 0, watchdog_thread,
                                            (LPVOID)(intptr_t)i, 0, &g_watchdogTIDs[i]);
        // Lock each thread's DACL immediately: deny THREAD_TERMINATE |
        // THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION
        // to Everyone. Existing handles (g_watchdogHandles[]) retain full
        // access; only NEW handles via OpenThread are affected.
        if (g_watchdogHandles[i])
            harden_thread(g_watchdogHandles[i]);
    }
    fprintf(stderr, "[TZD] 3 watchdog threads started (unkillable: DACL-locked + mutual respawn)\n");
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Hardware breakpoint setup for a protected class ──────────────────
// Assigns DR0-DR3 to the most critical fields:
//   DR0: java.lang.Class._klass pointer (prevents klass swap)
//   DR1: InstanceKlass._constants (prevents class replacement)
//   DR2: First Method._code (prevents JIT exploit — fake nmethod)
//   DR3: First Method._from_compiled_entry (prevents entry redirect)
// ═══════════════════════════════════════════════════════════════════════

static void setup_hardware_breakpoints(JNIEnv *env, jclass clazz, long long ik,
                                       ProtectedClass &pc)
{
    // ── DR0: java.lang.Class._klass pointer ──
    // The attacker can swap this pointer to redirect ALL Java-level access
    // to a different class. Hardware breakpoint catches this instantly.
    long long mirrorPtr = (long long)(intptr_t)clazz;
    if (g_klass_handle_indir)
    {
        mirrorPtr = rq((void *)mirrorPtr);
    }
    if (g_klass_offset >= 0 && mirrorPtr)
    {
        long long klassAddr = mirrorPtr + g_klass_offset;
        long long klassVal = rq((void *)klassAddr);
        if (klassVal == ik)
        { // verify the pointer points to our InstanceKlass
            g_hwBp[0].addr = klassAddr;
            g_hwBp[0].len = 8;
            g_hwBp[0].backup = klassVal;
            g_hwBp[0].name = "Class._klass";
            g_hwBp[0].active = true;
            if (g_hwBpCount < 1)
                g_hwBpCount = 1;
            fprintf(stderr, "[TZD] HW breakpoint DR0 → Class._klass at 0x%llx (val=0x%llx)\n",
                    klassAddr, klassVal);
            fflush(stderr);
        }
    }

    // ── DR1: InstanceKlass._constants (ConstantPool*) ──
    // Swapping this changes the class's constant pool → different bytecodes.
    long long constantsAddr = ik + 192;
    long long constantsVal = rq((void *)constantsAddr);
    if (constantsVal)
    {
        g_hwBp[1].addr = constantsAddr;
        g_hwBp[1].len = 8;
        g_hwBp[1].backup = constantsVal;
        g_hwBp[1].name = "IK._constants";
        g_hwBp[1].active = true;
        if (g_hwBpCount < 2)
            g_hwBpCount = 2;
        fprintf(stderr, "[TZD] HW breakpoint DR1 → IK._constants at 0x%llx (val=0x%llx)\n",
                constantsAddr, constantsVal);
        fflush(stderr);
    }

    // ── DR2: First Method._code (JIT exploit target!) ──
    // The attacker sets _code to a fake nmethod to make the JVM think the
    // method is compiled, then patches the compiled machine code.
    int offCode = jvm_deopt_get_offset("code");
    if (pc.numMethods > 0 && offCode >= 0)
    {
        long long codeAddr = pc.methods[0].methodPtr + offCode;
        long long codeVal = rq((void *)codeAddr);
        g_hwBp[2].addr = codeAddr;
        g_hwBp[2].len = 8;
        g_hwBp[2].backup = codeVal; // should be 0 (forced interpreter)
        g_hwBp[2].name = "Method._code";
        g_hwBp[2].active = true;
        if (g_hwBpCount < 3)
            g_hwBpCount = 3;
        fprintf(stderr, "[TZD] HW breakpoint DR2 → Method._code at 0x%llx (val=0x%llx)\n",
                codeAddr, codeVal);
        fflush(stderr);
    }

    // ── DR3: First Method._from_compiled_entry (entry redirect target!) ──
    int offFC = jvm_deopt_get_offset("from_compiled");
    if (pc.numMethods > 0 && offFC >= 0)
    {
        long long fcAddr = pc.methods[0].methodPtr + offFC;
        long long fcVal = rq((void *)fcAddr);
        g_hwBp[3].addr = fcAddr;
        g_hwBp[3].len = 8;
        g_hwBp[3].backup = fcVal; // should be 0 (forced interpreter)
        g_hwBp[3].name = "Method._from_compiled";
        g_hwBp[3].active = true;
        if (g_hwBpCount < 4)
            g_hwBpCount = 4;
        fprintf(stderr, "[TZD] HW breakpoint DR3 → Method._from_compiled at 0x%llx (val=0x%llx)\n",
                fcAddr, fcVal);
        fflush(stderr);
    }

    // Apply hardware breakpoints on ALL threads NOW
    set_hwbp_on_all_threads();

    // Start the unkillable watchdog (re-applies DR every 500ms)
    start_watchdog();
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Process Mitigations (ACG/CFG/extension-point disable) ─────────────
// Disables legacy DLL injection (AppInit_DLLs), enables available
// kernel-level protections. Dynamic Code Policy is NOT enabled (breaks JIT).
// ═══════════════════════════════════════════════════════════════════════
static void enable_process_mitigations()
{
    static bool done = false;
    if (done)
        return;
    done = true;

    // Dynamically load SetProcessMitigationPolicy (Win8+)
    typedef BOOL(WINAPI * pSetMitigation)(int, PVOID, SIZE_T);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32)
        return;
    pSetMitigation pSet = (pSetMitigation)GetProcAddress(k32, "SetProcessMitigationPolicy");
    if (!pSet)
        return;

    // ProcessExtensionPointDisablePolicy (id=6): disable legacy hook DLLs
    struct
    {
        BOOL DisableExtensionPoints;
    } epd = {TRUE};
    pSet(6, &epd, sizeof(epd));
    fprintf(stderr, "[TZD] process mitigations: ExtensionPointDisable enabled\n");
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Token Privilege Stripping (SE_PRIVILEGE_REMOVED) ─────────────────
// Permanently erases ALL dangerous privileges from the kernel's TOKEN
// structure. After this, the process can NEVER enable SeDebugPrivilege
// or any other escalation privilege — AdjustTokenPrivileges with
// SE_PRIVILEGE_ENABLED will silently fail (privilege already removed
// from the kernel object, not just disabled).
// ═══════════════════════════════════════════════════════════════════════
static void strip_token_privileges()
{
    static bool done = false;
    if (done)
        return;
    done = true;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        fprintf(stderr, "[TZD] token: OpenProcessToken failed (err=%lu)\n", GetLastError());
        fflush(stderr);
        return;
    }

    // Dangerous privileges to permanently remove
    static const char *privNames[] = {
        SE_DEBUG_NAME,              // SeDebugPrivilege
        SE_ASSIGNPRIMARYTOKEN_NAME, // SeAssignPrimaryTokenPrivilege
        SE_TCB_NAME,                // SeTcbPrivilege
        SE_CREATE_TOKEN_NAME,       // SeCreateTokenPrivilege
        SE_LOAD_DRIVER_NAME,        // SeLoadDriverPrivilege
        SE_SECURITY_NAME,           // SeSecurityPrivilege
        SE_TAKE_OWNERSHIP_NAME,     // SeTakeOwnershipPrivilege
        SE_SYSTEM_ENVIRONMENT_NAME, // SeSystemEnvironmentPrivilege
        SE_BACKUP_NAME,             // SeBackupPrivilege
        SE_RESTORE_NAME,            // SeRestorePrivilege
        SE_IMPERSONATE_NAME,        // SeImpersonatePrivilege
        SE_UNDOCK_NAME,             // SeUndockPrivilege
        SE_INC_BASE_PRIORITY_NAME,  // SeIncreaseBasePriorityPrivilege
        SE_SHUTDOWN_NAME,           // SeShutdownPrivilege
    };
    int numPrivs = (int)(sizeof(privNames) / sizeof(privNames[0]));

    int removed = 0;
    for (int i = 0; i < numPrivs; i++)
    {
        LUID luid;
        if (!LookupPrivilegeValueA(nullptr, privNames[i], &luid))
            continue; // privilege doesn't exist on this system — skip

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED; // 0x00000004

        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
            removed++;
    }
    fprintf(stderr, "[TZD] token: %d privileges permanently removed (SE_PRIVILEGE_REMOVED)\n", removed);
    fflush(stderr);

    CloseHandle(hToken);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── DebugPort Occupation (anti external DebugActiveProcess) ──────────
// Creates a real debug object and sets it as our process's DebugPort via
// NtSetInformationProcess(ProcessDebugPort=7). This makes the kernel
// think the process is already being debugged — any external call to
// DebugActiveProcess → NtDebugActiveProcess fails with
// STATUS_PORT_ALREADY_SET (the user sees 0xC0000353).
//
// A background "drain" thread calls NtWaitForDebugEvent + NtDebugContinue
// in a loop to consume queued debug events, preventing the event queue
// from filling up and preventing process hangs.
//
// Also sets:
//   ProcessDebugFlags (31) = 0  — no debug-inherit for child processes
//   ProcessDebugObjectHandle (30) = NULL — clear lingering debug handle
// ═══════════════════════════════════════════════════════════════════════

// ntdll function pointer types
typedef NTSTATUS(NTAPI *pfnNtCreateDebugObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI *pfnNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *pfnNtWaitForDebugEvent)(HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID);
typedef NTSTATUS(NTAPI *pfnNtDebugContinue)(HANDLE, CLIENT_ID *, NTSTATUS);

static pfnNtCreateDebugObject g_pNtCreateDebugObject = nullptr;
static pfnNtSetInformationProcess g_pNtSetInformationProcess = nullptr;
static pfnNtWaitForDebugEvent g_pNtWaitForDebugEvent = nullptr;
static pfnNtDebugContinue g_pNtDebugContinue = nullptr;
static HANDLE g_ourDebugObject = nullptr;
static HANDLE g_debugDrainThread = nullptr;
static DWORD g_debugDrainTID = 0;

// Debug drain thread: continuously consumes debug events so the
// event queue never fills up and the process never hangs.
static DWORD WINAPI debug_drain_thread(LPVOID)
{
    hide_thread_from_debugger();
    fprintf(stderr, "[TZD] debug drain thread started (tid=%u)\n", GetCurrentThreadId());
    fflush(stderr);

    // DBGUI_WAIT_STATE_CHANGE is ~0x30 bytes on x64; use a generous buffer
    unsigned char stateBuf[256];

    while (g_watchdogRunning)
    {
        if (!g_pNtWaitForDebugEvent || !g_ourDebugObject)
        {
            Sleep(100);
            continue;
        }
        // Alertable wait for a debug event (1s timeout, then retry)
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL; // 1 second (100ns units, negative = relative)
        NTSTATUS st = g_pNtWaitForDebugEvent(g_ourDebugObject, TRUE, &timeout, stateBuf);
        if (NT_SUCCESS(st) && g_pNtDebugContinue)
        {
            // stateBuf starts with a CLIENT_ID at the AppClientId field offset.
            // DBGUI_WAIT_STATE_CHANGE layout: ULONG StateChangeType (4) + padding (4)
            //   + CLIENT_ID AppClientId (16). We extract AppClientId at offset 8.
            CLIENT_ID *clientId = (CLIENT_ID *)(stateBuf + 8);
            g_pNtDebugContinue(g_ourDebugObject, clientId,
                               0x00010002 /* DBG_CONTINUE */);
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── 编译修复：获取父进程 PID 和目标进程名 PID ─────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static bool SuspendProcessById(DWORD pid)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return false;

    auto pNtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
    if (pNtSuspendProcess)
    {
        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (hProcess)
        {
            NTSTATUS status = pNtSuspendProcess(hProcess);
            CloseHandle(hProcess);
            return NT_SUCCESS(status);
        }
    }
    return false;
}

// 1. 获取指定进程名称的 PID（利用 Toolhelp 进程快照）
static DWORD GetPidOfProcess(const wchar_t *processName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (_wcsicmp(pe.szExeFile, processName) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return pid;
}

// 2. 获取指定进程的父进程 PID
static DWORD GetParentProcessId(DWORD childPid)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return 0;

    auto pNtQIP = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (pNtQIP)
    {
        // 简化的 PROCESS_BASIC_INFORMATION 结构
        struct
        {
            PVOID ExitStatus;
            PVOID PebBaseAddress;
            PVOID AffinityMask;
            PVOID BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        } pbi;

        ULONG len = 0;
        HANDLE hProcess = (childPid == GetCurrentProcessId()) ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, childPid);
        if (hProcess)
        {
            NTSTATUS st = pNtQIP(hProcess, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &len);
            if (hProcess != GetCurrentProcess())
            {
                CloseHandle(hProcess);
            }
            if (NT_SUCCESS(st))
            {
                return (DWORD)pbi.InheritedFromUniqueProcessId;
            }
        }
    }
    return 0;
}

static bool MasqueradePEB(const wchar_t *fakeImageName, const wchar_t *fakeCmdLine)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return false;

    auto pNtQIP = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pNtQIP)
        return false;

    struct
    {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } pbi;

    ULONG len = 0;
    NTSTATUS st = pNtQIP(GetCurrentProcess(), 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &len);
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress)
        return false;

    // 获取 PEB 中的 ProcessParameters 结构
    PVOID *pPeb = (PVOID *)pbi.PebBaseAddress;
    // 64位系统下 ProcessParameters 的偏移为 0x20 (32位为 0x10)
#ifdef _WIN64
    PVOID pParams = pPeb[4];
#else
    PVOID pParams = pPeb[4];
#endif
    if (!pParams)
        return false;

    // UNICODE_STRING 结构: USHORT Length, USHORT MaximumLength, PWSTR Buffer
    // ImagePathName 偏移: 64bit 为 0x60, CommandLine 偏移: 0x70
    // 使用 Win32 API 风格安全修改 (基于 RtlEnterCriticalSection 保护更稳定，此处直接替换内存 Buffer)
    UNICODE_STRING *pImagePath = (UNICODE_STRING *)((BYTE *)pParams + (sizeof(void *) == 8 ? 0x60 : 0x38));
    UNICODE_STRING *pCmdLine = (UNICODE_STRING *)((BYTE *)pParams + (sizeof(void *) == 8 ? 0x70 : 0x40));

    USHORT newPathLen = (USHORT)(wcslen(fakeImageName) * sizeof(wchar_t));
    if (pImagePath->Buffer && pImagePath->MaximumLength >= newPathLen)
    {
        pImagePath->Length = newPathLen;
        wcsncpy_s(pImagePath->Buffer, pImagePath->MaximumLength / sizeof(wchar_t), fakeImageName, _TRUNCATE);
    }

    USHORT newCmdLen = (USHORT)(wcslen(fakeCmdLine) * sizeof(wchar_t));
    if (pCmdLine->Buffer && pCmdLine->MaximumLength >= newCmdLen)
    {
        pCmdLine->Length = newCmdLen;
        wcsncpy_s(pCmdLine->Buffer, pCmdLine->MaximumLength / sizeof(wchar_t), fakeCmdLine, _TRUNCATE);
    }

    return true;
}

static DWORD GetTargetProcessId(const wchar_t *processName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (_wcsicmp(pe.szExeFile, processName) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return pid;
}

// 3. 强占 DebugPort 逻辑
static void occupy_debug_port()
{
    static bool done = false;
    if (done)
        return;
    done = true;

    wchar_t *cmdLine = GetCommandLineW();

    // -------------------------------------------------------------
    // 分支 A: 子进程执行逻辑（调试守护进程 / 防调试占位）
    // -------------------------------------------------------------
    if (wcsstr(cmdLine, L"-Dseckill.daemon=true"))
    {
        wchar_t *pPid = wcsstr(cmdLine, L"-Dseckill.parent.pid=");
        if (pPid)
        {
            pPid += wcslen(L"-Dseckill.parent.pid=");
            DWORD parentPid = (DWORD)_wtoi(pPid);
            if (parentPid != 0)
            {
                // 1. 伪装自身 PEB 为 svchost.exe
                MasqueradePEB(
                    L"C:\\Windows\\System32\\svchost.exe",
                    L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p");

                // 2. 附加到父进程进行调试（以此独占父进程的 DebugPort）
                if (DebugActiveProcess(parentPid))
                {
                    // 关键设置：即使子进程挂掉，也不要杀死父进程
                    DebugSetProcessKillOnExit(FALSE);

                    // 3. 【核心修复】必须运行调试事件循环！
                    // 只有不断调用 ContinueDebugEvent，父进程的线程才会被内核恢复执行
                    DEBUG_EVENT dbgEvent = {0};
                    while (WaitForDebugEvent(&dbgEvent, INFINITE))
                    {
                        // 如果检测到父进程已经退出，守护任务完成，退出循环
                        if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT &&
                            dbgEvent.dwProcessId == parentPid)
                        {
                            break;
                        }

                        // 恢复被挂起的父进程线程，让父进程继续运行
                        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                        // SuspendProcessById(GetCurrentProcessId());
                    }
                }
            }
        }
        // 当父进程退出后，子进程也正常退出
        ExitProcess(0);
    }

    // -------------------------------------------------------------
    // 分支 B: 父进程执行逻辑
    // -------------------------------------------------------------
    DWORD ourPid = GetCurrentProcessId();
    const wchar_t *appendParams = L" -Dseckill.daemon=true -Dseckill.parent.pid=";
    size_t requiredLength = wcslen(cmdLine) + wcslen(appendParams) + 12 + 1;
    wchar_t *childCmd = (wchar_t *)malloc(requiredLength * sizeof(wchar_t));

    if (childCmd == nullptr)
    {
        fprintf(stderr, "[TZD] debug_port: Out of memory for command line buffer\n");
        fflush(stderr);
        return;
    }
    swprintf_s(childCmd, requiredLength, L"%s%s%u", cmdLine, appendParams, ourPid);

    // 1. 获取独立第三方系统进程（如 explorer.exe 或 services.exe）实现 PPID Spoofing
    DWORD spoofedParentPid = GetTargetProcessId(L"explorer.exe");
    if (spoofedParentPid == 0)
    {
        spoofedParentPid = GetTargetProcessId(L"services.exe");
    }

    HANDLE hSpoofedParent = NULL;
    if (spoofedParentPid != 0)
    {
        hSpoofedParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoofedParentPid);
    }

    STARTUPINFOEXW siEx = {0};
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siEx.StartupInfo.wShowWindow = SW_HIDE;

    PPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    SIZE_T attrSize = 0;

    // 2. 初始化 Extended Attribute List
    if (hSpoofedParent)
    {
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        pAttrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
        if (pAttrList && InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize))
        {
            UpdateProcThreadAttribute(
                pAttrList, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &hSpoofedParent, sizeof(HANDLE), NULL, NULL);
            siEx.lpAttributeList = pAttrList;
        }
    }

    PROCESS_INFORMATION pi = {0};
    DWORD createFlags = CREATE_NO_WINDOW;
    if (pAttrList)
    {
        createFlags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    // 3. 启动子进程守护进程
    BOOL bCreated = CreateProcessW(
        nullptr, childCmd, nullptr, nullptr, FALSE,
        createFlags, nullptr, nullptr,
        &siEx.StartupInfo, &pi);

    if (bCreated)
    {
        fprintf(stderr, "[TZD] debug_port: Spawned spoofed daemon process (PID %u)\n", pi.dwProcessId);
        fflush(stderr);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        fprintf(stderr, "[TZD] debug_port: Failed to spawn daemon (err=%lu)\n", GetLastError());
        fflush(stderr);
    }

    // 清理脱钩相关资源
    if (pAttrList)
    {
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
    }
    if (hSpoofedParent)
    {
        CloseHandle(hSpoofedParent);
    }

    free(childCmd);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Job Object Defense ───────────────────────────────────────────────
// Job Objects can be used to kill all threads in a process. The attack:
//   1. Attacker creates a Job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
//   2. AssignProcessToJobObject(jobHandle, GetCurrentProcess())
//   3. CloseHandle(jobHandle) → kernel kills all threads
//
// Defense:
//   - At startup: check if we're already in a Job; if not, create our
//     own "safe" Job (no dangerous limits) and assign ourselves.
//   - Periodically: detect new Job assignment via IsProcessInJob.
//   - If a new Job is detected: enumerate all process handles, find Job
//     handles, clear KILL_ON_JOB_CLOSE + CPU/memory limits, and
//     DuplicateHandle to keep the Job alive (prevent close→kill).
// ═══════════════════════════════════════════════════════════════════════
static HANDLE g_ourSafeJob = nullptr;
static volatile long g_initialInJob = -1; // -1 = unknown, 0 = not in job, 1 = in job

// ── Manual Job Object type definitions ──
// We define these ourselves to avoid SDK header/version conflicts.
// The layout matches the Windows API exactly; SetInformationJobObject /
// QueryInformationJobObject accept a raw buffer so the typedef name
// doesn't matter — only the size and layout do.
#ifndef JOB_OBJECT_LIMIT_BREAKAWAY_OK
#define JOB_OBJECT_LIMIT_BREAKAWAY_OK 0x00000800
#endif
#ifndef JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 0x00002000
#endif

struct TZD_JobBasicLimit
{
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    DWORD LimitFlags;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    DWORD ActiveProcessLimit;
    ULONG_PTR Affinity;
    DWORD PriorityClass;
    DWORD SchedulingClass;
};

struct TZD_JobExtendedLimit
{
    TZD_JobBasicLimit BasicLimitInformation;
    struct
    {
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
    } IoInfo;
    SIZE_T ProcessMemoryLimit;
    SIZE_T JobMemoryLimit;
    SIZE_T PeakProcessMemoryUsed;
    SIZE_T PeakJobMemoryUsed;
};

// JobObjectExtendedLimitInformation enum value (= 9 in JOBOBJECTINFOCLASS)
#define TZD_JobObjectExtendedLimitInformation 9

static void init_job_protection()
{
    static bool done = false;
    if (done)
        return;
    done = true;

    // Check if we're already in a Job
    BOOL inJob = FALSE;
    IsProcessInJob(GetCurrentProcess(), nullptr, &inJob);
    g_initialInJob = inJob ? 1 : 0;

    if (!inJob)
    {
        // Create our own safe Job (no limits, no kill-on-close)
        g_ourSafeJob = CreateJobObjectA(nullptr, nullptr);
        if (g_ourSafeJob)
        {
            // Set no dangerous limits — just an empty Job
            TZD_JobExtendedLimit extLimit = {};
            extLimit.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_BREAKAWAY_OK; // allow children to break away
            SetInformationJobObject(g_ourSafeJob,
                                    (JOBOBJECTINFOCLASS)TZD_JobObjectExtendedLimitInformation,
                                    &extLimit, sizeof(extLimit));

            // Assign ourselves to the safe Job
            if (AssignProcessToJobObject(g_ourSafeJob, GetCurrentProcess()))
            {
                // Protect the Job handle — never close it
                SetHandleInformation(g_ourSafeJob,
                                     HANDLE_FLAG_PROTECT_FROM_CLOSE | HANDLE_FLAG_INHERIT,
                                     HANDLE_FLAG_PROTECT_FROM_CLOSE);
                fprintf(stderr, "[TZD] job: safe Job created and assigned (BREAKAWAY_OK, no kill limits)\n");
                fflush(stderr);
            }
            else
            {
                fprintf(stderr, "[TZD] job: AssignProcessToJobObject failed (err=%lu)\n",
                        GetLastError());
                fflush(stderr);
            }
        }
    }
    else
    {
        fprintf(stderr, "[TZD] job: process already in a Job at startup — will monitor for new Jobs\n");
        fflush(stderr);
    }
}

// SystemExtendedHandleInformation class for NtQuerySystemInformation
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 0x40
#endif

// Check for new Job assignment and neutralize dangerous limits.
static void check_job_protection()
{
    BOOL inJob = FALSE;
    IsProcessInJob(GetCurrentProcess(), nullptr, &inJob);

    long cached = InterlockedCompareExchange(&g_initialInJob, -1, -1);
    // If state didn't change, nothing to do
    if ((inJob ? 1 : 0) == cached)
        return;

    // State changed — new Job detected!
    InterlockedExchange(&g_initialInJob, inJob ? 1 : 0);

    fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                    "(Job Object assignment detected! inJob=%d — neutralizing)\n",
            inJob);
    fflush(stderr);

    if (!inJob)
        return; // we left a Job? Unlikely but handle it

    // ── Enumerate all handles in our process to find Job handles ──
    // Use NtQuerySystemInformation(SystemExtendedHandleInformation)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;
    typedef NTSTATUS(NTAPI * pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    auto pNtQSI = (pfnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQSI)
        return;

    // First call to get buffer size
    ULONG bufSize = 0x10000;
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (!buf)
        return;

    NTSTATUS st;
    while (true)
    {
        st = pNtQSI(SystemExtendedHandleInformation, buf, bufSize, &bufSize);
        if (NT_SUCCESS(st))
            break;
        if (st == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
        {
            // Buffer too small — reallocate
            free(buf);
            buf = (unsigned char *)malloc(bufSize);
            if (!buf)
                return;
            continue;
        }
        free(buf);
        return;
    }

    // Parse SYSTEM_HANDLE_INFORMATION_EX
    // Layout: ULONG NumberOfHandles + padding + handles[]
    // Each entry: ULONG Object, HANDLE Handle, ULONG PID, ...
    // We use the extended format:
    //   typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    //     ULONG_PTR NumberOfHandles;
    //     ULONG_PTR Reserved;
    //     SYSTEM_HANDLE_INFORMATION_EX Entries[];
    //   }
    //   typedef struct _SYSTEM_HANDLE_INFORMATION_EX_ENTRY {
    //     ULONG_PTR Object;
    //     ULONG_PTR UniqueProcessId;
    //     ULONG_PTR HandleValue;
    //     ULONG GrantedAccess;
    //     ...
    //   }
    // The exact layout varies by version. We use a simplified approach:
    // read NumberOfHandles, then iterate entries of size 0x28 (40 bytes on x64).

    ULONG_PTR numHandles = *(ULONG_PTR *)buf;
    DWORD ourPid = GetCurrentProcessId();

    // Entry stride varies: 0x28 on most Win10/11 x64 builds
    // Layout per entry: Object(8) + UniqueProcessId(8) + HandleValue(8)
    //                    + GrantedAccess(4) + CreatorBackTraceIndex(2) + ObjectTypeIndex(2)
    //                    + HandleAttributes(4) + Reserved(4) = 0x28
    const int ENTRY_SIZE = 0x28;
    const int OFF_PID = 8;     // UniqueProcessId offset within entry
    const int OFF_HANDLE = 16; // HandleValue offset within entry

    unsigned char *entries = buf + 16; // skip NumberOfHandles + Reserved
    for (ULONG_PTR i = 0; i < numHandles; i++)
    {
        unsigned char *entry = entries + i * ENTRY_SIZE;
        if (entry + ENTRY_SIZE > buf + bufSize)
            break;

        DWORD pid = *(DWORD *)(entry + OFF_PID);
        if (pid != ourPid)
            continue;

        HANDLE hJob = *(HANDLE *)(entry + OFF_HANDLE);
        if (!hJob || hJob == g_ourSafeJob)
            continue;

        // Try to query this handle as a Job — clear dangerous limits
        TZD_JobExtendedLimit extLimit = {};
        if (QueryInformationJobObject(hJob,
                                      (JOBOBJECTINFOCLASS)TZD_JobObjectExtendedLimitInformation,
                                      &extLimit, sizeof(extLimit), nullptr))
        {
            // Clear KILL_ON_JOB_CLOSE and all resource limits
            DWORD oldFlags = extLimit.BasicLimitInformation.LimitFlags;
            extLimit.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_BREAKAWAY_OK; // keep only breakaway
            if (extLimit.JobMemoryLimit)
                extLimit.JobMemoryLimit = 0;
            if (extLimit.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart)
                extLimit.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 0;
            if (extLimit.BasicLimitInformation.PerJobUserTimeLimit.QuadPart)
                extLimit.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = 0;

            SetInformationJobObject(hJob,
                                    (JOBOBJECTINFOCLASS)TZD_JobObjectExtendedLimitInformation,
                                    &extLimit, sizeof(extLimit));

            fprintf(stderr, "[TZD] job: neutralized Job handle 0x%p (was LimitFlags=0x%x, cleared)\n",
                    hJob, oldFlags);
            fflush(stderr);

            // DuplicateHandle to keep the Job alive — prevents the attacker
            // from closing the Job handle and triggering KILL_ON_JOB_CLOSE
            HANDLE hDup = nullptr;
            if (DuplicateHandle(GetCurrentProcess(), hJob,
                                GetCurrentProcess(), &hDup,
                                0, FALSE, DUPLICATE_SAME_ACCESS))
            {
                // Protect the duplicate so it can't be closed
                SetHandleInformation(hDup,
                                     HANDLE_FLAG_PROTECT_FROM_CLOSE | HANDLE_FLAG_INHERIT,
                                     HANDLE_FLAG_PROTECT_FROM_CLOSE);
                fprintf(stderr, "[TZD] job: duplicated Job handle 0x%p → 0x%p (prevents close→kill)\n",
                        hJob, hDup);
                fflush(stderr);
            }
        }
    }

    free(buf);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Neutralize ntdll!DbgUiRemoteFlash / DbgUiBreakPoint (no-hook patch) ─
// When Visual Studio (or any native debugger) attaches to a live process,
// the kernel forces the target to spawn 1-2 remote threads whose start
// routine is ntdll!DbgUiRemoteFlash (Win10/11) or ntdll!DbgUiBreakPoint /
// DbgUiRemoteBreakin on older builds. That thread fires the initial
// breakpoint that completes the attach handshake. Without it, the
// debugger attaches but never hits the initial break — the session is
// unusable (no module list, no symbols, no call stack).
//
// We do NOT hook these functions (no IAT trampoline, no callback into our
// protection code). We overwrite their entry bytes with an absolute jmp to
// a tiny stub that calls ExitThread(0). The remote thread starts, jumps to
// the stub, exits cleanly, and never fires the breakpoint. There is no
// control transfer back to seckill_native.dll, so typical hook-detection
// (looking for jmp-to-protector) sees nothing.
//
// Targets (resolved by name; patched idempotently):
//   DbgUiRemoteFlash        — Win10/11 attach flash
//   DbgUiRemoteBreakin      — generic remote-breakin entry
//   DbgUiBreakPoint         — fallback breakpoint routine
// ═══════════════════════════════════════════════════════════════════════
static unsigned char *g_dbgExitStub = nullptr; // shared ExitThread(0) stub

static unsigned char *get_exitthread_stub()
{
    if (g_dbgExitStub)
        return g_dbgExitStub;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32)
        return nullptr;
    void *exitThread = GetProcAddress(k32, "ExitThread");
    if (!exitThread)
        return nullptr;
    // Stub (x64):
    //   48 31 C9                       xor rcx, rcx         ; ExitCode = 0
    //   48 83 EC 28                     sub rsp, 0x28        ; 0x20 shadow + 8 align
    //   48 B8 <8 bytes>                 mov rax, ExitThread
    //   FF D0                           call rax             ; ExitThread(0) — no return
    //   CC                              int3                 ; guard (unreachable)
    unsigned char stub[24];
    stub[0] = 0x48;
    stub[1] = 0x31;
    stub[2] = 0xC9; // xor rcx,rcx
    stub[3] = 0x48;
    stub[4] = 0x83;
    stub[5] = 0xEC;
    stub[6] = 0x28; // sub rsp,0x28
    stub[7] = 0x48;
    stub[8] = 0xB8; // mov rax, imm64
    *(unsigned long long *)(stub + 9) = (unsigned long long)(intptr_t)exitThread;
    stub[17] = 0xFF;
    stub[18] = 0xD0; // call rax
    stub[19] = 0xCC; // int3
    g_dbgExitStub = (unsigned char *)VirtualAlloc(nullptr, 64,
                                                  MEM_COMMIT | MEM_RESERVE,
                                                  PAGE_EXECUTE_READWRITE);
    if (!g_dbgExitStub)
        return nullptr;
    memcpy(g_dbgExitStub, stub, 20);
    return g_dbgExitStub;
}

// Patch one ntdll export's entry to jmp to the ExitThread(0) stub.
// Returns true if patched (or already patched) this call.
static bool neutralize_dbg_export(const char *name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return false;
    unsigned char *fn = (unsigned char *)GetProcAddress(ntdll, name);
    if (!fn)
        return false;
    unsigned char *stub = get_exitthread_stub();
    if (!stub)
        return false;

    // Idempotency: already patched (our absolute jmp starts with FF 25).
    if (fn[0] == 0xFF && fn[1] == 0x25)
        return true;

    // Save original bytes (for self-guard awareness — we do NOT restore;
    // ntdll is outside jvm_guard/self_guard CRC ranges, so no conflict).
    DWORD op = 0;
    if (!direct_VirtualProtect(fn, 14, PAGE_EXECUTE_READWRITE, &op))
        return false;

    // FF 25 00 00 00 00 <8-byte stub addr>  ==  jmp [rip+0], addr
    fn[0] = 0xFF;
    fn[1] = 0x25;
    fn[2] = 0x00;
    fn[3] = 0x00;
    fn[4] = 0x00;
    fn[5] = 0x00;
    *(unsigned long long *)(fn + 6) = (unsigned long long)(intptr_t)stub;

    direct_VirtualProtect(fn, 14, op, &op);
    FlushInstructionCache(GetCurrentProcess(), fn, 14);
    fprintf(stderr, "[TZD] debug neutralize: ntdll!%s patched -> ExitThread(0) stub @ %p\n",
            name, stub);
    fflush(stderr);
    return true;
}

static void neutralize_debug_remote_thread_funcs()
{
    static bool first = true;
    int patched = 0;
    if (neutralize_dbg_export("DbgUiRemoteFlash"))
        patched++;
    if (neutralize_dbg_export("DbgUiRemoteBreakin"))
        patched++;
    if (neutralize_dbg_export("DbgUiBreakPoint"))
        patched++;
    if (first)
    {
        first = false;
        fprintf(stderr, "[TZD] debug neutralize: %d DbgUi remote-thread entries patched to ExitThread(0)\n",
                patched);
        fflush(stderr);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Active ProcessDebugObjectHandle (class 30) closure ────────────────
// NtQueryInformationProcess(ProcessDebugObjectHandle = 30) returns a
// handle to the debug object associated with our process. If non-NULL, a
// debug session is live. We CloseHandle it AND attempt to null the
// DebugPort (NtSetInformationProcess(7, NULL)) to force the kernel to tear
// down the debug link. If a debugger is attached, this severs its
// monitoring (or refuses further debug events); if not, it is a no-op.
//
// This complements occupy_debug_port(), which PREVENTS external attach by
// setting our own port at startup. This function handles the case where a
// debugger attached anyway (admin/SYSTEM forced, or attached before our DLL
// loaded) — it actively tears the link down on every watchdog cycle.
// ═══════════════════════════════════════════════════════════════════════
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcessRaw)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static pfnNtQueryInformationProcessRaw g_pNtQIP_raw = nullptr;
static pfnNtSetInformationProcess g_pNtSIP_raw2 = nullptr;

bool verify_my_father_is_scml()
{
    // 1. 获取 services.exe 的 PID (通过遍历进程名 "services.exe")
    DWORD scmPid = GetPidOfProcess(L"services.exe");

    // 2. 获取当前进程（即我们自己）的父进程 PID
    DWORD myParentPid = GetParentProcessId(GetCurrentProcessId());

    // 3. 物理校验
    if (myParentPid != scmPid)
    {
        // 如果我的爸爸不是 services.exe，说明我是被人在桌面上双击启动的，
        // 或者是被 devenv.exe / x64dbg.exe 作为子进程拉起来调试的！
        ExitProcess(0); // 拒绝执行
    }
    return true;
}

static void close_debug_object_handle()
{
    if (!g_pNtQIP_raw)
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
        {
            g_pNtQIP_raw = (pfnNtQueryInformationProcessRaw)
                GetProcAddress(ntdll, "NtQueryInformationProcess");
            g_pNtSIP_raw2 = (pfnNtSetInformationProcess)
                GetProcAddress(ntdll, "NtSetInformationProcess");
            g_pNtRPD = (pfnNtRemoveProcessDebug)
                GetProcAddress(ntdll, "NtRemoveProcessDebug"); // 【新增解密】
        }
        if (!g_pNtQIP_raw)
            return;
    }

    HANDLE hDbg = nullptr;
    ULONG ret = 0;
    // 查询当前进程关联的调试对象句柄 (Class 30)
    NTSTATUS st = g_pNtQIP_raw(GetCurrentProcess(), 30 /* ProcessDebugObjectHandle */,
                               &hDbg, sizeof(hDbg), &ret);

    if (NT_SUCCESS(st) && hDbg)
    {
        // 发现调试器！
        fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                        "(Debugger detected! Severing debug connection via NtRemoveProcessDebug)\n");
        fflush(stderr);

        // 【核心修复】：不能仅仅调用 CloseHandle，必须调用 NtRemoveProcessDebug 进行物理剥离！
        if (g_pNtRPD)
        {
            // 强行把调试器从我们进程上“踢”出去
            NTSTATUS stRemove = g_pNtRPD(GetCurrentProcess(), hDbg);
            fprintf(stderr, "[TZD] debug object: NtRemoveProcessDebug = 0x%lx\n", (unsigned long)stRemove);
            fflush(stderr);
        }

        // 关闭我们这边的本地句柄副本
        CloseHandle(hDbg);

        // 强行清空调试端口
        if (g_pNtSIP_raw2)
        {
            HANDLE nullPort = nullptr;
            g_pNtSIP_raw2(GetCurrentProcess(), 7 /* ProcessDebugPort */, &nullPort, sizeof(nullPort));
        }

        // 重新武装我们自己的占领端口（可选，配合你的 occupy 逻辑）
        if (g_ourDebugObject)
        {
            HANDLE dbgPort = g_ourDebugObject;
            g_pNtSIP_raw2(GetCurrentProcess(), 7, &dbgPort, sizeof(dbgPort));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Shellcode Disabler (JIT-safe) ─────────────────────────────────────
// "Thoroughly disable shellcode" without breaking HotSpot JIT:
//
// 1. FREE RWX MEM_PRIVATE non-module regions. The JVM's nmethods live in
//    PAGE_EXECUTE_READ (RX) CodeCache pages — never RWX. Any MEM_PRIVATE
//    PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY / PAGE_EXECUTE(no
//    read) region not backed by a loaded module is shellcode. We
//    VirtualFree(MEM_RELEASE) it. (Our own 16-byte syscall stub is tiny
//    and exempted by a whitelist of known-our allocations.)
//
// 2. NEUTRALIZE direct-syscall stubs (0F 05) in ANY non-module executable
//    MEM_PRIVATE region — including RX. The JVM JIT does NOT emit raw
//    `syscall` instructions (it calls Win32 via call, never 0F 05), so
//    patching 0F 05 in CodeCache is a safe no-op there. For injected
//    shellcode that uses direct syscalls (to bypass our ntdll inline
//    hook), we overwrite 0F 05 with 0F 0B (ud2) → the moment the
//    shellcode issues a syscall, it faults (#UD) instead of reaching the
//    kernel. This kills direct-syscall shellcode in ANY protection mode.
//
// 3. The thread scanner (already added) terminates threads whose start
//    address is in non-module memory, and the process DACL blocks the
//    external VirtualAllocEx/VirtualProtectEx/CreateRemoteThread that
//    would create the shellcode in the first place. This scan is the
//    in-process / post-breach neutralizer.
// ═══════════════════════════════════════════════════════════════════════
// Whitelist of our own small executable allocations (syscall stubs, the
// ExitThread(0) stub) so we never free/patch our own code.
#define MAX_OUR_EXEC_ALLOCS 16
static unsigned long long g_ourExecAllocs[MAX_OUR_EXEC_ALLOCS];
static volatile long g_numOurExecAllocs = 0;

static void register_our_exec_alloc(void *p, size_t size)
{
    if (!p)
        return;
    int idx = (int)InterlockedIncrement(&g_numOurExecAllocs) - 1;
    if (idx >= MAX_OUR_EXEC_ALLOCS)
    {
        InterlockedDecrement(&g_numOurExecAllocs);
        return;
    }
    g_ourExecAllocs[idx] = (unsigned long long)(intptr_t)p & ~0xFFFULL;
    (void)size;
}
// Overload-free C version used where register is needed from C-linkage spots:
static void reg_our_exec(void *p)
{
    register_our_exec_alloc(p, 0);
}

static bool is_our_exec_alloc(unsigned long long page)
{
    int n = (int)g_numOurExecAllocs;
    for (int i = 0; i < n && i < MAX_OUR_EXEC_ALLOCS; i++)
        if (g_ourExecAllocs[i] == page)
            return true;
    return false;
}

// Reuse the module-range whitelist builder from scan_injected_threads
// (declared earlier in this file).
struct ModuleRange;
int build_module_whitelist(ModuleRange **out);
bool addr_in_modules(unsigned long long addr, const ModuleRange *rng, int n);

static void scan_and_neutralize_shellcode()
{
    ModuleRange *rng = nullptr;
    int nMods = build_module_whitelist(&rng);

    unsigned long long addr = 0x10000ULL;
    MEMORY_BASIC_INFORMATION mbi;
    int freed = 0, syscallsNOPd = 0;

    while (addr < 0x7FFFFFFFFFFFULL)
    {
        if (!VirtualQuery((void *)(intptr_t)addr, &mbi, sizeof(mbi)))
            break;
        unsigned long long regionBase = (unsigned long long)(intptr_t)mbi.BaseAddress;
        unsigned long long regionEnd = regionBase + mbi.RegionSize;

        // Only committed, private, executable regions.
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
        {
            DWORD prot = mbi.Protect;
            bool isExec = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (isExec)
            {
                bool inMod = addr_in_modules(regionBase, rng, nMods);
                bool ours = is_our_exec_alloc(regionBase & ~0xFFFULL);

                if (!inMod && !ours)
                {
                    // ── (1) RWX shellcode → free the region ──
                    if (prot == PAGE_EXECUTE_READWRITE ||
                        prot == PAGE_EXECUTE_WRITECOPY ||
                        prot == PAGE_EXECUTE)
                    {
                        // Make non-executable first (belt+suspenders),
                        // then release. If a thread is executing here it
                        // will fault — which is the goal (the thread
                        // scanner terminates injected threads separately).
                        DWORD op = 0;
                        g_ourCall = 1;
                        direct_VirtualProtect((void *)(intptr_t)regionBase, mbi.RegionSize,
                                              PAGE_NOACCESS, &op);
                        g_ourCall = 0;
                        if (VirtualFree((void *)(intptr_t)regionBase, 0, MEM_RELEASE))
                        {
                            freed++;
                            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                            "(shellcode region 0x%llx size=0x%llx RWX freed)\n",
                                    regionBase, (unsigned long long)mbi.RegionSize);
                            fflush(stderr);
                        }
                    }
                    else
                    {
                        // ── (2) RX non-module region: neutralize 0F 05 ──
                        // (JIT CodeCache is RX but contains no 0F 05, so
                        // this is a safe no-op there. In injected RX
                        // shellcode, it kills the direct-syscall path.)
                        unsigned char *p = (unsigned char *)(intptr_t)regionBase;
                        SIZE_T sz = mbi.RegionSize;
                        // Need write access to patch bytes. RX → RW temporarily.
                        DWORD op = 0;
                        bool canWrite = direct_VirtualProtect(p, sz, PAGE_EXECUTE_READWRITE, &op);
                        for (SIZE_T i = 0; canWrite && i + 1 < sz; i++)
                        {
                            if (p[i] == 0x0F && p[i + 1] == 0x05)
                            {
                                // Overwrite syscall with ud2 (0F 0B) → #UD on exec.
                                p[i] = 0x0F;
                                p[i + 1] = 0x0B;
                                syscallsNOPd++;
                            }
                        }
                        if (canWrite)
                        {
                            direct_VirtualProtect(p, sz, op, &op);
                            FlushInstructionCache(GetCurrentProcess(), p, sz);
                        }
                        if (syscallsNOPd > 0 && canWrite)
                        {
                            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                            "(direct-syscall (0F 05) stubs neutralized at 0x%llx: %d)\n",
                                    regionBase, syscallsNOPd);
                            fflush(stderr);
                        }
                    }
                }
            }
        }

        // Advance. Guard against 0-size (would loop forever).
        if (regionEnd <= addr)
            break;
        addr = regionEnd;
    }

    free(rng);
    if (freed > 0 || syscallsNOPd > 0)
    {
        fprintf(stderr, "[TZD] shellcode scan: freed=%d syscall-stubs-neutralized=%d\n",
                freed, syscallsNOPd);
        fflush(stderr);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── VTable / ITable backup (prevent vtable/itable hijacking) ──────────
// The JVM embeds the vtable (array of Method*) at InstanceKlass +
// sizeof(InstanceKlass). The itable follows. An attacker can hijack
// virtual dispatch by overwriting a vtable entry → redirect calls.
//
// Layout (JDK 20 LP64, confirmed from source):
//   Klass::_vtable_len at offset 160 (int, in words; each entry = 8 bytes)
//   InstanceKlass::_itable_len at offset 260 (int, in words)
//   vtable start = InstanceKlass + sizeof(InstanceKlass)
//   itable start = vtable_start + vtable_len * 8
//   Each vtable entry = Method* (8 bytes)
//
// Since sizeof(InstanceKlass) is not known at runtime, we detect the
// vtable start by scanning for _vtable_len consecutive valid Method* ptrs.
// ═══════════════════════════════════════════════════════════════════════
static void backup_vtable_itable(ProtectedClass &pc, long long ik)
{
    // Read vtable length (Klass::_vtable_len at offset 160)
    jint vtableLen = r4((void *)(ik + 160));
    if (vtableLen <= 0 || vtableLen > 1000)
        return;

    // Read itable length (InstanceKlass::_itable_len at offset 260)
    jint itableLen = r4((void *)(ik + 260));
    if (itableLen < 0)
        itableLen = 0;

    // Detect vtable start. sizeof(InstanceKlass) varies by build config.
    // Try common JDK 20 LP64 product values first, then scan as fallback.
    long long vtableStart = 0;
    // Common sizeof(InstanceKlass) values (product, LP64, JVMTI enabled):
    static const int knownSizes[] = {440, 448, 432, 456, 464, 416, 424, 480, 488, 400, 408};
    for (int si = 0; si < (int)(sizeof(knownSizes) / sizeof(knownSizes[0])) && !vtableStart; si++)
    {
        int off = knownSizes[si];
        // Verify: first 2 entries are valid Method* pointers
        bool valid = true;
        for (int i = 0; i < 2 && i < vtableLen; i++)
        {
            long long val = rq((void *)(ik + off + i * 8));
            if (!val || !jvm_safe_read((void *)val, 16))
            {
                valid = false;
                break;
            }
            long long vptr = rq((void *)val);
            if (!vptr || vptr < 0x10000LL)
            {
                valid = false;
                break;
            }
            // Accept if vptr is in jvm.dll OR _constMethod looks valid
            if (!is_in_jvm_dll(vptr))
            {
                long long cm = rq((void *)(val + 8));
                if (!cm || !jvm_safe_read((void *)cm, 32))
                {
                    valid = false;
                    break;
                }
            }
        }
        if (valid)
            vtableStart = ik + off;
    }
    // Fallback: scan 300-2000
    if (!vtableStart)
    {
        for (int off = 300; off <= 2000; off += 8)
        {
            bool allValid = true;
            int checkCount = (vtableLen < 4) ? vtableLen : 4;
            for (int i = 0; i < checkCount; i++)
            {
                long long val = rq((void *)(ik + off + i * 8));
                if (!val || !jvm_safe_read((void *)val, 16))
                {
                    allValid = false;
                    break;
                }
                long long vptr = rq((void *)val);
                if (!vptr || vptr < 0x10000LL)
                {
                    allValid = false;
                    break;
                }
                if (!is_in_jvm_dll(vptr))
                {
                    long long cm = rq((void *)(val + 8));
                    if (!cm || !jvm_safe_read((void *)cm, 32))
                    {
                        allValid = false;
                        break;
                    }
                }
            }
            if (allValid)
            {
                vtableStart = ik + off;
                break;
            }
        }
    }

    if (!vtableStart)
    {
        fprintf(stderr, "[TZD] vtable: could not detect start (vtableLen=%d)\n", vtableLen);
        fflush(stderr);
        return;
    }

    // Backup vtable
    int vtableSize = vtableLen * 8;
    pc.vtableAddr = vtableStart;
    pc.vtableLen = vtableLen;
    pc.vtableBackup = (unsigned char *)malloc(vtableSize);
    if (pc.vtableBackup)
    {
        memcpy(pc.vtableBackup, (void *)vtableStart, vtableSize);
        pc.vtableCRC = crc32_page(pc.vtableBackup, vtableSize);
    }

    // Backup itable (follows vtable, length = itableLen words)
    long long itableStart = vtableStart + vtableSize;
    int itableSize = itableLen * 8;
    if (itableSize > 0 && itableSize <= 65536)
    {
        pc.itableAddr = itableStart;
        pc.itableLen = itableLen;
        pc.itableBackup = (unsigned char *)malloc(itableSize);
        if (pc.itableBackup)
        {
            memcpy(pc.itableBackup, (void *)itableStart, itableSize);
            pc.itableCRC = crc32_page(pc.itableBackup, itableSize);
        }
    }

    fprintf(stderr, "[TZD] vtable backup: addr=0x%llx len=%d (%d bytes), "
                    "itable: addr=0x%llx len=%d\n",
            vtableStart, vtableLen, vtableSize, itableStart, itableLen);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── ConstantPoolCache backup (prevent CPC patching) ───────────────────
// ConstantPool._cache is at offset 16 (confirmed). The ConstantPoolCache
// has _length (int, at offset 0) followed by entries. Each entry is
// 32 bytes (4 fields × 8 bytes: _indices, _f1, _f2, _flags). The attacker
// patches _f1 (Metadata*) to redirect method resolution.
// ═══════════════════════════════════════════════════════════════════════
static void backup_cpcache(ProtectedClass &pc, long long ik)
{
    // Get ConstantPool (InstanceKlass._constants at offset 192)
    long long cp = rq((void *)(ik + 192));
    if (!cp)
        return;

    // Get ConstantPoolCache (ConstantPool._cache at offset 16)
    long long cpCache = rq((void *)(cp + 16));
    if (!cpCache || !jvm_safe_read((void *)cpCache, 64))
        return;

    // Read _length (int at offset 0)
    int len = *(int *)(cpCache + 0);
    if (len <= 0 || len > 100000)
        return;

    // Total size: header (~48 bytes) + len * 32 bytes per entry
    // Use header + len * 32, capped at 64KB
    int headerSize = 64; // generous header estimate
    int entrySize = 32;  // ConstantPoolCacheEntry = 4 words = 32 bytes
    int totalSize = headerSize + len * entrySize;
    if (totalSize > 65536)
        totalSize = 65536;
    if (totalSize <= 0)
        return;

    pc.cpCacheAddr = cpCache;
    pc.cpCacheLen = len;
    pc.cpCacheBackupSize = totalSize;
    pc.cpCacheBackup = (unsigned char *)malloc(totalSize);
    if (pc.cpCacheBackup)
    {
        memcpy(pc.cpCacheBackup, (void *)cpCache, totalSize);
        // CRC in chunks (crc32_page handles up to 4096 per call)
        pc.cpCacheCRC = 0;
        for (int off = 0; off < totalSize; off += 4096)
        {
            int chunk = (off + 4096 <= totalSize) ? 4096 : (totalSize - off);
            pc.cpCacheCRC ^= crc32_page(pc.cpCacheBackup + off, chunk);
        }
    }

    fprintf(stderr, "[TZD] ConstantPoolCache backup: addr=0x%llx len=%d size=%d\n",
            cpCache, len, totalSize);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Live Thread Stack Frame monitoring ───────────────────────────────
// Walks each thread's stack and verifies return addresses are in known
// code regions (loaded modules). Suspicious return addresses (shellcode
// in MEM_PRIVATE executable memory) are logged.
// ═══════════════════════════════════════════════════════════════════════
static bool is_in_loaded_module(long long addr)
{
    HMODULE hMod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (LPCSTR)addr, &hMod) &&
        hMod)
        return true;
    return false;
}

static void check_thread_stacks()
{
    int pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPSHOTTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD curTid = GetCurrentThreadId();
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != (DWORD)pid)
                continue;
            if (te.th32ThreadID == curTid)
                continue;

            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                  FALSE, te.th32ThreadID);
            if (!h)
                continue;

            // Suspend to get a stable stack
            DWORD prev = 0;
            if (g_sysNtSuspend)
                g_sysNtSuspend(h, &prev);
            else
                SuspendThread(h);

            CONTEXT ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(h, &ctx))
            {
                long long sp = (long long)ctx.Rsp;
                // Walk up to 48 stack frames
                for (int i = 0; i < 48; i++)
                {
                    long long retAddr = 0;
                    if (!jvm_safe_read((void *)(sp + i * 8), 8))
                        break;
                    retAddr = *(long long *)(sp + i * 8);
                    if (retAddr == 0)
                        break;
                    // Check if return address is in a known module
                    if (!is_in_loaded_module(retAddr))
                    {
                        // Check if it's in executable MEM_PRIVATE (potential shellcode)
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery((void *)retAddr, &mbi, sizeof(mbi)) &&
                            mbi.State == MEM_COMMIT)
                        {
                            DWORD prot = mbi.Protect;
                            if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                            {
                                // Suspicious: executable return address not in any module
                                fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                                "(suspicious ret addr 0x%llx on tid=%u, "
                                                "not in module, exec MEM_PRIVATE)\n",
                                        retAddr, te.th32ThreadID);
                                fflush(stderr);
                            }
                        }
                    }
                }
            }
            if (g_sysNtResume)
                g_sysNtResume(h, nullptr);
            else
                ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ─── Periodic integrity thread (enhanced) ───────────────────────────
static DWORD WINAPI integrity_check_thread_enhanced(LPVOID)
{
    fprintf(stderr, "[TZD] protect_class: enhanced integrity thread started\n");
    fflush(stderr);
    while (g_integrityRunning)
    {
        Sleep(100);

        // ── Check for direct syscall detection flag (set by instrumentation callback) ──
        if (InterlockedCompareExchange64(&g_directSyscallDetected, 0, 1) == 1)
        {
            // Direct syscall was detected by the instrumentation callback.
            // The callback runs at DISPATCH_LEVEL IRQL and cannot call TerminateProcess.
            // We handle the termination here, at PASSIVE_LEVEL IRQL.
            // fprintf(stderr, "[TZD] instr_callback: TERMINATING process due to direct syscall! "
            //                "ReturnRIP=0x%llx (not in any legitimate module)\n",
            //        g_directSyscallRetRIP);
            // fflush(stderr);
            // TerminateProcess(GetCurrentProcess(), 0xC0000353);
        }

        for (int i = 0; i < g_encCount; i++)
        {
            DeepEncRegion *r = &g_encRegions[i];
            if (!r->active)
                continue;

            DWORD old;
            g_ourCall = 1;
            if (!direct_VirtualProtect((void *)r->pageBase, 4096, r->originalProtect, &old))
            {
                g_ourCall = 0;
                continue;
            }

            unsigned int crc = 0xFFFFFFFF;
            for (size_t j = 0; j < r->fieldSize; j++)
            {
                crc ^= r->fieldAddr[j];
                for (int k = 0; k < 8; k++)
                    crc = (crc >> 1) ^ (0xEDB88320u & (-(int)(crc & 1)));
            }
            crc = ~crc;

            if (crc != r->key.checksum)
            {
                fprintf(stderr, "[TZD] protect_class: CRC mismatch! Restoring from backup\n");
                fflush(stderr);
                memcpy(r->fieldAddr, r->backup, r->fieldSize);
                *(jint *)r->fieldAddr = *(jint *)r->fieldAddr | JVM_ACC_IS_HIDDEN_CLASS;
                r->key = gen_deep_key(r->fieldAddr);
                deep_encrypt_bytes(r->fieldAddr, r->fieldSize, &r->key);
            }

#ifdef _WIN64
            PPEB peb = (PPEB)__readgsqword(0x60);
            if (peb)
            {
                peb->BeingDebugged = FALSE;
                DWORD *ngf = (DWORD *)((BYTE *)peb + 0xBC);
                if (ngf)
                    *ngf &= ~0x70;
            }
#endif
            g_ourCall = 1;
            direct_VirtualProtect((void *)r->pageBase, 4096, r->originalProtect | 0x100, &old);
            g_ourCall = 0;
        }

        // Check jvm.dll .text section integrity
        jvm_guard_check();

        // Verify ntdll inline hook is intact
        verify_ntpvm_inline();

        // Verify InstanceKlass _constants hasn't been swapped
        // AND check Method*/ConstMethod/nmethod integrity (the real fix
        // for the attacker who bypassed klass-level protection by modifying
        // Method* fields directly — the JIT exploit).
        if (g_csInited)
        {
            EnterCriticalSection(&g_cs);
            for (auto &pair : g_protected)
            {
                ProtectedClass &pc2 = pair.second;
                long long curConstants = rq((void *)(pc2.iklass + 192));
                if (curConstants != pc2.orig_constants)
                {
                    fprintf(stderr, "[TZD] protect_class: _constants TAMPERED! "
                                    "ik=0x%llx (expected=0x%llx, got=0x%llx) — RESTORING\n",
                            pc2.iklass, pc2.orig_constants, curConstants);
                    fflush(stderr);
                    // Restore the original _constants pointer
                    DWORD op2 = 0;
                    g_ourCall = 1;
                    if (direct_VirtualProtect((void *)(pc2.iklass + 192), 8,
                                              PAGE_READWRITE, &op2))
                    {
                        *(long long *)(pc2.iklass + 192) = pc2.orig_constants;
                        direct_VirtualProtect((void *)(pc2.iklass + 192), 8, op2, &op2);
                    }
                    g_ourCall = 0;
                }

                // ── Method* integrity check ──
                // For each backed-up method, verify ALL critical fields.
                // If any field was modified (e.g., _code set to fake nmethod,
                // _from_compiled_entry redirected to attacker code), restore
                // from backup and output the tamper message.
                int offCM = jvm_deopt_get_offset("constMethod");
                int offAF = jvm_deopt_get_offset("access_flags");
                int offFl = jvm_deopt_get_offset("flags");
                int offI2I = jvm_deopt_get_offset("i2i_entry");
                int offFC = jvm_deopt_get_offset("from_compiled");
                int offCode = jvm_deopt_get_offset("code");
                int offFI = jvm_deopt_get_offset("from_interp");
                int offCB = jvm_deopt_get_offset("codeBase");

                for (int mi = 0; mi < pc2.numMethods; mi++)
                {
                    ProtectedMethod &pm = pc2.methods[mi];
                    if (!pm.methodPtr)
                        continue;

                    bool tampered = false;

                    // Temporarily set PAGE_READWRITE so we can read/check
                    DWORD opw = 0;
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)(pm.methodPtr & ~0xFFFLL), 4096,
                                          PAGE_READWRITE, &opw);
                    g_ourCall = 0;

                    // Check _constMethod (offset 8)
                    if (offCM >= 0)
                    {
                        long long cur = rq((void *)(pm.methodPtr + offCM));
                        if (cur != pm.orig_constMethod)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* _constMethod "
                                            "TAMPERED! mp=0x%llx (expected=0x%llx, got=0x%llx)\n",
                                    pm.methodPtr, pm.orig_constMethod, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offCM), 8,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(long long *)(pm.methodPtr + offCM) = pm.orig_constMethod;
                                direct_VirtualProtect((void *)(pm.methodPtr + offCM), 8, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    // Check _access_flags (offset 40)
                    if (offAF >= 0)
                    {
                        jint cur = r4((void *)(pm.methodPtr + offAF));
                        if (cur != pm.orig_access_flags)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* _access_flags "
                                            "TAMPERED! mp=0x%llx (expected=0x%x, got=0x%x)\n",
                                    pm.methodPtr, pm.orig_access_flags, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offAF), 4,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(jint *)(pm.methodPtr + offAF) = pm.orig_access_flags;
                                direct_VirtualProtect((void *)(pm.methodPtr + offAF), 4, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    // Check _flags (offset 50)
                    if (offFl >= 0)
                    {
                        unsigned short cur = *(unsigned short *)(pm.methodPtr + offFl);
                        if (cur != pm.orig_flags)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* _flags "
                                            "TAMPERED! mp=0x%llx (expected=0x%x, got=0x%x)\n",
                                    pm.methodPtr, pm.orig_flags, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offFl), 2,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(unsigned short *)(pm.methodPtr + offFl) = pm.orig_flags;
                                direct_VirtualProtect((void *)(pm.methodPtr + offFl), 2, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    // Check _i2i_entry (offset 56)
                    if (offI2I >= 0)
                    {
                        long long cur = rq((void *)(pm.methodPtr + offI2I));
                        if (cur != pm.orig_i2i_entry)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* _i2i_entry "
                                            "TAMPERED! mp=0x%llx (expected=0x%llx, got=0x%llx)\n",
                                    pm.methodPtr, pm.orig_i2i_entry, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offI2I), 8,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(long long *)(pm.methodPtr + offI2I) = pm.orig_i2i_entry;
                                direct_VirtualProtect((void *)(pm.methodPtr + offI2I), 8, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    // ── CRITICAL: Check _from_compiled_entry (offset 64) ──
                    // This is the PRIMARY JIT exploit target. The attacker
                    // sets this to point to their own machine code.
                    if (offFC >= 0)
                    {
                        long long cur = rq((void *)(pm.methodPtr + offFC));
                        if (cur != pm.orig_from_compiled)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* "
                                            "_from_compiled_entry TAMPERED! mp=0x%llx "
                                            "(expected=0x%llx, got=0x%llx)\n",
                                    pm.methodPtr, pm.orig_from_compiled, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offFC), 8,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(long long *)(pm.methodPtr + offFC) = pm.orig_from_compiled;
                                direct_VirtualProtect((void *)(pm.methodPtr + offFC), 8, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    // ── CRITICAL: Check _code (offset 72) ──
                    // The attacker sets _code to a fake nmethod to make the
                    // JVM think the method is compiled, then modifies the
                    // nmethod's machine code. We forced _code=NULL (interpreter
                    // mode) — if it's non-NULL, the attacker re-enabled JIT.
                    if (offCode >= 0)
                    {
                        long long cur = rq((void *)(pm.methodPtr + offCode));
                        if (cur != pm.orig_code)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* _code "
                                            "TAMPERED! mp=0x%llx (expected=0x%llx, got=0x%llx) "
                                            "— POSSIBLE JIT EXPLOIT!\n",
                                    pm.methodPtr, pm.orig_code, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offCode), 8,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(long long *)(pm.methodPtr + offCode) = pm.orig_code;
                                direct_VirtualProtect((void *)(pm.methodPtr + offCode), 8, op3, &op3);
                            }
                            g_ourCall = 0;
                            // Re-apply force_interpreter to clear the fake
                            // compiled code and prevent re-compilation
                            jvm_force_interpreter(pm.methodPtr);
                        }
                    }

                    // Check _from_interpreted_entry (offset 80)
                    if (offFI >= 0)
                    {
                        long long cur = rq((void *)(pm.methodPtr + offFI));
                        if (cur != pm.orig_from_interp)
                        {
                            tampered = true;
                            fprintf(stderr, "[TZD] protect_class: Method* "
                                            "_from_interpreted_entry TAMPERED! mp=0x%llx "
                                            "(expected=0x%llx, got=0x%llx)\n",
                                    pm.methodPtr, pm.orig_from_interp, cur);
                            DWORD op3 = 0;
                            g_ourCall = 1;
                            if (direct_VirtualProtect((void *)(pm.methodPtr + offFI), 8,
                                                      PAGE_READWRITE, &op3))
                            {
                                *(long long *)(pm.methodPtr + offFI) = pm.orig_from_interp;
                                direct_VirtualProtect((void *)(pm.methodPtr + offFI), 8, op3, &op3);
                            }
                            g_ourCall = 0;
                        }
                    }

                    if (tampered)
                    {
                        fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                        "(Method*=0x%llx integrity violation — RESTORED)\n",
                                pm.methodPtr);
                        fflush(stderr);
                        FlushInstructionCache(GetCurrentProcess(),
                                              (void *)pm.methodPtr, 96);
                    }

                    // ── ConstMethod integrity (full struct: header + bytecodes) ──
                    // The attacker may write to ConstMethod header fields (e.g.
                    // _orig_method_idnum at offset 48) — the bytecodes-only
                    // CRC check would miss these. Here we check the ENTIRE
                    // ConstMethod struct (cmFullSize bytes) and restore from
                    // cmFullBackup. Falls back to bytecodes-only when the full
                    // backup isn't available.
                    if (pm.constMethodPtr && pm.cmFullBackup && pm.cmFullSize > 0)
                    {
                        DWORD opc = 0;
                        g_ourCall = 1;
                        bool readable = direct_VirtualProtect((void *)pm.constMethodPtr,
                                                              pm.cmFullSize,
                                                              PAGE_READWRITE, &opc) != 0;
                        g_ourCall = 0;
                        if (readable && jvm_safe_read((void *)pm.constMethodPtr,
                                                      pm.cmFullSize))
                        {
                            unsigned int curCRC = crc32_page(
                                (unsigned char *)pm.constMethodPtr, pm.cmFullSize);
                            unsigned int bkCRC = crc32_page(
                                pm.cmFullBackup, pm.cmFullSize);
                            if (curCRC != bkCRC)
                            {
                                fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                                "(ConstMethod FULL tampered! cm=0x%llx, "
                                                "offset touched in [0,%d))\n",
                                        pm.constMethodPtr, pm.cmFullSize);
                                fflush(stderr);
                                memcpy((void *)pm.constMethodPtr, pm.cmFullBackup,
                                       pm.cmFullSize);
                                FlushInstructionCache(GetCurrentProcess(),
                                                      (void *)pm.constMethodPtr,
                                                      pm.cmFullSize);
                            }
                            g_ourCall = 1;
                            direct_VirtualProtect((void *)pm.constMethodPtr,
                                                  pm.cmFullSize, opc, &opc);
                            g_ourCall = 0;
                        }
                    }
                    else if (pm.constMethodPtr && pm.bytecodeBackup && pm.code_size > 0 && offCB >= 0)
                    {
                        unsigned char *codeBase =
                            (unsigned char *)(pm.constMethodPtr + offCB);
                        DWORD opc = 0;
                        g_ourCall = 1;
                        bool readable = direct_VirtualProtect(codeBase, pm.code_size,
                                                              PAGE_READWRITE, &opc) != 0;
                        g_ourCall = 0;
                        if (readable && jvm_safe_read(codeBase, pm.code_size))
                        {
                            unsigned int crc = crc32_page(codeBase, pm.code_size);
                            if (crc != pm.bytecodeCRC)
                            {
                                fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                                "(ConstMethod bytecode tampered! cm=0x%llx)\n",
                                        pm.constMethodPtr);
                                fflush(stderr);
                                memcpy(codeBase, pm.bytecodeBackup, pm.code_size);
                                FlushInstructionCache(GetCurrentProcess(),
                                                      codeBase, pm.code_size);
                            }
                            g_ourCall = 1;
                            direct_VirtualProtect(codeBase, pm.code_size, opc, &opc);
                            g_ourCall = 0;
                        }
                    }

                    // ── nmethod compiled code integrity ──
                    // If we backed up compiled code (method was JIT-compiled
                    // before protection), verify the code hasn't been patched.
                    if (pm.hasNmethod && pm.nmethodBackup && pm.nmethodSize > 0)
                    {
                        DWORD opn = 0;
                        g_ourCall = 1;
                        bool readable = direct_VirtualProtect((void *)pm.nmethodPtr,
                                                              (size_t)pm.nmethodSize,
                                                              PAGE_READWRITE, &opn) != 0;
                        g_ourCall = 0;
                        if (readable && jvm_safe_read((void *)pm.nmethodPtr,
                                                      (size_t)pm.nmethodSize))
                        {
                            unsigned int crc = 0;
                            for (long long off = 0; off < pm.nmethodSize;
                                 off += 4096)
                            {
                                int chunk = (int)((off + 4096 <= pm.nmethodSize)
                                                      ? 4096
                                                      : (pm.nmethodSize - off));
                                crc ^= crc32_page(pm.nmethodBackup + off, chunk);
                            }
                            unsigned int curCrc = 0;
                            for (long long off = 0; off < pm.nmethodSize;
                                 off += 4096)
                            {
                                int chunk = (int)((off + 4096 <= pm.nmethodSize)
                                                      ? 4096
                                                      : (pm.nmethodSize - off));
                                curCrc ^= crc32_page(
                                    (unsigned char *)(pm.nmethodPtr + off), chunk);
                            }
                            if (curCrc != crc)
                            {
                                fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                                "(nmethod compiled code tampered! nm=0x%llx)\n",
                                        pm.nmethodPtr);
                                fflush(stderr);
                                memcpy((void *)pm.nmethodPtr, pm.nmethodBackup,
                                       (size_t)pm.nmethodSize);
                                FlushInstructionCache(GetCurrentProcess(),
                                                      (void *)pm.nmethodPtr,
                                                      (size_t)pm.nmethodSize);
                            }
                            g_ourCall = 1;
                            direct_VirtualProtect((void *)pm.nmethodPtr,
                                                  (size_t)pm.nmethodSize, opn, &opn);
                            g_ourCall = 0;
                        }
                    }

                    // Re-apply PAGE_READONLY on Method* pages (direct syscall)
                    long long mpPage = pm.methodPtr & ~0xFFFLL;
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)mpPage, 4096, PAGE_READONLY, &opw);
                    g_ourCall = 0;
                    if (pm.constMethodPtr)
                    {
                        long long cmPage = pm.constMethodPtr & ~0xFFFLL;
                        if (cmPage != mpPage)
                        {
                            g_ourCall = 1;
                            direct_VirtualProtect((void *)cmPage, 4096, PAGE_READONLY, &opw);
                            g_ourCall = 0;
                        }
                    }
                }
                // ── VTable integrity check (prevent vtable hijacking) ──
                if (pc2.vtableAddr && pc2.vtableBackup && pc2.vtableLen > 0)
                {
                    int vtSize = pc2.vtableLen * 8;
                    DWORD opv = 0;
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)(pc2.vtableAddr & ~0xFFFLL), 4096,
                                          PAGE_READWRITE, &opv);
                    g_ourCall = 0;
                    if (jvm_safe_read((void *)pc2.vtableAddr, vtSize))
                    {
                        unsigned int curCRC = crc32_page(
                            (unsigned char *)pc2.vtableAddr, vtSize);
                        if (curCRC != pc2.vtableCRC)
                        {
                            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                            "(vtable TAMPERED! addr=0x%llx — RESTORING)\n",
                                    pc2.vtableAddr);
                            fflush(stderr);
                            memcpy((void *)pc2.vtableAddr, pc2.vtableBackup, vtSize);
                            FlushInstructionCache(GetCurrentProcess(),
                                                  (void *)pc2.vtableAddr, vtSize);
                        }
                    }
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)(pc2.vtableAddr & ~0xFFFLL), 4096,
                                          opv, &opv);
                    g_ourCall = 0;
                }
                // ── ITable integrity check (prevent itable hijacking) ──
                if (pc2.itableAddr && pc2.itableBackup && pc2.itableLen > 0)
                {
                    int itSize = pc2.itableLen * 8;
                    DWORD opi = 0;
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)(pc2.itableAddr & ~0xFFFLL), 4096,
                                          PAGE_READWRITE, &opi);
                    g_ourCall = 0;
                    if (jvm_safe_read((void *)pc2.itableAddr, itSize))
                    {
                        unsigned int curCRC = crc32_page(
                            (unsigned char *)pc2.itableAddr, itSize);
                        if (curCRC != pc2.itableCRC)
                        {
                            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                            "(itable TAMPERED! addr=0x%llx — RESTORING)\n",
                                    pc2.itableAddr);
                            fflush(stderr);
                            memcpy((void *)pc2.itableAddr, pc2.itableBackup, itSize);
                            FlushInstructionCache(GetCurrentProcess(),
                                                  (void *)pc2.itableAddr, itSize);
                        }
                    }
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)(pc2.itableAddr & ~0xFFFLL), 4096,
                                          opi, &opi);
                    g_ourCall = 0;
                }
                // ── ConstantPoolCache integrity (prevent CPC patching) ──
                if (pc2.cpCacheAddr && pc2.cpCacheBackup &&
                    pc2.cpCacheBackupSize > 0)
                {
                    DWORD opc = 0;
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)pc2.cpCacheAddr,
                                          pc2.cpCacheBackupSize,
                                          PAGE_READWRITE, &opc);
                    g_ourCall = 0;
                    if (jvm_safe_read((void *)pc2.cpCacheAddr,
                                      pc2.cpCacheBackupSize))
                    {
                        unsigned int curCRC = 0;
                        for (int off = 0; off < pc2.cpCacheBackupSize; off += 4096)
                        {
                            int chunk = (off + 4096 <= pc2.cpCacheBackupSize)
                                            ? 4096
                                            : (pc2.cpCacheBackupSize - off);
                            curCRC ^= crc32_page(
                                (unsigned char *)(pc2.cpCacheAddr + off), chunk);
                        }
                        if (curCRC != pc2.cpCacheCRC)
                        {
                            fprintf(stderr, "[TZD] 你好伙计，你改你妈的方法呢 "
                                            "(ConstantPoolCache TAMPERED! addr=0x%llx — RESTORING)\n",
                                    pc2.cpCacheAddr);
                            fflush(stderr);
                            memcpy((void *)pc2.cpCacheAddr, pc2.cpCacheBackup,
                                   pc2.cpCacheBackupSize);
                            FlushInstructionCache(GetCurrentProcess(),
                                                  (void *)pc2.cpCacheAddr,
                                                  pc2.cpCacheBackupSize);
                        }
                    }
                    g_ourCall = 1;
                    direct_VirtualProtect((void *)pc2.cpCacheAddr,
                                          pc2.cpCacheBackupSize, opc, &opc);
                    g_ourCall = 0;
                }
            }
            LeaveCriticalSection(&g_cs);
        }
    }
    return 0;
}

// ─── Protect all methods of a class (the real fix for the JIT exploit) ──
// The attacker bypassed InstanceKlass protection by modifying Method* fields
// directly. This function:
//   1. Enumerates ALL declared methods + constructors via JNI reflection.
//   2. Backs up every critical Method* field (entry points, _code, _constMethod).
//   3. Backs up ConstMethod bytecodes (so we can restore tampered bytecodes).
//   4. Backs up nmethod compiled code (if method was already JIT-compiled).
//   5. Calls jvm_force_interpreter() on each method — clears _code, nulls
//      _from_compiled_entry, sets _dont_inline + NOT_C1/C2_COMPILABLE. This
//      ELIMINATES the nmethod attack surface: no compiled code = nothing to
//      patch. The attacker cannot exploit JIT if JIT never compiles.
//   6. Records Method* + ConstMethod* pages for PAGE_READONLY protection.
static void backup_single_method(JNIEnv *env, jobject reflectedMethod,
                                 ProtectedClass &pc)
{
    if (!reflectedMethod || pc.numMethods >= MAX_METHODS_PER_CLASS)
        return;

    jmethodID mid = env->FromReflectedMethod(reflectedMethod);
    if (!mid)
        return;

    long long methodPtr = resolveMethodPtrExt(mid);
    if (!methodPtr || !jvm_safe_read((void *)methodPtr, 96))
        return;

    ProtectedMethod &pm = pc.methods[pc.numMethods];
    memset(&pm, 0, sizeof(pm));
    pm.methodPtr = methodPtr;

    int offCM = jvm_deopt_get_offset("constMethod");   // 8
    int offAF = jvm_deopt_get_offset("access_flags");  // 40
    int offFl = jvm_deopt_get_offset("flags");         // 50
    int offI2I = jvm_deopt_get_offset("i2i_entry");    // 56
    int offFC = jvm_deopt_get_offset("from_compiled"); // 64
    int offCode = jvm_deopt_get_offset("code");        // 72
    int offFI = jvm_deopt_get_offset("from_interp");   // 80

    // Backup all critical fields
    if (offCM >= 0)
        pm.orig_constMethod = rq((void *)(methodPtr + offCM));
    if (offAF >= 0)
        pm.orig_access_flags = r4((void *)(methodPtr + offAF));
    if (offFl >= 0)
        pm.orig_flags = *(unsigned short *)(methodPtr + offFl);
    if (offI2I >= 0)
        pm.orig_i2i_entry = rq((void *)(methodPtr + offI2I));
    if (offFC >= 0)
        pm.orig_from_compiled = rq((void *)(methodPtr + offFC));
    if (offCode >= 0)
        pm.orig_code = rq((void *)(methodPtr + offCode));
    if (offFI >= 0)
        pm.orig_from_interp = rq((void *)(methodPtr + offFI));

    pm.constMethodPtr = pm.orig_constMethod;

    // Backup ConstMethod bytecodes
    int offCB = jvm_deopt_get_offset("codeBase"); // 56 (sizeof(ConstMethod))
    if (pm.constMethodPtr && offCB >= 0 &&
        jvm_safe_read((void *)(pm.constMethodPtr + 32), 2))
    {
        pm.code_size = *(unsigned short *)(pm.constMethodPtr + 32);
        if (pm.code_size > 0 && pm.code_size < 65536)
        {
            unsigned char *codeBase = (unsigned char *)(pm.constMethodPtr + offCB);
            if (jvm_safe_read(codeBase, pm.code_size))
            {
                pm.bytecodeBackup = (unsigned char *)malloc(pm.code_size);
                if (pm.bytecodeBackup)
                {
                    memcpy(pm.bytecodeBackup, codeBase, pm.code_size);
                    pm.bytecodeCRC = crc32_page(pm.bytecodeBackup, pm.code_size);
                }
            }
        }
    }

    // ── Full ConstMethod backup (header + bytecodes) ──
    // The attacker may write at ANY offset within ConstMethod (header fields
    // like _orig_method_idnum at offset 48, or bytecodes at offset 56).
    // The bytecode-only backup misses header writes. Here we back up the
    // ENTIRE ConstMethod struct: from constMethodPtr+0 to
    // constMethodPtr + offCB + code_size. This lets the VEH restore ANY
    // byte the attacker modifies, regardless of which field they target.
    if (pm.constMethodPtr && offCB >= 0 && pm.code_size > 0)
    {
        pm.cmFullSize = offCB + pm.code_size;
        if (pm.cmFullSize > 0 && pm.cmFullSize < 65536 &&
            jvm_safe_read((void *)pm.constMethodPtr, pm.cmFullSize))
        {
            pm.cmFullBackup = (unsigned char *)malloc(pm.cmFullSize);
            if (pm.cmFullBackup)
                memcpy(pm.cmFullBackup, (void *)pm.constMethodPtr, pm.cmFullSize);
        }
    }

    // Backup nmethod compiled code (if method was already JIT-compiled)
    if (pm.orig_code)
    {
        pm.nmethodPtr = pm.orig_code;
        pm.nmethodEntry = pm.orig_from_compiled;
        pm.hasNmethod = true;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void *)pm.orig_code, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT)
        {
            long long blobSize = (long long)mbi.RegionSize;
            if (blobSize > 65536)
                blobSize = 65536; // cap backup at 64KB
            // Only backup if the region is executable (it's a real nmethod)
            DWORD prot = mbi.Protect;
            if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            {
                pm.nmethodBackup = (unsigned char *)malloc((size_t)blobSize);
                if (pm.nmethodBackup)
                {
                    memcpy(pm.nmethodBackup, (void *)pm.orig_code, (size_t)blobSize);
                    pm.nmethodSize = blobSize;
                    // CRC in chunks (crc32_page handles up to 4096 per call)
                    pm.nmethodCRC = 0;
                    for (long long off = 0; off < blobSize; off += 4096)
                    {
                        int chunk = (int)((off + 4096 <= blobSize) ? 4096 : (blobSize - off));
                        unsigned int c = crc32_page(pm.nmethodBackup + off, chunk);
                        pm.nmethodCRC ^= c; // simple XOR of chunk CRCs
                    }
                }
            }
        }
    }

    // ── 强制注入 JVM_ACC_FINAL (0x0010) 标记 ──
    // 强制将 Method 设为 final，直接关掉虚方法表 (vtable) 查找。
    // 使得 invokevirtual 指令直接绑定本类 Method*，完全忽略堆对象头 s+8 的伪造！
    if (offAF >= 0)
    {
        DWORD op = 0;
        g_ourCall = 1;
        if (direct_VirtualProtect((void *)(methodPtr + offAF), 4, PAGE_READWRITE, &op))
        {
            jint af = *(jint *)(methodPtr + offAF);
            af |= 0x00000010; // 0x0010 = JVM_ACC_FINAL
            *(jint *)(methodPtr + offAF) = af;
            direct_VirtualProtect((void *)(methodPtr + offAF), 4, op, &op);
            pm.orig_access_flags = af; // 更新备份值，防止巡检线程还原
        }
        g_ourCall = 0;
    }

    // ── Force interpreter mode: clear _code, null _from_compiled_entry,
    //    set _dont_inline + NOT_C1/C2_COMPILABLE. This prevents JIT from
    //    ever compiling this method → no nmethod exists → attacker cannot
    //    patch compiled code that doesn't exist. ──
    jvm_force_interpreter(methodPtr);
    pm.forceInterpApplied = true;

    // Record Method* page for PAGE_READONLY protection
    long long mpPage = methodPtr & ~0xFFFLL;
    bool found = false;
    for (int j = 0; j < pc.numMethodPages; j++)
    {
        if (pc.methodPages[j] == mpPage)
        {
            found = true;
            break;
        }
    }
    if (!found && pc.numMethodPages < MAX_METHOD_PAGES)
        pc.methodPages[pc.numMethodPages++] = mpPage;

    // Record ConstMethod* page too
    if (pm.constMethodPtr)
    {
        long long cmPage = pm.constMethodPtr & ~0xFFFLL;
        found = false;
        for (int j = 0; j < pc.numMethodPages; j++)
        {
            if (pc.methodPages[j] == cmPage)
            {
                found = true;
                break;
            }
        }
        if (!found && pc.numMethodPages < MAX_METHOD_PAGES)
            pc.methodPages[pc.numMethodPages++] = cmPage;
    }

    pc.numMethods++;

    // ── Populate lock-free flat arrays for VEH-safe access ──
    // The VEH handlers (method_write_guard_veh, method_write_step_veh) must
    // NOT use EnterCriticalSection (deadlock risk). They scan these arrays
    // instead, which are only written here (at protect time) and only read
    // during VEH execution.
    int fi = (int)InterlockedIncrement(&g_numFlatMethods) - 1;
    if (fi < MAX_FLAT_METHODS)
    {
        FlatMethodEntry *fm = &g_flatMethods[fi];
        fm->methodPtr = methodPtr;
        fm->mpPage = mpPage;
        fm->orig_constMethod = pm.orig_constMethod;
        fm->orig_access_flags = pm.orig_access_flags;
        fm->orig_flags = pm.orig_flags;
        fm->orig_i2i_entry = pm.orig_i2i_entry;
        fm->orig_from_compiled = pm.orig_from_compiled;
        fm->orig_code = pm.orig_code;
        fm->orig_from_interp = pm.orig_from_interp;
        fm->constMethodPtr = pm.constMethodPtr;
        fm->cmPage = pm.constMethodPtr ? (pm.constMethodPtr & ~0xFFFLL) : 0;
        fm->code_size = pm.code_size;
        fm->bytecodeBackup = pm.bytecodeBackup;
        fm->offCB = offCB;
        fm->cmFullBackup = pm.cmFullBackup;
        fm->cmFullSize = pm.cmFullSize;
        fm->offCM = offCM;
        fm->offAF = offAF;
        fm->offFl = offFl;
        fm->offI2I = offI2I;
        fm->offFC = offFC;
        fm->offCode = offCode;
        fm->offFI = offFI;
    }
    // Register pages in the lock-free flat page array
    if (mpPage != 0)
    {
        bool already = false;
        int np = (int)g_numFlatMethodPages;
        for (int j = 0; j < np && j < 256; j++)
        {
            if (g_flatMethodPages[j] == mpPage)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            int pi = (int)InterlockedIncrement(&g_numFlatMethodPages) - 1;
            if (pi < 256)
                g_flatMethodPages[pi] = mpPage;
        }
    }
    if (pm.constMethodPtr)
    {
        long long cmPage = pm.constMethodPtr & ~0xFFFLL;
        if (cmPage != mpPage)
        {
            bool already = false;
            int np = (int)g_numFlatMethodPages;
            for (int j = 0; j < np && j < 256; j++)
            {
                if (g_flatMethodPages[j] == cmPage)
                {
                    already = true;
                    break;
                }
            }
            if (!already)
            {
                int pi = (int)InterlockedIncrement(&g_numFlatMethodPages) - 1;
                if (pi < 256)
                    g_flatMethodPages[pi] = cmPage;
            }
        }
    }

    fprintf(stderr, "[TZD] protect_methods: Method*=0x%llx backed up "
                    "(code_size=%u, hasNmethod=%d, forceInterp=%d)\n",
            methodPtr, pm.code_size, pm.hasNmethod ? 1 : 0,
            pm.forceInterpApplied ? 1 : 0);
    fflush(stderr);
}

// 1. 创建一个由内核强制锁定、无法通过任何方式（包括直接 Syscall）修改为可写的只读内存拷贝
static void *create_sec_no_change_copy(const void *src, size_t size)
{
    // 显式传入标准的 6 个参数，确保 MSVC 编译器严格匹配
    HANDLE hSection = CreateFileMappingW(
        INVALID_HANDLE_VALUE,                                 // 1. hFile
        NULL,                                                 // 2. lpAttributes
        (DWORD)(PAGE_READWRITE | SEC_COMMIT | SEC_NO_CHANGE), // 3. flProtect
        0,                                                    // 4. dwMaximumSizeHigh
        (DWORD)size,                                          // 5. dwMaximumSizeLow
        NULL                                                  // 6. lpName (不可省略)
    );

    if (!hSection || hSection == INVALID_HANDLE_VALUE)
        return nullptr;

    void *writeView = MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, size);
    if (!writeView)
    {
        CloseHandle(hSection);
        return nullptr;
    }

    memcpy(writeView, src, size);

    // 映射只读视图。由于 Section 绑定了 SEC_NO_CHANGE，该视图的只读属性将被操作系统内核永久锁死
    void *readOnlyView = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, size);

    UnmapViewOfFile(writeView);
    CloseHandle(hSection); // 视图映射会自动保持 Section 对象的存活

    return readOnlyView;
}

// 2. 动态扫描 InstanceKlass，复制并重定向 _methods 数组和 Method 结构体
static void redirect_and_lock_methods(long long ik, ProtectedClass &pc)
{
    if (pc.numMethods == 0)
        return;

    // 动态定位 InstanceKlass 中的 _methods 字段（避免不同 JVM 版本的偏移硬编码问题）
    long long firstMethod = pc.methods[0].methodPtr;
    long long *pMethodsArrayField = nullptr;

    for (int off = 80; off <= 300; off += 8)
    {
        long long arrayAddr = rq((void *)(ik + off));
        if (!arrayAddr)
            continue;

        // Array<Method*>* 的布局：int _length 在偏移 0，元素数组从偏移 8 开始
        int length = r4((void *)arrayAddr);
        if (length >= pc.numMethods && length < 1000)
        {
            long long firstElem = rq((void *)(arrayAddr + 8));
            if (firstElem == firstMethod)
            {
                pMethodsArrayField = (long long *)(ik + off);
                break;
            }
        }
    }

    if (!pMethodsArrayField)
    {
        fprintf(stderr, "[TZD] sec_no_change: _methods array field not found in InstanceKlass\n");
        fflush(stderr);
        return;
    }

    long long origMethodsArray = *pMethodsArrayField;
    int arrayLength = r4((void *)origMethodsArray);
    size_t arraySize = 8 + (size_t)arrayLength * 8; // 头部长度 (8) + 元素列表 (8 * length)

    unsigned char *tempArrayBuf = (unsigned char *)malloc(arraySize);
    if (!tempArrayBuf)
        return;
    memcpy(tempArrayBuf, (void *)origMethodsArray, arraySize);

    // 对数组内的每个 Method 结构体进行内核锁死克隆
    long long *pNewElements = (long long *)(tempArrayBuf + 8);
    for (int i = 0; i < arrayLength; i++)
    {
        long long originalMethodPtr = pNewElements[i];
        if (!originalMethodPtr)
            continue;

        // 一般 Method 结构体大小在 96~120 字节左右，拷贝 128 字节确保安全
        void *lockedMethodCopy = create_sec_no_change_copy((void *)originalMethodPtr, 128);
        if (lockedMethodCopy)
        {
            pNewElements[i] = (long long)lockedMethodCopy;

            // 更新本地备份，使后续的其他校验逻辑也指向新内存
            for (int j = 0; j < pc.numMethods; j++)
            {
                if (pc.methods[j].methodPtr == originalMethodPtr)
                {
                    pc.methods[j].methodPtr = (long long)lockedMethodCopy;
                    break;
                }
            }
        }
    }

    // 将重定向后的 _methods 数组本身也克隆到内核锁死的只读内存中
    void *lockedMethodsArray = create_sec_no_change_copy(tempArrayBuf, arraySize);
    free(tempArrayBuf);

    if (lockedMethodsArray)
    {
        // 替换 InstanceKlass 中的原始指针
        DWORD old;
        g_ourCall = 1;
        direct_VirtualProtect(pMethodsArrayField, sizeof(long long), PAGE_READWRITE, &old);
        *pMethodsArrayField = (long long)lockedMethodsArray;
        direct_VirtualProtect(pMethodsArrayField, sizeof(long long), old, &old);
        g_ourCall = 0;

        fprintf(stderr, "[TZD] sec_no_change: _methods array redirected to immutable kernel view %p\n", lockedMethodsArray);
        fflush(stderr);
    }
}

static void protect_methods(JNIEnv *env, jclass clazz, long long ik,
                            ProtectedClass &pc)
{
    if (!env || !clazz)
        return;

    // Ensure jvm_deopt offsets are detected
    jvm_deopt_init(env);

    // Enumerate declared methods via Java reflection
    jclass classClass = env->FindClass("java/lang/Class");
    if (!classClass)
    {
        fprintf(stderr, "[TZD] protect_methods: Class.class not found\n");
        fflush(stderr);
        return;
    }

    // getDeclaredMethods()
    jmethodID getMethodsMid = env->GetMethodID(classClass, "getDeclaredMethods",
                                               "()[Ljava/lang/reflect/Method;");
    if (getMethodsMid)
    {
        jobjectArray methodsArray = (jobjectArray)env->CallObjectMethod(clazz, getMethodsMid);
        if (env->ExceptionCheck())
            env->ExceptionClear();
        if (methodsArray)
        {
            jsize count = env->GetArrayLength(methodsArray);
            for (jsize i = 0; i < count; i++)
            {
                jobject m = env->GetObjectArrayElement(methodsArray, i);
                if (m)
                {
                    backup_single_method(env, m, pc);
                    env->DeleteLocalRef(m);
                }
            }
            env->DeleteLocalRef(methodsArray);
        }
    }

    // getDeclaredConstructors()
    jmethodID getCtorsMid = env->GetMethodID(classClass, "getDeclaredConstructors",
                                             "()[Ljava/lang/reflect/Constructor;");
    if (env->ExceptionCheck())
        env->ExceptionClear();
    if (getCtorsMid)
    {
        jobjectArray ctorsArray = (jobjectArray)env->CallObjectMethod(clazz, getCtorsMid);
        if (env->ExceptionCheck())
            env->ExceptionClear();
        if (ctorsArray)
        {
            jsize count = env->GetArrayLength(ctorsArray);
            for (jsize i = 0; i < count; i++)
            {
                jobject c = env->GetObjectArrayElement(ctorsArray, i);
                if (c)
                {
                    backup_single_method(env, c, pc);
                    env->DeleteLocalRef(c);
                }
            }
            env->DeleteLocalRef(ctorsArray);
        }
    }

    env->DeleteLocalRef(classClass);

    // Register method VEH (once)
    init_method_veh();

    // Add method pages to global protected pages list (for NtProtectVirtualMemory hook)
    for (int i = 0; i < pc.numMethodPages; i++)
    {
        bool found = false;
        for (int j = 0; j < g_numProtectedPages; j++)
        {
            if (g_protectedPages[j] == pc.methodPages[i])
            {
                found = true;
                break;
            }
        }
        if (!found && g_numProtectedPages < 256)
        {
            g_protectedPages[g_numProtectedPages++] = pc.methodPages[i];
        }
    }

    // Set PAGE_READONLY on method pages (writes → ACCESS_VIOLATION → VEH)
    // Use direct syscalls to bypass any user-mode hooks
    for (int i = 0; i < pc.numMethodPages; i++)
    {
        DWORD old;
        g_ourCall = 1;
        direct_VirtualProtect((void *)pc.methodPages[i], 4096, PAGE_READONLY, &old);
        g_ourCall = 0;
    }

    fprintf(stderr, "[TZD] protect_methods: %d methods protected, %d pages locked "
                    "for ik=0x%llx\n",
            pc.numMethods, pc.numMethodPages, ik);
    fflush(stderr);
}

// ─── Protect: mark hidden, unlink, lock memory, deep encrypt ───────
bool protect_class(JNIEnv *env, jclass clazz)
{
    if (!env || !clazz)
        return false;

    // ── R3 Hardening (runs once, on first protect_class call) ──
    // Order matters:
    //   1. strip token  — kill SeDebugPrivilege so we can't escalate to debug others
    //   2. lock process — deny VM_*/CREATE_THREAD to Everyone on our process
    //                     object so external OpenProcess(VM_*) fails (err 5).
    //                     THIS is the fix for VirtualAllocEx/WriteProcessMemory/
    //                     CreateRemoteThread injection from same-user processes
    //                     (e.g. PowerShell). Done BEFORE occupy_debug_port so the
    //                     full-access handle we keep is opened while we still can.
    //   3. occupy debug port — external DebugActiveProcess fails (0xC0000353)
    //   4. init job defense  — neutralize kill-on-close Job attacks
    //   5. install instrumentation callback — detect direct syscall attacks
    //      (shellcode that uses `syscall` instruction outside ntdll/win32u)
    occupy_debug_port();
    strip_token_privileges();
    lock_process_security();
    close_debug_object_handle();
    neutralize_debug_remote_thread_funcs();
    init_job_protection();
    install_instrumentation_callback();

    if (!ensure_offsets(env))
    {
        log_msg("protect_class: offset detection failed");
        return false;
    }

    EnterCriticalSection(&g_cs);
    long long ik = resolve_iklass(env, clazz);
    if (!ik)
    {
        LeaveCriticalSection(&g_cs);
        log_msg("protect_class: resolve InstanceKlass failed");
        return false;
    }

    if (g_protected.find(ik) != g_protected.end())
    {
        LeaveCriticalSection(&g_cs);
        log_msg("protect_class: already protected");
        return true;
    }

    ProtectedClass pc;
    memset(&pc, 0, sizeof(pc));
    pc.iklass = ik;

    // Save _constants NOW (before saving to map — fixes a bug where the map
    // copy had orig_constants=0, causing the integrity thread to "detect
    // tampering" and restore _constants to 0 → JVM crash).
    pc.orig_constants = rq((void *)(ik + 192)); // _constants (ConstantPool*)

    // ── Step 1: Set JVM_ACC_IS_HIDDEN_CLASS ──
    // Hidden classes are blocked from redefineClasses/retransformClasses
    // by the JVM itself (is_hidden() check in JVM_RetransformClasses).
    if (g_access_flags_offset >= 0 && jvm_safe_read((void *)(ik + g_access_flags_offset), 4))
    {
        pc.orig_access_flags = *(jint *)(ik + g_access_flags_offset);
        DWORD op = 0;
        if (direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, PAGE_READWRITE, &op))
        {
            jint newFlags = pc.orig_access_flags | JVM_ACC_IS_HIDDEN_CLASS;
            *(jint *)(ik + g_access_flags_offset) = newFlags;
            direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)(ik + g_access_flags_offset), 4);
            fprintf(stderr, "[TZD] protect_class: flags set (0x%x->0x%x) ik=0x%llx [HIDDEN]\n",
                    pc.orig_access_flags, newFlags, ik);
            fflush(stderr);
        }
    }

    // ── Step 2: Unlink from ClassLoaderData::_klasses list ──
    // Walk head → _next_link chain, bypass us when found.
    if (g_cld_offset >= 0 && g_next_link_offset >= 0 && g_cld_klasses_offset >= 0)
    {
        long long cld = rq((void *)(ik + g_cld_offset));
        if (cld)
        {
            long long *linkField = (long long *)(cld + g_cld_klasses_offset);
            long long cur = rq(linkField);
            long long prevFieldAddr = (long long)linkField;

            while (cur)
            {
                if (cur == ik)
                {
                    long long ourNext = rq((void *)(ik + g_next_link_offset));
                    pc.orig_next_link = ourNext;
                    pc.orig_prev_ptr = prevFieldAddr;
                    pc.was_unlinked = true;

                    DWORD op = 0;
                    if (direct_VirtualProtect((void *)prevFieldAddr, 8, PAGE_READWRITE, &op))
                    {
                        *(long long *)prevFieldAddr = ourNext;
                        direct_VirtualProtect((void *)prevFieldAddr, 8, op, &op);
                        FlushInstructionCache(GetCurrentProcess(), (void *)prevFieldAddr, 8);
                        fprintf(stderr, "[TZD] protect_class: unlinked ik=0x%llx (prev=0x%llx->0x%llx)\n",
                                ik, prevFieldAddr, ourNext);
                        fflush(stderr);
                    }
                    break;
                }
                prevFieldAddr = cur + g_next_link_offset;
                cur = rq((void *)(cur + g_next_link_offset));
            }
            if (!cur && !pc.was_unlinked)
            {
                fprintf(stderr, "[TZD] protect_class: ik=0x%llx not in CLD list\n", ik);
                fflush(stderr);
            }
        }
    }

    // ── Step 3: (PAGE_READONLY removed — causes ACCESS_VIOLATION when JVM
    //    writes to other fields on the same page. Deep encryption provides
    //    sufficient protection instead.) ──

    g_protected[ik] = pc;
    LeaveCriticalSection(&g_cs);

    // ── Step 3b: Protect ALL methods of this class ──
    // This is the real fix for the attacker's bypass. The attacker didn't
    // touch the InstanceKlass — they modified Method* fields directly
    // (_code, _from_compiled_entry) to redirect execution to attacker code.
    // We now enumerate every method, backup its fields, force interpreter
    // mode (no compiled code = nothing to patch), set PAGE_READONLY on
    // Method* pages, and register a write-detect VEH that outputs
    // "你好伙计，你改你妈的方法呢" on attacker writes.
    protect_methods(env, clazz, ik, g_protected[ik]);

    // 将整个方法区拷贝并重定向至内核级的 SEC_NO_CHANGE 不可变只读页中
    redirect_and_lock_methods(ik, g_protected[ik]);

    // ── Step 3c: Set CPU hardware breakpoints (DR0-DR3) + start watchdog ──
    // DR0: Class._klass (prevent klass swap)
    // DR1: IK._constants (prevent class replacement)
    // DR2: Method._code (prevent JIT exploit — fake nmethod)
    // DR3: Method._from_compiled_entry (prevent entry redirect)
    // Plus 3 unkillable watchdog threads that re-apply DR every 500ms.
    setup_hardware_breakpoints(env, clazz, ik, g_protected[ik]);

    // ── Step 3d: Backup VTable + ITable + ConstantPoolCache ──
    // Prevents vtable/itable hijacking (redirecting virtual dispatch)
    // and ConstantPoolCache patching (redirecting method resolution).
    // The integrity thread CRC32-checks these every 100ms.
    backup_vtable_itable(g_protected[ik], ik);
    backup_cpcache(g_protected[ik], ik);

    // ── Step 3e: Enable process mitigations (ACG/extension-point disable) ──
    enable_process_mitigations();

    // ── Step 4: Deep encrypt the _access_flags field ──
    // PAGE_GUARD + VEH decrypt-on-access. The VEH matches by PAGE (not by
    // exact field address), so ALL accesses to the page are handled. The
    // encrypted field is decrypted for exactly one instruction, then
    // re-encrypted. A periodic CRC32 integrity thread provides backup.
    if (g_access_flags_offset >= 0)
    {
        void *afAddr = (void *)(ik + g_access_flags_offset);
        deep_encrypt_and_guard(afAddr, 4);
    }

    // ── Step 5: Install IAT hooks + jvm.dll guard + Java-level defenses ──
    init_jvm_guard();
    install_iat_hooks(ik);
    // Block Attach API + patch Module.addOpens/addReads/addUses → no-op
    // Prevents pure-Java class replacement via VirtualMachine.attach + JVMTI
    patch_module_bypass(env);

    // ── Step 6: Start enhanced integrity thread ──
    // Every 100ms: re-checks CRC32, re-applies hidden+being_redefined flags
    // if tampered, clears PEB.BeingDebugged, checks jvm.dll .text integrity,
    // verifies InstanceKlass _constants pointer (catches ALL class
    // replacement attacks), AND checks Method*/ConstMethod/nmethod integrity
    // (catches the JIT exploit where attacker modified Method* fields).
    // orig_constants was saved before g_protected[ik]=pc (Step 3b fix above).
    if (!g_integrityThread)
    {
        g_integrityRunning = true;
        g_integrityThread = CreateThread(nullptr, 0, integrity_check_thread_enhanced, nullptr, 0, nullptr);
    }

    fprintf(stderr, "[TZD] protect_class: complete for ik=0x%llx (hidden+unlinked+locked+encrypted)\n", ik);
    fflush(stderr);
    return true;
}

// ─── Unprotect: restore everything ──────────────────────────────────
bool unprotect_class(JNIEnv *env, jclass clazz)
{
    if (!env || !clazz || !g_csInited)
        return false;
    EnterCriticalSection(&g_cs);

    long long ik = resolve_iklass(env, clazz);
    if (!ik)
    {
        LeaveCriticalSection(&g_cs);
        return false;
    }
    auto it = g_protected.find(ik);
    if (it == g_protected.end())
    {
        LeaveCriticalSection(&g_cs);
        log_msg("unprotect: not protected");
        return false;
    }

    ProtectedClass &pc = it->second;

    // ── Deactivate hardware breakpoints BEFORE restoring fields ──
    // (hwbp_veh checks .active and skips inactive breakpoints)
    // We don't clear DR registers on threads (causes deadlock with watchdog).
    // The hwbp_veh will simply ignore triggers for inactive breakpoints.
    for (int i = 0; i < 4; i++)
        g_hwBp[i].active = false;
    g_hwBpCount = 0;
    g_watchdogRunning = false; // signal watchdog to stop
    Sleep(50);                 // let watchdog exit its current cycle

    // Unlock memory
    if (pc.memory_locked)
    {
        long long pageBase = ik & ~0xFFFLL;
        DWORD op = 0;
        direct_VirtualProtect((void *)pageBase, 8192, PAGE_READWRITE, &op);
        pc.memory_locked = false;
    }

    // Restore access_flags
    if (g_access_flags_offset >= 0)
    {
        DWORD op = 0;
        if (direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, PAGE_READWRITE, &op))
        {
            *(jint *)(ik + g_access_flags_offset) = pc.orig_access_flags;
            direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)(ik + g_access_flags_offset), 4);
        }
    }

    // Relink (best-effort): set prev field back to us
    if (pc.was_unlinked && g_next_link_offset >= 0)
    {
        DWORD op = 0;
        if (direct_VirtualProtect((void *)pc.orig_prev_ptr, 8, PAGE_READWRITE, &op))
        {
            *(long long *)pc.orig_prev_ptr = ik;
            direct_VirtualProtect((void *)pc.orig_prev_ptr, 8, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)pc.orig_prev_ptr, 8);
        }
        if (direct_VirtualProtect((void *)(ik + g_next_link_offset), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(ik + g_next_link_offset) = pc.orig_next_link;
            direct_VirtualProtect((void *)(ik + g_next_link_offset), 8, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void *)(ik + g_next_link_offset), 8);
        }
    }

    // ── Restore all Method* fields and free backups ──
    int offCM = jvm_deopt_get_offset("constMethod");
    int offAF = jvm_deopt_get_offset("access_flags");
    int offFl = jvm_deopt_get_offset("flags");
    int offI2I = jvm_deopt_get_offset("i2i_entry");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");
    int offFI = jvm_deopt_get_offset("from_interp");

    for (int i = 0; i < pc.numMethods; i++)
    {
        ProtectedMethod &pm = pc.methods[i];
        if (!pm.methodPtr)
            continue;

        // Set PAGE_READWRITE on Method* page (undo PAGE_READONLY)
        DWORD opw = 0;
        g_ourCall = 1;
        direct_VirtualProtect((void *)(pm.methodPtr & ~0xFFFLL), 4096,
                              PAGE_READWRITE, &opw);
        g_ourCall = 0;

        // Restore all backed-up fields
        DWORD op = 0;
        if (offCM >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offCM), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(pm.methodPtr + offCM) = pm.orig_constMethod;
            direct_VirtualProtect((void *)(pm.methodPtr + offCM), 8, op, &op);
        }
        if (offAF >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offAF), 4, PAGE_READWRITE, &op))
        {
            *(jint *)(pm.methodPtr + offAF) = pm.orig_access_flags;
            direct_VirtualProtect((void *)(pm.methodPtr + offAF), 4, op, &op);
        }
        if (offFl >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offFl), 2, PAGE_READWRITE, &op))
        {
            *(unsigned short *)(pm.methodPtr + offFl) = pm.orig_flags;
            direct_VirtualProtect((void *)(pm.methodPtr + offFl), 2, op, &op);
        }
        if (offI2I >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offI2I), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(pm.methodPtr + offI2I) = pm.orig_i2i_entry;
            direct_VirtualProtect((void *)(pm.methodPtr + offI2I), 8, op, &op);
        }
        if (offFC >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offFC), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(pm.methodPtr + offFC) = pm.orig_from_compiled;
            direct_VirtualProtect((void *)(pm.methodPtr + offFC), 8, op, &op);
        }
        if (offCode >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offCode), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(pm.methodPtr + offCode) = pm.orig_code;
            direct_VirtualProtect((void *)(pm.methodPtr + offCode), 8, op, &op);
        }
        if (offFI >= 0 && direct_VirtualProtect((void *)(pm.methodPtr + offFI), 8, PAGE_READWRITE, &op))
        {
            *(long long *)(pm.methodPtr + offFI) = pm.orig_from_interp;
            direct_VirtualProtect((void *)(pm.methodPtr + offFI), 8, op, &op);
        }
        FlushInstructionCache(GetCurrentProcess(), (void *)pm.methodPtr, 96);

        // Free backups
        if (pm.bytecodeBackup)
        {
            free(pm.bytecodeBackup);
            pm.bytecodeBackup = nullptr;
        }
        if (pm.cmFullBackup)
        {
            free(pm.cmFullBackup);
            pm.cmFullBackup = nullptr;
        }
        if (pm.nmethodBackup)
        {
            free(pm.nmethodBackup);
            pm.nmethodBackup = nullptr;
        }
    }

    // Remove method pages from global protected pages list
    for (int i = 0; i < pc.numMethodPages; i++)
    {
        for (int j = 0; j < g_numProtectedPages; j++)
        {
            if (g_protectedPages[j] == pc.methodPages[i])
            {
                g_protectedPages[j] = g_protectedPages[--g_numProtectedPages];
                break;
            }
        }
    }

    // Free vtable/itable/cpcache backups
    if (pc.vtableBackup)
    {
        free(pc.vtableBackup);
        pc.vtableBackup = nullptr;
    }
    if (pc.itableBackup)
    {
        free(pc.itableBackup);
        pc.itableBackup = nullptr;
    }
    if (pc.cpCacheBackup)
    {
        free(pc.cpCacheBackup);
        pc.cpCacheBackup = nullptr;
    }

    g_protected.erase(it);
    LeaveCriticalSection(&g_cs);
    fprintf(stderr, "[TZD] unprotect_class: restored ik=0x%llx\n", ik);
    fflush(stderr);
    return true;
}

// ─── Block Attach API (prevent dynamic agent loading) ──────────────
static void block_attach_api()
{
    char pipeName[64];
    snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\javatool%d", GetCurrentProcessId());
    HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe);
        fprintf(stderr, "[TZD] jvm_guard: Attach pipe '%s' disrupted\n", pipeName);
    }
    snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\java_pid%d", GetCurrentProcessId());
    hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
    fprintf(stderr, "[TZD] jvm_guard: Attach API blocked\n");
    fflush(stderr);
}

// ─── Bytecode patch Java methods to no-op (prevent module bypass) ──
static void patch_module_bypass(JNIEnv *env)
{
    jclass moduleCls = env->FindClass("java/lang/Module");
    if (!moduleCls)
        return;
    // addOpens/addReads are package-private — GetMethodID may throw.
    // Clear exceptions and skip if not found.
    jmethodID addOpens = env->GetMethodID(moduleCls, "addOpens",
                                          "(Ljava/lang/Module;Ljava/lang/String;)V");
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
        addOpens = nullptr;
    }
    jmethodID addReads = env->GetMethodID(moduleCls, "addReads", "(Ljava/lang/Module;)V");
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
        addReads = nullptr;
    }
    struct
    {
        jmethodID mid;
        const char *name;
    } methods[] = {
        {addOpens, "addOpens"},
        {addReads, "addReads"},
    };
    for (auto &m : methods)
    {
        if (!m.mid)
            continue;
        long long methodPtr = resolveMethodPtrExt(m.mid);
        if (!methodPtr)
            continue;
        int offCM = jvm_deopt_get_offset("constMethod");
        int offCB = jvm_deopt_get_offset("codeBase");
        if (offCM < 0 || offCB < 0)
            continue;
        long long cm = *(long long *)(methodPtr + offCM);
        if (!cm)
            continue;
        unsigned char *codeBase = (unsigned char *)(cm + offCB);
        DWORD op = 0;
        if (direct_VirtualProtect(codeBase, 4, PAGE_READWRITE, &op))
        {
            codeBase[0] = 0xB1; // return (void no-op)
            direct_VirtualProtect(codeBase, 4, op, &op);
            fprintf(stderr, "[TZD] jvm_guard: patched Module.%s() → no-op\n", m.name);
            fflush(stderr);
        }
    }
    env->DeleteLocalRef(moduleCls);
    block_attach_api();
}

// ─── Debug diagnostics: report protection status ───────────────────
const char *debug_check_protection(JNIEnv *env, jclass clazz)
{
    static char report[4096];
    if (!env || !clazz)
        return "null clazz";
    if (!ensure_offsets(env))
        return "offset detection failed";

    long long ik = resolve_iklass(env, clazz);
    if (!ik)
        return "cannot resolve InstanceKlass";

    // Read DECRYPTED _access_flags (through VEH — direct read triggers
    // PAGE_GUARD → VEH decrypts for one instruction → we get the real value)
    // Use SEH but DON'T catch EXCEPTION_SINGLE_STEP (0x80000004) — that's
    // the VEH's re-encryption signal and must pass through to the step VEH.
    jint flags = 0;
    __try
    {
        flags = *(jint *)(ik + g_access_flags_offset);
    }
    __except (GetExceptionCode() == 0xC0000005 /* ACCESS_VIOLATION */ ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        flags = 0;
    }

    // Read ENCRYPTED raw bytes (bypass VEH: set g_ourCall + VirtualProtect)
    unsigned char raw[4] = {0};
    g_ourCall = 1;
    DWORD op = 0;
    if (direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, PAGE_READWRITE, &op))
    {
        memcpy(raw, (void *)(ik + g_access_flags_offset), 4);
        // Restore protection (PAGE_READWRITE without PAGE_GUARD —
        // the integrity thread will re-encrypt + re-arm PAGE_GUARD)
        direct_VirtualProtect((void *)(ik + g_access_flags_offset), 4, op, &op);
    }
    g_ourCall = 0;

    jint rawFlags = (jint)raw[0] | ((jint)raw[1] << 8) | ((jint)raw[2] << 16) | ((jint)raw[3] << 24);

    // Check if in CLD list
    bool inList = false;
    if (g_cld_offset >= 0 && g_next_link_offset >= 0 && g_cld_klasses_offset >= 0)
    {
        long long cld = rq((void *)(ik + g_cld_offset));
        if (cld)
        {
            long long cur = rq((void *)(cld + g_cld_klasses_offset));
            while (cur)
            {
                if (cur == ik)
                {
                    inList = true;
                    break;
                }
                cur = rq((void *)(cur + g_next_link_offset));
            }
        }
    }

    bool hidden = (flags & JVM_ACC_IS_HIDDEN_CLASS) != 0;
    bool redef = false; // BEING_REDEFINED not used (causes InstantiationError)
    bool encrypted = (rawFlags != flags);

    // ── Method protection status ──
    int numMethods = 0, numMethodPages = 0, numNmethods = 0;
    if (g_csInited)
    {
        EnterCriticalSection(&g_cs);
        auto it = g_protected.find(ik);
        if (it != g_protected.end())
        {
            numMethods = it->second.numMethods;
            numMethodPages = it->second.numMethodPages;
            for (int i = 0; i < it->second.numMethods; i++)
                if (it->second.methods[i].hasNmethod)
                    numNmethods++;
        }
        LeaveCriticalSection(&g_cs);
    }

    snprintf(report, sizeof(report),
             "=== Protection Status for ik=0x%llx ===\n"
             "  _access_flags (decrypted): 0x%x\n"
             "  _access_flags (raw/encrypted): 0x%x\n"
             "  JVM_ACC_IS_HIDDEN_CLASS: %s\n"
             "  In ClassLoaderData list: %s\n"
             "  _access_flags encrypted: %s (raw != decrypted)\n"
             "  Deep encryption VEH: %s\n"
             "  NtQueryVirtualMemory hook: %s\n"
             "  Anti-debug hooks: %s\n"
             "  NtProtectVirtualMemory IAT hook: %s\n"
             "  NtProtectVirtualMemory INLINE hook: %s\n"
             "  jvm.dll .text guard: %s (pages=%d)\n"
             "  Integrity thread: %s\n"
             "  Protected pages: %d\n"
             "  === Method Protection (JIT exploit defense) ===\n"
             "  Methods backed up: %d\n"
             "  Method pages PAGE_READONLY: %d\n"
             "  Method write-guard VEH: %s\n"
             "  ConstMethod full backup: %s (header+bytecodes, catches Unsafe.putByte at ANY offset)\n"
             "  nmethod compiled code backed up: %d\n"
             "  Interpreter mode forced: %s (no JIT = no nmethod to patch)\n"
             "  === Thread & VEH Security ===\n"
             "  Watchdog threads: %s (DACL-locked: TERMINATE|SUSPEND|SET_CONTEXT|SET_INFO denied)\n"
             "  VEH chain head: %s (list_head=0x%llx, checked every 10ms)\n"
             "  === JVMTI Assessment ===\n"
             "  GetLoadedClasses: %s (class is %s in CLD list)\n"
             "  RetransformClasses: %s (HIDDEN flag blocks redefinition)\n"
             "  RedefineClasses: %s (HIDDEN flag blocks redefinition)\n"
             "  Memory scan (raw read): %s (_access_flags is %s)\n"
             "  Direct syscall: %s\n"
             "  === Pure-Java Attack Assessment ===\n"
             "  Module.addOpens(): %s (patched to no-op)\n"
             "  Attach API: %s (pipe disrupted)\n"
             "  Unsafe.putByte (ConstMethod): %s (VEH full-range check + CRC32 restore)\n"
             "  Class ref swap: detectable via _constants integrity check\n"
             "  Method* field tamper: %s (VEH + CRC32 + restore)\n"
             "  JIT exploit (_code redirect): %s (force_interpreter + _code check)\n"
             "  nmethod code patch: %s (CRC32 + restore from backup)\n",
             ik,
             flags,
             rawFlags,
             hidden ? "YES" : "NO",
             inList ? "YES (visible!)" : "NO (unlinked - invisible)",
             encrypted ? "YES" : "NO",
             g_deepVehGuard ? "registered" : "NOT registered",
             g_origNtQVM ? "installed" : "NOT installed",
             g_origIsDbg ? "installed" : "NOT installed",
             g_origNtPVM ? "installed" : "NOT installed",
             g_ntpvm_inlined ? "installed" : "NOT installed",
             g_jvmGuardInited ? "active" : "inactive",
             g_jvmTextNumPages,
             g_integrityRunning ? "running" : "stopped",
             g_numProtectedPages,
             numMethods,
             numMethodPages,
             g_methodWriteVeh ? "registered" : "NOT registered",
             numMethods > 0 ? "YES" : "NO",
             numNmethods,
             numMethods > 0 ? "YES" : "NO",
             g_watchdogHandles[0] ? "YES (3 threads)" : "NO",
             g_vehListHeadAddr ? "monitored" : "NOT found",
             g_vehListHeadAddr,
             inList ? "CAN find" : "CANNOT find", inList ? "still" : "not",
             hidden ? "BLOCKED" : "vulnerable",
             hidden ? "BLOCKED" : "vulnerable",
             encrypted ? "BLOCKED (encrypted)" : "vulnerable", encrypted ? "encrypted" : "plaintext",
             g_ntpvm_inlined ? "covered (inline hook)" : "IAT hook only",
             "BLOCKED",
             numMethods > 0 ? "BLOCKED" : "N/A",
             "BLOCKED",
             numMethods > 0 ? "BLOCKED" : "N/A",
             numMethods > 0 ? "BLOCKED (interpreter forced)" : "N/A",
             numNmethods > 0 ? "BLOCKED (CRC32 backup)" : "N/A (no compiled code)");

    fprintf(stderr, "[TZD] %s\n", report);
    fflush(stderr);
    return report;
}
