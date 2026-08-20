// Architect: tzdwindows 7
// syscall_hook: Universal R3 syscall interception engine.
//
// STRATEGY:
//   1. Enumerate ALL ntdll Nt*/Zw* syscall stubs at startup.
//   2. When enabled: replace `syscall` (0F 05) with `ud2` (0F 0B) in every stub.
//   3. VEH handler catches EXCEPTION_ILLEGAL_INSTRUCTION:
//      - Redirect to private `syscall; ret` stub (transparent pass-through)
//      - For dangerous syscalls from non-bypass callers: block with STATUS_ACCESS_DENIED
//   4. Our DLL's direct syscall stubs (in VirtualAlloc'd memory) are NOT patched —
//      they have their own `syscall` instruction and bypass everything.
//   5. Scanner: walks non-module executable memory for `0F 05` (attacker shellcode),
//      patches them with `0F 0B`.
//   6. Watchdog: re-applies ntdll patches if tampered, re-scans for new shellcode.
//   7. Optional driver: IOCTL to \\.\SyscallGuard for R0 enforcement.
#include "syscall_hook.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>
#include <intrin.h>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

// ═══════════════════════════════════════════════════════════════════════
// ─── Data structures ────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

#define MAX_SYSCALL_STUBS 512
#define MAX_DANGEROUS_NAMES 32

struct SyscallStub {
    unsigned char* syscallAddr;   // address of the 0F 05 (now 0F 0B) instruction
    unsigned char  origBytes[2];   // original bytes (should be 0F 05)
    int            syscallNum;     // syscall number from mov eax, XX
    bool           dangerous;      // is this a "dangerous" syscall?
    bool           patched;        // is the ud2 patch currently applied?
};

static SyscallStub g_stubs[MAX_SYSCALL_STUBS];
static int g_numStubs = 0;
static bool g_enabled = false;
static bool g_inited = false;

// Private `syscall; ret` stub (3 bytes: 0F 05 C3) for transparent redirection.
static unsigned char* g_privateSyscallStub = nullptr;

// VEH handler handle
static PVOID g_vehHandler = nullptr;

// Thread-local bypass flag (our DLL sets this before CRT calls)
static __declspec(thread) int g_bypass = 0;

// Trusted stub region (our direct syscall stubs — scanner skips these)
static unsigned char* g_trustedBase = nullptr;
static unsigned char* g_trustedEnd = nullptr;

// ntdll base/size (for fast "is this in ntdll?" check)
static long long g_ntdllBase = 0;
static long long g_ntdllSize = 0;

// Driver handle (INVALID_HANDLE_VALUE if not connected)
static HANDLE g_driverHandle = INVALID_HANDLE_VALUE;

// Statistics
static volatile long long g_totalIntercepted = 0;
static volatile long long g_totalBlocked = 0;

// Dangerous syscall function names (checked at enumeration time)
static const char* g_dangerousNames[] = {
    "NtProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtSetInformationThread",
    "NtOpenProcess",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtFreeVirtualMemory",
    "NtCreateFile",
    "NtSetContextThread",
    "NtSuspendThread",
    "NtResumeThread",
    "NtTerminateThread",
    "NtCreateSection",
    "NtProtectVirtualMemoryEx",
};

static bool is_dangerous_name(const char* name) {
    for (int i = 0; i < (int)(sizeof(g_dangerousNames)/sizeof(g_dangerousNames[0])); i++) {
        if (strcmp(name, g_dangerousNames[i]) == 0) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── ntdll syscall stub enumeration ─────────────────────────────────────
// Walk ntdll's export table. For each Nt*/Zw* function:
//   - Verify the prologue pattern (4C 8B D1 B8 xx 00 00 00)
//   - Find the `0F 05` (syscall) instruction
//   - Record address, syscall number, dangerous flag
// ═══════════════════════════════════════════════════════════════════════

static void enumerate_ntdll_stubs() {
    if (g_numStubs > 0) return; // already enumerated

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { log_msg("syscall_hook: ntdll not found"); return; }

    // Record ntdll base/size
    MODULEINFO mi; memset(&mi, 0, sizeof(mi));
    if (GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi))) {
        g_ntdllBase = (long long)mi.lpBaseOfDll;
        g_ntdllSize = (long long)mi.SizeOfImage;
    }

    BYTE* base = (BYTE*)ntdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + exportDir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames && g_numStubs < MAX_SYSCALL_STUBS; i++) {
        const char* name = (const char*)(base + names[i]);
        // Only Nt* and Zw* functions are syscall stubs
        if (strncmp(name, "Nt", 2) != 0 && strncmp(name, "Zw", 2) != 0) continue;
        // Skip Ntdll internal functions (NtdllDialog should not match anyway)
        if (strlen(name) < 3) continue;

        DWORD funcRVA = functions[ordinals[i]];
        unsigned char* func = base + funcRVA;

        // Verify prologue: 4C 8B D1 B8 xx 00 00 00 (mov r10,rcx; mov eax,num)
        if (func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1 || func[3] != 0xB8) continue;
        if (func[6] != 0x00 || func[7] != 0x00) continue;

        int syscallNum = *(int*)(func + 4);

        // Find the 0F 05 (syscall) instruction within the first 32 bytes
        int syscallOff = -1;
        for (int j = 0; j < 32; j++) {
            if (func[j] == 0x0F && j + 1 < 32 && func[j + 1] == 0x05) {
                syscallOff = j;
                break;
            }
        }
        if (syscallOff < 0) continue;

        // Record the stub
        SyscallStub* stub = &g_stubs[g_numStubs];
        stub->syscallAddr = func + syscallOff;
        stub->origBytes[0] = func[syscallOff];     // 0x0F
        stub->origBytes[1] = func[syscallOff + 1]; // 0x05
        stub->syscallNum = syscallNum;
        stub->dangerous = is_dangerous_name(name);
        stub->patched = false;
        g_numStubs++;
    }

    fprintf(stderr, "[TZD] syscall_hook: enumerated %d ntdll syscall stubs "
            "(ntdll=0x%llx+0x%llx)\n", g_numStubs, g_ntdllBase, g_ntdllSize);
    fflush(stderr);
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Private `syscall; ret` stub ─────────────────────────────────────────
// 3 bytes: 0F 05 C3 (syscall; ret). The VEH handler redirects RIP here to
// execute the real syscall with the current register state (r10, eax, rdx,
// r8, r9 already set by the ntdll stub's prologue). The `ret` returns to
// the original caller of the ntdll stub.
// ═══════════════════════════════════════════════════════════════════════

static void create_private_stub() {
    if (g_privateSyscallStub) return;
    // 0F 05 C3 = syscall; ret
    unsigned char code[3] = { 0x0F, 0x05, 0xC3 };
    g_privateSyscallStub = (unsigned char*)VirtualAlloc(
        nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (g_privateSyscallStub) {
        memcpy(g_privateSyscallStub, code, 3);
        // Register as trusted region (scanner skips this)
        g_trustedBase = g_privateSyscallStub;
        g_trustedEnd = g_privateSyscallStub + 16;
        fprintf(stderr, "[TZD] syscall_hook: private syscall;ret stub at %p\n",
                g_privateSyscallStub);
        fflush(stderr);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── VEH Handler ────────────────────────────────────────────────────────
// Catches EXCEPTION_ILLEGAL_INSTRUCTION (0xC000001D) from our ud2 patches.
// The faulting instruction is `0F 0B` (ud2) at a ntdll syscall stub address.
//
// At the time of the exception, the context has:
//   RIP = address of 0F 0B in ntdll
//   R10 = rcx (first syscall arg, Windows x64 ABI)
//   EAX = syscall number
//   RDX, R8, R9 = args 2-4
//   [RSP] = return address to original caller
//
// Actions:
//   Bypass flag set → redirect to private syscall;ret stub (transparent)
//   Bypass flag NOT set + dangerous syscall → block (RAX=0xC0000022, RIP→ret)
//   Bypass flag NOT set + non-dangerous → redirect to private stub (allow)
// ═══════════════════════════════════════════════════════════════════════

// Thread-local "our call" flag for VEH handler (set by our own code)
static __declspec(thread) int g_ourSyscall = 0;

// Helper: check if address is in ntdll range
static bool is_in_ntdll(long long addr) {
    if (!g_ntdllBase || !g_ntdllSize) return false;
    return addr >= g_ntdllBase && addr < g_ntdllBase + g_ntdllSize;
}

// Helper: check if address is in our trusted stub region
static bool is_in_trusted_region(long long addr) {
    if (!g_trustedBase) return false;
    return addr >= (long long)(intptr_t)g_trustedBase &&
           addr < (long long)(intptr_t)g_trustedEnd;
}

// Find the SyscallStub entry for a given ntdll address
static SyscallStub* find_stub_by_addr(unsigned char* addr) {
    for (int i = 0; i < g_numStubs; i++) {
        if (g_stubs[i].syscallAddr == addr) return &g_stubs[i];
    }
    return nullptr;
}

// Dangerous syscall number lookup (for addresses we don't have in g_stubs,
// e.g., direct syscall shellcode found by the scanner)
static bool is_dangerous_syscall_num(int num) {
    for (int i = 0; i < g_numStubs; i++) {
        if (g_stubs[i].syscallNum == num && g_stubs[i].dangerous) return true;
    }
    return false;
}

static LONG CALLBACK syscall_veh_handler(PEXCEPTION_POINTERS exc) {
    if (exc->ExceptionRecord->ExceptionCode != 0xC000001D)
        return EXCEPTION_CONTINUE_SEARCH; // not EXCEPTION_ILLEGAL_INSTRUCTION

    long long rip = exc->ContextRecord->Rip;
    unsigned char* faultAddr = (unsigned char*)rip;

    // Check if the faulting instruction is our ud2 patch (0F 0B)
    if (faultAddr[0] != 0x0F || faultAddr[1] != 0x0B)
        return EXCEPTION_CONTINUE_SEARCH; // not our patch

    // Is this in ntdll? (could also be in non-module memory patched by scanner)
    bool inNtdll = is_in_ntdll(rip);
    bool inTrusted = is_in_trusted_region(rip);

    // If it's in our trusted region, something is wrong — skip
    if (inTrusted) return EXCEPTION_CONTINUE_SEARCH;

    // Read the syscall number from EAX (preserved by the ntdll prologue)
    int syscallNum = (int)exc->ContextRecord->Rax;

    InterlockedIncrement64(&g_totalIntercepted);

    // Check thread-local bypass flag
    if (g_bypass || g_ourSyscall) {
        // ── OUR DLL's call (via ntdll) — allow transparently ──
        // Redirect to our private syscall;ret stub.
        // Registers (r10, eax, rdx, r8, r9, stack) are already set up.
        if (g_privateSyscallStub) {
            exc->ContextRecord->Rip = (DWORD64)(intptr_t)g_privateSyscallStub;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // Fallback: skip the ud2, land on the next instruction (ret)
        exc->ContextRecord->Rip = rip + 2;
        exc->ContextRecord->Rax = 0; // no result
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── NOT our DLL — check if dangerous ──
    bool dangerous = false;
    if (inNtdll) {
        SyscallStub* stub = find_stub_by_addr(faultAddr);
        if (stub) dangerous = stub->dangerous;
    } else {
        // Patched in non-module memory — check by syscall number
        dangerous = is_dangerous_syscall_num(syscallNum);
    }

    if (dangerous) {
        // ── BLOCK: return STATUS_ACCESS_DENIED ──
        InterlockedIncrement64(&g_totalBlocked);
        fprintf(stderr, "[TZD] syscall_hook: BLOCKED syscall #%d (IP=0x%llx, "
                "dangerous) — STATUS_ACCESS_DENIED\n", syscallNum, rip);
        fflush(stderr);
        // Skip ud2 (2 bytes) → land on ret (the next instruction after syscall)
        exc->ContextRecord->Rip = rip + 2;
        exc->ContextRecord->Rax = 0xC0000022; // STATUS_ACCESS_DENIED
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── Non-dangerous syscall — allow transparently ──
    // Redirect to our private syscall;ret stub.
    if (g_privateSyscallStub) {
        exc->ContextRecord->Rip = (DWORD64)(intptr_t)g_privateSyscallStub;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // Fallback: skip ud2 → land on ret (but no syscall executed)
    exc->ContextRecord->Rip = rip + 2;
    exc->ContextRecord->Rax = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── ud2 Patching (enable/disable) ──────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static void patch_stub(SyscallStub* stub) {
    if (stub->patched) return;
    DWORD oldProt = 0;
    if (!VirtualProtect(stub->syscallAddr, 2, PAGE_EXECUTE_READWRITE, &oldProt))
        return;
    stub->syscallAddr[0] = 0x0F; // ud2
    stub->syscallAddr[1] = 0x0B;
    VirtualProtect(stub->syscallAddr, 2, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), stub->syscallAddr, 2);
    stub->patched = true;
}

static void unpatch_stub(SyscallStub* stub) {
    if (!stub->patched) return;
    DWORD oldProt = 0;
    if (!VirtualProtect(stub->syscallAddr, 2, PAGE_EXECUTE_READWRITE, &oldProt))
        return;
    stub->syscallAddr[0] = stub->origBytes[0]; // 0F
    stub->syscallAddr[1] = stub->origBytes[1]; // 05
    VirtualProtect(stub->syscallAddr, 2, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), stub->syscallAddr, 2);
    stub->patched = false;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Direct syscall scanner (attacker shellcode detection) ──────────────
// Walks all committed executable memory not in a loaded module.
// Scans for `0F 05` (syscall) pattern. Patches with `0F 0B`.
// Skips our trusted stub region.
// ═══════════════════════════════════════════════════════════════════════

static bool is_in_any_module(long long addr) {
    HMODULE hMod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (LPCSTR)addr, &hMod) && hMod)
        return true;
    return false;
}

int syscall_hook_scan_direct() {
    if (!g_enabled) return 0;
    int patched = 0;
    long long addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    // Scan in chunks to avoid spending too long
    long long scanLimit = 0x7FFFFFFFFFFFLL;
    int regionsScanned = 0;

    while (addr < scanLimit && regionsScanned < 256) {
        if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) break;
        addr = (long long)mbi.BaseAddress + mbi.RegionSize;
        if (addr <= 0) break;

        if (mbi.State != MEM_COMMIT) continue;
        // Only executable regions
        DWORD prot = mbi.Protect;
        if (!(prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            continue;

        long long regionStart = (long long)mbi.BaseAddress;
        long long regionEnd = regionStart + mbi.RegionSize;

        // Skip if in a loaded module (ntdll, jvm.dll, etc.)
        if (is_in_any_module(regionStart)) continue;
        // Skip our trusted stub region
        if (is_in_trusted_region(regionStart)) continue;

        // Scan this region for 0F 05
        unsigned char* p = (unsigned char*)regionStart;
        size_t sz = mbi.RegionSize;
        for (size_t i = 0; i + 1 < sz; i++) {
            if (p[i] == 0x0F && p[i + 1] == 0x05) {
                // Found a syscall instruction in non-module memory!
                unsigned char* scAddr = p + i;
                // Check if it's already patched (0F 0B)
                if (i > 0 && p[i - 1] == 0x0F && p[i] == 0x05) continue;
                // Patch it with ud2
                DWORD op = 0;
                if (VirtualProtect(scAddr, 2, PAGE_EXECUTE_READWRITE, &op)) {
                    fprintf(stderr, "[TZD] syscall_hook: PATCHED direct syscall "
                            "at 0x%p in non-module memory (shellcode?)\n", scAddr);
                    fflush(stderr);
                    scAddr[0] = 0x0F; // ud2
                    scAddr[1] = 0x0B;
                    VirtualProtect(scAddr, 2, op, &op);
                    FlushInstructionCache(GetCurrentProcess(), scAddr, 2);
                    patched++;
                }
                i++; // skip the 05
            }
        }
        regionsScanned++;
    }
    return patched;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Re-apply patches (called by watchdog) ──────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

int syscall_hook_reapply_patches() {
    if (!g_enabled) return 0;
    int rePatched = 0;
    for (int i = 0; i < g_numStubs; i++) {
        // Check if the patch is still in place
        if (g_stubs[i].syscallAddr[0] == 0x0F && g_stubs[i].syscallAddr[1] == 0x0B) {
            // Still patched
            g_stubs[i].patched = true;
            continue;
        }
        // Patch was tampered — re-apply
        patch_stub(&g_stubs[i]);
        rePatched++;
    }
    if (rePatched > 0) {
        fprintf(stderr, "[TZD] syscall_hook: re-applied %d tampered ntdll patches\n", rePatched);
        fflush(stderr);
    }
    return rePatched;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Driver communication ───────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

bool syscall_hook_driver_connect() {
    if (g_driverHandle != INVALID_HANDLE_VALUE) return true;

    g_driverHandle = CreateFileA(
        SYSCALLGUARD_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (g_driverHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[TZD] syscall_hook: driver not present (R3-only mode)\n");
        fflush(stderr);
        return false;
    }

    // Register our PID + trusted stub range
    SYSCALLGUARD_REGISTER_DATA data;
    memset(&data, 0, sizeof(data));
    data.ProcessId = GetCurrentProcessId();
    data.TrustedStubBase = (ULONG64)(intptr_t)g_trustedBase;
    data.TrustedStubEnd = (ULONG64)(intptr_t)g_trustedEnd;
    data.NumPatchedStubs = g_numStubs;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        g_driverHandle, IOCTL_SYSCALLGUARD_REGISTER,
        &data, sizeof(data),
        nullptr, 0,
        &bytesReturned, nullptr);

    if (ok) {
        fprintf(stderr, "[TZD] syscall_hook: driver connected + registered "
                "(PID=%u, stubs=%d, trusted=0x%llx-0x%llx)\n",
                data.ProcessId, data.NumPatchedStubs,
                data.TrustedStubBase, data.TrustedStubEnd);
    } else {
        fprintf(stderr, "[TZD] syscall_hook: driver IOCTL failed (err=%lu)\n",
                GetLastError());
        CloseHandle(g_driverHandle);
        g_driverHandle = INVALID_HANDLE_VALUE;
    }
    fflush(stderr);
    return ok != FALSE;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Public API ─────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

void syscall_hook_init() {
    if (g_inited) return;
    g_inited = true;

    enumerate_ntdll_stubs();
    create_private_stub();

    // Register VEH handler (highest priority)
    g_vehHandler = AddVectoredExceptionHandler(1, syscall_veh_handler);
    if (g_vehHandler) {
        fprintf(stderr, "[TZD] syscall_hook: VEH handler registered\n");
    } else {
        log_msg("syscall_hook: VEH registration FAILED");
    }
    fflush(stderr);
}

void syscall_hook_enable() {
    if (!g_inited) syscall_hook_init();
    if (g_enabled) return;

    int patched = 0;
    for (int i = 0; i < g_numStubs; i++) {
        patch_stub(&g_stubs[i]);
        if (g_stubs[i].patched) patched++;
    }

    g_enabled = true;

    // Try to connect to driver (optional)
    syscall_hook_driver_connect();

    fprintf(stderr, "[TZD] syscall_hook: ENABLED — %d/%d ntdll stubs patched "
            "(ud2 interception active)\n", patched, g_numStubs);
    fflush(stderr);
}

void syscall_hook_disable() {
    if (!g_enabled) return;
    for (int i = 0; i < g_numStubs; i++) {
        unpatch_stub(&g_stubs[i]);
    }
    g_enabled = false;

    // Unregister from driver
    if (g_driverHandle != INVALID_HANDLE_VALUE) {
        DWORD ret;
        DeviceIoControl(g_driverHandle, IOCTL_SYSCALLGUARD_UNREGISTER,
                         nullptr, 0, nullptr, 0, &ret, nullptr);
        CloseHandle(g_driverHandle);
        g_driverHandle = INVALID_HANDLE_VALUE;
    }

    fprintf(stderr, "[TZD] syscall_hook: DISABLED — ntdll stubs restored\n");
    fflush(stderr);
}

bool syscall_hook_is_enabled() {
    return g_enabled;
}

void syscall_hook_set_bypass(int flag) {
    g_bypass = flag;
}

int syscall_hook_get_bypass() {
    return g_bypass;
}

void syscall_hook_get_stats(long long* intercepted, long long* blocked) {
    if (intercepted) *intercepted = g_totalIntercepted;
    if (blocked) *blocked = g_totalBlocked;
}
