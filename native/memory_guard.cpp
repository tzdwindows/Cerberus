// Architect: tzdwindows 7
// Memory guard: inline-hook VirtualProtect / VirtualProtectEx /
// WriteProcessMemory / NtProtectVirtualMemory.
// Each hook checks the caller's module against a whitelist of
// JVM-default and system modules. Non-whitelisted callers are blocked.
#include "memory_guard.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>

#ifdef _MSC_VER
#include <intrin.h>
#else
#define _ReturnAddress() __builtin_return_address(0)
#endif

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

// ─── Whitelist of trusted modules ──────────────────────────
// Only these modules are allowed to modify memory protection.
// Any other module attempting VirtualProtect etc. is blocked.

static const char* const WHITELIST[] = {
    // JVM core
    "jvm.dll", "java.dll", "net.dll", "nio.dll", "zip.dll",
    "verify.dll", "jawt.dll", "java.exe", "jimage.dll",
    "instrument.dll", "management.dll", "jfr.dll",
    // Windows system
    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ws2_32.dll", "winmm.dll", "version.dll",
    "msvcrt.dll", "vcruntime140.dll", "ucrtbase.dll",
    "shell32.dll", "ole32.dll", "combase.dll", "sechost.dll",
    "rpcrt4.dll", "crypt32.dll", "bcrypt.dll", "msvcp140.dll",
    "kernelbase.dll",  // VirtualProtect forwards here
    // Our own
    "seckill_native.dll", "tzd_sec.dll",
    nullptr
};

// ─── Hook entry ─────────────────────────────────────────────

struct HookEntry {
    const char* funcName;
    const char* moduleName;
    FARPROC  targetAddr;    // original function address
    void*    hookAddr;      // our hook function
    void*    trampoline;    // allocated executable trampoline
    BYTE     originalBytes[32];
    DWORD    originalProt;
    bool     installed;
};

static HookEntry g_hooks[4];
static int       g_hookCount = 0;
static volatile LONG g_blockCount = 0;
static CRITICAL_SECTION g_lock;

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

// ─── Caller module check ────────────────────────────────────

static bool isModuleWhitelisted(const char* modName) {
    for (int i = 0; WHITELIST[i]; i++) {
        if (_stricmp(modName, WHITELIST[i]) == 0) return true;
    }
    // Also allow any DLL whose name starts with "tzd" or contains "seckill"
    if (strstr(modName, "tzd") || strstr(modName, "seckill")) return true;
    return false;
}

// Determine if the caller (given a return address) belongs to a whitelisted module.
static bool isCallerWhitelisted(void* returnAddress) {
    if (!returnAddress) return false;
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            (LPCSTR)returnAddress, &hMod)) {
        return false; // can't resolve — block
    }
    char name[MAX_PATH] = {0};
    if (!GetModuleBaseNameA(GetCurrentProcess(), hMod, name, MAX_PATH)) {
        return false;
    }
    return isModuleWhitelisted(name);
}

// ─── Trampoline: REMOVED ────────────────────────────────────
// The trampoline approach (copy original bytes + JMP back) can
// crash if instructions span the 14-byte boundary. Instead we use
// the unhook-call-rehook pattern in the hook functions above.

// ─── Install inline hook ────────────────────────────────────
// Writes a 14-byte absolute JMP (mov rax, addr; jmp rax) at the
// target function's entry point.
//
// IMPORTANT: We leave the target page as PAGE_EXECUTE_READWRITE
// after patching. This is required because the unhook-call-rehook
// pattern in the hook functions needs to write to the target
// WITHOUT calling VirtualProtect (which would cause infinite
// recursion since VirtualProtect itself is hooked).
// The hook scanner provides additional protection by detecting
// and repairing any unauthorized modifications to these pages.

static bool installHook(HookEntry& h) {
    if (h.installed) return true;

    // Save original bytes
    memcpy(h.originalBytes, (void*)h.targetAddr, 32);

    // Make target writable — and KEEP it writable (don't restore)
    DWORD oldProt = 0;
    if (!VirtualProtect((void*)h.targetAddr, 32, PAGE_EXECUTE_READWRITE, &oldProt)) {
        log_msg("memguard: VirtualProtect on target failed");
        return false;
    }
    h.originalProt = oldProt;

    // Write the JMP: mov rax, hookAddr; jmp rax
    BYTE patch[14];
    patch[0] = 0x48;  // REX.W
    patch[1] = 0xB8;  // mov rax, imm64
    memcpy(patch + 2, &h.hookAddr, 8);
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    patch[12] = 0x90; // nop
    patch[13] = 0x90;
    memcpy((void*)h.targetAddr, patch, 14);

    // Do NOT restore protection — keep PAGE_EXECUTE_READWRITE
    // so callOriginal/rehook can write without VirtualProtect
    FlushInstructionCache(GetCurrentProcess(), (void*)h.targetAddr, 14);

    h.installed = true;
    fprintf(stderr, "[TZD] memguard: hooked %s!%s at 0x%p\n",
            h.moduleName, h.funcName, (void*)h.targetAddr);
    fflush(stderr);
    return true;
}

// Temporarily restore original bytes (direct write — no VirtualProtect).
// The page is already writable from installHook.
static void callOriginal(HookEntry& h) {
    EnterCriticalSection(&g_lock);
    memcpy((void*)h.targetAddr, h.originalBytes, 14);
    FlushInstructionCache(GetCurrentProcess(), (void*)h.targetAddr, 14);
}

// Re-install the hook (direct write — no VirtualProtect).
static void rehook(HookEntry& h) {
    BYTE patch[14];
    patch[0] = 0x48; patch[1] = 0xB8;
    memcpy(patch + 2, &h.hookAddr, 8);
    patch[10] = 0xFF; patch[11] = 0xE0;
    patch[12] = 0x90; patch[13] = 0x90;
    memcpy((void*)h.targetAddr, patch, 14);
    FlushInstructionCache(GetCurrentProcess(), (void*)h.targetAddr, 14);
    LeaveCriticalSection(&g_lock);
}

// ─── Restore original bytes ─────────────────────────────────

static void uninstallHook(HookEntry& h) {
    if (!h.installed) return;
    DWORD oldProt = 0;
    if (VirtualProtect((void*)h.targetAddr, 32, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy((void*)h.targetAddr, h.originalBytes, 14);
        VirtualProtect((void*)h.targetAddr, 32, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), (void*)h.targetAddr, 14);
    }
    if (h.trampoline) {
        VirtualFree(h.trampoline, 0, MEM_RELEASE);
        h.trampoline = nullptr;
    }
    h.installed = false;
}

// ─── Hook functions ─────────────────────────────────────────
// Each hook checks the caller's module. Whitelisted → unhook,
// call original, rehook. Non-whitelisted → block.

static BOOL WINAPI hookedVirtualProtect(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect)
{
    void* ret = _ReturnAddress();
    if (isCallerWhitelisted(ret)) {
        // Unhook, call original, rehook
        callOriginal(g_hooks[0]);
        BOOL result = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        rehook(g_hooks[0]);
        return result;
    }
    InterlockedIncrement(&g_blockCount);
    char name[MAX_PATH] = {0};
    HMODULE hMod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          (LPCSTR)ret, &hMod)) {
        GetModuleBaseNameA(GetCurrentProcess(), hMod, name, MAX_PATH);
    }
    fprintf(stderr, "[TZD] BLOCKED VirtualProtect from %s @0x%p\n", name, ret);
    fflush(stderr);
    if (lpflOldProtect) *lpflOldProtect = PAGE_NOACCESS;
    return FALSE;
}

static BOOL WINAPI hookedVirtualProtectEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect)
{
    void* ret = _ReturnAddress();
    if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
        if (!isCallerWhitelisted(ret)) {
            InterlockedIncrement(&g_blockCount);
            return FALSE;
        }
    }
    if (isCallerWhitelisted(ret)) {
        callOriginal(g_hooks[1]);
        BOOL result = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
        rehook(g_hooks[1]);
        return result;
    }
    InterlockedIncrement(&g_blockCount);
    return FALSE;
}

static BOOL WINAPI hookedWriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    void* ret = _ReturnAddress();
    if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
        if (!isCallerWhitelisted(ret)) {
            InterlockedIncrement(&g_blockCount);
            return FALSE;
        }
    }
    if (isCallerWhitelisted(ret)) {
        callOriginal(g_hooks[2]);
        BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        rehook(g_hooks[2]);
        return result;
    }
    InterlockedIncrement(&g_blockCount);
    return FALSE;
}

// NtProtectVirtualMemory hook (ntdll)
typedef LONG (WINAPI *NtProtectVirtualMemory_t)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static LONG WINAPI hookedNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    void* ret = _ReturnAddress();
    if (isCallerWhitelisted(ret)) {
        callOriginal(g_hooks[3]);
        // Call original via GetProcAddress (we unhooked it)
        FARPROC fn = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
        LONG result = ((NtProtectVirtualMemory_t)fn)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        rehook(g_hooks[3]);
        return result;
    }
    InterlockedIncrement(&g_blockCount);
    if (OldProtect) *OldProtect = 0;
    return (LONG)0xC0000005L;
}

// ─── Installation ───────────────────────────────────────────

void memguard_install() {
    InitializeCriticalSection(&g_lock);
    g_hookCount = 0;

    // Hook 0: VirtualProtect (kernel32)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        g_hooks[g_hookCount].funcName   = "VirtualProtect";
        g_hooks[g_hookCount].moduleName = "kernel32.dll";
        g_hooks[g_hookCount].targetAddr = GetProcAddress(hKernel32, "VirtualProtect");
        g_hooks[g_hookCount].hookAddr   = (void*)hookedVirtualProtect;
        g_hooks[g_hookCount].installed  = false;
        if (g_hooks[g_hookCount].targetAddr) {
            installHook(g_hooks[g_hookCount]);
            g_hookCount++;
        }
    }

    // Hook 1: VirtualProtectEx (kernel32)
    if (hKernel32) {
        g_hooks[g_hookCount].funcName   = "VirtualProtectEx";
        g_hooks[g_hookCount].moduleName = "kernel32.dll";
        g_hooks[g_hookCount].targetAddr = GetProcAddress(hKernel32, "VirtualProtectEx");
        g_hooks[g_hookCount].hookAddr   = (void*)hookedVirtualProtectEx;
        g_hooks[g_hookCount].installed  = false;
        if (g_hooks[g_hookCount].targetAddr) {
            installHook(g_hooks[g_hookCount]);
            g_hookCount++;
        }
    }

    // Hook 2: WriteProcessMemory (kernel32)
    if (hKernel32) {
        g_hooks[g_hookCount].funcName   = "WriteProcessMemory";
        g_hooks[g_hookCount].moduleName = "kernel32.dll";
        g_hooks[g_hookCount].targetAddr = GetProcAddress(hKernel32, "WriteProcessMemory");
        g_hooks[g_hookCount].hookAddr   = (void*)hookedWriteProcessMemory;
        g_hooks[g_hookCount].installed  = false;
        if (g_hooks[g_hookCount].targetAddr) {
            installHook(g_hooks[g_hookCount]);
            g_hookCount++;
        }
    }

    // Note: NtProtectVirtualMemory is NOT hooked because it's the
    // low-level function that the JVM itself uses for stack guard
    // page protection. Hooking it would interfere with JVM internals.
    // The higher-level VirtualProtect/VirtualProtectEx/WriteProcessMemory
    // hooks are sufficient to block non-JVM modules.

    fprintf(stderr, "[TZD] memguard installed: %d hooks active, blocks=%d\n",
            g_hookCount, g_blockCount);
    fflush(stderr);
}

void memguard_uninstall() {
    for (int i = 0; i < g_hookCount; i++) {
        uninstallHook(g_hooks[i]);
    }
    g_hookCount = 0;
    DeleteCriticalSection(&g_lock);
    log_msg("memguard uninstalled");
}

DWORD memguard_get_block_count() {
    return (DWORD)g_blockCount;
}

intptr_t memguard_get_jvm_base() {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return 0;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        if (GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
            if (_stricmp(name, "jvm.dll") == 0) return (intptr_t)mods[i];
        }
    }
    return 0;
}
