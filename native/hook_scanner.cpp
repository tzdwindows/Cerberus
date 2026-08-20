// Architect: tzdwindows 7
#include "hook_scanner.h"
#include "pristine_store.h"
#include "memory_guard.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>
#include <process.h>

static HANDLE g_scannerThread = nullptr;
static volatile bool g_scanning = false;
static DWORD g_repairCount = 0;

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

// Check if a function entry has a typical detour pattern: E9/EB/FF25 at offset 0
static bool looks_like_hook(void* addr) {
    BYTE* p = (BYTE*)addr;
    if (p[0] == 0xE9) return true;   // near jmp rel32
    if (p[0] == 0xEB) return true;   // short jmp rel8
    if (p[0] == 0xFF && p[1] == 0x25) return true; // jmp [rip+disp]
    // movabs rax, imm64; jmp rax
    if (p[0] == 0x48 && p[1] == 0xB8 &&
        p[10] == 0xFF && p[11] == 0xE0) return true;
    // push imm32; ret (5 bytes)
    if (p[0] == 0x68) {
        if (p[5] == 0xC3) return true;
    }
    return false;
}

// Scan IAT of jvm.dll for redirected entries
static int scan_iat() {
    int redirects = 0;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return 0;
    DWORD count = needed / sizeof(HMODULE);

    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        if (!GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH)) continue;
        if (_stricmp(name, "jvm.dll") != 0) continue;

        BYTE* base = (BYTE*)mods[i];
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir->VirtualAddress == 0) continue;

        IMAGE_IMPORT_DESCRIPTOR* imp =
            (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir->VirtualAddress);
        for (; imp->Name != 0; imp++) {
            const char* dllName = (const char*)(base + imp->Name);
            IMAGE_THUNK_DATA* thunk =
                (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            for (; thunk->u1.AddressOfData != 0; thunk++) {
                DWORD_PTR addr = thunk->u1.Function;
                HMODULE hMod = nullptr;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                      (LPCSTR)addr, &hMod)) {
                    char modName[MAX_PATH] = {0};
                    GetModuleBaseNameA(GetCurrentProcess(), hMod, modName, MAX_PATH);
                    if (_stricmp(modName, dllName) != 0 &&
                        strstr(modName, "seckill") == nullptr &&
                        strstr(modName, "tzd") == nullptr) {
                        fprintf(stderr,
                            "[TZD] IAT redirect: %s!%s -> %s\n",
                            dllName, "?", modName);
                        fflush(stderr);
                        redirects++;
                    }
                }
            }
        }
    }
    return redirects;
}

// Scan all loaded modules' IAT for suspicious redirects targeting jvm.dll exports
static int scan_all_iats() {
    int total = 0;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return 0;
    DWORD count = needed / sizeof(HMODULE);

    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        if (!GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH)) continue;
        // Skip our own and JVM/system modules
        if (strstr(name, "tzd") || strstr(name, "seckill")) continue;
        if (_stricmp(name, "jvm.dll") == 0) continue;
        if (_stricmp(name, "kernel32.dll") == 0) continue;
        if (_stricmp(name, "ntdll.dll") == 0) continue;

        BYTE* base = (BYTE*)mods[i];
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != 0x5A4D) continue; // not MZ
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != 0x4550) continue; // not PE
        IMAGE_DATA_DIRECTORY* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir->VirtualAddress == 0) continue;

        IMAGE_IMPORT_DESCRIPTOR* imp =
            (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir->VirtualAddress);
        for (; imp->Name != 0; imp++) {
            const char* dllName = (const char*)(base + imp->Name);
            if (_stricmp(dllName, "jvm.dll") != 0) continue; // only care about jvm.dll imports

            IMAGE_THUNK_DATA* thunk =
                (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            for (; thunk->u1.AddressOfData != 0; thunk++) {
                DWORD_PTR addr = thunk->u1.Function;
                HMODULE hMod = nullptr;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                      (LPCSTR)addr, &hMod)) {
                    char modName[MAX_PATH] = {0};
                    GetModuleBaseNameA(GetCurrentProcess(), hMod, modName, MAX_PATH);
                    if (_stricmp(modName, "jvm.dll") != 0) {
                        fprintf(stderr,
                            "[TZD] IAT hijack: %s imports jvm.dll!%s -> %s\n",
                            name, "?", modName);
                        fflush(stderr);
                        total++;
                    }
                }
            }
        }
    }
    return total;
}

// Full scan cycle: pristine functions + IAT + all module IATs
static int full_scan_cycle() {
    int issues = 0;

    // 1. Scan pristine-stored JVM functions for inline hooks and repair
    fprintf(stderr, "[TZD] scanner: scanning %zu pristine functions...\n",
            pristine_count());
    fflush(stderr);
    pristine_scan_and_repair_all();

    // 2. Scan jvm.dll IAT
    issues += scan_iat();

    // 3. Scan all modules' IAT for jvm.dll hijacks
    issues += scan_all_iats();

    if (issues > 0) {
        fprintf(stderr, "[TZD] scanner: %d IAT issues found\n", issues);
        fflush(stderr);
    }
    return issues;
}

static unsigned __stdcall scanner_thread(void*) {
    log_msg("hook scanner thread started");
    // Initial scan immediately on start
    full_scan_cycle();
    while (g_scanning) {
        full_scan_cycle();
        Sleep(2000); // scan every 2 seconds
    }
    log_msg("hook scanner thread stopped");
    return 0;
}

void scanner_start() {
    if (g_scanning) return;
    g_scanning = true;
    g_scannerThread = (HANDLE)_beginthreadex(nullptr, 0, scanner_thread, nullptr, 0, nullptr);
}

void scanner_stop() {
    g_scanning = false;
    if (g_scannerThread) {
        WaitForSingleObject(g_scannerThread, 5000);
        CloseHandle(g_scannerThread);
        g_scannerThread = nullptr;
    }
}

DWORD scanner_get_repair_count() { return g_repairCount; }

int scanner_scan_now() {
    return full_scan_cycle();
}
