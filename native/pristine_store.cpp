// Architect: tzdwindows 7
#include "pristine_store.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>

static HMODULE g_jvmDll = nullptr;
static char g_jvmPath[MAX_PATH] = {0};
static std::unordered_map<std::string, PristineEntry> g_store;
static const int PRISTINE_SIZE = 32;

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

static HMODULE find_jvm_dll() {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char name[MAX_PATH] = {0};
            if (GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
                if (_stricmp(name, "jvm.dll") == 0) return mods[i];
            }
        }
    }
    return nullptr;
}

// Expanded list: all critical JVM/JVMTI/JNI entry points + memory APIs.
// If any of these get inline-hooked, we detect and repair.
static const char* CRITICAL_FUNCS[] = {
    // JNI entry points
    "JNI_CreateJavaVM",
    "JNI_GetCreatedJavaVMs",
    "JNI_GetDefaultJavaVMInitArgs",
    "JNI_OnLoad",
    // JVM_GetEnv and class loading
    "JVM_GetEnv",
    "JVM_FindClassFromBootLoader",
    "JVM_DefineClassSource",
    "JVM_FindClassFromClassLoader",
    "JVM_LoadLibrary",
    "JVM_UnloadLibrary",
    "JVM_FindLibraryEntry",
    // JVMTI class manipulation
    "JVM_RedefineClasses",
    "JVM_RetransformClasses",
    "JVM_GetLoadedClasses",
    "JVM_ClassGetName",
    // Agent support
    "JVM_Agent_OnLoad",
    "JVM_Agent_OnAttach",
    "JVM_Agent_OnUnload",
    // System property / classpath
    "JVM_InitProperties",
    "JVM_SetProperties",
    // Thread management
    "JVM_StartThread",
    "JVM_StopThread",
    "JVM_IsThreadAlive",
    // Memory / GC
    "JVM_TotalMemory",
    "JVM_FreeMemory",
    "JVM_MaxMemory",
    "JVM_GC",
    // Safety / security
    "JVM_LatestUserDefinedLoader",
    "JVM_GetCallerClass",
    "JVM_ResolveClass",
    nullptr
};

void pristine_init() {
    g_jvmDll = find_jvm_dll();
    if (!g_jvmDll) { log_msg("pristine: jvm.dll not found"); return; }
    GetModuleFileNameA(g_jvmDll, g_jvmPath, MAX_PATH);
    log_msg(g_jvmPath);

    for (int i = 0; CRITICAL_FUNCS[i]; i++) {
        const char* fname = CRITICAL_FUNCS[i];
        FARPROC addr = GetProcAddress(g_jvmDll, fname);
        if (!addr) continue;
        PristineEntry e;
        e.funcAddr = (void*)addr;
        e.pristineBytes = (BYTE*)malloc(PRISTINE_SIZE);
        memcpy(e.pristineBytes, (const void*)addr, PRISTINE_SIZE);
        e.size = PRISTINE_SIZE;
        g_store[fname] = e;
    }
    fprintf(stderr, "[TZD] pristine stored %zu functions\n", g_store.size());
    fflush(stderr);
}

const PristineEntry* pristine_get(const char* funcName) {
    auto it = g_store.find(funcName);
    return (it == g_store.end()) ? nullptr : &it->second;
}

BOOL pristine_restore(const char* funcName) {
    const PristineEntry* e = pristine_get(funcName);
    if (!e) return FALSE;
    DWORD oldProt = 0;
    if (!VirtualProtect(e->funcAddr, e->size, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;
    memcpy(e->funcAddr, e->pristineBytes, e->size);
    VirtualProtect(e->funcAddr, e->size, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), e->funcAddr, e->size);
    log_msg("pristine: restored function bytes");
    return TRUE;
}

void pristine_scan_and_repair_all() {
    int detected = 0;
    int repaired = 0;
    for (auto& pair : g_store) {
        const PristineEntry& e = pair.second;
        BYTE current[PRISTINE_SIZE];
        memcpy(current, e.funcAddr, PRISTINE_SIZE);
        if (memcmp(current, e.pristineBytes, PRISTINE_SIZE) != 0) {
            fprintf(stderr, "[TZD] HOOK DETECTED on %s — repairing\n", pair.first.c_str());
            fflush(stderr);
            detected++;
            if (pristine_restore(pair.first.c_str())) repaired++;
        }
    }
    if (detected > 0) {
        fprintf(stderr, "[TZD] scan cycle: %d hooks detected, %d repaired\n", detected, repaired);
        fflush(stderr);
    }
}

SIZE_T pristine_count() { return g_store.size(); }

intptr_t pristine_get_jvm_base() {
    return (intptr_t)g_jvmDll;
}
