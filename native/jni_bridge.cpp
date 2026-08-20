// Architect: tzdwindows 7
#include <jni.h>
#include <jvmti.h>
#include <cstring>
#include <cstdio>
#include <cfloat>
#include <windows.h>
#include <psapi.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#define _ReturnAddress() __builtin_return_address(0)
#endif
#include "memory_guard.h"
#include "hook_scanner.h"
#include "pristine_store.h"
#include "method_replace.h"
#include "interpreter_hook.h"
#include "jvm_deopt.h"
#include "anti_tamper.h"
#include "dispatch_hook.h"
#include "protect_class.h"
#include "syscall_hook.h"
#include "process_protect.h"
#include "etw_consumer.h"

// Resolve jmethodID to Method* (from method_replace.cpp)
extern long long resolveMethodPtrExt(jmethodID mid);

static JavaVM *g_jvm = nullptr;
static jvmtiEnv *g_jvmti = nullptr;
static bool g_ready = false;

static void log_msg(const char *m)
{
    fprintf(stderr, "[TZD] %s\n", m);
    fflush(stderr);
}

// ─── JVM_GetEnv interception ────────────────────────────────
// We inline-hook JVM_GetEnv (exported by jvm.dll) so that calls
// from non-JVM modules are rejected. This prevents competitor mods
// from acquiring a JVMTI environment after we do.

typedef jint(JNICALL *JVM_GetEnv_t)(JavaVM *, void **, jint);
static JVM_GetEnv_t g_origGetEnv = nullptr;
static BYTE g_getEnvOrigBytes[16] = {0};
static bool g_getEnvHooked = false;

// Whitelist for JVM_GetEnv callers
static bool isGetEnvCallerAllowed(void *retAddr)
{
    if (!retAddr)
        return false;
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            (LPCSTR)retAddr, &hMod))
        return false;
    char name[MAX_PATH] = {0};
    if (!GetModuleBaseNameA(GetCurrentProcess(), hMod, name, MAX_PATH))
        return false;
    // Allow JVM and system modules
    const char *allowed[] = {
        "jvm.dll", "java.dll", "net.dll", "nio.dll", "zip.dll",
        "verify.dll", "java.exe", "kernel32.dll", "ntdll.dll",
        nullptr};
    for (int i = 0; allowed[i]; i++)
    {
        if (_stricmp(name, allowed[i]) == 0)
            return true;
    }
    if (strstr(name, "tzd") || strstr(name, "seckill"))
        return true;
    return false;
}

// Our replacement for JVM_GetEnv
static jint JNICALL hookedJVM_GetEnv(JavaVM *vm, void **penv, jint version)
{
    void *ret = _ReturnAddress();
    if (!isGetEnvCallerAllowed(ret))
    {
        char name[MAX_PATH] = {0};
        HMODULE hMod = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                               (LPCSTR)ret, &hMod))
        {
            GetModuleBaseNameA(GetCurrentProcess(), hMod, name, MAX_PATH);
        }
        fprintf(stderr, "[TZD] BLOCKED JVM_GetEnv from %s @0x%p (version=0x%x)\n",
                name, ret, version);
        fflush(stderr);
        if (penv)
            *penv = nullptr;
        return JNI_ERR;
    }
    // Call original via saved function pointer
    if (g_origGetEnv)
        return g_origGetEnv(vm, penv, version);
    return JNI_ERR;
}

// Install inline hook on JVM_GetEnv
static void installGetEnvHook()
{
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
    {
        log_msg("GetEnv hook: jvm.dll not found");
        return;
    }

    FARPROC getEnv = GetProcAddress(hJvm, "JVM_GetEnv");
    if (!getEnv)
    {
        log_msg("GetEnv hook: JVM_GetEnv not found");
        return;
    }

    // Save original bytes
    memcpy(g_getEnvOrigBytes, (void *)getEnv, 16);

    // Make writable
    DWORD oldProt = 0;
    if (!VirtualProtect((void *)getEnv, 32, PAGE_EXECUTE_READWRITE, &oldProt))
    {
        log_msg("GetEnv hook: VirtualProtect failed");
        return;
    }

    // Write: mov rax, hookedJVM_GetEnv; jmp rax (14 bytes)
    BYTE patch[14];
    patch[0] = 0x48; // REX.W
    patch[1] = 0xB8; // mov rax, imm64
    void *hookAddr = (void *)hookedJVM_GetEnv;
    memcpy(patch + 2, &hookAddr, 8);
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    patch[12] = 0x90; // nop
    patch[13] = 0x90;
    memcpy((void *)getEnv, patch, 14);

    VirtualProtect((void *)getEnv, 32, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void *)getEnv, 14);

    g_getEnvHooked = true;
    fprintf(stderr, "[TZD] JVM_GetEnv hooked at 0x%p -> 0x%p\n",
            (void *)getEnv, hookAddr);
    fflush(stderr);
}

extern "C"
{

    // Forward declaration (defined in ghost_class.cpp)
    jclass create_ghost_class(JNIEnv *env, jbyteArray bytecodes, jclass templateClass);

    // ─── JNI_OnLoad ────────────────────────────────────────────

    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
    {
        (void)reserved;
        g_jvm = vm;
        JNIEnv *env = nullptr;
        // The DLL is built against JDK 20 headers, but Minecraft/Forge ships
        // JDK 17, which does not recognize JNI_VERSION_20. Probe for the
        // highest JNI version this JVM supports so we load on JDK 17 and 20+
        // alike (we only use JNI 1.2-era functions, so any version suffices).
        static const jint tryVer[] = {
            0x00150000 /*21*/, 0x00140000 /*20*/, 0x00130000 /*19*/,
            0x000a0000 /*10*/, JNI_VERSION_1_8, JNI_VERSION_1_6,
            JNI_VERSION_1_4, JNI_VERSION_1_2};
        jint jniVer = 0;
        for (jint v : tryVer)
        {
            if (vm->GetEnv((void **)&env, v) == JNI_OK && env)
            {
                jniVer = v;
                break;
            }
        }
        if (!jniVer)
        {
            log_msg("GetEnv JNI fail (no supported JNI version)");
            return JNI_ERR;
        }

        // Preempt: acquire JVMTI with ALL capabilities before anyone else.
        // Probe JVMTI versions too — JDK 17 may not offer 1_2.
        static const jint tryJvmti[] = {0x30010200 /*1_2*/, 0x30010100 /*1_1*/, 0x30010000 /*1_0*/};
        jint rc = JNI_ERR;
        for (jint v : tryJvmti)
        {
            rc = vm->GetEnv((void **)&g_jvmti, v);
            if (rc == JNI_OK && g_jvmti)
            {
                break;
            }
            g_jvmti = nullptr;
        }
        if (rc == JNI_OK && g_jvmti)
        {
            jvmtiCapabilities caps;
            memset(&caps, 0, sizeof(caps));
            caps.can_redefine_classes = 1;
            caps.can_retransform_classes = 1;
            caps.can_retransform_any_class = 1;
            caps.can_tag_objects = 1;
            caps.can_pop_frame = 1;
            caps.can_force_early_return = 1;
            caps.can_get_constant_pool = 1;
            caps.can_get_source_file_name = 1;
            caps.can_get_line_numbers = 1;
            caps.can_generate_all_class_hook_events = 1;
            caps.can_maintain_original_method_order = 1;
            g_jvmti->AddCapabilities(&caps);
            g_ready = true;
            jvm_deopt_set_jvmti(g_jvmti); // enable safe (safepoint-based) deopt
            log_msg("JVMTI ready (capabilities preempted)");
            // Patch the shared JVMTI interface table so adversary
            // Retransform/Redefine re-applies our hooks; start the fast guard
            // thread for direct Method* tampering.
            anti_tamper_install(g_jvmti);
            interp_hook_init();
            interp_hook_start_guard();
            // dispatch_hook_init(env) — called later by NativeBridge.dispatchHookInit0()
            // Don't call it here: the data scan is slow (~13MB) and not needed
            // for ghost class creation.
        }
        else
        {
            log_msg("JVMTI acquisition failed");
        }

        // Initialize pristine store (save original bytes of all critical functions)
        pristine_init();

        // Install JVM_GetEnv hook to block competitor JVMTI acquisition
        installGetEnvHook();

        return jniVer;
    }

    // ─── Existing JNI methods ───────────────────────────────────

    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getJvmtiVersion0(JNIEnv *, jclass)
    {
        return g_ready ? (jint)JVMTI_VERSION : 0;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_addToBootstrapSearch0(JNIEnv *env, jclass, jstring path)
    {
        if (!g_ready || !g_jvmti || !path)
            return JNI_FALSE;
        const char *p = env->GetStringUTFChars(path, nullptr);
        if (!p)
            return JNI_FALSE;
        jvmtiError err = g_jvmti->AddToBootstrapClassLoaderSearch(const_cast<char *>(p));
        env->ReleaseStringUTFChars(path, p);
        if (err == JVMTI_ERROR_NONE)
        {
            log_msg("bootstrap search added");
            return JNI_TRUE;
        }
        fprintf(stderr, "[TZD] bootstrap err=%d\n", (int)err);
        fflush(stderr);
        return JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_addToSystemSearch0(JNIEnv *env, jclass, jstring path)
    {
        if (!g_ready || !g_jvmti || !path)
            return JNI_FALSE;
        const char *p = env->GetStringUTFChars(path, nullptr);
        if (!p)
            return JNI_FALSE;
        jvmtiError err = g_jvmti->AddToSystemClassLoaderSearch(const_cast<char *>(p));
        env->ReleaseStringUTFChars(path, p);
        return err == JVMTI_ERROR_NONE ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getLoadedClassCount0(JNIEnv *, jclass)
    {
        if (!g_ready || !g_jvmti)
            return -1;
        jint count = 0;
        g_jvmti->GetLoadedClasses(&count, nullptr);
        return count;
    }

    // ─── Phase 2 JNI methods ────────────────────────────────────

    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_installMemoryGuard0(JNIEnv *, jclass)
    {
        memguard_install();
    }

    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_startHookScanner0(JNIEnv *, jclass)
    {
        scanner_start();
    }

    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_stopHookScanner0(JNIEnv *, jclass)
    {
        scanner_stop();
    }

    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getMemoryGuardBlockCount0(JNIEnv *, jclass)
    {
        return (jlong)memguard_get_block_count();
    }

    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getHookScannerRepairCount0(JNIEnv *, jclass)
    {
        return (jlong)scanner_get_repair_count();
    }

    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_scanAndRepairNow0(JNIEnv *, jclass)
    {
        return (jint)scanner_scan_now();
    }

    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getJvmBaseAddress0(JNIEnv *, jclass)
    {
        return (jlong)pristine_get_jvm_base();
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_isFunctionHooked0(JNIEnv *, jclass, jlong addr, jint size)
    {
        if (addr == 0 || size <= 0)
            return JNI_FALSE;
        BYTE *p = (BYTE *)addr;
        // Check for common hook prologues
        if (p[0] == 0xE9)
            return JNI_TRUE; // jmp rel32
        if (p[0] == 0xEB)
            return JNI_TRUE; // jmp rel8
        if (p[0] == 0xFF && p[1] == 0x25)
            return JNI_TRUE; // jmp [rip+disp]
        if (p[0] == 0x48 && p[1] == 0xB8 &&
            p[10] == 0xFF && p[11] == 0xE0)
            return JNI_TRUE; // movabs rax; jmp rax
        // Compare to pristine if available
        return JNI_FALSE;
    }

    // ─── Method replacement (no JVMTI, no bytecode modification) ──

    // Find a method by class + name + signature. Returns a jlong handle.
    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodFind0(
        JNIEnv *env, jclass, jclass clazz, jstring name, jstring sig)
    {
        if (!clazz || !name || !sig)
            return 0;
        const char *n = env->GetStringUTFChars(name, nullptr);
        const char *s = env->GetStringUTFChars(sig, nullptr);
        if (!n || !s)
        {
            if (n)
                env->ReleaseStringUTFChars(name, n);
            if (s)
                env->ReleaseStringUTFChars(sig, s);
            return 0;
        }
        ReplacedMethod *rm = method_find(env, clazz, n, s);
        env->ReleaseStringUTFChars(name, n);
        env->ReleaseStringUTFChars(sig, s);
        return (jlong)(intptr_t)rm;
    }

    // Redirect a method's entry point to a native function pointer.
    // Forces interpreter mode (clears _code/nmethod).
    // Bytecodes remain unchanged — JVMTI GetBytecodes sees original.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodRedirect0(
        JNIEnv *, jclass, jlong handle, jlong funcPtr)
    {
        ReplacedMethod *rm = (ReplacedMethod *)(intptr_t)handle;
        if (!rm || !funcPtr)
            return JNI_FALSE;
        return method_redirect(rm, (void *)(intptr_t)funcPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // Restore the original entry point
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodRestore0(
        JNIEnv *, jclass, jlong handle)
    {
        ReplacedMethod *rm = (ReplacedMethod *)(intptr_t)handle;
        if (!rm)
            return JNI_FALSE;
        return method_restore(rm) ? JNI_TRUE : JNI_FALSE;
    }

    // Detect Method* field offsets at runtime
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodDetectOffsets0(
        JNIEnv *env, jclass)
    {
        jvm_deopt_init(env);
    }

    // Verify redirect is still in place (guard against bypass via
    // JIT recompilation / link_method / clear_code / RetransformClasses)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodVerify0(
        JNIEnv *, jclass, jlong handle, jlong funcPtr)
    {
        ReplacedMethod *rm = (ReplacedMethod *)(intptr_t)handle;
        if (!rm || !funcPtr)
            return JNI_FALSE;
        return method_verify_and_reapply(rm, (void *)(intptr_t)funcPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // ─── Replacement functions for method redirect tests ────────
    // These are C functions that will be called when the redirected
    // Java method is invoked. They receive arguments via the platform
    // ABI (Windows x64: rcx=1st, rdx=2nd, r8=3rd, r9=4th).
    //
    // For a non-static Java method called through _from_compiled_entry,
    // the calling convention is:
    //   rcx = JNIEnv* (or the method's first argument)
    //   rdx = jobject thisObj (receiver)
    //
    // For a method returning float, the return value goes in xmm0.

    // Replacement for getHealth() — returns FLT_MAX (one-shot kill)
    extern "C" __declspec(dllexport)
    jfloat
    tzd_replacement_getHealth(void *arg1, void *arg2)
    {
        fprintf(stderr, "[TZD] replacement getHealth called! returning FLT_MAX\n");
        fflush(stderr);
        return FLT_MAX; // 3.4028235E38
    }

    // Replacement for getHealth() — returns 0 (instant death for enemies)
    extern "C" __declspec(dllexport)
    jfloat
    tzd_replacement_getHealth_zero(void *arg1, void *arg2)
    {
        return 0.0f;
    }

    // Replacement for int-returning methods — returns 999
    extern "C" __declspec(dllexport)
    jint
    tzd_replacement_getInt_999(void *arg1, void *arg2)
    {
        fprintf(stderr, "[TZD] replacement getInt called! returning 999\n");
        fflush(stderr);
        return 999;
    }

    // Get replacement function pointer by index
    // 0 = getHealth returning FLT_MAX
    // 1 = getHealth returning 0
    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getReplacementFuncByIndex0(
        JNIEnv *, jclass, jint index)
    {
        switch (index)
        {
        case 0:
            return (jlong)(intptr_t)&tzd_replacement_getHealth;
        case 1:
            return (jlong)(intptr_t)&tzd_replacement_getHealth_zero;
        case 2:
            return (jlong)(intptr_t)&tzd_replacement_getInt_999;
        default:
            return 0;
        }
    }

    // ─── Interpreter hook (separate from method_replace) ────────
    // These hook the interpreter's dispatch table directly.

    // Initialize: find the dispatch table in jvm.dll
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookInit0(
        JNIEnv *, jclass)
    {
        return interp_hook_init() ? JNI_TRUE : JNI_FALSE;
    }

    // Resolve a reflected Method to its raw Method* address.
    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodPtrOf0(
        JNIEnv *env, jclass, jobject m)
    {
        if (!m)
            return 0;
        jmethodID mid = env->FromReflectedMethod(m);
        if (!mid)
            return 0;
        return (jlong)resolveMethodPtrExt(mid);
    }

    // Start/stop the fast guard thread (auto-started in JNI_OnLoad, but exposed
    // for explicit control).
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookStartGuard0(
        JNIEnv *, jclass) { interp_hook_start_guard(); }
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookStopGuard0(
        JNIEnv *, jclass) { interp_hook_stop_guard(); }

    // Self-test: trigger a JVMTI RetransformClasses on `clazz` via our own env.
    // Because anti_tamper patched the shared JVMTI table, this hits our filter,
    // which re-applies hooks after the retransform — so an adversary's
    // retransform can't revert us. Returns the jvmtiError code.
    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_selfRetransform0(
        JNIEnv *, jclass, jclass clazz)
    {
        if (!g_ready || !g_jvmti || !clazz)
            return -1;
        return (jint)g_jvmti->RetransformClasses(1, &clazz);
    }

    // Test helper: simulate an adversary reverting src._constMethod. The guard
    // thread should re-apply within ~1ms.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_testTamperConstMethod0(
        JNIEnv *, jclass, jlong srcMethodPtr)
    {
        return interp_hook_test_tamper((long long)srcMethodPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // ─── Real interpreter hook (dispatch-table level, Method*-independent) ──
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_dispatchHookInit0(
        JNIEnv *env, jclass)
    {
        return dispatch_hook_init(env) ? JNI_TRUE : JNI_FALSE;
    }
    // Install: at src's freturn, if bcp is in src's bytecode range, invoke the
    // (static) target Java method via JNI and return its float. src's Method*
    // is NEVER written.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_dispatchHookFreturn0(
        JNIEnv *env, jclass, jlong srcMethodPtr, jobject tgtMethod)
    {
        if (!srcMethodPtr || !tgtMethod)
            return JNI_FALSE;
        return dispatch_hook_freturn(env, (long long)srcMethodPtr,
                                     (long long)(intptr_t)tgtMethod)
                   ? JNI_TRUE
                   : JNI_FALSE;
    }
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_dispatchHookFreturnRemove0(
        JNIEnv *, jclass, jlong srcMethodPtr)
    {
        return dispatch_hook_remove((long long)srcMethodPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // Install hook: make src return a captured constant (stub-based, no
    // constMethod swap). The target method is invoked once via JNI to capture
    // its return value; a tiny executable stub is generated that returns that
    // value, and src's _from_interpreted_entry / _from_compiled_entry are
    // redirected to it. The JIT compiler's metadata chain stays intact.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookFreturn0(
        JNIEnv *env, jclass, jlong srcMethodPtr, jobject tgtMethod)
    {
        if (!srcMethodPtr || !tgtMethod)
            return JNI_FALSE;

        // Resolve the target's declaring class + jmethodID
        jmethodID tgtMid = env->FromReflectedMethod(tgtMethod);
        if (!tgtMid)
        {
            log_msg("interpHookFreturn0: FromReflectedMethod failed");
            return JNI_FALSE;
        }

        jclass methodCls = env->FindClass("java/lang/reflect/Method");
        if (!methodCls)
            return JNI_FALSE;
        jmethodID getDC = env->GetMethodID(methodCls, "getDeclaringClass", "()Ljava/lang/Class;");
        jmethodID getMods = env->GetMethodID(methodCls, "getModifiers", "()I");
        jmethodID getRT = env->GetMethodID(methodCls, "getReturnType", "()Ljava/lang/Class;");
        if (!getDC || !getMods || !getRT)
        {
            env->DeleteLocalRef(methodCls);
            return JNI_FALSE;
        }

        jclass tgtClass = (jclass)env->CallObjectMethod(tgtMethod, getDC);
        if (!tgtClass || env->ExceptionCheck())
        {
            env->DeleteLocalRef(methodCls);
            return JNI_FALSE;
        }
        tgtClass = (jclass)env->NewGlobalRef(tgtClass);

        jint mods = env->CallIntMethod(tgtMethod, getMods);
        if (env->ExceptionCheck())
        {
            env->ExceptionClear();
            env->DeleteGlobalRef(tgtClass);
            env->DeleteLocalRef(methodCls);
            return JNI_FALSE;
        }
        bool isStatic = (mods & 0x00000008) != 0;

        // Detect return type
        jclass rtClass = (jclass)env->CallObjectMethod(tgtMethod, getRT);
        if (env->ExceptionCheck())
        {
            env->ExceptionClear();
            env->DeleteGlobalRef(tgtClass);
            env->DeleteLocalRef(methodCls);
            return JNI_FALSE;
        }

        // Detect return type using Class.getName() to handle primitive types
        // correctly (float.class != java.lang.Float in JNI IsSameObject).
        jclass classCls2 = env->FindClass("java/lang/Class");
        jmethodID getName = env->GetMethodID(classCls2, "getName", "()Ljava/lang/String;");
        jstring rtName = (jstring)env->CallObjectMethod(rtClass, getName);
        const char *rtNameStr = env->GetStringUTFChars(rtName, nullptr);

        int retType = 2; // default void
        long long retBits = 0;

        if (strcmp(rtNameStr, "float") == 0)
        {
            retType = 0; // float → xmm0
        }
        else if (strcmp(rtNameStr, "double") == 0)
        {
            retType = 1; // double → xmm0
        }
        else if (strcmp(rtNameStr, "int") == 0 ||
                 strcmp(rtNameStr, "short") == 0 ||
                 strcmp(rtNameStr, "byte") == 0 ||
                 strcmp(rtNameStr, "char") == 0 ||
                 strcmp(rtNameStr, "boolean") == 0)
        {
            retType = 2; // int → eax
        }
        else if (strcmp(rtNameStr, "long") == 0)
        {
            retType = 3; // long → rax
        }
        else if (strcmp(rtNameStr, "void") == 0)
        {
            retType = 5; // void → no return
        }
        else
        {
            retType = 4; // object → null (rax=0)
        }

        env->ReleaseStringUTFChars(rtName, rtNameStr);
        env->DeleteLocalRef(rtName);
        env->DeleteLocalRef(classCls2);

        // Invoke target to capture return value (only for types that have a value)
        if (retType == 0)
        {
            // Float return
            jfloat fv;
            if (isStatic)
                fv = env->CallStaticFloatMethod(tgtClass, tgtMid);
            else
            {
                jobject recv = env->AllocObject(tgtClass);
                if (recv)
                {
                    fv = env->CallFloatMethod(recv, tgtMid);
                    env->DeleteLocalRef(recv);
                }
                else
                {
                    env->DeleteGlobalRef(tgtClass);
                    env->DeleteLocalRef(methodCls);
                    env->DeleteLocalRef(rtClass);
                    return JNI_FALSE;
                }
            }
            if (env->ExceptionCheck())
            {
                env->ExceptionClear();
                log_msg("target threw");
                env->DeleteGlobalRef(tgtClass);
                env->DeleteLocalRef(methodCls);
                env->DeleteLocalRef(rtClass);
                return JNI_FALSE;
            }
            float fv2 = fv;
            memcpy(&retBits, &fv2, 4);
        }
        else if (retType == 1)
        {
            // Double return
            jdouble dv;
            if (isStatic)
                dv = env->CallStaticDoubleMethod(tgtClass, tgtMid);
            else
            {
                jobject recv = env->AllocObject(tgtClass);
                if (recv)
                {
                    dv = env->CallDoubleMethod(recv, tgtMid);
                    env->DeleteLocalRef(recv);
                }
                else
                {
                    env->DeleteGlobalRef(tgtClass);
                    env->DeleteLocalRef(methodCls);
                    env->DeleteLocalRef(rtClass);
                    return JNI_FALSE;
                }
            }
            if (env->ExceptionCheck())
            {
                env->ExceptionClear();
                log_msg("target threw");
                env->DeleteGlobalRef(tgtClass);
                env->DeleteLocalRef(methodCls);
                env->DeleteLocalRef(rtClass);
                return JNI_FALSE;
            }
            memcpy(&retBits, &dv, 8);
        }
        else if (retType == 2)
        {
            // Int return (also short, byte, char, boolean)
            jint iv;
            if (isStatic)
                iv = env->CallStaticIntMethod(tgtClass, tgtMid);
            else
            {
                jobject recv = env->AllocObject(tgtClass);
                if (recv)
                {
                    iv = env->CallIntMethod(recv, tgtMid);
                    env->DeleteLocalRef(recv);
                }
                else
                {
                    env->DeleteGlobalRef(tgtClass);
                    env->DeleteLocalRef(methodCls);
                    env->DeleteLocalRef(rtClass);
                    return JNI_FALSE;
                }
            }
            if (env->ExceptionCheck())
            {
                env->ExceptionClear();
                log_msg("target threw");
                env->DeleteGlobalRef(tgtClass);
                env->DeleteLocalRef(methodCls);
                env->DeleteLocalRef(rtClass);
                return JNI_FALSE;
            }
            retBits = (long long)(int)iv;
        }
        else if (retType == 3)
        {
            // Long return
            jlong lv;
            if (isStatic)
                lv = env->CallStaticLongMethod(tgtClass, tgtMid);
            else
            {
                jobject recv = env->AllocObject(tgtClass);
                if (recv)
                {
                    lv = env->CallLongMethod(recv, tgtMid);
                    env->DeleteLocalRef(recv);
                }
                else
                {
                    env->DeleteGlobalRef(tgtClass);
                    env->DeleteLocalRef(methodCls);
                    env->DeleteLocalRef(rtClass);
                    return JNI_FALSE;
                }
            }
            if (env->ExceptionCheck())
            {
                env->ExceptionClear();
                log_msg("target threw");
                env->DeleteGlobalRef(tgtClass);
                env->DeleteLocalRef(methodCls);
                env->DeleteLocalRef(rtClass);
                return JNI_FALSE;
            }
            retBits = (long long)lv;
        }
        else if (retType == 4)
        {
            // Object return → return null (retBits = 0)
            retBits = 0;
        }
        // retType == 5 (void): retBits = 0, no capture needed

        env->DeleteGlobalRef(tgtClass);
        env->DeleteLocalRef(methodCls);
        env->DeleteLocalRef(rtClass);

        fprintf(stderr, "[TZD] interpHookFreturn0: src=0x%llx retType=%d retBits=0x%llx\n",
                (long long)srcMethodPtr, retType, retBits);
        fflush(stderr);

        // Use the stub-based hook (no constMethod swap)
        return interp_hook_stub((long long)srcMethodPtr, retType, retBits) ? JNI_TRUE : JNI_FALSE;
    }

    // Remove hook: restore src's original constMethod + entry points.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookFreturnRemove0(
        JNIEnv *, jclass, jlong srcMethodPtr)
    {
        return interp_hook_remove((long long)srcMethodPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // Deoptimize a method (set _code = NULL, force interpreter mode)
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookDeoptimize0(
        JNIEnv *, jclass, jlong methodPtr, jint codeOffset)
    {
        interp_hook_deoptimize((long long)methodPtr, (int)codeOffset);
    }

    // Get the raw Method* from a ReplacedMethod handle (for passing to interp hook)
    JNIEXPORT jlong JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_methodGetRawPtr0(
        JNIEnv *, jclass, jlong handle)
    {
        ReplacedMethod *rm = (ReplacedMethod *)(intptr_t)handle;
        return (jlong)(intptr_t)method_get_raw(rm);
    }

    // ─── Unified Framework JNI methods ──────────────────────────

    // Initialize jvm_deopt (detect Method* offsets)
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_jvmDeoptInit0(
        JNIEnv *env, jclass)
    {
        jvm_deopt_init(env);
    }

    // Framework 1: Method* entry-point replacement (src ← target)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_replaceMethod0(
        JNIEnv *env, jclass, jobject srcMethod, jobject tgtMethod)
    {
        if (!srcMethod || !tgtMethod)
            return JNI_FALSE;
        jvm_deopt_init(env);
        jmethodID srcMid = env->FromReflectedMethod(srcMethod);
        jmethodID tgtMid = env->FromReflectedMethod(tgtMethod);
        if (!srcMid || !tgtMid)
            return JNI_FALSE;
        long long srcPtr = resolveMethodPtrExt(srcMid);
        long long tgtPtr = resolveMethodPtrExt(tgtMid);
        if (!srcPtr || !tgtPtr)
            return JNI_FALSE;
        return method_replace_java(srcPtr, tgtPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // Framework 2: Interpreter-level hook (src ← target)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_hookInterpreterMethod0(
        JNIEnv *env, jclass, jobject srcMethod, jobject tgtMethod)
    {
        if (!srcMethod || !tgtMethod)
            return JNI_FALSE;
        jvm_deopt_init(env);
        jmethodID srcMid = env->FromReflectedMethod(srcMethod);
        jmethodID tgtMid = env->FromReflectedMethod(tgtMethod);
        if (!srcMid || !tgtMid)
            return JNI_FALSE;
        long long srcPtr = resolveMethodPtrExt(srcMid);
        long long tgtPtr = resolveMethodPtrExt(tgtMid);
        if (!srcPtr || !tgtPtr)
            return JNI_FALSE;
        return interp_hook_java(srcPtr, tgtPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // Remove interpreter hook by src Method
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_removeInterpreterHook0(
        JNIEnv *env, jclass, jobject srcMethod)
    {
        if (!srcMethod)
            return JNI_FALSE;
        jmethodID srcMid = env->FromReflectedMethod(srcMethod);
        if (!srcMid)
            return JNI_FALSE;
        long long srcPtr = resolveMethodPtrExt(srcMid);
        if (!srcPtr)
            return JNI_FALSE;
        return interp_hook_remove(srcPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // ─── Stub-based interpreter hook (no constMethod swap) ──────────────
    // Allocates a tiny executable stub that returns a captured constant and
    // redirects src's _from_interpreted_entry / _from_compiled_entry to it.
    //   retType: 0 = float, 1 = int, 2 = void
    //   retValueBits: raw bits of the return value
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookStub0(
        JNIEnv *, jclass, jlong srcMethodPtr, jint retType, jlong retValueBits)
    {
        if (!srcMethodPtr)
            return JNI_FALSE;
        return interp_hook_stub((long long)srcMethodPtr, (int)retType,
                                (long long)retValueBits)
                   ? JNI_TRUE
                   : JNI_FALSE;
    }

    // ─── Complete method replacement (entry-point copy for methods with params) ──
    // Copies target's _from_interpreted_entry / _from_compiled_entry to src.
    // src executes target's bytecodes (this + args shared via interpreter frame).
    // No constMethod swap — JIT metadata chain stays intact.
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_interpHookReplace0(
        JNIEnv *env, jclass, jlong srcMethodPtr, jobject tgtMethod)
    {
        if (!srcMethodPtr || !tgtMethod)
            return JNI_FALSE;
        jmethodID tgtMid = env->FromReflectedMethod(tgtMethod);
        if (!tgtMid)
        {
            log_msg("interpHookReplace0: FromReflectedMethod failed");
            return JNI_FALSE;
        }
        long long tgtPtr = resolveMethodPtrExt(tgtMid);
        if (!tgtPtr)
        {
            log_msg("interpHookReplace0: resolve target Method* failed");
            return JNI_FALSE;
        }
        return interp_hook_replace((long long)srcMethodPtr, tgtPtr) ? JNI_TRUE : JNI_FALSE;
    }

    // ─── Class protection (pure native, no JVMTI) ───────────────────────
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_protectClass0(
        JNIEnv *env, jclass, jclass clazz)
    {
        if (!clazz)
            return JNI_FALSE;
        return protect_class(env, clazz) ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_unprotectClass0(
        JNIEnv *env, jclass, jclass clazz)
    {
        if (!clazz)
            return JNI_FALSE;
        return unprotect_class(env, clazz) ? JNI_TRUE : JNI_FALSE;
    }

    // ─── Debug: protection status report ──────────────────────────────
    JNIEXPORT jstring JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_debugCheckProtection0(
        JNIEnv *env, jclass, jclass clazz)
    {
        if (!clazz)
            return env->NewStringUTF("null clazz");
        const char *report = debug_check_protection(env, clazz);
        return env->NewStringUTF(report);
    }

    // ─── Ghost class: inject bytecodes as hidden class (bypass ClassLoader) ──
    // Creates a class by cloning a template InstanceKlass and replacing
    // bytecodes — NO Lookup, NO defineClass, NO JVM_DefineClass.
    // The class lives in VirtualAlloc'd memory, invisible to SystemDictionary.
    JNIEXPORT jclass JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_defineGhostClass0(
        JNIEnv *env, jclass, jbyteArray bytecodes, jclass hostClass)
    {
        return create_ghost_class(env, bytecodes, hostClass);
    }

    // ─── Syscall Hook: universal R3 syscall interception ───
    // Patches ALL ntdll syscall stubs (0F 05 → 0F 0B). A VEH handler
    // catches the resulting EXCEPTION_ILLEGAL_INSTRUCTION and redirects
    // to a private syscall;ret stub. Only our DLL's direct syscall stubs
    // bypass the interception. Dangerous syscalls from non-bypass callers
    // are blocked with STATUS_ACCESS_DENIED.
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_syscallHookEnable0(
        JNIEnv *, jclass)
    {
        // syscall_hook_enable();
    }

    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_syscallHookDisable0(
        JNIEnv *, jclass)
    {
        // syscall_hook_disable();
    }

    // ─── 进程保护 (PPL via BYOVD) ──────────────────────────────────
    // 详见 docs/PPL_RESEARCH.md。强制启用 PPL 保护:
    //   driverPath : .sys 驱动文件绝对路径; null=仅查询状态
    //   driverType : 0=NONE, 1=RTCore64, 2=GENERIC, 3=CUSTOM, 4=APPID, 5=KERNCORE(KernCoreLib64.sys)
    //   targetPpl  : 目标 PPL 字节 (0xC1=WinTcb PPL, 0xA1=Windows PPL...)
    // 返回 0=成功, 负数=错误码 (见 process_protect.h TZD_PP_ERR_*)
    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_processProtect0(
        JNIEnv *env, jclass, jstring driverPath, jint driverType, jint targetPpl)
    {
        const char *path = nullptr;
        if (driverPath)
            path = env->GetStringUTFChars(driverPath, nullptr);
        int rc = process_protect_byovd(path, (int)driverType,
                                       (unsigned char)(int)targetPpl);
        if (path)
            env->ReleaseStringUTFChars(driverPath, path);
        return (jint)rc;
    }

    // 查询当前进程 PPL 保护字节 (0=无保护, 0xC1=WinTcb PPL, -1=查询失败)
    JNIEXPORT jint JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getProcessProtectionByte0(
        JNIEnv *, jclass)
    {
        return (jint)process_protect_get_protection_byte();
    }

    // 获取保护状态 JSON 字串
    JNIEXPORT jstring JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_getProcessProtectionStatus0(
        JNIEnv *env, jclass)
    {
        return env->NewStringUTF(process_protect_get_status());
    }

    // 设置通用驱动 IOCTL 协议 (driverType=GENERIC 时使用)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_setGenericDriverIoctl0(
        JNIEnv *env, jclass, jstring deviceName, jint readIoctl, jint writeIoctl)
    {
        if (!deviceName)
            return JNI_FALSE;
        const char *dev = env->GetStringUTFChars(deviceName, nullptr);
        bool ok = process_protect_set_generic_ioctl(dev,
                     (unsigned int)(int)readIoctl,
                     (unsigned int)(int)writeIoctl);
        env->ReleaseStringUTFChars(deviceName, dev);
        return ok ? JNI_TRUE : JNI_FALSE;
    }

    // 设置 KernCoreLib64 物理扫描的 hole-free RAM 物理范围 (CSV: "base,len;...")
    //   仅扫描这些范围 → 绝不盲扫 → 不会卡死; 空则 kerncore 拒绝 (TZD_PP_ERR_NO_RAMMAP)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_setRamRanges0(
        JNIEnv *env, jclass, jstring rangesCsv)
    {
        if (!rangesCsv)
            return JNI_FALSE;
        const char *csv = env->GetStringUTFChars(rangesCsv, nullptr);
        bool ok = process_protect_set_ram_ranges(csv);
        env->ReleaseStringUTFChars(rangesCsv, csv);
        return ok ? JNI_TRUE : JNI_FALSE;
    }

    // 卸载已加载的 BYOVD 驱动服务
    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_unloadProtectDriver0(
        JNIEnv *, jclass)
    {
        process_protect_unload_driver();
    }

    // ════════════════════════════════════════════════════════════════
    // ─── 反 shellcode / ETW-TI / systrace / 进程保护 JNI 方法 ──────────
    // ════════════════════════════════════════════════════════════════

    // 设置 syscall 扫描监控 PID
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_setMonitorPid0(
        JNIEnv *, jclass, jint pid)
    {
        return process_protect_kernel_set_monitor_pid((unsigned long)pid)
               ? JNI_TRUE : JNI_FALSE;
    }

    // 扫描 syscall stub → 返回 long[]{hits, nxBlocked}
    JNIEXPORT jlongArray JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_scanSyscalls0(
        JNIEnv *env, jclass)
    {
        unsigned long hits = 0, nxBlocked = 0;
        process_protect_kernel_scan_syscalls(&hits, &nxBlocked);
        jlong vals[2] = { (jlong)hits, (jlong)nxBlocked };
        jlongArray arr = env->NewLongArray(2);
        if (arr) env->SetLongArrayRegion(arr, 0, 2, vals);
        return arr;
    }

    // 事件驱动进程保护 (ObRegisterCallbacks)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_protectPid0(
        JNIEnv *, jclass, jint pid)
    {
        return process_protect_kernel_protect_pid((unsigned long)pid)
               ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_unprotectPid0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_unprotect_pid() ? JNI_TRUE : JNI_FALSE;
    }

    // 反 shellcode 防御武装 (自动启动告警轮询)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_armScDefense0(
        JNIEnv *, jclass, jint pid)
    {
        return process_protect_kernel_arm_sc_defense((unsigned long)pid)
               ? JNI_TRUE : JNI_FALSE;
    }

    // 反 shellcode 防御解除 (自动停止告警轮询)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_disarmScDefense0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_disarm_sc_defense() ? JNI_TRUE : JNI_FALSE;
    }

    // 查询反 shellcode 统计 → long[]{scans, pagesNx, threadsSeen, imagesSeen,
    //   unsignedImgs, filelessPe, etwTiEnabled}
    JNIEXPORT jlongArray JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_queryScStats0(
        JNIEnv *env, jclass)
    {
        unsigned long scans=0, pagesNx=0, threadsSeen=0, imagesSeen=0,
                      unsignedImgs=0, filelessPe=0, etwTiEnabled=0;
        process_protect_kernel_query_sc_stats(&scans, &pagesNx, &threadsSeen,
                                              &imagesSeen, &unsignedImgs,
                                              &filelessPe, &etwTiEnabled);
        jlong vals[7] = { (jlong)scans, (jlong)pagesNx, (jlong)threadsSeen,
                          (jlong)imagesSeen, (jlong)unsignedImgs,
                          (jlong)filelessPe, (jlong)etwTiEnabled };
        jlongArray arr = env->NewLongArray(7);
        if (arr) env->SetLongArrayRegion(arr, 0, 7, vals);
        return arr;
    }

    // ETW Threat-Intelligence 主方案
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_armEtwTi0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_arm_etw_ti() ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_disarmEtwTi0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_disarm_etw_ti() ? JNI_TRUE : JNI_FALSE;
    }

    // 系统调用追踪 (KiDynamicTraceMask gate)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_armSystrace0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_arm_systrace() ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_disarmSystrace0(
        JNIEnv *, jclass)
    {
        return process_protect_kernel_disarm_systrace() ? JNI_TRUE : JNI_FALSE;
    }

    // 查询告警 → long[]{compromised, childBlocked, lastShellcodeType,
    //   creatorThreadId, lastShellcodeVa}
    JNIEXPORT jlongArray JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_queryAlert0(
        JNIEnv *env, jclass)
    {
        unsigned long compromised=0, childBlocked=0, type=0, tid=0;
        unsigned long long va=0;
        process_protect_kernel_query_alert(&compromised, &childBlocked,
                                           &type, &tid, &va);
        jlong vals[5] = { (jlong)compromised, (jlong)childBlocked,
                         (jlong)type, (jlong)tid, (jlong)va };
        jlongArray arr = env->NewLongArray(5);
        if (arr) env->SetLongArrayRegion(arr, 0, 5, vals);
        return arr;
    }

    // 告警轮询线程 (500ms poll → compromised=1 → kill 0x5C)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_startAlertPolling0(
        JNIEnv *, jclass)
    {
        return process_protect_start_alert_polling() ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_stopAlertPolling0(
        JNIEnv *, jclass)
    {
        return process_protect_stop_alert_polling() ? JNI_TRUE : JNI_FALSE;
    }

    // ════════════════════════════════════════════════════════════════
    // ─── ETW ThreatIntelligence consumer ──────────────────────────────
    //   开 trace session + 启用 ThreatInt provider + 后台线程消费事件。
    //   ThreatInt 事件含 NtProtectVM/NtAllocateVM/NtCreateThread 等 syscall。
    //   需 PPL Antimalware Light 订阅 (setPpl=true 自动设)。
    // ════════════════════════════════════════════════════════════════

    // 启动 ETW consumer: setPpl=true 自动设 PPL Antimalware Light
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_startEtwConsumer0(
        JNIEnv *, jclass, jint pid, jboolean setPpl)
    {
        return etw_consumer_start((unsigned long)pid, setPpl ? 1 : 0)
               ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_stopEtwConsumer0(
        JNIEnv *, jclass)
    {
        return etw_consumer_stop() ? JNI_TRUE : JNI_FALSE;
    }

    // Thin Hypervisor (VMX + EPT)
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_armHypervisor0(
        JNIEnv *, jclass)
    {
        return process_protect_arm_hypervisor() ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT void JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_disarmHypervisor0(
        JNIEnv *, jclass)
    {
        process_protect_disarm_hypervisor();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ─── JIT 代码缓存写保护 (EPT-based: 区分 JIT 合法写 vs 恶意篡改) ──────────
    //   调用前需先 armHypervisor0() 成功武装 hypervisor
    // ═══════════════════════════════════════════════════════════════════════

    // 注册 JIT 代码缓存 GVA 范围 (JDK20 有 3 个代码堆, 各调一次)
    //   pid  : 目标 Java 进程 PID (附着进程走页表限制物理页)
    //   base : JIT 代码缓存堆 GVA 基址
    //   size : JIT 代码缓存堆 GVA 大小
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_registerJitRange0(
        JNIEnv *, jclass, jint pid, jlong base, jlong size)
    {
        return process_protect_register_jit_range((unsigned long)pid,
                                                   (unsigned long long)base,
                                                   (unsigned long long)size)
                   ? JNI_TRUE : JNI_FALSE;
    }

    // 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段; 合法 JIT 补丁的写者 RIP 必在此内)
    //   jvmBase : jvm.dll/java.exe 代码段基址
    //   jvmSize : jvm.dll/java.exe 代码段大小
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_setJvmWriter0(
        JNIEnv *, jclass, jlong jvmBase, jlong jvmSize)
    {
        return process_protect_set_jvm_writer((unsigned long long)jvmBase,
                                               (unsigned long long)jvmSize)
                   ? JNI_TRUE : JNI_FALSE;
    }

    // 查询 JIT 篡改告警 — jitTampered=1 → 用户层应 kill 进程
    //   返回 long[6]: { tampered, blocks, allows, rangeCount, tamperRip(低32), tamperRip(高32) }
    //   或用 tamperRip/tamperVa 的 long[2] out 参数 (此处用 long[] 一并返回)
    JNIEXPORT jlongArray JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_queryJitAlert0(
        JNIEnv *env, jclass)
    {
        unsigned long tampered = 0, blocks = 0, allows = 0, rangeCount = 0;
        unsigned long long tamperRip = 0, tamperVa = 0;
        if (!process_protect_query_jit_alert(&tampered, &blocks, &allows,
                                             &rangeCount, &tamperRip, &tamperVa)) {
            // 返回全 0 数组 (调用失败)
            tampered = blocks = allows = rangeCount = 0;
            tamperRip = tamperVa = 0;
        }
        jlong arr[6];
        arr[0] = (jlong)tampered;
        arr[1] = (jlong)blocks;
        arr[2] = (jlong)allows;
        arr[3] = (jlong)rangeCount;
        arr[4] = (jlong)tamperRip;
        arr[5] = (jlong)tamperVa;
        jlongArray result = env->NewLongArray(6);
        if (result)
            env->SetLongArrayRegion(result, 0, 6, arr);
        return result;
    }

    // 清除所有 JIT 范围 + 恢复 restricted EPT 为 RWX
    JNIEXPORT jboolean JNICALL Java_it_unimi_dsi_fastutil_tzd_bridge_NativeBridge_clearJitRanges0(
        JNIEnv *, jclass)
    {
        return process_protect_clear_jit_ranges() ? JNI_TRUE : JNI_FALSE;
    }

} // extern "C"
