// Architect: tzdwindows 7
// method_replace: Method* entry-point replacement framework.
// Copies target method's entry points (_i2i_entry, _from_interpreted_entry,
// _from_compiled_entry) to source method, making src execute target's code.
// Uses jvm_deopt to prevent JIT inlining and re-compilation.
//
// API: method_replace_java(Method* src, Method* target)
// Java: NativeBridge.replaceMethod(Method srcMethod, Method targetMethod)
//
// this access: When target is a non-static method, it naturally receives
// the receiver (this) from the interpreter frame. When target is static,
// declare first param as Object thiz to receive the receiver.
#include "method_replace.h"
#include "jvm_deopt.h"
#include <cstring>
#include <cstdio>

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

// ─── ReplacedMethod handle ──────────────────────────────────
struct ReplacedMethod {
    long long srcMethodPtr;
    long long tgtMethodPtr;
    long long origI2I;
    long long origFromInterp;
    long long origFromCompiled;
    long long origCode;
    bool redirected;
};

// Resolve jmethodID to Method* (delegates to jvm_deopt)
extern long long resolveMethodPtrExt(jmethodID mid) {
    // Use jvm_deopt's resolution — we need to replicate it here
    if (!mid) return 0;
    long long raw = (long long)mid;
    if (jvm_safe_read((void*)raw, 8)) {
        long long derefed = *(long long*)raw;
        if (derefed && jvm_safe_read((void*)derefed, 64)) {
            long long firstQword = *(long long*)derefed;
            if (firstQword && jvm_safe_read((void*)firstQword, 8))
                return derefed;
        }
    }
    return raw;
}

// ─── Core: replace src's entry points with target's ────────
bool method_replace_java(long long srcMethodPtr, long long tgtMethodPtr) {
    if (!srcMethodPtr || !tgtMethodPtr) return false;

    int offI2I = jvm_deopt_get_offset("i2i_entry");
    int offFI  = jvm_deopt_get_offset("from_interp");
    int offFC  = jvm_deopt_get_offset("from_compiled");
    if (offI2I < 0 || offFI < 0 || offFC < 0) {
        log_msg("method_replace: offsets not detected");
        return false;
    }

    // Step 1: Force src into interpreter mode (deoptimize + anti-inline)
    jvm_force_interpreter(srcMethodPtr);

    // Step 2: Read target's entry points
    long long tgtI2I = 0, tgtFI = 0, tgtFC = 0;
    if (jvm_safe_read((void*)(tgtMethodPtr + offI2I), 8))
        tgtI2I = *(long long*)(tgtMethodPtr + offI2I);
    if (jvm_safe_read((void*)(tgtMethodPtr + offFI), 8))
        tgtFI = *(long long*)(tgtMethodPtr + offFI);
    if (jvm_safe_read((void*)(tgtMethodPtr + offFC), 8))
        tgtFC = *(long long*)(tgtMethodPtr + offFC);

    fprintf(stderr, "[TZD] method_replace: src=0x%llx tgt=0x%llx "
            "tgtI2I=0x%llx tgtFI=0x%llx tgtFC=0x%llx\n",
            srcMethodPtr, tgtMethodPtr, tgtI2I, tgtFI, tgtFC);
    fflush(stderr);

    // Step 3: Make src writable
    DWORD origProt = 0;
    if (!VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &origProt)) {
        log_msg("method_replace: VirtualProtect failed");
        return false;
    }

    // Step 4: Copy target's entry points to src
    *(long long*)(srcMethodPtr + offI2I) = tgtI2I;
    *(long long*)(srcMethodPtr + offFI)  = tgtFI;
    *(long long*)(srcMethodPtr + offFC)  = tgtFC;

    VirtualProtect((void*)srcMethodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);

    fprintf(stderr, "[TZD] method_replace: entry points copied src←tgt (bytecodes unchanged)\n");
    fflush(stderr);
    return true;
}

// ─── Legacy API (for backward compat) ───────────────────────
ReplacedMethod* method_find(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    if (!env || !clazz || !name || !sig) return nullptr;
    jvm_deopt_init(env);
    jmethodID mid = env->GetMethodID(clazz, name, sig);
    if (!mid) mid = env->GetStaticMethodID(clazz, name, sig);
    if (!mid) return nullptr;
    long long mp = resolveMethodPtrExt(mid);
    if (!mp) return nullptr;
    ReplacedMethod* rm = new ReplacedMethod();
    memset(rm, 0, sizeof(*rm));
    rm->srcMethodPtr = mp;
    int offI2I = jvm_deopt_get_offset("i2i_entry");
    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");
    if (offI2I >= 0 && jvm_safe_read((void*)(mp + offI2I), 8))
        rm->origI2I = *(long long*)(mp + offI2I);
    if (offFI >= 0 && jvm_safe_read((void*)(mp + offFI), 8))
        rm->origFromInterp = *(long long*)(mp + offFI);
    if (offFC >= 0 && jvm_safe_read((void*)(mp + offFC), 8))
        rm->origFromCompiled = *(long long*)(mp + offFC);
    if (offCode >= 0 && jvm_safe_read((void*)(mp + offCode), 8))
        rm->origCode = *(long long*)(mp + offCode);
    return rm;
}

bool method_redirect(ReplacedMethod* rm, void* replacementFunc) {
    if (!rm || !replacementFunc || rm->redirected) return false;
    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offI2I = jvm_deopt_get_offset("i2i_entry");
    if (offFI < 0 || offFC < 0) return false;
    jvm_force_interpreter(rm->srcMethodPtr);
    DWORD origProt = 0;
    if (!VirtualProtect((void*)rm->srcMethodPtr, 256, PAGE_READWRITE, &origProt)) return false;
    long long func = (long long)replacementFunc;
    if (offI2I >= 0) *(long long*)(rm->srcMethodPtr + offI2I) = func;
    *(long long*)(rm->srcMethodPtr + offFI) = func;
    *(long long*)(rm->srcMethodPtr + offFC) = func;
    VirtualProtect((void*)rm->srcMethodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)rm->srcMethodPtr, 256);
    rm->redirected = true;
    return true;
}

bool method_restore(ReplacedMethod* rm) {
    if (!rm || !rm->redirected) return false;
    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offI2I = jvm_deopt_get_offset("i2i_entry");
    int offCode = jvm_deopt_get_offset("code");
    DWORD origProt = 0;
    if (!VirtualProtect((void*)rm->srcMethodPtr, 256, PAGE_READWRITE, &origProt)) return false;
    if (offI2I >= 0) *(long long*)(rm->srcMethodPtr + offI2I) = rm->origI2I;
    if (offFI >= 0) *(long long*)(rm->srcMethodPtr + offFI) = rm->origFromInterp;
    if (offFC >= 0) *(long long*)(rm->srcMethodPtr + offFC) = rm->origFromCompiled;
    if (offCode >= 0) *(long long*)(rm->srcMethodPtr + offCode) = rm->origCode;
    VirtualProtect((void*)rm->srcMethodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)rm->srcMethodPtr, 256);
    rm->redirected = false;
    return true;
}

bool method_verify_and_reapply(ReplacedMethod* rm, void* replacementFunc) {
    if (!rm || !rm->redirected || !replacementFunc) return false;
    // Check if redirect was overwritten
    int offFI = jvm_deopt_get_offset("from_interp");
    long long func = (long long)replacementFunc;
    if (offFI >= 0 && jvm_safe_read((void*)(rm->srcMethodPtr + offFI), 8)) {
        if (*(long long*)(rm->srcMethodPtr + offFI) != func) {
            return method_redirect(rm, replacementFunc);
        }
    }
    return true;
}

void* method_get_raw(ReplacedMethod* rm) {
    return rm ? (void*)rm->srcMethodPtr : nullptr;
}
