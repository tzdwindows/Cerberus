// Architect: tzdwindows 7
#include "anti_tamper.h"
#include "interpreter_hook.h"
#include <cstdio>
#include <cstddef>

static intptr_t* g_table = nullptr;       // the jvmtiInterface_1_ function table
static intptr_t  g_origRetransform = 0;
static intptr_t  g_origRedefine = 0;
static size_t    g_offRT = 0, g_offRD = 0;

// Filter: call the original RetransformClasses, then immediately re-apply
// our method hooks (constMethod swap). The adversary's redefinition is
// overwritten before the call returns.
static jvmtiError JNICALL my_retransform(jvmtiEnv* env, jint class_count,
                                         const jclass* classes) {
    typedef jvmtiError (JNICALL *fn_t)(jvmtiEnv*, jint, const jclass*);
    jvmtiError e = JVMTI_ERROR_NONE;
    if (g_origRetransform)
        e = ((fn_t)g_origRetransform)(env, class_count, classes);
    interp_hook_guard();
    fprintf(stderr, "[TZD] anti-tamper: RetransformClasses intercepted, "
            "hooks re-applied (rc=%d, n=%d)\n", (int)e, (int)class_count);
    fflush(stderr);
    return e;
}

static jvmtiError JNICALL my_redefine(jvmtiEnv* env, jint class_count,
                                      const jvmtiClassDefinition* defs) {
    typedef jvmtiError (JNICALL *fn_t)(jvmtiEnv*, jint, const jvmtiClassDefinition*);
    jvmtiError e = JVMTI_ERROR_NONE;
    if (g_origRedefine)
        e = ((fn_t)g_origRedefine)(env, class_count, defs);
    interp_hook_guard();
    fprintf(stderr, "[TZD] anti-tamper: RedefineClasses intercepted, "
            "hooks re-applied (rc=%d, n=%d)\n", (int)e, (int)class_count);
    fflush(stderr);
    return e;
}

static bool patch_slot(intptr_t* slot, intptr_t newfn, const char* name) {
    DWORD op = 0;
    if (!VirtualProtect(slot, 8, PAGE_READWRITE, &op)) {
        fprintf(stderr, "[TZD] anti-tamper: VirtualProtect failed for %s\n", name);
        fflush(stderr);
        return false;
    }
    *slot = newfn;
    VirtualProtect(slot, 8, op, &op);
    FlushInstructionCache(GetCurrentProcess(), slot, 8);
    return true;
}

bool anti_tamper_install(jvmtiEnv* env) {
    if (!env) return false;
    g_offRT = offsetof(jvmtiInterface_1_, RetransformClasses);
    g_offRD = offsetof(jvmtiInterface_1_, RedefineClasses);
    // _jvmtiEnv.functions is the first member (offset 0); it points to the
    // shared jvmtiInterface_1_ table.
    g_table = *(intptr_t**)env;
    if (!g_table) return false;

    intptr_t* slotRT = (intptr_t*)((char*)g_table + g_offRT);
    intptr_t* slotRD = (intptr_t*)((char*)g_table + g_offRD);
    g_origRetransform = *slotRT;
    g_origRedefine    = *slotRD;

    bool ok = true;
    ok &= patch_slot(slotRT, (intptr_t)(void*)&my_retransform, "RetransformClasses");
    ok &= patch_slot(slotRD, (intptr_t)(void*)&my_redefine,    "RedefineClasses");

    fprintf(stderr, "[TZD] anti-tamper: JVMTI table=0x%p RT(off=%zu) RD(off=%zu) "
            "origRT=0x%llx origRD=0x%llx (%s)\n",
            (void*)g_table, g_offRT, g_offRD,
            (unsigned long long)g_origRetransform, (unsigned long long)g_origRedefine,
            ok ? "armed" : "PARTIAL");
    fflush(stderr);
    return ok;
}

void anti_tamper_uninstall() {
    if (!g_table) return;
    intptr_t* slotRT = (intptr_t*)((char*)g_table + g_offRT);
    intptr_t* slotRD = (intptr_t*)((char*)g_table + g_offRD);
    if (g_origRetransform) patch_slot(slotRT, g_origRetransform, "RetransformClasses");
    if (g_origRedefine)    patch_slot(slotRD, g_origRedefine,    "RedefineClasses");
    g_table = nullptr;
}
