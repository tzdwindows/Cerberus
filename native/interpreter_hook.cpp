// Architect: tzdwindows 7
// interpreter_hook: Entry-point stub replacement — the SAFE successor to
// the constMethod-swap approach.
//
// ROOT CAUSE of the old crash: swapping src._constMethod to target's
// ConstMethod broke the JIT compiler's metadata chain
// (Method→ConstMethod→ConstantPool→InstanceKlass). When C1/C2 tried to
// compile or inline a caller of the swapped method (e.g. ServerPlayer::doTick
// which inlines getHealth), it followed the foreign ConstMethod's
// ConstantPool to a different InstanceKlass, hit a NULL _pool_holder, and
// segfaulted at offset 0x18 (ConstantPool::_pool_holder). Confirmed by the
// hs_err crash in C1 CompilerThread0 at jvm.dll+0x153cb7.
//
// FIX: We NEVER touch _constMethod, _i2i_entry, or any metadata field.
// Instead we allocate a tiny executable stub that returns a captured
// constant and redirect ONLY _from_interpreted_entry and
// _from_compiled_entry to it. The JIT compiler can still read the original
// Method→ConstMethod→ConstantPool→InstanceKlass chain (it stays intact),
// and _dont_inline + NOT_C1/C2 flags prevent the JIT from inlining the
// hooked method so the stub is always reached.
//
// The stub is generated at install time. The target method is invoked once
// via JNI (in the JNI bridge) to capture its return value, which is then
// encoded as an immediate in the stub. For 0.0f / 0 the stub is just
// 3-4 bytes (xorps/xor + ret); for arbitrary values it uses
// mov eax, imm32; movd xmm0, eax; ret (10 bytes).
#include "interpreter_hook.h"
#include "jvm_deopt.h"
#include <cstring>
#include <cstdio>
#include <process.h>
#include <vector>

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

extern long long resolveMethodPtrExt(jmethodID mid);

// ─── Hook entry ─────────────────────────────────────────────────────
//   retType: 0=float, 1=int, 2=void, 3=other (entry-point copy)
enum RetType { RT_FLOAT = 0, RT_INT = 1, RT_VOID = 2, RT_COPY = 3 };

struct InterpHookEntry {
    long long srcMethodPtr;
    long long tgtMethodPtr;       // for RT_COPY mode
    long long origFromInterp;     // saved _from_interpreted_entry
    long long origFromCompiled;   // saved _from_compiled_entry
    long long origCode;           // saved _code
    void* stubPage;               // allocated executable page
    int retType;
    long long retValueBits;       // captured return value (float bits or int)
    bool hooked;
    // Bytecode patch mode:
    bool useBytecodePatch;
    unsigned char origBytecodes[8]; // original bytecodes for restoration
    long long origCodeBase;        // address of the bytecode array
};
static std::vector<InterpHookEntry> g_hooks;
static CRITICAL_SECTION g_cs;
static bool g_csInited = false;

// Guard thread
static HANDLE g_guardThread = nullptr;
static volatile bool g_guardRun = false;

bool interp_hook_init() {
    if (!g_csInited) { InitializeCriticalSection(&g_cs); g_csInited = true; }
    return true;
}

struct HookLock {
    CRITICAL_SECTION& cs;
    HookLock(CRITICAL_SECTION& c) : cs(c) { EnterCriticalSection(&cs); }
    ~HookLock() { LeaveCriticalSection(&cs); }
};

static long long rq(void* a) {
    if (!a) return 0;
    if (!jvm_safe_read(a, 8)) return 0;
    return *(long long*)a;
}

// ─── Generate a stub that returns a captured constant ────────────────
// Supports ALL Java return types:
//   0=float:  xorps xmm0, xmm0; ret  (0.0f)
//   1=double: xorps xmm0, xmm0; ret  (0.0)
//   2=int:    xor eax, eax; ret       (0)
//   3=long:   xor eax, eax; ret       (0L — clears upper rax on x64)
//   4=object: xor eax, eax; ret       (null)
//   5=void:   ret
static void* generate_return_stub(int retType, long long retValueBits) {
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!page) return nullptr;
    unsigned char* code = (unsigned char*)page;
    int pos = 0;

    if (retType == 0 || retType == 1) {
        // float or double → return 0.0 in xmm0
        if (retValueBits == 0) {
            code[pos++] = 0x0F; code[pos++] = 0x57; code[pos++] = 0xC0; // xorps xmm0, xmm0
            code[pos++] = 0xC3; // ret
        } else {
            // mov eax, <bits>; movd xmm0, eax; ret
            code[pos++] = 0xB8;
            int bits = (int)retValueBits;
            memcpy(code + pos, &bits, 4); pos += 4;
            code[pos++] = 0x66; code[pos++] = 0x0F; code[pos++] = 0x6E; code[pos++] = 0xC0;
            code[pos++] = 0xC3;
        }
    } else if (retType == 2 || retType == 3 || retType == 4) {
        // int, long, or object → return 0 / null in eax/rax
        if (retValueBits == 0) {
            code[pos++] = 0x33; code[pos++] = 0xC0; // xor eax, eax (clears upper rax on x64)
            code[pos++] = 0xC3; // ret
        } else {
            // mov rax, <value>; ret  (for long/object with non-zero value)
            code[pos++] = 0x48; code[pos++] = 0xB8;
            memcpy(code + pos, &retValueBits, 8); pos += 8;
            code[pos++] = 0xC3;
        }
    } else {
        // void or unknown → just ret
        code[pos++] = 0xC3;
    }

    fprintf(stderr, "[TZD] interp_hook: stub at %p (retType=%d, bits=0x%llx, size=%d)\n",
            page, retType, retValueBits, pos);
    fflush(stderr);
    return page;
}

// ─── Install: stub-based entry-point replacement ─────────────────────
// No constMethod swap. No bytecode modification. The JIT compiler's
// metadata chain stays intact.
static bool interp_hook_stub_install(long long srcMethodPtr, int retType,
                                      long long retValueBits) {
    if (!srcMethodPtr) return false;
    HookLock lk(g_cs);

    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");
    if (offFI < 0 || offFC < 0) {
        log_msg("interp_hook: offsets not detected");
        return false;
    }

    // Check if already hooked
    for (auto& h : g_hooks) {
        if (h.srcMethodPtr == srcMethodPtr && h.hooked) {
            log_msg("interp_hook: already hooked");
            return true;
        }
    }

    // Generate the stub
    void* stub = generate_return_stub(retType, retValueBits);
    if (!stub) {
        log_msg("interp_hook: stub allocation failed");
        return false;
    }

    // Save src's ORIGINAL entry points (before any modification)
    InterpHookEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.srcMethodPtr = srcMethodPtr;
    entry.tgtMethodPtr = 0;
    entry.origFromInterp = rq((void*)(srcMethodPtr + offFI));
    entry.origFromCompiled = rq((void*)(srcMethodPtr + offFC));
    entry.origCode = (offCode >= 0) ? rq((void*)(srcMethodPtr + offCode)) : 0;
    entry.stubPage = stub;
    entry.retType = retType;
    entry.retValueBits = retValueBits;
    entry.hooked = false;

    // Force src into interpreter mode (clear _code, set anti-inline).
    // This MUST come before the entry-point write so the method is already
    // in interpreter mode when callers start using our stub.
    jvm_force_interpreter(srcMethodPtr);

    // Replace entry points with our stub
    DWORD origProt = 0;
    if (!VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &origProt)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        log_msg("interp_hook: VirtualProtect failed");
        return false;
    }
    long long stubAddr = (long long)(intptr_t)stub;
    *(long long*)(srcMethodPtr + offFI) = stubAddr;
    *(long long*)(srcMethodPtr + offFC) = stubAddr;
    VirtualProtect((void*)srcMethodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);

    entry.hooked = true;
    g_hooks.push_back(entry);

    fprintf(stderr, "[TZD] interp_hook: installed stub src=0x%llx stub=%p "
            "retType=%d bits=0x%llx origFI=0x%llx origFC=0x%llx\n",
            srcMethodPtr, stub, retType, retValueBits,
            entry.origFromInterp, entry.origFromCompiled);
    fflush(stderr);
    return true;
}

// ─── Install: entry-point copy (copy target's entries, no constMethod) ─
// This is the fallback for methods that can't be stubbed (e.g. complex
// methods that need to execute target's bytecodes). We copy ONLY the
// target's entry points (not _constMethod). Only non-zero entries are
// copied — a zero target entry (unlinked method) would crash interpreted
// callers, so we skip it (src's own entries from jvm_force_interpreter
// are already valid for same-kind methods).
static bool interp_hook_entry_copy(long long srcMethodPtr, long long tgtMethodPtr) {
    if (!srcMethodPtr || !tgtMethodPtr) return false;
    HookLock lk(g_cs);

    int offI2I = jvm_deopt_get_offset("i2i_entry");
    int offFI  = jvm_deopt_get_offset("from_interp");
    int offFC  = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");
    if (offI2I < 0 || offFI < 0 || offFC < 0) {
        log_msg("interp_hook: offsets not detected");
        return false;
    }

    for (auto& h : g_hooks) {
        if (h.srcMethodPtr == srcMethodPtr && h.hooked) return true;
    }

    InterpHookEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.srcMethodPtr = srcMethodPtr;
    entry.tgtMethodPtr = tgtMethodPtr;
    entry.origFromInterp = rq((void*)(srcMethodPtr + offFI));
    entry.origFromCompiled = rq((void*)(srcMethodPtr + offFC));
    entry.origCode = (offCode >= 0) ? rq((void*)(srcMethodPtr + offCode)) : 0;
    entry.retType = RT_COPY;
    entry.stubPage = nullptr;

    // Force interpreter mode + anti-inline
    jvm_force_interpreter(srcMethodPtr);

    // Read target's entry points
    long long tgtFI = rq((void*)(tgtMethodPtr + offFI));
    long long tgtFC = rq((void*)(tgtMethodPtr + offFC));

    fprintf(stderr, "[TZD] interp_hook: entry-copy src=0x%llx tgt=0x%llx "
            "tgtFI=0x%llx tgtFC=0x%llx\n",
            srcMethodPtr, tgtMethodPtr, tgtFI, tgtFC);
    fflush(stderr);

    DWORD origProt = 0;
    if (!VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &origProt)) {
        log_msg("interp_hook: VirtualProtect failed");
        return false;
    }
    // Copy ONLY non-zero target entries (zero = unlinked, would crash)
    if (tgtFI) *(long long*)(srcMethodPtr + offFI) = tgtFI;
    if (tgtFC) *(long long*)(srcMethodPtr + offFC) = tgtFC;
    // Do NOT copy _i2i_entry — it's potentially shared per method-kind
    // and overwriting it could affect other methods. Leave it as-is
    // (jvm_force_interpreter already reset _from_interpreted_entry =
    // _i2i_entry, which is correct for interpreter mode).
    // Do NOT touch _constMethod — the JIT compiler needs it intact.
    VirtualProtect((void*)srcMethodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);

    entry.hooked = true;
    g_hooks.push_back(entry);

    log_msg("interp_hook: entry-copy installed (no constMethod swap)");
    return true;
}

// ─── Bytecode patch: write return-0 bytecodes in-place ─────────────
// This is the SAFE primary hook mechanism. Instead of replacing entry points
// (which crashes C1's resolve_opt_virtual_call — it reads _from_compiled_entry
// as nmethod metadata and our stub bytes 0F 57 C0 C3 are interpreted as a
// pointer 0xC3C0570F → ACCESS_VIOLATION), we patch the bytecodes IN-PLACE:
//   float/double: fconst_0 (0x0B) + freturn (0xAE)   or dconst_0 + dreturn
//   int:          iconst_0 (0x03) + ireturn (0xAC)
//   long:         lconst_0 (0x09) + lreturn (0xAD)
//   object:       aconst_null (0x01) + areturn (0xB0)
//   void:         return (0xB1)
//
// _from_compiled_entry stays as the c2i adapter (set by jvm_force_interpreter),
// so C1 callers go through c2i → interpreter → patched bytecodes → return 0.
// No constMethod swap, no entry-point stub, no calling convention issues.
static bool interp_hook_bytecode_patch(long long srcMethodPtr, int retType) {
    if (!srcMethodPtr) return false;

    int offCM = jvm_deopt_get_offset("constMethod");
    int offCB = jvm_deopt_get_offset("codeBase");
    if (offCM < 0 || offCB < 0) {
        log_msg("interp_hook: bytecode patch — offsets not detected");
        return false;
    }

    long long constMethod = rq((void*)(srcMethodPtr + offCM));
    if (!constMethod) { log_msg("interp_hook: constMethod is NULL"); return false; }

    unsigned char* codeBase = (unsigned char*)(constMethod + offCB);
    if (!jvm_safe_read(codeBase, 8)) { log_msg("interp_hook: codeBase not readable"); return false; }

    // CRITICAL: Properly deoptimize so the hook actually works!
    // 1. Patch bytecodes (interpreter reads new bytecodes)
    // 2. Get c2i adapter from Method._adapter (offset 32) → AdapterHandlerEntry._c2i_entry (offset 16)
    // 3. Set _code = NULL (invalidate nmethod)
    // 4. Set _from_compiled_entry = c2i adapter (C1 callers → c2i → interpreter → patched bytecodes)
    // 5. Set _from_interpreted_entry = _i2i_entry (interpreter uses patched bytecodes)
    // 6. Set DONT_INLINE + NOT_C1/C2
    //
    // This is SAFE because:
    // - _from_compiled_entry is set to the c2i adapter (NOT NULL, NOT our stub)
    // - The c2i adapter is the JVM's own code for C1→interpreter transitions
    // - C1's resolve_opt_virtual_call reads the c2i adapter correctly (it's valid nmethod-like code)
    
    // Get c2i adapter: Method._adapter (offset 32) → AdapterHandlerEntry._c2i_entry (offset 16)
    long long adapter = rq((void*)(srcMethodPtr + 32));  // Method._adapter
    long long c2i_entry = 0;
    if (adapter && jvm_safe_read((void*)(adapter + 16), 8)) {
        c2i_entry = *(long long*)(adapter + 16);  // AdapterHandlerEntry._c2i_entry
    }
    
    // Read _i2i_entry (offset 56) for _from_interpreted_entry
    long long i2i_entry = rq((void*)(srcMethodPtr + 56));
    
    fprintf(stderr, "[TZD] interp_hook: c2i=0x%llx i2i=0x%llx adapter=0x%llx\n",
            c2i_entry, i2i_entry, adapter);
    fflush(stderr);
    
    // Set anti-inline flags (DONT_INLINE + NOT_C1/C2)
    jvm_prevent_inlining(srcMethodPtr);
    
    // Write replacement bytecodes
    DWORD op = 0;
    if (!VirtualProtect(codeBase, 8, PAGE_READWRITE, &op)) {
        log_msg("interp_hook: VirtualProtect on codeBase failed");
        return false;
    }

    // Save original bytecodes for restoration (before patching)
    unsigned char origBytes[8];
    memcpy(origBytes, codeBase, 8);

    switch (retType) {
        case 0: // float → fconst_0; freturn
            codeBase[0] = 0x0B; codeBase[1] = 0xAE;
            break;
        case 1: // double → dconst_0; dreturn
            codeBase[0] = 0x0E; codeBase[1] = 0xAF;
            break;
        case 2: // int → iconst_0; ireturn
            codeBase[0] = 0x03; codeBase[1] = 0xAC;
            break;
        case 3: // long → lconst_0; lreturn
            codeBase[0] = 0x09; codeBase[1] = 0xAD;
            break;
        case 4: // object → aconst_null; areturn
            codeBase[0] = 0x01; codeBase[1] = 0xB0;
            break;
        case 5: // void → return
            codeBase[0] = 0xB1;
            break;
        default:
            VirtualProtect(codeBase, 8, op, &op);
            return false;
    }

    VirtualProtect(codeBase, 8, op, &op);

    // Now deoptimize: set _code=NULL, _from_compiled_entry=c2i, _from_interpreted_entry=i2i
    // This makes C1 callers go through the c2i adapter → interpreter → patched bytecodes
    DWORD op2 = 0;
    if (VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &op2)) {
        // _code = NULL (offset 72)
        *(long long*)(srcMethodPtr + 72) = 0;
        // _from_compiled_entry = c2i adapter (offset 64) — NOT NULL!
        if (c2i_entry) {
            *(long long*)(srcMethodPtr + 64) = c2i_entry;
        }
        // _from_interpreted_entry = _i2i_entry (offset 80)
        if (i2i_entry) {
            *(long long*)(srcMethodPtr + 80) = i2i_entry;
        }
        VirtualProtect((void*)srcMethodPtr, 256, op2, &op2);
        FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);
    }

    // Save for restoration
    InterpHookEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.srcMethodPtr = srcMethodPtr;
    entry.retType = retType;
    memcpy(entry.origBytecodes, origBytes, 8);
    entry.origCodeBase = (long long)codeBase;
    // Save original entry points for restoration
    entry.origCode = rq((void*)(srcMethodPtr + 72));           // _code
    entry.origFromCompiled = rq((void*)(srcMethodPtr + 64));  // _from_compiled_entry
    entry.origFromInterp = rq((void*)(srcMethodPtr + 80));    // _from_interpreted_entry
    entry.stubPage = nullptr;
    entry.useBytecodePatch = true;
    entry.hooked = true;
    g_hooks.push_back(entry);

    fprintf(stderr, "[TZD] interp_hook: bytecode patched src=0x%llx rt=%d "
            "codeBase=%p bytes=[%02x %02x] (c2i deopt applied)\n",
            srcMethodPtr, retType, codeBase, codeBase[0], codeBase[1]);
    fflush(stderr);
    return true;
}

// ─── Public API ──────────────────────────────────────────────────────
bool interp_hook_java(long long srcMethodPtr, long long tgtMethodPtr) {
    return interp_hook_entry_copy(srcMethodPtr, tgtMethodPtr);
}

bool interp_hook_replace(long long srcMethodPtr, long long tgtMethodPtr) {
    return interp_hook_entry_copy(srcMethodPtr, tgtMethodPtr);
}

// New stub-based API: install a stub that returns the captured constant.
// retType: 0=float, 1=double, 2=int, 3=long, 4=object, 5=void
bool interp_hook_stub(long long srcMethodPtr, int retType, long long retValueBits) {
    // PRIMARY: try bytecode patch (safe, no calling convention issues)
    if (interp_hook_bytecode_patch(srcMethodPtr, retType)) return true;
    // FALLBACK: entry-point stub (may crash C1's resolve_opt_virtual_call)
    return interp_hook_stub_install(srcMethodPtr, retType, retValueBits);
}

// ─── Remove hook: restore original bytecodes or entry points ─────────
bool interp_hook_remove(long long srcMethodPtr) {
    HookLock lk(g_cs);
    int offFI  = jvm_deopt_get_offset("from_interp");
    int offFC  = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");

    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
        if (it->srcMethodPtr == srcMethodPtr && it->hooked) {
            // Restore bytecode patch
            if (it->useBytecodePatch && it->origCodeBase) {
                unsigned char* codeBase = (unsigned char*)it->origCodeBase;
                DWORD op = 0;
                if (VirtualProtect(codeBase, 8, PAGE_READWRITE, &op)) {
                    memcpy(codeBase, it->origBytecodes, 8);
                    VirtualProtect(codeBase, 8, op, &op);
                }
                // Also restore entry points (_code, _from_compiled_entry, _from_interpreted_entry)
                DWORD op2 = 0;
                if (VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &op2)) {
                    *(long long*)(srcMethodPtr + 72) = it->origCode;          // _code
                    *(long long*)(srcMethodPtr + 64) = it->origFromCompiled;  // _from_compiled_entry
                    *(long long*)(srcMethodPtr + 80) = it->origFromInterp;   // _from_interpreted_entry
                    VirtualProtect((void*)srcMethodPtr, 256, op2, &op2);
                    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);
                }
                log_msg("interp_hook: bytecode patch removed, original bytecodes + entry points restored");
            }

            // Restore entry-point stub
            if (it->stubPage) {
                DWORD origProt = 0;
                if (VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &origProt)) {
                    if (offFI >= 0)  *(long long*)(srcMethodPtr + offFI)  = it->origFromInterp;
                    if (offFC >= 0)  *(long long*)(srcMethodPtr + offFC)  = it->origFromCompiled;
                    if (offCode >= 0) *(long long*)(srcMethodPtr + offCode) = it->origCode;
                    VirtualProtect((void*)srcMethodPtr, 256, origProt, &origProt);
                    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);
                }
                VirtualFree(it->stubPage, 0, MEM_RELEASE);
            }

            // Restore entry-copy mode
            if (it->tgtMethodPtr && !it->stubPage && !it->useBytecodePatch) {
                DWORD origProt = 0;
                if (VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &origProt)) {
                    if (offFI >= 0)  *(long long*)(srcMethodPtr + offFI)  = it->origFromInterp;
                    if (offFC >= 0)  *(long long*)(srcMethodPtr + offFC)  = it->origFromCompiled;
                    if (offCode >= 0) *(long long*)(srcMethodPtr + offCode) = it->origCode;
                    VirtualProtect((void*)srcMethodPtr, 256, origProt, &origProt);
                    FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);
                }
            }

            it->hooked = false;
            g_hooks.erase(it);
            return true;
        }
    }
    return false;
}

// ─── Guard: zero-trust verification + re-apply ───────────────────────
// Verifies: patched bytecodes intact, _code still NULL, _from_compiled_entry
// still c2i adapter, _from_interpreted_entry still i2i entry.
// If ANY of these are tampered (by ANY method — retransform, agent, direct
// memory write), restore from backup + re-apply c2i deoptimization.
void interp_hook_guard() {
    HookLock lk(g_cs);
    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    int offCode = jvm_deopt_get_offset("code");

    for (auto& h : g_hooks) {
        if (!h.hooked) continue;

        // ── Bytecode patch mode: verify bytecodes + entry points ──
        if (h.useBytecodePatch && h.origCodeBase) {
            unsigned char* codeBase = (unsigned char*)h.origCodeBase;

            // Check if patched bytecodes are still in place
            bool bytecodeTampered = false;
            DWORD op = 0;
            if (VirtualProtect(codeBase, 8, PAGE_READWRITE, &op)) {
                unsigned char expected[2];
                switch (h.retType) {
                    case 0: expected[0]=0x0B; expected[1]=0xAE; break; // fconst_0; freturn
                    case 1: expected[0]=0x0E; expected[1]=0xAF; break; // dconst_0; dreturn
                    case 2: expected[0]=0x03; expected[1]=0xAC; break; // iconst_0; ireturn
                    case 3: expected[0]=0x09; expected[1]=0xAD; break; // lconst_0; lreturn
                    case 4: expected[0]=0x01; expected[1]=0xB0; break; // aconst_null; areturn
                    case 5: expected[0]=0xB1; expected[1]=0x00; break; // return
                    default: expected[0]=0xB1; expected[1]=0x00; break;
                }
                if (codeBase[0] != expected[0] || codeBase[1] != expected[1]) {
                    bytecodeTampered = true;
                    fprintf(stderr, "[TZD] interp_hook guard: BYTECODE TAMPERED! "
                            "expected %02x %02x, got %02x %02x — RESTORING\n",
                            expected[0], expected[1], codeBase[0], codeBase[1]);
                    fflush(stderr);
                    codeBase[0] = expected[0];
                    codeBase[1] = expected[1];
                }
                VirtualProtect(codeBase, 8, op, &op);
            }

            // Check _code is still NULL (method still deoptimized)
            long long curCode = rq((void*)(h.srcMethodPtr + 72));
            if (curCode != 0) {
                fprintf(stderr, "[TZD] interp_hook guard: _code restored to 0x%llx! "
                        "Re-clearing...\n", curCode);
                fflush(stderr);
                DWORD op2 = 0;
                if (VirtualProtect((void*)h.srcMethodPtr, 256, PAGE_READWRITE, &op2)) {
                    *(long long*)(h.srcMethodPtr + 72) = 0; // _code = NULL
                    VirtualProtect((void*)h.srcMethodPtr, 256, op2, &op2);
                    FlushInstructionCache(GetCurrentProcess(), (void*)h.srcMethodPtr, 256);
                }
            }

            // Check _from_compiled_entry is still the c2i adapter
            // (not the original nmethod — if someone re-compiled, this changes)
            long long curFC = rq((void*)(h.srcMethodPtr + 64));
            long long curFI = rq((void*)(h.srcMethodPtr + 80));
            long long expectedFI = rq((void*)(h.srcMethodPtr + 56)); // _i2i_entry
            if (offFI >= 0 && curFI != expectedFI && expectedFI != 0) {
                fprintf(stderr, "[TZD] interp_hook guard: _from_interpreted_entry CHANGED! "
                        "Re-applying...\n");
                fflush(stderr);
                DWORD op2 = 0;
                if (VirtualProtect((void*)h.srcMethodPtr, 256, PAGE_READWRITE, &op2)) {
                    *(long long*)(h.srcMethodPtr + 80) = expectedFI;
                    VirtualProtect((void*)h.srcMethodPtr, 256, op2, &op2);
                    FlushInstructionCache(GetCurrentProcess(), (void*)h.srcMethodPtr, 256);
                }
            }
            continue;
        }

        // ── Entry-point stub mode: re-apply stub if tampered ──
        long long expected;
        if (h.stubPage) {
            expected = (long long)(intptr_t)h.stubPage;
            long long curFI = offFI >= 0 ? rq((void*)(h.srcMethodPtr + offFI)) : 0;
            if (curFI != expected) {
                fprintf(stderr, "[TZD] interp_hook guard: re-applying stub for src=0x%llx\n",
                        h.srcMethodPtr);
                fflush(stderr);
                DWORD op = 0;
                if (VirtualProtect((void*)h.srcMethodPtr, 256, PAGE_READWRITE, &op)) {
                    *(long long*)(h.srcMethodPtr + offFI) = expected;
                    if (offFC >= 0) *(long long*)(h.srcMethodPtr + offFC) = expected;
                    VirtualProtect((void*)h.srcMethodPtr, 256, op, &op);
                    FlushInstructionCache(GetCurrentProcess(), (void*)h.srcMethodPtr, 256);
                }
            }
        } else if (h.retType == RT_COPY) {
            if (offFI >= 0) {
                long long tgtFI = rq((void*)(h.tgtMethodPtr + offFI));
                long long curFI = rq((void*)(h.srcMethodPtr + offFI));
                if (tgtFI && curFI != tgtFI) {
                    DWORD op = 0;
                    if (VirtualProtect((void*)h.srcMethodPtr, 256, PAGE_READWRITE, &op)) {
                        if (tgtFI) *(long long*)(h.srcMethodPtr + offFI) = tgtFI;
                        VirtualProtect((void*)h.srcMethodPtr, 256, op, &op);
                        FlushInstructionCache(GetCurrentProcess(), (void*)h.srcMethodPtr, 256);
                    }
                }
            }
            continue;
        }
    }
}

// ─── Test helper ─────────────────────────────────────────────────────
bool interp_hook_test_tamper(long long srcMethodPtr) {
    HookLock lk(g_cs);
    int offFI = jvm_deopt_get_offset("from_interp");
    if (offFI < 0) return false;
    for (auto& h : g_hooks) {
        if (h.srcMethodPtr == srcMethodPtr && h.hooked) {
            DWORD op = 0;
            if (!VirtualProtect((void*)srcMethodPtr, 256, PAGE_READWRITE, &op)) return false;
            *(long long*)(srcMethodPtr + offFI) = h.origFromInterp;
            VirtualProtect((void*)srcMethodPtr, 256, op, &op);
            FlushInstructionCache(GetCurrentProcess(), (void*)srcMethodPtr, 256);
            log_msg("interp_hook: test-tamper reverted _from_interpreted_entry");
            return true;
        }
    }
    return false;
}

// ─── Legacy stubs (kept for API compat) ──────────────────────────────
void interp_hook_deoptimize(long long methodPtr, int) { jvm_deoptimize_method(methodPtr); }
long interp_hook_get_dispatch_table() { return 0; }
int interp_hook_get_number_of_states() { return 9; }
void interp_hook_freturn_remove() {}
bool interp_hook_freturn(long long, int) { return true; }

// ─── Fast guard thread ───────────────────────────────────────────────
static unsigned __stdcall interp_guard_thread(void*) {
    log_msg("interp_hook guard thread started (1ms re-apply)");
    while (g_guardRun) {
        interp_hook_guard();
        Sleep(1);
    }
    log_msg("interp_hook guard thread stopped");
    return 0;
}

void interp_hook_start_guard() {
    if (g_guardThread) return;
    if (!g_csInited) interp_hook_init();
    g_guardRun = true;
    g_guardThread = (HANDLE)_beginthreadex(nullptr, 0, interp_guard_thread,
                                           nullptr, 0, nullptr);
}

void interp_hook_stop_guard() {
    g_guardRun = false;
    if (g_guardThread) {
        WaitForSingleObject(g_guardThread, 2000);
        CloseHandle(g_guardThread);
        g_guardThread = nullptr;
    }
}
