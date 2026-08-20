// Architect: tzdwindows 7
#include "jvm_deopt.h"
#include <jvmti.h>
#include <psapi.h>
#include <cstring>
#include <cstdio>
#include <unordered_map>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

// JVMTI env (set from JNI_OnLoad) used for SAFE, safepoint-based deoptimization
// (DeoptimizeMethod). This replaces the old tier2 path which patched nmethod
// verified-entry bytes directly without a safepoint — that raced with threads
// executing those nmethods and crashed MC (pc=0x0 in Player.aiStep).
static jvmtiEnv* g_jvmti = nullptr;
void jvm_deopt_set_jvmti(void* j) { g_jvmti = (jvmtiEnv*)j; }

// JDK 20 Method* offsets (detected at runtime, fallback to hardcoded)
static int OFF_CONST_METHOD  = 8;
static int OFF_ACCESS_FLAGS   = 40;
static int OFF_FLAGS          = 50;
static int OFF_I2I_ENTRY     = 56;
static int OFF_FROM_COMPILED = 64;
static int OFF_CODE          = 72;
static int OFF_FROM_INTERP   = 80;
static int OFF_CODE_BASE     = -1;  // offset from ConstMethod* to bytecodes
static bool g_initialized    = false;

// Flag bit values
static const jint FLAG_NOT_C2 = 0x02000000;
static const jint FLAG_NOT_C1 = 0x04000000;
static const unsigned short FLAG_DONT_INLINE = 0x04;

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }

bool jvm_safe_read(const void* addr, size_t size) {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_NOACCESS) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    return true;
}

static bool isExecutablePtr(long long val) {
    if (val < 0x10000LL || val > 0x7FFFFFFFFFFFLL) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)val, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect;
    return (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Resolve jmethodID to Method* (multi-JDK: JDK 16+ needs dereference)
static long long resolveMethodPtr(jmethodID mid) {
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

// Forward decl: Tier 2 init (defined after jvm_force_interpreter).
static void jvm_deopt_tier2_init(JNIEnv* env);

void jvm_deopt_init(JNIEnv* env) {
    if (g_initialized) return;
    g_initialized = true;

    // Probe Object.toString to verify offsets
    jclass objClass = env->FindClass("java/lang/Object");
    if (!objClass) { log_msg("jvm_deopt: Object class not found"); return; }
    jmethodID mid = env->GetMethodID(objClass, "toString", "()Ljava/lang/String;");
    if (!mid) { env->DeleteLocalRef(objClass); return; }

    // Call it to ensure linking
    jobject obj = env->AllocObject(objClass);
    if (obj) { env->CallObjectMethod(obj, mid); env->DeleteLocalRef(obj); }
    env->DeleteLocalRef(objClass);

    long long mp = resolveMethodPtr(mid);
    if (!mp) { log_msg("jvm_deopt: could not resolve Method*"); return; }

    // JDK 20 Method layout (confirmed from source):
    //   0: vptr, 8: _constMethod, 16: _method_data, 24: _method_counters,
    //  32: _adapter, 40: _access_flags, 44: _vtable_index, 48: _intrinsic_id,
    //  50: _flags, 56: _i2i_entry, 64: _from_compiled_entry,
    //  72: _code (CompiledMethod*), 80: _from_interpreted_entry
    //
    // The old detection scanned for executable pointers, but when the method
    // is compiled, _code (72) is also executable → OFF_FROM_INTERP gets set
    // to 72 (= OFF_CODE) instead of 80. This is FATAL: writing to
    // _from_interpreted_entry at offset 72 overwrites _code.
    //
    // FIX: hardcode the JDK 20 offsets (verified from method.hpp source).
    // The detection scan is kept only for verification/logging.
    int codePtrOffsets[16];
    int numCodePtrs = 0;
    for (int off = 0; off < 96 && numCodePtrs < 16; off += 8) {
        long long addr = mp + off;
        if (!jvm_safe_read((void*)addr, 8)) break;
        long long val = *(long long*)addr;
        if (isExecutablePtr(val))
            codePtrOffsets[numCodePtrs++] = off;
    }
    // DO NOT overwrite hardcoded offsets — the scan is unreliable when _code
    // is non-NULL (compiled). The hardcoded values are correct for JDK 20.
    // OFF_I2I_ENTRY=56, OFF_FROM_COMPILED=64, OFF_CODE=72, OFF_FROM_INTERP=80
    // (intentionally NOT assigned from codePtrOffsets)

    OFF_ACCESS_FLAGS = OFF_I2I_ENTRY - 16;  // 56 - 16 = 40
    OFF_FLAGS = OFF_ACCESS_FLAGS + 10;       // 40 + 10 = 50

    fprintf(stderr, "[TZD] jvm_deopt offsets: constMethod=%d access_flags=%d flags=%d "
            "i2i=%d fromCompiled=%d code=%d fromInterp=%d (codePtrs=%d)\n",
            OFF_CONST_METHOD, OFF_ACCESS_FLAGS, OFF_FLAGS, OFF_I2I_ENTRY, OFF_FROM_COMPILED,
            OFF_CODE, OFF_FROM_INTERP, numCodePtrs);
    fflush(stderr);

    // Detect ConstMethod's code_base offset.
    // JDK 20: sizeof(ConstMethod) = 56 bytes (confirmed from source).
    // ConstMethod has NO vptr (unlike Method). Fields from offset 0:
    //   _fingerprint(8), _constants(8), _stackmap_data(8), _constMethod_size(4),
    //   _flags(2), _result_type(1), pad(1), _code_size(2), _name_index(2),
    //   _signature_index(2), _method_idnum(2), _max_stack(2), _max_locals(2),
    //   _size_of_parameters(2), _num_stack_arg_slots(2), _orig_method_idnum(2)
    //   = 50 bytes, padded to 56 (8-byte alignment from uint64_t).
    // code_base() = (address)(this + 1) = this + sizeof(ConstMethod) = this + 56.
    // _code_size is at offset 32 (u2) — we verify it to validate the offset.
    if (OFF_CONST_METHOD >= 0) {
        long long cm = *(long long*)(mp + OFF_CONST_METHOD);
        if (cm && jvm_safe_read((void*)cm, 128)) {
            // Verify: _code_size at ConstMethod+32 should be reasonable (2-10000)
            unsigned short codeSize = *(unsigned short*)(cm + 32);
            // Bytecodes at ConstMethod+56: first byte should be valid opcode
            unsigned char* cb56 = (unsigned char*)(cm + 56);
            if (codeSize >= 2 && codeSize <= 10000 && jvm_safe_read(cb56, 8)) {
                unsigned char b0 = cb56[0];
                // Valid bytecode opcodes: 0x00-0xCA (plus some extended)
                if (b0 <= 0xCA) {
                    OFF_CODE_BASE = 56;
                    fprintf(stderr, "[TZD] jvm_deopt: codeBase = 56 (code_size=%u, first opcode=0x%02x)\n",
                            codeSize, b0);
                    fflush(stderr);
                }
            }
            // Fallback: scan for valid bytecodes (less reliable)
            if (OFF_CODE_BASE < 0) {
                int candidates[] = {56, 48, 40, 64, 32, 72};
                for (int off : candidates) {
                    unsigned char* codeBase = (unsigned char*)(cm + off);
                    if (!jvm_safe_read(codeBase, 32)) continue;
                    unsigned char b = codeBase[0];
                    if (b == 0x00 || b == 0xFF || b == 0xCC) continue;
                    bool foundReturn = false;
                    for (int j = 0; j < 30; j++) {
                        if (codeBase[j] >= 0xAC && codeBase[j] <= 0xB1) {
                            foundReturn = true; break;
                        }
                    }
                    if (foundReturn) {
                        OFF_CODE_BASE = off;
                        fprintf(stderr, "[TZD] jvm_deopt: codeBase detected via scan = %d "
                                "(first opcode=0x%02x)\n", off, b);
                        fflush(stderr);
                        break;
                    }
                }
            }
        }
    }

    jvm_deopt_tier2_init(env);
}

void jvm_prevent_inlining(long long methodPtr) {
    if (!methodPtr) return;
    DWORD origProt = 0;
    if (!VirtualProtect((void*)methodPtr, 256, PAGE_READWRITE, &origProt)) return;

    // Set _dont_inline flag (bit 2 in _flags at OFF_FLAGS)
    if (jvm_safe_read((void*)(methodPtr + OFF_FLAGS), 2)) {
        unsigned short flags = *(unsigned short*)(methodPtr + OFF_FLAGS);
        flags |= FLAG_DONT_INLINE;
        *(unsigned short*)(methodPtr + OFF_FLAGS) = flags;
    }

    // Set NOT_C1_COMPILABLE + NOT_C2_COMPILABLE in _access_flags
    if (jvm_safe_read((void*)(methodPtr + OFF_ACCESS_FLAGS), 4)) {
        jint af = *(jint*)(methodPtr + OFF_ACCESS_FLAGS);
        af |= FLAG_NOT_C1 | FLAG_NOT_C2;
        *(jint*)(methodPtr + OFF_ACCESS_FLAGS) = af;
    }

    VirtualProtect((void*)methodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)methodPtr, 256);
    fprintf(stderr, "[TZD] jvm_prevent_inlining: Method*=0x%llx (DONT_INLINE + NOT_C1/C2)\n",
            methodPtr);
    fflush(stderr);
}

void jvm_deoptimize_method(long long methodPtr) {
    if (!methodPtr) return;
    DWORD origProt = 0;
    if (!VirtualProtect((void*)methodPtr, 256, PAGE_READWRITE, &origProt)) return;

    // Clear _code (nmethod*) — forces interpreter mode
    if (OFF_CODE >= 0 && jvm_safe_read((void*)(methodPtr + OFF_CODE), 8))
        *(long long*)(methodPtr + OFF_CODE) = 0;

    // Null _from_compiled_entry — prevents compiled calls from reaching old nmethod
    if (jvm_safe_read((void*)(methodPtr + OFF_FROM_COMPILED), 8))
        *(long long*)(methodPtr + OFF_FROM_COMPILED) = 0;

    // Set _from_interpreted_entry = _i2i_entry (pure interpreter mode)
    if (OFF_I2I_ENTRY >= 0 && jvm_safe_read((void*)(methodPtr + OFF_I2I_ENTRY), 8)) {
        long long i2i = *(long long*)(methodPtr + OFF_I2I_ENTRY);
        if (OFF_FROM_INTERP >= 0 && jvm_safe_read((void*)(methodPtr + OFF_FROM_INTERP), 8))
            *(long long*)(methodPtr + OFF_FROM_INTERP) = i2i;
    }

    VirtualProtect((void*)methodPtr, 256, origProt, &origProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)methodPtr, 256);
    fprintf(stderr, "[TZD] jvm_deoptimize: Method*=0x%llx (_code=NULL, entries reset)\n",
            methodPtr);
    fflush(stderr);
}

void jvm_force_interpreter(long long methodPtr) {
    jvm_deoptimize_method(methodPtr);
    jvm_prevent_inlining(methodPtr);
}

int jvm_deopt_get_offset(const char* name) {
    if (!name) return -1;
    if (strcmp(name, "constMethod") == 0) return OFF_CONST_METHOD;
    if (strcmp(name, "access_flags") == 0) return OFF_ACCESS_FLAGS;
    if (strcmp(name, "flags") == 0) return OFF_FLAGS;
    if (strcmp(name, "i2i_entry") == 0) return OFF_I2I_ENTRY;
    if (strcmp(name, "from_compiled") == 0) return OFF_FROM_COMPILED;
    if (strcmp(name, "code") == 0) return OFF_CODE;
    if (strcmp(name, "from_interp") == 0) return OFF_FROM_INTERP;
    if (strcmp(name, "codeBase") == 0) return OFF_CODE_BASE;
    return -1;
}

// ─── Tier 2: invalidate nmethods that inlined src (no JVMTI) ──────────
// Strategy: reach src's holder InstanceKlass via
//   src._constMethod -> ConstMethod._constants -> ConstantPool._pool_holder
// then walk holder._dep_context (nmethodBucket list — the JVM's own record of
// nmethods that depend on this klass). For each dependent nmethod:
//   - harvest the wrong-method stub from any already-not_entrant nmethod
//     (its verified entry was patched by HotSpot with E9 rel32 -> stub), and
//     record the _verified_entry_point field offset;
//   - patch each in-use nmethod's verified entry with the same E9 rel32 jump,
//     so baked direct/inline-cache calls bounce to the deopt stub and the
//     caller re-resolves src (now through the interpreter -> swapped
//     constMethod -> target's bytecodes).
//
// nmethod identification (no symbols): a real nmethod lives in the code cache
// (NOT in jvm.dll), its first qword is a vtable INTO jvm.dll, and its blob
// contains an executable code pointer near itself. This distinguishes it from
// ConstantPool / InstanceKlass / vtable-misreads.
//
// Layout (JDK 20, 64-bit product):
//   Method:        +8 _constMethod
//   ConstMethod:   +8 _constants (no vtable)
//   ConstantPool:  +24 _pool_holder (vtable@0, _tags@8, _cache@16)
//   nmethodBucket: _nmethod @ {0 or 8}, _next @ {16}
//   nmethod:       _verified_entry_point (executable ptr in own blob), _state(signed char)

static JNIEnv* g_env = nullptr;
static long long g_jvm_base = 0, g_jvm_size = 0;
static long long g_nmethod_vtable = 0;   // harvested
static long long g_wrong_method_stub = 0; // harvested from a not_entrant nmethod
static int g_off_iklass_dep_context = -1;
static int g_off_bucket_nmethod = -1;
static int g_off_bucket_next = -1;
static int g_off_nmethod_vep = -1;
static bool g_tier2_inited = false;

static bool tier2_in_jvm(long long a) {
    if (!g_jvm_size) return false;
    return a >= g_jvm_base && a < g_jvm_base + g_jvm_size;
}

static long long rq(long long addr) {
    if (!jvm_safe_read((void*)addr, 8)) return 0;
    return *(long long*)addr;
}

// Is `N` a real nmethod? (code-cache object with a jvm.dll vtable and
// executable code within its own blob).
static bool tier2_is_nmethod(long long N) {
    if (!N) return false;
    if (tier2_in_jvm(N)) return false;                 // nmethods live in code cache, not jvm.dll
    long long v = rq(N);
    if (!tier2_in_jvm(v)) return false;                // first qword must be a vtable in jvm.dll
    if (g_nmethod_vtable && v != g_nmethod_vtable) {
        // Once harvested, insist on the nmethod vtable. But early on (before
        // harvest) accept any jvm.dll vtable and harvest it.
        // (fall through to the self-code check, then harvest)
    }
    // require an executable code pointer within the blob (near N)
    for (int off = 8; off < 256; off += 8) {
        long long Q = rq(N + off);
        if (!Q) continue;
        if (!isExecutablePtr(Q)) continue;
        long long d = Q - N;
        if (d >= 16 && d < (256 * 1024)) {
            if (!g_nmethod_vtable) g_nmethod_vtable = v;
            return true;
        }
    }
    return false;
}

// Return the _nmethod field of a bucket; set g_off_bucket_nmethod.
static long long tier2_bucket_nmethod(long long bucket) {
    for (int off = 0; off <= 8; off += 8) {
        long long N = rq(bucket + off);
        if (tier2_is_nmethod(N)) { g_off_bucket_nmethod = off; return N; }
    }
    return 0;
}

// Return the _next field of a bucket; set g_off_bucket_next.
static long long tier2_bucket_next(long long bucket) {
    if (g_off_bucket_next >= 0) return rq(bucket + g_off_bucket_next);
    for (int off = 8; off <= 32; off += 8) {
        long long nxt = rq(bucket + off);
        if (nxt == 0) { g_off_bucket_next = off; return 0; }
        if (tier2_bucket_nmethod(nxt)) { g_off_bucket_next = off; return nxt; }
    }
    return 0;
}

// Find holder._dep_context (head nmethodBucket*) by scanning the InstanceKlass.
static long long tier2_find_dep_context(long long holder) {
    if (g_off_iklass_dep_context >= 0) return rq(holder + g_off_iklass_dep_context);
    for (int off = 0; off < 8192; off += 8) {
        long long P = rq(holder + off);
        if (!P) continue;
        if (tier2_bucket_nmethod(P)) { g_off_iklass_dep_context = off; return P; }
    }
    return 0;
}

// jvm_deopt_inlined_callers is a NO-OP deopt. Rationale:
//  - The JDK 20 jvmti.h exposes NO DeoptimizeMethod/DeoptimizeAll (JVMTI only
//    triggers deopt via RetransformClasses/RedefineClasses, which take a jclass).
//  - The old tier2 path patched dependent nmethods' verified-entry bytes
//    DIRECTLY (E9 -> wrong-method stub) with no safepoint, racing with threads
//    executing those nmethods -> crashed MC (pc=0x0 in Player.aiStep). Removed.
// Safe deopt of inliners is done on the Java side via NativeBridge.selfRetransform0
// (holderClass) -> JVMTI RetransformClasses, which uses the JVM's safepoint
// machinery to invalidate all class-dependent nmethods (the inliners). The
// constMethod swap is re-applied by the guard thread / anti-tamper filter.

static void jvm_deopt_tier2_init(JNIEnv* env) {
    if (g_tier2_inited) return;
    g_env = env;
    HMODULE hj = GetModuleHandleA("jvm.dll");
    if (hj) {
        MODULEINFO mi; memset(&mi, 0, sizeof(mi));
        if (GetModuleInformation(GetCurrentProcess(), hj, &mi, sizeof(mi))) {
            g_jvm_base = (long long)mi.lpBaseOfDll;
            g_jvm_size = (long long)mi.SizeOfImage;
        }
    }
    g_tier2_inited = true;
    fprintf(stderr, "[TZD] tier2 init: jvm.dll base=0x%llx size=0x%llx\n",
            g_jvm_base, g_jvm_size);
    fflush(stderr);
}

int jvm_deopt_inlined_callers(long long srcMethodPtr) {
    (void)srcMethodPtr;
    // NO-OP deopt — see the comment block above this function. Summary:
    //  - The JDK 20 jvmti.h has no DeoptimizeMethod/DeoptimizeAll (JVMTI only
    //    triggers deopt via RetransformClasses/RedefineClasses, which need a jclass).
    //  - The old tier2 patched nmethod verified-entry bytes directly with no
    //    safepoint, racing with executing threads and crashing MC (pc=0x0).
    // The SAFE deopt of inliners is done on the Java side:
    //   NativeBridge.selfRetransform0(holderClass)  ->  JVMTI RetransformClasses
    // which uses the JVM's safepoint machinery to invalidate ALL class-dependent
    // nmethods (the inliners of src). The constMethod swap is then re-applied
    // by the interp_hook guard thread (~1ms) / anti-tamper filter, so callers
    // that re-run (interpreted) or recompile (without inlining src, since
    // jvm_force_interpreter set _dont_inline) pick up the swapped bytecodes.
    // Returns 0 (native does not deopt; Java side does via RetransformClasses).
    return 0;
}
