// Architect: tzdwindows 7
// ghost_class.cpp — Ghost class definition from raw bytecodes.
//
// Two modes:
//   hostClass != null: FindClass + HIDDEN flag (existing approach)
//   hostClass == null: Walk ClassLoaderData::_klasses list to find the
//     class by name WITHOUT FindClass. If not found, create from scratch
//     in the compressed class space (clone IK + commit pages + build mirror).
//
// NO JVM API is used for the user's class in hostClass=null mode:
//   - No FindClass for the user's class
//   - No Lookup.defineClass
//   - No JVM_DefineClass
// Only FindClass("java/lang/Object") and FindClass("sun/misc/Unsafe") are
// used for bootstrapping (layout detection + mirror allocation).
#include "protect_class.h"
#include "jvm_deopt.h"
#include <cstring>
#include <cstdio>
#include <psapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

static void log_msg(const char* m) { fprintf(stderr, "[TZD] %s\n", m); fflush(stderr); }
static long long rq(void* a) { if (!a || !jvm_safe_read(a, 8)) return 0; return *(long long*)a; }

static int be_u2(const unsigned char* p) { return (p[0] << 8) | p[1]; }
static int be_u4(const unsigned char* p) { return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

// ─── ClassFile parser (same as before) ──────────────────────────────
struct CPEntry { int tag; char* utf8; int utf8_len; int index1; int index2; int value; long long value64; };
struct MethodInfo { int access_flags; int name_index; int desc_index; int max_stack; int max_locals; int code_length; const unsigned char* code; };
struct ClassFile { int cp_count; CPEntry cp[4096]; int access_flags; int this_class; int super_class; int method_count; MethodInfo methods[64]; };

static bool parse_class_file(const unsigned char* bytes, int len, ClassFile* cf) {
    memset(cf, 0, sizeof(*cf));
    if (!bytes || len < 10) return false;
    if (be_u4(bytes) != 0xCAFEBABE) return false;
    int pos = 8;
    cf->cp_count = be_u2(bytes + pos); pos += 2;
    int cp_count = cf->cp_count - 1;
    for (int i = 0; i < cp_count; i++) {
        if (pos >= len) return false;
        int tag = bytes[pos++];
        cf->cp[i].tag = tag;
        switch (tag) {
            case 1: { int slen = be_u2(bytes + pos); pos += 2;
                if (pos + slen > len) return false;
                cf->cp[i].utf8 = (char*)malloc(slen + 1);
                memcpy(cf->cp[i].utf8, bytes + pos, slen);
                cf->cp[i].utf8[slen] = 0; cf->cp[i].utf8_len = slen;
                pos += slen; break; }
            case 3: case 4: cf->cp[i].value = be_u4(bytes + pos); pos += 4; break;
            case 5: case 6: cf->cp[i].value64 = ((long long)be_u4(bytes + pos) << 32) | be_u4(bytes + pos + 4); pos += 8; i++; break;
            case 7: case 8: case 16: case 19: case 20: cf->cp[i].index1 = be_u2(bytes + pos); pos += 2; break;
            case 9: case 10: case 11: case 12: case 17: case 18:
                cf->cp[i].index1 = be_u2(bytes + pos); pos += 2;
                cf->cp[i].index2 = be_u2(bytes + pos); pos += 2; break;
            case 15: cf->cp[i].index1 = bytes[pos++]; cf->cp[i].index2 = be_u2(bytes + pos); pos += 2; break;
            default: return false;
        }
    }
    cf->access_flags = be_u2(bytes + pos); pos += 2;
    cf->this_class = be_u2(bytes + pos); pos += 2;
    cf->super_class = be_u2(bytes + pos); pos += 2;
    int iface_count = be_u2(bytes + pos); pos += 2 + iface_count * 2;
    int field_count = be_u2(bytes + pos); pos += 2;
    for (int i = 0; i < field_count; i++) {
        pos += 6; int ac = be_u2(bytes + pos); pos += 2;
        for (int j = 0; j < ac; j++) { pos += 2; int al = be_u4(bytes + pos); pos += 4 + al; }
    }
    cf->method_count = be_u2(bytes + pos); pos += 2;
    if (cf->method_count > 64) cf->method_count = 64;
    for (int i = 0; i < cf->method_count; i++) {
        if (pos + 6 > len) break;
        MethodInfo& m = cf->methods[i];
        m.access_flags = be_u2(bytes + pos); pos += 2;
        m.name_index = be_u2(bytes + pos); pos += 2;
        m.desc_index = be_u2(bytes + pos); pos += 2;
        int ac = be_u2(bytes + pos); pos += 2;
        m.code = nullptr; m.code_length = 0; m.max_stack = 0; m.max_locals = 0;
        for (int j = 0; j < ac; j++) {
            pos += 2; int al = be_u4(bytes + pos); pos += 4;
            if (al >= 8 && pos + 8 <= len) {
                m.max_stack = be_u2(bytes + pos);
                m.max_locals = be_u2(bytes + pos + 2);
                m.code_length = be_u4(bytes + pos + 4);
                if (m.code_length > 0 && pos + 8 + m.code_length <= len) {
                    m.code = (const unsigned char*)malloc(m.code_length);
                    if (m.code) memcpy((void*)m.code, bytes + pos + 8, m.code_length);
                }
            }
            pos += al;
        }
    }
    return cf->method_count > 0;
}

// resolveMethodPtrExt is defined in method_replace.cpp (C++ linkage)
extern long long resolveMethodPtrExt(jmethodID mid);

// ─── JDK 20 hardcoded offsets (from protect_class.h) ──────────────────
// Klass:
//   +8   _layout_helper, +24 _name, +112 _java_mirror (OopHandle),
//   +120 _super, +144 _next_link, +152 _class_loader_data,
//   +160 _vtable_len, +164 _access_flags
// InstanceKlass: +192 _constants (ConstantPool*)
// ConstantPool: +0 vtable, +8 _tags, +16 _cache, +24 _pool_holder
// ConstMethod: +8 _constants, bytecodes at +56 (sizeof ConstMethod)
// CLD: +140 _klasses
static const int IK_LAYOUT_HELPER  = 8;
static const int IK_NAME           = 24;
static const int IK_JAVA_MIRROR    = 112;
static const int IK_SUPER          = 120;
static const int IK_NEXT_LINK      = 144;
static const int IK_CLD            = 152;
static const int IK_VTABLE_LEN     = 160;
static const int IK_ACCESS_FLAGS   = 164;
static const int IK_CONSTANTS      = 192;
static const int CLD_KLASSES       = 140;
static const jint JVM_ACC_HIDDEN   = 0x04000000;

// ─── jvm.dll range (cached) ──────────────────────────────────────────
static long long s_jvm_base = 0, s_jvm_size = 0;
static void init_jvm_range() {
    if (s_jvm_base) return;
    HMODULE hj = GetModuleHandleA("jvm.dll");
    if (!hj) return;
    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), hj, &mi, sizeof(mi))) {
        s_jvm_base = (long long)mi.lpBaseOfDll;
        s_jvm_size = (long long)mi.SizeOfImage;
    }
}
static bool is_in_jvm(long long p) {
    init_jvm_range();
    return p >= s_jvm_base && p < s_jvm_base + s_jvm_size;
}

// ─── Forward declarations for _klass_offset detection (defined later) ──
static int  g_klass_offset  = -1;
static bool g_handle_indir  = false;
static bool detect_klass_offset_gc(JNIEnv* env);

// ─── Bootstrap: get Object's IK via Method* chain (for _klass_offset detection) ──
// Only works correctly for classes that DEFINE the method (not inherited).
// Used to detect _klass_offset by comparing with Object's Class mirror.
static long long bootstrap_ik(JNIEnv* env, jclass cls) {
    if (!cls) return 0;
    jmethodID mid = env->GetMethodID(cls, "hashCode", "()I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!mid) {
        mid = env->GetMethodID(cls, "toString", "()Ljava/lang/String;");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!mid) return 0;
    long long mp = resolveMethodPtrExt(mid);
    if (!mp) return 0;
    int offCM = jvm_deopt_get_offset("constMethod");
    if (offCM < 0) return 0;
    long long cm = rq((void*)(mp + offCM));
    if (!cm) return 0;
    long long cp = rq((void*)(cm + 8));       // ConstMethod._constants
    if (!cp) return 0;
    return rq((void*)(cp + 24));              // ConstantPool._pool_holder
}

// ─── Get IK from any jclass via Class mirror _klass_offset ───────────
// This reads the InstanceKlass* directly from the Class object's
// java_lang_Class::_klass field. It does NOT use the Method chain
// (which would resolve to the super class's IK for inherited methods).
static long long get_ik_from_class_mirror(JNIEnv* env, jclass cls) {
    if (!cls) return 0;
    if (!detect_klass_offset_gc(env)) return 0;
    long long oop = (long long)(intptr_t)cls;
    if (g_handle_indir) {
        oop = rq((void*)oop);
        if (!oop) return 0;
    }
    return rq((void*)(oop + g_klass_offset));
}

// ─── Detect java_lang_Class::_klass_offset + handle indirection ──────

static bool detect_klass_offset_gc(JNIEnv* env) {
    if (g_klass_offset >= 0) return true;
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return false;
    long long ik = bootstrap_ik(env, objCls);
    if (!ik) { env->DeleteLocalRef(objCls); return false; }

    long long mirror = (long long)(intptr_t)objCls;
    // Direct: jobject IS the oop
    for (int off = 0; off <= 200; off++) {
        if (rq((void*)(mirror + off)) == ik) {
            g_klass_offset = off; g_handle_indir = false;
            break;
        }
    }
    // Indirect: jobject is a handle (oop*)
    if (g_klass_offset < 0) {
        long long derefed = rq((void*)mirror);
        if (derefed) {
            for (int off = 0; off <= 200; off++) {
                if (rq((void*)(derefed + off)) == ik) {
                    g_klass_offset = off; g_handle_indir = true;
                    break;
                }
            }
        }
    }
    env->DeleteLocalRef(objCls);
    if (g_klass_offset >= 0) {
        fprintf(stderr, "[TZD] ghost_class: _klass_offset=%d indir=%d\n",
                g_klass_offset, (int)g_handle_indir);
        fflush(stderr);
        return true;
    }
    log_msg("ghost_class: can't detect _klass_offset");
    return false;
}

// ─── Symbol layout detection ─────────────────────────────────────────
// Symbol: { _length(u2), _refcount(u2), _body[...] } at offset 0 or 8
static int g_sym_len_off = -1, g_sym_body_off = -1;

static bool detect_symbol_layout(JNIEnv* env) {
    if (g_sym_len_off >= 0) return true;
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return false;
    long long ik = bootstrap_ik(env, objCls);
    env->DeleteLocalRef(objCls);
    if (!ik) return false;
    long long sym = rq((void*)(ik + IK_NAME));
    if (!sym) return false;

    const char* expect = "java/lang/Object";
    int expectLen = (int)strlen(expect);
    // Try length offsets 0, 2, 4, 8; body offsets len+2, len+4
    int lenOffs[] = {0, 2, 4, 8};
    for (int li = 0; li < 4; li++) {
        int loff = lenOffs[li];
        if (!jvm_safe_read((void*)(sym + loff), 2)) continue;
        unsigned short len = *(unsigned short*)(sym + loff);
        if (len != expectLen) continue;
        int bodyOffs[] = {loff + 2, loff + 4, loff + 6};
        for (int bi = 0; bi < 3; bi++) {
            int boff = bodyOffs[bi];
            if (!jvm_safe_read((void*)(sym + boff), len)) continue;
            if (memcmp((void*)(sym + boff), expect, len) == 0) {
                g_sym_len_off = loff; g_sym_body_off = boff;
                fprintf(stderr, "[TZD] ghost_class: Symbol len@%d body@%d\n", loff, boff);
                fflush(stderr);
                return true;
            }
        }
    }
    log_msg("ghost_class: can't detect Symbol layout");
    return false;
}

static bool symbol_equals(long long sym, const char* str) {
    if (!sym || !jvm_safe_read((void*)sym, 8) || g_sym_len_off < 0) return false;
    unsigned short len = *(unsigned short*)(sym + g_sym_len_off);
    int slen = (int)strlen(str);
    if (len != slen) return false;
    if (!jvm_safe_read((void*)(sym + g_sym_body_off), len)) return false;
    return memcmp((void*)(sym + g_sym_body_off), str, len) == 0;
}

// ─── Detect CLD::_next offset ────────────────────────────────────────
static int g_cld_next_off = -1;

static bool detect_cld_next(JNIEnv* env) {
    if (g_cld_next_off >= 0) return true;
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return false;
    long long ik = bootstrap_ik(env, objCls);
    env->DeleteLocalRef(objCls);
    if (!ik) return false;
    long long cld = rq((void*)(ik + IK_CLD));
    if (!cld) return false;

    // Scan for a pointer to another CLD.
    // Don't require a vtable (CLD in JDK 20 may not have one).
    // Instead, validate by checking _klasses (offset 140) is NULL or a valid IK.
    for (int off = 0; off < CLD_KLASSES; off += 8) {
        long long next = rq((void*)(cld + off));
        if (!next || next == cld) continue;
        // Check _klasses (offset 140) of the candidate
        long long klasses = rq((void*)(next + CLD_KLASSES));
        if (klasses == 0) {
            // Empty CLD — valid
            g_cld_next_off = off;
            fprintf(stderr, "[TZD] ghost_class: CLD::_next @ %d (empty CLD)\n", off);
            fflush(stderr);
            return true;
        }
        // Check if klasses points to a valid IK (has plausible access_flags)
        if (jvm_safe_read((void*)(klasses + IK_ACCESS_FLAGS), 4)) {
            long long af = *(jint*)(klasses + IK_ACCESS_FLAGS);
            if (af != 0 && (af & 0xFFFF) != 0 && (af & 0xFFFF) != 0xFFFF) {
                g_cld_next_off = off;
                fprintf(stderr, "[TZD] ghost_class: CLD::_next @ %d\n", off);
                fflush(stderr);
                return true;
            }
        }
    }
    log_msg("ghost_class: can't detect CLD::_next");
    return false;
}

// ─── Forward declarations (defined later) ────────────────────────────
static bool find_compressed_class_space(JNIEnv* env);

// Compressed class space (detected once, cached)
static long long s_ccs_base = 0, s_ccs_size = 0;

// ─── Find AppClassLoader's CLD via Thread.currentThread().getContextClassLoader() ─
// Scans the ClassLoader object for a pointer to a CLD. This avoids the
// need to walk the CLD::_next chain.
static long long find_app_cld(JNIEnv* env) {
    // Get context class loader
    jclass threadCls = env->FindClass("java/lang/Thread");
    if (!threadCls) return 0;
    jmethodID currentThread = env->GetStaticMethodID(threadCls, "currentThread", "()Ljava/lang/Thread;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!currentThread) { env->DeleteLocalRef(threadCls); return 0; }
    jobject thread = env->CallStaticObjectMethod(threadCls, currentThread);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(threadCls);
    if (!thread) return 0;

    jmethodID getCCL = env->GetMethodID(env->GetObjectClass(thread),
        "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!getCCL) { env->DeleteLocalRef(thread); return 0; }
    jobject classLoader = env->CallObjectMethod(thread, getCCL);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(thread);
    if (!classLoader) return 0;

    // Get the raw oop
    long long clOop = (long long)(intptr_t)classLoader;
    // Detect handle indirection
    if (!detect_klass_offset_gc(env)) { env->DeleteLocalRef(classLoader); return 0; }
    long long rawOop = clOop;
    if (g_handle_indir) rawOop = rq((void*)clOop);
    env->DeleteLocalRef(classLoader);

    // Scan the ClassLoader object for a pointer that looks like a CLD.
    // java.lang.ClassLoader has a field (ClassLoaderData*) that stores the CLD.
    // In JDK 20, this is typically at offset 24-40 (after the 16-byte header
    // + a few Java fields like parent, name, etc.).
    for (int off = 16; off < 200; off += 8) {
        if (!jvm_safe_read((void*)(rawOop + off), 8)) break;
        long long val = *(long long*)(rawOop + off);
        if (!val || val == rawOop) continue;
        // Check if val looks like a CLD: _klasses (140) is NULL or valid IK
        long long klasses = rq((void*)(val + CLD_KLASSES));
        if (klasses == 0) continue;  // skip empty — probably not our CLD
        // Check if klasses points to a valid IK
        long long af = rq((void*)(klasses + IK_ACCESS_FLAGS));
        if (af != 0 && (af & 0xFFFF) != 0 && (af & 0xFFFF) != 0xFFFF) {
            fprintf(stderr, "[TZD] ghost_class: found CLD @ CL+0x%x (cld=0x%llx, klasses=0x%llx)\n",
                    off, val, klasses);
            fflush(stderr);
            return val;
        }
    }
    log_msg("ghost_class: can't find AppClassLoader CLD");
    return 0;
}

// ─── Walk CLD list: find IK by class name (NO FindClass) ─────────────
static long long find_ik_by_name(JNIEnv* env, const char* className) {
    if (!detect_symbol_layout(env)) return 0;

    // Strategy: find the AppClassLoader's CLD directly (via context class loader),
    // then walk its _klasses list. If not found, also try the CLD chain from
    // the bootstrap CLD.
    long long cld = find_app_cld(env);

    // Walk the CLD's _klasses list
    if (cld) {
        long long k = rq((void*)(cld + CLD_KLASSES));
        int kCount = 0;
        while (k && kCount < 100000) {
            kCount++;
            long long sym = rq((void*)(k + IK_NAME));
            if (symbol_equals(sym, className)) {
                fprintf(stderr, "[TZD] ghost_class: found '%s' in AppCLD (ik=0x%llx)\n",
                        className, k);
                fflush(stderr);
                return k;
            }
            k = rq((void*)(k + IK_NEXT_LINK));
        }
    }

    // Fallback: scan the compressed class space directly for InstanceKlass
    // objects with matching _name. This is slower but doesn't depend on CLD
    // chain detection.
    if (find_compressed_class_space(env) && detect_symbol_layout(env)) {
        init_jvm_range();
        long long addr = s_ccs_base;
        long long endAddr = s_ccs_base + s_ccs_size;
        MEMORY_BASIC_INFORMATION mbi;
        int checked = 0;
        int pagesScanned = 0;

        while (addr < endAddr) {
            if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
            long long regionEnd = addr + mbi.RegionSize;

            if (mbi.State == MEM_COMMIT) {
                pagesScanned++;
                // Scan directly — NO jvm_safe_read/rq per qword (they call
                // VirtualQuery which is too slow). Use SEH for safety.
                long long scanStart = addr;
                long long scanEnd = regionEnd - 200;
                __try {
                    for (long long off = scanStart; off < scanEnd; off += 8) {
                        long long vt = *(long long*)off;
                        if (!is_in_jvm(vt)) continue;
                        long long sym = *(long long*)(off + IK_NAME);
                        if (!sym) continue;
                        checked++;
                        // Inline symbol_equals for speed (no VirtualQuery)
                        unsigned short len = *(unsigned short*)(sym + g_sym_len_off);
                        int slen = (int)strlen(className);
                        if (len != slen) continue;
                        if (memcmp((void*)(sym + g_sym_body_off), className, len) == 0) {
                            fprintf(stderr, "[TZD] ghost_class: found '%s' via CCS scan (ik=0x%llx, checked=%d)\n",
                                    className, off, checked);
                            fflush(stderr);
                            return off;
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    // Page boundary — skip to next region
                }
            }
            if (regionEnd <= addr) break; // overflow guard
            addr = regionEnd;
        }
        fprintf(stderr, "[TZD] ghost_class: CCS scan: %d committed pages, %d IKs checked, no match for '%s'\n",
                pagesScanned, checked, className);
        fflush(stderr);
    }

    return 0;
}

// ─── Create a new Class mirror via AllocObject (no Unsafe needed) ────
// Returns a jclass that is a DIFFERENT Class object but points to the
// same InstanceKlass. We use env->AllocObject(Class.class) to create
// an uninitialized Class instance, then set the _klass_offset field.
// ─── Create a new Class mirror via Unsafe (reflection-based) ────────
// Uses Java reflection to get Unsafe (bypasses module restrictions),
// then Unsafe.allocateInstance(Class.class) to create the mirror.
static jclass create_class_mirror(JNIEnv* env, long long ik) {
    if (!detect_klass_offset_gc(env)) return nullptr;

    // Get Unsafe via reflection (bypass module checks)
    jclass classCls = env->FindClass("java/lang/Class");
    jclass fieldCls = env->FindClass("java/lang/reflect/Field");
    if (!classCls || !fieldCls) { if(classCls) env->DeleteLocalRef(classCls); if(fieldCls) env->DeleteLocalRef(fieldCls); return nullptr; }

    jmethodID getDeclaredField = env->GetMethodID(classCls, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    // Get Unsafe.class and call getDeclaredField("theUnsafe") on it
    jclass unsafeCls = env->FindClass("sun/misc/Unsafe");
    if (!unsafeCls) { env->DeleteLocalRef(classCls); env->DeleteLocalRef(fieldCls); return nullptr; }
    jstring fieldName = env->NewStringUTF("theUnsafe");
    jobject field = env->CallObjectMethod(unsafeCls, getDeclaredField, fieldName);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(fieldName);
    if (!field) { env->DeleteLocalRef(classCls); env->DeleteLocalRef(fieldCls); env->DeleteLocalRef(unsafeCls); return nullptr; }

    jmethodID setAccessible = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    env->CallVoidMethod(field, setAccessible, JNI_TRUE);
    if (env->ExceptionCheck()) env->ExceptionClear();
    jmethodID fieldGet = env->GetMethodID(fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject unsafe = env->CallObjectMethod(field, fieldGet, nullptr);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(field);
    env->DeleteLocalRef(fieldCls);
    if (!unsafe) { env->DeleteLocalRef(classCls); env->DeleteLocalRef(unsafeCls); return nullptr; }

    jmethodID allocMid = env->GetMethodID(unsafeCls, "allocateInstance",
        "(Ljava/lang/Class;)Ljava/lang/Object;");
    env->DeleteLocalRef(unsafeCls);
    if (!allocMid) { env->DeleteLocalRef(classCls); env->DeleteLocalRef(unsafe); return nullptr; }

    // Can't allocateInstance(Class.class) — Class is special.
    // Instead: allocateInstance(Object.class), then swap the narrow Klass
    // to Class's narrow Klass. This makes the Object look like a Class.
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) { env->DeleteLocalRef(classCls); env->DeleteLocalRef(unsafe); return nullptr; }
    jobject newObj = env->CallObjectMethod(unsafe, allocMid, objCls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(unsafe);
    env->DeleteLocalRef(objCls);
    if (!newObj) { env->DeleteLocalRef(classCls); log_msg("ghost_class: allocateInstance(Object) failed"); return nullptr; }

    // Read Class.class's narrow Klass from its object header (offset 8)
    long long classOop = (long long)(intptr_t)classCls;
    if (g_handle_indir) classOop = *(long long*)classOop;
    unsigned int classNarrowKlass = *(unsigned int*)(classOop + 8);
    env->DeleteLocalRef(classCls);

    // Get raw oop of the new Object
    long long newOop = (long long)(intptr_t)newObj;
    if (g_handle_indir) newOop = *(long long*)newOop;

    // Swap narrow Klass to Class's (makes it look like a Class object)
    DWORD op = 0;
    if (VirtualProtect((void*)(newOop + 8), 4, PAGE_READWRITE, &op)) {
        *(unsigned int*)(newOop + 8) = classNarrowKlass;
        VirtualProtect((void*)(newOop + 8), 4, op, &op);
    }

    // Set _klass_offset to our cloned IK
    if (VirtualProtect((void*)(newOop + g_klass_offset), 8, PAGE_READWRITE, &op)) {
        *(long long*)(newOop + g_klass_offset) = ik;
        VirtualProtect((void*)(newOop + g_klass_offset), 8, op, &op);
    }

    fprintf(stderr, "[TZD] ghost_class: created Class mirror oop=0x%llx ik=0x%llx (narrowKlass=0x%x)\n",
            newOop, ik, classNarrowKlass);
    fflush(stderr);
    return (jclass)newObj;
}

// ─── Create a Symbol (fake — not interned, but readable) ─────────────
static long long create_symbol(const char* str) {
    int len = (int)strlen(str);
    // Symbol layout: _length(u2) + _refcount(u2) + body[len]
    // We allocate with VirtualAlloc (page-aligned, persistent)
    int total = g_sym_len_off + len + 16;
    // Round up to 8 bytes
    total = (total + 7) & ~7;
    long long mem = (long long)VirtualAlloc(nullptr, total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 0;
    memset((void*)mem, 0, total);
    *(unsigned short*)(mem + g_sym_len_off) = (unsigned short)len;
    *(unsigned short*)(mem + g_sym_len_off + 2) = 1; // refcount
    memcpy((void*)(mem + g_sym_body_off), str, len);
    return mem;
}

// ─── Find compressed class space region ──────────────────────────────
static bool find_compressed_class_space(JNIEnv* env) {
    if (s_ccs_base) return true;
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return false;
    long long ik = bootstrap_ik(env, objCls);
    env->DeleteLocalRef(objCls);
    if (!ik) return false;
    // VirtualQuery on the IK to find the region
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)ik, &mbi, sizeof(mbi))) return false;
    s_ccs_base = (long long)mbi.AllocationBase;
    // Find total size by querying the whole reserved region
    long long addr = s_ccs_base;
    long long endAddr = addr;
    while (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) && mbi.AllocationBase == (void*)s_ccs_base) {
        endAddr = addr + mbi.RegionSize;
        addr = endAddr;
        if (addr - s_ccs_base > 0x80000000LL) break; // 2GB safety
    }
    s_ccs_size = endAddr - s_ccs_base;
    fprintf(stderr, "[TZD] ghost_class: compressed class space base=0x%llx size=0x%llx\n",
            s_ccs_base, s_ccs_size);
    fflush(stderr);
    return s_ccs_size > 0;
}

// ─── Commit a free page in the compressed class space ────────────────
static long long commit_page_in_ccs() {
    if (!s_ccs_base || !s_ccs_size) return 0;
    // Scan for MEM_RESERVE (uncommitted) pages within the CCS
    long long addr = s_ccs_base;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < s_ccs_base + s_ccs_size) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_RESERVE && mbi.RegionSize >= 4096) {
            // Commit a page
            void* p = VirtualAlloc((void*)addr, 4096, MEM_COMMIT, PAGE_READWRITE);
            if (p) {
                fprintf(stderr, "[TZD] ghost_class: committed page @ 0x%llx in CCS\n",
                        (long long)p);
                fflush(stderr);
                return (long long)p;
            }
        }
        addr += mbi.RegionSize;
        if (addr <= s_ccs_base) break; // overflow
    }
    // Fallback: try to VirtualAlloc at the end of the CCS
    long long tryAddr = s_ccs_base + s_ccs_size - 0x10000; // 64KB before end
    while (tryAddr < s_ccs_base + s_ccs_size) {
        void* p = VirtualAlloc((void*)tryAddr, 4096, MEM_COMMIT, PAGE_READWRITE);
        if (p) {
            fprintf(stderr, "[TZD] ghost_class: committed fallback page @ 0x%llx\n",
                    (long long)p);
            fflush(stderr);
            return (long long)p;
        }
        tryAddr += 4096;
    }
    log_msg("ghost_class: can't commit page in CCS");
    return 0;
}

// ─── Detect _methods offset in InstanceKlass ─────────────────────────
static int g_methods_offset = -1;

static int detect_methods_offset(JNIEnv* env) {
    if (g_methods_offset >= 0) return g_methods_offset;
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return -1;
    long long objIK = bootstrap_ik(env, objCls);
    jmethodID mid = env->GetMethodID(objCls, "hashCode", "()I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(objCls);
    if (!objIK || !mid) return -1;
    long long donorMethod = resolveMethodPtrExt(mid);
    if (!donorMethod) return -1;

    // Scan IK for a pointer to an Array<Method*> whose elements match donorMethod
    // Array<T> layout: +0 length(int), +4 padding, +8 data[0]
    for (int off = IK_CONSTANTS; off < 400; off += 8) {
        long long arrPtr = rq((void*)(objIK + off));
        if (!arrPtr) continue;
        if (!jvm_safe_read((void*)arrPtr, 16)) continue;
        int len = *(int*)arrPtr;
        if (len <= 0 || len > 1000) continue;
        // Check if any element matches donorMethod
        for (int i = 0; i < len && i < 200; i++) {
            long long m = 0;
            if (jvm_safe_read((void*)(arrPtr + 8 + i * 8), 8))
                m = *(long long*)(arrPtr + 8 + i * 8);
            if (m == donorMethod) {
                g_methods_offset = off;
                fprintf(stderr, "[TZD] ghost_class: _methods offset = %d (len=%d, match@%d)\n", off, len, i);
                fflush(stderr);
                return off;
            }
        }
    }
    log_msg("ghost_class: can't detect _methods offset");
    return -1;
}

// ─── Detect Class.class's "classRedefinedCount" field offset ──────────
// This is a Java field of java.lang.Class (an int). Incrementing it on
// the donor's Class mirror invalidates the cached ReflectionData (whose
// redefinedCount won't match), forcing privateGetDeclaredMethods to call
// getDeclaredMethods0() native → JVM_GetClassDeclaredMethods → reads
// InstanceKlass::_methods (our renamed methods). This is exactly what
// JVMTI RedefineClasses does to flush the reflection cache.
static int g_class_redefined_count_offset = -1;

static int detect_class_redefined_count_offset(JNIEnv* env) {
    if (g_class_redefined_count_offset >= 0) return g_class_redefined_count_offset;
    jclass classCls = env->FindClass("java/lang/Class");
    jclass fieldCls  = env->FindClass("java/lang/reflect/Field");
    jclass unsafeCls = env->FindClass("sun/misc/Unsafe");
    if (!classCls || !fieldCls || !unsafeCls) {
        if (classCls) env->DeleteLocalRef(classCls);
        if (fieldCls) env->DeleteLocalRef(fieldCls);
        if (unsafeCls) env->DeleteLocalRef(unsafeCls);
        return -1;
    }
    jmethodID getDF = env->GetMethodID(classCls, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    // Class.class.getDeclaredField("classRedefinedCount")
    jstring crcName = env->NewStringUTF("classRedefinedCount");
    jobject crcField = getDF ? env->CallObjectMethod(classCls, getDF, crcName) : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(crcName);

    // Unsafe.class.getDeclaredField("theUnsafe")
    jstring tibName = env->NewStringUTF("theUnsafe");
    jobject unsField = getDF ? env->CallObjectMethod(unsafeCls, getDF, tibName) : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(tibName);

    if (!crcField || !unsField) {
        if (crcField) env->DeleteLocalRef(crcField);
        if (unsField) env->DeleteLocalRef(unsField);
        env->DeleteLocalRef(classCls); env->DeleteLocalRef(fieldCls); env->DeleteLocalRef(unsafeCls);
        log_msg("ghost_class: can't get classRedefinedCount/theUnsafe Field");
        return -1;
    }
    jmethodID setAcc = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    env->CallVoidMethod(unsField, setAcc, JNI_TRUE);
    if (env->ExceptionCheck()) env->ExceptionClear();
    jmethodID fGet = env->GetMethodID(fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject unsafe = env->CallObjectMethod(unsField, fGet, nullptr);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(unsField);

    // unsafe.objectFieldOffset(classRedefinedCountField) → offset
    jmethodID offMid = env->GetMethodID(unsafeCls, "objectFieldOffset",
        "(Ljava/lang/reflect/Field;)J");
    jlong off = offMid ? env->CallLongMethod(unsafe, offMid, crcField) : -1;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(crcField);
    env->DeleteLocalRef(unsafe);
    env->DeleteLocalRef(classCls); env->DeleteLocalRef(fieldCls); env->DeleteLocalRef(unsafeCls);

    if (off < 0) { log_msg("ghost_class: can't get classRedefinedCount offset"); return -1; }
    g_class_redefined_count_offset = (int)off;
    fprintf(stderr, "[TZD] ghost_class: classRedefinedCount offset = %d\n", (int)off);
    fflush(stderr);
    return g_class_redefined_count_offset;
}

// ─── Find a donor IK by matching method count + bytecode lengths ─────
static long long find_donor_ik(JNIEnv* env, const ClassFile* cf, int methodsOffset) {
    init_jvm_range();
    long long addr = s_ccs_base;
    long long endAddr = s_ccs_base + s_ccs_size;
    MEMORY_BASIC_INFORMATION mbi;
    int checked = 0;

    while (addr < endAddr) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        long long regionEnd = addr + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) {
            long long scanEnd = regionEnd - 400;
            __try {
                for (long long off = addr; off < scanEnd; off += 8) {
                    long long vt = *(long long*)off;
                    if (!is_in_jvm(vt)) continue;
                    // Read _methods array pointer
                    long long methodsArr = *(long long*)(off + methodsOffset);
                    if (!methodsArr) continue;
                    int methodCount = *(int*)methodsArr;
                    if (methodCount != cf->method_count) continue;

                    // Compare bytecode lengths as a SET (sorted, not ordered).
                    // _code_size is u2 at ConstMethod+32 (NOT int — verified
                    // from debug: reading as int gives 0x00050005, as u2 gives 5).
                    // JVM may reorder methods in _methods array.
                    int donorSizes[64], userSizes[64];
                    for (int i = 0; i < methodCount && i < 64; i++) {
                        long long methodPtr = *(long long*)(methodsArr + 8 + i * 8);
                        long long cm2 = methodPtr ? *(long long*)(methodPtr + 8) : 0;
                        donorSizes[i] = cm2 ? *(unsigned short*)(cm2 + 32) : -1;
                    }
                    for (int i = 0; i < cf->method_count && i < 64; i++)
                        userSizes[i] = cf->methods[i].code_length;

                    // Simple sort for comparison
                    for (int i = 0; i < methodCount; i++)
                        for (int j = i+1; j < methodCount; j++)
                            if (donorSizes[j] < donorSizes[i]) { int t = donorSizes[i]; donorSizes[i] = donorSizes[j]; donorSizes[j] = t; }
                    for (int i = 0; i < cf->method_count; i++)
                        for (int j = i+1; j < cf->method_count; j++)
                            if (userSizes[j] < userSizes[i]) { int t = userSizes[i]; userSizes[i] = userSizes[j]; userSizes[j] = t; }

                    if (checked < 10) {
                        fprintf(stderr, "[TZD] ghost_class: candidate IK@0x%llx methods=%d donor={",
                                off, methodCount);
                        for (int i = 0; i < methodCount && i < 8; i++) fprintf(stderr, "%d,", donorSizes[i]);
                        fprintf(stderr, "} user={");
                        for (int i = 0; i < cf->method_count && i < 8; i++) fprintf(stderr, "%d,", userSizes[i]);
                        fprintf(stderr, "}\n");
                        fflush(stderr);
                    }

                    bool match = true;
                    for (int i = 0; i < methodCount && match; i++)
                        if (donorSizes[i] != userSizes[i]) match = false;
                    checked++;
                    if (match) {
                        fprintf(stderr, "[TZD] ghost_class: found donor IK at 0x%llx (checked=%d)\n", off, checked);
                        fflush(stderr);
                        return off;
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (regionEnd <= addr) break;
        addr = regionEnd;
    }
    fprintf(stderr, "[TZD] ghost_class: no donor IK found (checked %d candidates)\n", checked);
    fflush(stderr);
    return 0;
}

// ─── Mode C: create class from scratch (raw memory, NO JVM API) ──────
// CP layout detection + donor method cloning + CP-independent bytecodes
static int g_cp_header = -1, g_cp_entry_size = -1;
static int g_symbols_offset = -1;  // offset of _symbols field in ConstantPool

static bool detect_cp_layout(JNIEnv* env) {
    if (g_symbols_offset >= 0) return true;
    // Get Object's IK + CP via Method chain
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return false;
    long long objIK = bootstrap_ik(env, objCls);
    jmethodID hcMid = env->GetMethodID(objCls, "hashCode", "()I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    long long mp = hcMid ? resolveMethodPtrExt(hcMid) : 0;
    long long cm = mp ? rq((void*)(mp + 8)) : 0;
    long long cp = cm ? rq((void*)(cm + 8)) : 0;
    env->DeleteLocalRef(objCls);
    if (!objIK || !cp) { fprintf(stderr, "[TZD] ghost_class: detect_cp: objIK=0x%llx cp=0x%llx\n", objIK, cp); fflush(stderr); return false; }
    long long nameSym = rq((void*)(objIK + IK_NAME));
    if (!nameSym) return false;
    fprintf(stderr, "[TZD] ghost_class: detect_cp: cp=0x%llx nameSym=0x%llx objIK=0x%llx\n", cp, nameSym, objIK);
    fflush(stderr);

    // Scan CP fields for _symbols array (Array<Symbol*>)
    // First: try to find nameSym anywhere in the CP memory (inline entries)
    {
        int foundOff = -1;
        for (int off = 8; off < 4096; off += 4) {
            if (!jvm_safe_read((void*)(cp + off), 8)) break;
            if (*(long long*)(cp + off) == nameSym) {
                foundOff = off;
                fprintf(stderr, "[TZD] ghost_class: nameSym found INLINE at CP+%d\n", off);
                fflush(stderr);
                break;
            }
        }
        if (foundOff < 0) {
            fprintf(stderr, "[TZD] ghost_class: nameSym NOT found in CP (0-%d)\n", 4096);
            fflush(stderr);
        }
    }
    // Skip vtable (0), _pool_holder (24 = objIK)
    for (int off = 8; off < 128; off += 8) {
        if (off == 24) continue; // skip _pool_holder
        long long arrPtr = rq((void*)(cp + off));
        if (!arrPtr || arrPtr == objIK || arrPtr == nameSym) continue;
        if (!jvm_safe_read((void*)arrPtr, 12)) continue;
        int len = *(int*)arrPtr;
        if (len <= 0 || len > 10000) continue;
        // Debug: print this candidate
        int validSyms = 0;
        for (int i = 0; i < len && i < 10; i++) {
            long long elem = 0;
            if (!jvm_safe_read((void*)(arrPtr + 8 + i * 8), 8)) break;
            elem = *(long long*)(arrPtr + 8 + i * 8);
            if (!elem) continue;
            if (jvm_safe_read((void*)(elem + g_sym_len_off), 2)) {
                unsigned short sl = *(unsigned short*)(elem + g_sym_len_off);
                if (sl > 0 && sl < 1000) validSyms++;
            }
        }
        fprintf(stderr, "[TZD] ghost_class: CP+%d arr=0x%llx len=%d validSyms=%d\n", off, arrPtr, len, validSyms);
        fflush(stderr);
        // Scan ALL elements for nameSym
        for (int i = 0; i < len && i < 300; i++) {
            long long elem = 0;
            if (!jvm_safe_read((void*)(arrPtr + 8 + i * 8), 8)) break;
            elem = *(long long*)(arrPtr + 8 + i * 8);
            if (elem == nameSym) {
                g_symbols_offset = off;
                fprintf(stderr, "[TZD] ghost_class: _symbols @ CP+%d (len=%d, nameSym@%d)\n", off, len, i);
                fflush(stderr);
                return true;
            }
        }
        // Also accept arrays with many valid Symbol* (>= 3)
        if (validSyms >= 3) {
            g_symbols_offset = off;
            fprintf(stderr, "[TZD] ghost_class: _symbols @ CP+%d (len=%d, validSyms=%d, nameSym not found but accepting)\n", off, len, validSyms);
            fflush(stderr);
            return true;
        }
    }
    log_msg("ghost_class: can't detect _symbols offset");
    return false;
}

static jclass create_class_from_scratch_v2(JNIEnv* env,
        jbyteArray bytecodes, const ClassFile* cf, const char* userClassName) {
    if (!cf || !userClassName) return nullptr;
    (void)bytecodes;

    if (!find_compressed_class_space(env)) return nullptr;
    if (!detect_symbol_layout(env)) return nullptr;
    int methodsOff = detect_methods_offset(env);
    if (methodsOff < 0) return nullptr;

    // Extract user's method names from .class file
    const char* userMethodNames[64];
    int userMethodCount = 0;
    for (int i = 0; i < cf->method_count && i < 64; i++) {
        if (cf->methods[i].name_index > 0 && cf->methods[i].name_index <= cf->cp_count)
            userMethodNames[userMethodCount++] = cf->cp[cf->methods[i].name_index - 1].utf8;
    }

    // Get Object's IK (for fallback and to skip during scan)
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) return nullptr;
    long long objectIK = bootstrap_ik(env, objCls);
    env->DeleteLocalRef(objCls);
    if (!objectIK) return nullptr;
    if (!detect_klass_offset_gc(env)) return nullptr;

    // Scan CCS for a donor IK that has matching method names.
    // Uses JNI reflection (getDeclaredMethods + getName) — NOT defineClass.
    long long donorIK = 0;
    init_jvm_range();
    {
        long long addr = s_ccs_base;
        long long endAddr = s_ccs_base + s_ccs_size;
        MEMORY_BASIC_INFORMATION mbi;
        jclass classCls = env->FindClass("java/lang/Class");
        jmethodID getDM = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        jclass methodCls = env->FindClass("java/lang/reflect/Method");
        jmethodID getName = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (classCls) env->DeleteLocalRef(classCls);

        int scanned = 0;
        while (addr < endAddr && !donorIK) {
            if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
            long long regionEnd = addr + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT) {
                __try {
                    for (long long off = addr; off < regionEnd - 200 && !donorIK; off += 8) {
                        long long vt = *(long long*)off;
                        if (!is_in_jvm(vt)) continue;
                        // Validate this is a real InstanceKlass (not CP/Method/etc.)
                        // Check _layout_helper (offset 8) — should be reasonable instance size
                        int lh = *(int*)(off + IK_LAYOUT_HELPER);
                        if (lh < 8 || lh > 4096) continue;
                        // Check _name (offset 24) — should be a valid Symbol*
                        long long namePtr = *(long long*)(off + IK_NAME);
                        if (!namePtr) continue;
                        if (!jvm_safe_read((void*)(namePtr + g_sym_len_off), 2)) continue;
                        unsigned short nameLen = *(unsigned short*)(namePtr + g_sym_len_off);
                        if (nameLen == 0 || nameLen > 1000) continue;
                        // Check _access_flags (offset 164) — lower 16 bits should be reasonable
                        int af = *(int*)(off + IK_ACCESS_FLAGS);
                        if ((af & 0xFFFF) == 0 || (af & 0xFFFF) == 0xFFFF) continue;
                        // Skip Object (we already know it doesn't have getValue)
                        if (off == objectIK) continue;
                        // Get Class mirror from IK._java_mirror
                        long long oopHandle = *(long long*)(off + IK_JAVA_MIRROR);
                        if (!oopHandle) continue;
                        long long classOop = 0;
                        if (jvm_safe_read((void*)oopHandle, 8)) classOop = *(long long*)oopHandle;
                        if (!classOop) continue;
                        // Create JNI ref
                        jobject cls = nullptr;
                        if (g_handle_indir) cls = env->NewLocalRef((jobject)oopHandle);
                        else cls = env->NewLocalRef((jobject)classOop);
                        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
                        if (!cls) continue;
                        scanned++;
                        // Call getDeclaredMethods()
                        jobjectArray methods = (jobjectArray)env->CallObjectMethod(cls, getDM);
                        if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(cls); continue; }
                        if (!methods) { env->DeleteLocalRef(cls); continue; }
                        int nMethods = env->GetArrayLength(methods);
                        // Collect method names
                        bool allFound = true;
                        for (int ui = 0; ui < userMethodCount && allFound; ui++) {
                            bool found = false;
                            for (int mi = 0; mi < nMethods && !found; mi++) {
                                jobject m = env->GetObjectArrayElement(methods, mi);
                                if (!m) continue;
                                jstring nameStr = (jstring)env->CallObjectMethod(m, getName);
                                if (nameStr) {
                                    const char* nameC = env->GetStringUTFChars(nameStr, nullptr);
                                    if (nameC && strcmp(nameC, userMethodNames[ui]) == 0) found = true;
                                    if (nameC) env->ReleaseStringUTFChars(nameStr, nameC);
                                    env->DeleteLocalRef(nameStr);
                                }
                                env->DeleteLocalRef(m);
                            }
                            if (!found) allFound = false;
                        }
                        env->DeleteLocalRef(methods);
                        if (allFound) {
                            donorIK = off;
                            fprintf(stderr, "[TZD] ghost_class: found donor IK at 0x%llx with all %d method names (scanned %d)\n",
                                    off, userMethodCount, scanned);
                            fflush(stderr);
                        }
                        env->DeleteLocalRef(cls);
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            if (regionEnd <= addr) break;
            addr = regionEnd;
        }
        if (methodCls) env->DeleteLocalRef(methodCls);
        fprintf(stderr, "[TZD] ghost_class: scanned %d IKs for method name match\n", scanned);
        fflush(stderr);
    }

    // Fallback: use Object's IK if no donor found
    if (!donorIK) {
        fprintf(stderr, "[TZD] ghost_class: no donor with matching methods, using Object\n");
        fflush(stderr);
        donorIK = objectIK;
    }
    if (!donorIK) return nullptr;

    // Clone IK to CCS page (COMPLETE COPY — all pointers stay pointing to
    // donor's Method*, ConstMethod, ConstantPool, vtable. This keeps the
    // metadata chain consistent — no crashes.)
    long long page = commit_page_in_ccs();
    if (!page) return nullptr;
    memset((void*)page, 0, 4096);
    long long newIK = page;
    long long copySize = 1024;
    if (!jvm_safe_read((void*)donorIK, (size_t)copySize)) { copySize = 512; if (!jvm_safe_read((void*)donorIK, (size_t)copySize)) return nullptr; }
    memcpy((void*)newIK, (void*)donorIK, (size_t)copySize);

    // DO NOT modify the donor's ConstantPool (it's shared with the clone via
    // the IK copy). Modifying it would break Object.class for the entire JVM.
    // The clone's _constants still points to the donor's CP — this is fine
    // for method execution. getDeclaringClass() returns the donor (Object),
    // which is acceptable.

    // Rename + unlink (only modify the clone's own fields)
    // NOTE: We do NOT set JVM_ACC_HIDDEN on the clone IK. The HIDDEN flag
    // changes how InstanceKlass::module() resolves (returns the unnamed
    // module instead of java.base for hidden classes), which breaks
    // IMPL_LOOKUP's access checks. The clone is already invisible because
    // it's in VirtualAlloc'd CCS memory, not linked to any CLD's _klasses.
    DWORD op = 0;
    long long nameSym = create_symbol(userClassName);
    if (nameSym) { if (VirtualProtect((void*)(newIK + IK_NAME), 8, PAGE_READWRITE, &op)) { *(long long*)(newIK + IK_NAME) = nameSym; VirtualProtect((void*)(newIK + IK_NAME), 8, op, &op); } }
    // DO NOT set HIDDEN — see comment above
    // if (VirtualProtect((void*)(newIK + IK_ACCESS_FLAGS), 4, PAGE_READWRITE, &op)) { *(jint*)(newIK + IK_ACCESS_FLAGS) |= JVM_ACC_HIDDEN; VirtualProtect((void*)(newIK + IK_ACCESS_FLAGS), 4, op, &op); }
    // DO NOT clear _cld — keep donor's CLD for module/access checks
    // (Constructor.newInstance needs the module for access verification)
    if (VirtualProtect((void*)(newIK + IK_NEXT_LINK), 8, PAGE_READWRITE, &op)) { *(long long*)(newIK + IK_NEXT_LINK) = 0; VirtualProtect((void*)(newIK + IK_NEXT_LINK), 8, op, &op); }
    if (VirtualProtect((void*)(newIK + 128), 16, PAGE_READWRITE, &op)) { *(long long*)(newIK + 128) = 0; *(long long*)(newIK + 136) = 0; VirtualProtect((void*)(newIK + 128), 16, op, &op); }

    fprintf(stderr, "[TZD] ghost_class: cloned IK at 0x%llx (from donor 0x%llx), name=%s\n",
            newIK, donorIK, userClassName);
    fflush(stderr);

    // ─── Own defineClass: create CP + Method* + ConstMethod all in CCS ───
    // Everything is in the compressed class space (Metaspace) so the JVM's
    // Metaspace::contains() checks pass. Uses ORIGINAL (unrewritten) bytecodes
    // — the interpreter's original handlers resolve CP entries by raw index.

    // Detect CP layout (header size, entry size, _symbols offset, _constants offset)
    if (!detect_cp_layout(env)) return nullptr;

    // Get donor's CP from Method chain
    jclass objCls2 = env->FindClass("java/lang/Object");
    jmethodID hcMid2 = env->GetMethodID(objCls2, "hashCode", "()I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    long long mp2 = hcMid2 ? resolveMethodPtrExt(hcMid2) : 0;
    long long cm2 = mp2 ? rq((void*)(mp2 + 8)) : 0;
    long long donorCP = cm2 ? rq((void*)(cm2 + 8)) : 0;
    env->DeleteLocalRef(objCls2);
    if (!donorCP) { log_msg("ghost_class: can't get donor CP"); return nullptr; }

    // Detect _constants offset in IK
    int constantsOff = 208;
    for (int off = 0; off < 400; off += 8) {
        if (rq((void*)(donorIK + off)) == donorCP) { constantsOff = off; break; }
    }

    // Read donor CP size
    long long donorTags = rq((void*)(donorCP + 8));
    int cpLen = (donorTags && jvm_safe_read((void*)donorTags, 4)) ? *(int*)donorTags : 0;
    const int CP_HEADER = 144;
    const int CP_ENTRY = 8;
    long long cpTotal = CP_HEADER + (long long)cpLen * CP_ENTRY + 64;

    // Allocate a NEW CCS page for CP + ConstMethods + Method* objects
    long long metaPage = commit_page_in_ccs();
    if (!metaPage) { log_msg("ghost_class: can't commit meta page"); return nullptr; }
    memset((void*)metaPage, 0, 4096);

    // 1. Create new ConstantPool (clone donor CP, modify entries)
    long long newCP = metaPage;
    long long cpCopySize = cpTotal < 4096 ? cpTotal : 4096;
    if (jvm_safe_read((void*)donorCP, (size_t)cpCopySize)) {
        memcpy((void*)newCP, (void*)donorCP, (size_t)cpCopySize);
    }
    // Set _pool_holder to our clone IK
    *(long long*)(newCP + 24) = newIK;
    // Set clone IK's _constants to new CP
    {
    DWORD op2 = 0;
    if (VirtualProtect((void*)(newIK + constantsOff), 8, PAGE_READWRITE, &op2)) {
        *(long long*)(newIK + constantsOff) = newCP;
        VirtualProtect((void*)(newIK + constantsOff), 8, op2, &op2);
    }

    // 2. For each user method, create Method* + ConstMethod in CCS
    long long methodArea = metaPage + cpTotal; // after CP on same page
    long long methodAreaEnd = metaPage + 4096;
    long long donorMethodsArr = rq((void*)(donorIK + methodsOff));
    int donorMC = donorMethodsArr ? *(int*)donorMethodsArr : 0;

    struct { long long mp; long long cm; } newMethods[64];
    int newMC = 0;

    for (int i = 0; i < cf->method_count && i < 64; i++) {
        const MethodInfo* m = &cf->methods[i];
        if (!m->code) continue;
        const char* mname = cf->cp[m->name_index - 1].utf8;
        const char* mdesc = cf->cp[m->desc_index - 1].utf8;
        if (!mname || !mdesc) continue;

        // Parse return type from descriptor
        char rt = 'V';
        for (const char* p = mdesc; *p; p++) if (*p == ')') { rt = p[1]; break; }

        // Find donor Method* by return type
        long long donorMP = 0;
        for (int j = 0; j < donorMC && j < 100; j++) {
            long long dmp = rq((void*)(donorMethodsArr + 8 + j * 8));
            if (!dmp) continue;
            long long dcm = rq((void*)(dmp + 8));
            if (!dcm) continue;
            unsigned short drt = *(unsigned short*)(dcm + 30);
            bool match = (rt=='V'&&drt==14)||(rt=='F'&&drt==6)||(rt=='I'&&drt==10)||
                         (rt=='J'&&drt==11)||(rt=='D'&&drt==7)||
                         ((rt=='L'||rt=='[')&&(drt==12||drt==13));
            if (match) { donorMP = dmp; break; }
        }
        if (!donorMP && donorMC > 0) donorMP = rq((void*)(donorMethodsArr + 8));
        if (!donorMP) continue;

        // Allocate Method* (128 bytes) in CCS
        long long newMP = methodArea;
        methodArea += 128;
        if (methodArea > methodAreaEnd) break;
        if (jvm_safe_read((void*)donorMP, 128)) memcpy((void*)newMP, (void*)donorMP, 128);

        // Allocate ConstMethod (512 bytes) in CCS — create FROM SCRATCH
        // (not cloning donor) to avoid stale inline table data.
        // ConstMethod layout (NO vtable, fields start at offset 0):
        //   +0  _fingerprint(u8)  +8 _constants(P*)  +16 _stackmap_data(P*)
        //   +24 _constMethod_size(i4)  +28 _flags(u2)  +30 _result_type(u1)
        //   +32 _code_size(u2)  +34 _name_index(u2)  +36 _signature_index(u2)
        //   +38 _method_idnum(u2)  +48 _orig_method_idnum(u2)
        //   +56 bytecodes start (codeBase)
        long long donorCM = rq((void*)(donorMP + 8));
        long long newCM = methodArea;
        methodArea += 512;
        if (methodArea > methodAreaEnd) break;
        memset((void*)newCM, 0, 512);

        // Copy the fingerprint from the donor (needed for method matching)
        if (donorCM && jvm_safe_read((void*)donorCM, 8))
            memcpy((void*)newCM, (void*)donorCM, 8); // _fingerprint at +0

        // Set ConstMethod._constants to new CP
        *(long long*)(newCM + 8) = newCP;

        // _stackmap_data = NULL (already zeroed)
        // _constMethod_size = header_words + code_words
        //   header = codeBase (56 bytes) / 8 = 7 words
        //   code_words = align_up(code_length, 8) / 8
        int codeBase = jvm_deopt_get_offset("codeBase");
        int headerWords = (codeBase > 0 ? codeBase : 56) / 8;
        int codeWords = (m->code_length + 7) / 8;
        *(int*)(newCM + 24) = headerWords + codeWords; // _constMethod_size in words

        // _flags = 0 (NO inline tables — prevents Reflection::new_method crashes)
        *(unsigned short*)(newCM + 28) = 0;

        // Copy _result_type from donor (needed for return type matching)
        if (donorCM && jvm_safe_read((void*)(donorCM + 30), 1))
            *(unsigned char*)(newCM + 30) = *(unsigned char*)(donorCM + 30);

        // Write user's ORIGINAL (unrewritten) bytecodes at codeBase
        if (codeBase > 0 && m->code_length > 0 && m->code_length < 200) {
            memcpy((void*)(newCM + codeBase), (void*)m->code, m->code_length);
            *(unsigned short*)(newCM + 32) = (unsigned short)m->code_length; // _code_size
        }

        // Copy _max_stack, _max_locals, _size_of_parameters from donor
        if (donorCM && jvm_safe_read((void*)(donorCM + 40), 8)) {
            memcpy((void*)(newCM + 40), (void*)(donorCM + 40), 8); // max_stack, max_locals, size_of_params
        }

        // Link Method* to new ConstMethod
        if (VirtualProtect((void*)(newMP + 8), 8, PAGE_READWRITE, &op2)) {
            *(long long*)(newMP + 8) = newCM;
            VirtualProtect((void*)(newMP + 8), 8, op2, &op2);
        }

        // ── Update method metadata fields on the cloned ConstMethod ──
        // ConstMethod layout (no vtable; fields start at offset 0):
        //   +0  _fingerprint(u8)  +8 _constants(P*)  +16 _stackmap_data(P*)
        //   +24 _constMethod_size(i4)  +28 _flags(u2)  +30 _result_type(u1)
        //   +32 _code_size(u2)  +34 _name_index(u2)  +36 _signature_index(u2)
        //   +38 _method_idnum(u2)  +48 _orig_method_idnum(u2)
        //
        // Set _method_idnum = array index so method_with_idnum() finds it
        // at methods()->at(idnum) directly (no slow linear scan needed).
        *(unsigned short*)(newCM + 38) = (unsigned short)newMC;
        *(unsigned short*)(newCM + 48) = (unsigned short)newMC;

        // ── Rename: assign a UNIQUE CP slot for each method's name ──
        // All cloned methods share the SAME name_index (they're cloned from
        // the same donor method). If we rename the same CP slot multiple
        // times, only the last rename sticks → all methods get the last name.
        // FIX: for each method, find a DIFFERENT Utf8 CP slot, update the
        // ConstMethod's _name_index to that slot, then rename it.
        static int usedNameSlots[64]; // tracks CP slots already assigned
        static int usedNameCount = 0;
        // (re-init per call — static is fine since create_ghost_class is called once)
        if (newMC == 0) { usedNameCount = 0; }

        unsigned short nameIdx = *(unsigned short*)(newCM + 34);

        // Since ConstMethod is created from scratch (zeroed), nameIdx is 0.
        // We must ALWAYS find a free CP slot for the name.
        bool needNewSlot = (nameIdx == 0);
        if (!needNewSlot) {
            for (int u = 0; u < usedNameCount; u++) {
                if (usedNameSlots[u] == nameIdx) { needNewSlot = true; break; }
            }
        }

        if (needNewSlot) {
            // Find a DIFFERENT Utf8 CP slot (tag == 1) not yet used
            unsigned short newIdx = 0;
            for (int idx = 1; idx < cpLen && idx < 300; idx++) {
                unsigned char tag = *(unsigned char*)(donorTags + 8 + idx);
                if (tag != 1) continue; // Utf8 only
                bool taken = false;
                for (int u = 0; u < usedNameCount; u++) {
                    if (usedNameSlots[u] == idx) { taken = true; break; }
                }
                if (!taken) { newIdx = (unsigned short)idx; break; }
            }
            if (newIdx > 0) {
                nameIdx = newIdx;
                *(unsigned short*)(newCM + 34) = nameIdx; // update _name_index
            } else {
                fprintf(stderr, "[TZD] ghost_class: WARNING no free CP slot for %s\n", mname);
                fflush(stderr);
            }
        }

        // Track this slot as used
        if (usedNameCount < 64) usedNameSlots[usedNameCount++] = nameIdx;

        // Rename this CP slot with the user's method name
        if (nameIdx > 0 && nameIdx < cpLen && nameIdx < 300) {
            long long symAddr = newCP + CP_HEADER + (long long)nameIdx * CP_ENTRY;
            long long newSym = create_symbol(mname);
            if (newSym) {
                *(long long*)symAddr = newSym;
                fprintf(stderr, "[TZD] ghost_class: renamed CP[%u] -> %s (idnum=%d)\n",
                        nameIdx, mname, newMC);
                fflush(stderr);
            }
        }

        // ── Also assign a UNIQUE CP slot for the method's signature ──
        // The signature descriptor (e.g. "()F" for getValue) must be in a CP
        // Utf8 slot that the ConstMethod's _signature_index (+36) points to.
        // Without this, method->signature() returns NULL → crash at 0x4.
        unsigned short sigIdx = 0;
        for (int idx = 1; idx < cpLen && idx < 300; idx++) {
            unsigned char tag = *(unsigned char*)(donorTags + 8 + idx);
            if (tag != 1) continue; // Utf8 only
            bool taken = false;
            for (int u = 0; u < usedNameCount; u++) {
                if (usedNameSlots[u] == idx) { taken = true; break; }
            }
            if (!taken) { sigIdx = (unsigned short)idx; break; }
        }
        if (sigIdx > 0) {
            usedNameSlots[usedNameCount++] = sigIdx; // track as used
            *(unsigned short*)(newCM + 36) = sigIdx; // set _signature_index
            // Rename this CP slot with the method descriptor
            long long sigAddr = newCP + CP_HEADER + (long long)sigIdx * CP_ENTRY;
            long long sigSym = create_symbol(mdesc);
            if (sigSym) {
                *(long long*)sigAddr = sigSym;
                fprintf(stderr, "[TZD] ghost_class: renamed CP[%u] -> %s (signature)\n",
                        sigIdx, mdesc);
                fflush(stderr);
            }
        }

        newMethods[newMC].mp = newMP;
        newMethods[newMC].cm = newCM;
        newMC++;
        fprintf(stderr, "[TZD] ghost_class: method %s (%s) ret=%c, donorMP=0x%llx\n",
                mname, mdesc, rt, donorMP);
        fflush(stderr);
    }

    if (newMC > 0) {
        // Allocate Array<Method*> on the SAME CCS page (after Method*/ConstMethod)
        long long newMA = methodArea;
        long long maSize = 8 + (long long)newMC * 8;
        methodArea += maSize;
        if (methodArea > methodAreaEnd) {
            // Not enough space on page — allocate another CCS page
            long long extraPage = commit_page_in_ccs();
            if (extraPage) newMA = extraPage;
            else newMA = (long long)VirtualAlloc(nullptr, (SIZE_T)maSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        }
        if (newMA) {
            *(int*)newMA = newMC;
            for (int i = 0; i < newMC; i++)
                *(long long*)(newMA + 8 + i * 8) = newMethods[i].mp;
            DWORD op3 = 0;
            if (VirtualProtect((void*)(newIK + methodsOff), 8, PAGE_READWRITE, &op3)) {
                *(long long*)(newIK + methodsOff) = newMA;
                VirtualProtect((void*)(newIK + methodsOff), 8, op3, &op3);
            }
        }
        fprintf(stderr, "[TZD] ghost_class: created %d methods with own-defineClass\n", newMC);
        fflush(stderr);
    }

    // ── Create a FRESH Class mirror using Object[] array ───────────────
    // We can't redirect Object.class (breaks instanceof/type checks) and
    // can't allocateInstance(Class.class) (Class is InstanceMirrorKlass).
    // Instead: create an Object[25] array (212 bytes > Class's 200 bytes),
    // swap its narrowKlass to Class's, copy fields from Object.class's mirror,
    // and set _klass to our clone IK. Object.class is NOT modified.
    if (!detect_klass_offset_gc(env)) return nullptr;

    // ── ALL JNI calls MUST happen BEFORE NewObjectArray (to avoid GC moving the array) ──
    // Get donor's (Object's) Class mirror for field copying
    long long donorOopHandle = rq((void*)(donorIK + IK_JAVA_MIRROR));
    long long donorOop = 0;
    if (g_handle_indir && donorOopHandle) {
        donorOop = rq((void*)donorOopHandle);
    } else {
        donorOop = donorOopHandle;
    }
    if (!donorOop) { log_msg("ghost_class: can't get donor Class mirror raw oop"); return nullptr; }

    // Read Class.class's narrowKlass from its object header (offset 8)
    jclass classCls = env->FindClass("java/lang/Class");
    if (!classCls) { log_msg("ghost_class: can't FindClass Class"); return nullptr; }
    long long classRaw = (long long)(intptr_t)classCls;
    if (g_handle_indir) classRaw = *(long long*)classRaw;
    unsigned int classNarrowKlass = *(unsigned int*)(classRaw + 8);
    env->DeleteLocalRef(classCls);

    // Detect classRedefinedCount offset NOW (before array creation — JNI calls inside)
    int crcOff = detect_class_redefined_count_offset(env);

    // Now get the Object class for NewObjectArray
    jclass objCls = env->FindClass("java/lang/Object");
    if (!objCls) { log_msg("ghost_class: can't FindClass Object"); return nullptr; }

    // ── Create Object[25] — from here, NO JNI calls that could trigger GC ──
    // 12 byte header + 25*8 = 212 bytes total (> 200 for Class)
    jobjectArray arrObj = env->NewObjectArray(25, objCls, nullptr);
    env->DeleteLocalRef(objCls);
    if (!arrObj || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        log_msg("ghost_class: can't create Object[25] for mirror");
        return nullptr;
    }

    // Get raw oop of the array — all subsequent writes use this raw address.
    // NO JNI calls after this point (to prevent GC from moving the array).
    long long freshOop = (long long)(intptr_t)arrObj;
    if (g_handle_indir) freshOop = *(long long*)freshOop;
    int freshObjSize = 12 + 25 * 8; // 212 bytes

    // Zero all fields after the 12-byte header
    {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + 12), freshObjSize - 12, PAGE_READWRITE, &op3)) {
            memset((void*)(freshOop + 12), 0, freshObjSize - 12);
            VirtualProtect((void*)(freshOop + 12), freshObjSize - 12, op3, &op3);
        }
    }
    // Swap narrowKlass to Class's (makes the JVM treat it as a Class instance)
    {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + 8), 4, PAGE_READWRITE, &op3)) {
            *(unsigned int*)(freshOop + 8) = classNarrowKlass;
            VirtualProtect((void*)(freshOop + 8), 4, op3, &op3);
        }
    }

    // Copy only NON-oop, NON-reference fields from donor:
    //   _oop_size @32 (4 bytes) — instance size for Unsafe.allocateInstance
    //   _static_oop_field_count @36 — MUST be 0 (no static oop fields on fake mirror,
    //   otherwise GC scans non-existent static fields → infinite loop/hang)
    if (jvm_safe_read((void*)(donorOop + 32), 4)) {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + 32), 8, PAGE_READWRITE, &op3)) {
            memcpy((void*)(freshOop + 32), (void*)(donorOop + 32), 4); // _oop_size only
            *(unsigned int*)(freshOop + 36) = 0; // _static_oop_field_count = 0 (critical!)
            VirtualProtect((void*)(freshOop + 32), 8, op3, &op3);
        }
    }

    // Set _klass to our clone IK (the injected field at g_klass_offset)
    {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + g_klass_offset), 8, PAGE_READWRITE, &op3)) {
            *(long long*)(freshOop + g_klass_offset) = newIK;
            VirtualProtect((void*)(freshOop + g_klass_offset), 8, op3, &op3);
        }
    }
    // Set classRedefinedCount = 1 (invalidates any copied ReflectionData cache)
    if (crcOff >= 0) {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + crcOff), 4, PAGE_READWRITE, &op3)) {
            *(jint*)(freshOop + crcOff) = 1;
            VirtualProtect((void*)(freshOop + crcOff), 4, op3, &op3);
        }
    }
    // Null out reflectionData (force truly fresh cache)
    {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(freshOop + 68), 4, PAGE_READWRITE, &op3)) {
            *(unsigned int*)(freshOop + 68) = 0;
            VirtualProtect((void*)(freshOop + 68), 4, op3, &op3);
        }
    }

    // Set clone IK's _java_mirror to donor's OopHandle (shared, stable)
    {
        DWORD op3 = 0;
        if (VirtualProtect((void*)(newIK + IK_JAVA_MIRROR), 8, PAGE_READWRITE, &op3)) {
            *(long long*)(newIK + IK_JAVA_MIRROR) = donorOopHandle;
            VirtualProtect((void*)(newIK + IK_JAVA_MIRROR), 8, op3, &op3);
        }
    }

    // DEBUG: verify
    {
        long long vk = rq((void*)(freshOop + g_klass_offset));
        long long vma = rq((void*)(vk + methodsOff));
        int vmc = vma ? *(int*)vma : -1;
        fprintf(stderr, "[TZD] ghost_class: fresh mirror oop=0x%llx (NK=0x%x) _klass=0x%llx methods=0x%llx len=%d\n",
                freshOop, classNarrowKlass, vk, vma, vmc);
        fflush(stderr);
    }

    return (jclass)arrObj;
    } // end scope opened at CP holder block (op2 / method creation / mirror)
}

// ─── Mode C: create class via Lookup.defineClass (full Java syntax) ───
// Uses MethodHandles.Lookup.defineClass(byte[]) to create a fully
// functional class from raw bytecodes. The JVM handles:
//   - ConstantPool creation (with bytecode rewriting)
//   - Method* creation (with entry points, adapters)
//   - Vtable setup
//   - Super class / interface resolution
//   - Field layout
// This supports ALL Java syntax (inheritance, interfaces, generics, etc.).
// Then we set the HIDDEN flag on the resulting InstanceKlass.
static jclass create_class_via_lookup(JNIEnv* env, jbyteArray bytecodes,
                                       const char* userClassName) {
    if (!bytecodes) return nullptr;

    // Get MethodHandles.lookup() — this is caller-sensitive and returns
    // a lookup for NativeBridge's package. We need privateLookupIn to
    // get access to the target package.
    jclass mhCls = env->FindClass("java/lang/invoke/MethodHandles");
    if (!mhCls) { log_msg("ghost_class: FindClass(MethodHandles) failed"); return nullptr; }
    jmethodID lookupMid = env->GetStaticMethodID(mhCls, "lookup",
        "()Ljava/lang/invoke/MethodHandles$Lookup;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!lookupMid) { env->DeleteLocalRef(mhCls); return nullptr; }
    jobject baseLookup = env->CallStaticObjectMethod(mhCls, lookupMid);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!baseLookup) { env->DeleteLocalRef(mhCls); return nullptr; }

    // Extract the package from the user's class name and find a class
    // in that package for privateLookupIn.
    // e.g. "it/unimi/dsi/fastutil/tzd/test/QuickProtectTest$GhostSecret"
    //  → package "it/unimi/dsi/fastutil/tzd/test"
    //  → outer class "it/unimi/dsi/fastutil/tzd/test/QuickProtectTest"
    char pkgBuf[512];
    strncpy(pkgBuf, userClassName, sizeof(pkgBuf) - 1);
    pkgBuf[sizeof(pkgBuf) - 1] = 0;
    // Find last '/' — everything before it is the package
    char* lastSlash = strrchr(pkgBuf, '/');
    jobject lookup = baseLookup;  // default: use base lookup
    if (lastSlash) {
        *lastSlash = 0;  // Truncate to package path
        // Try to find the outer class (strip $Inner part)
        char outerBuf[512];
        strncpy(outerBuf, userClassName, sizeof(outerBuf) - 1);
        outerBuf[sizeof(outerBuf) - 1] = 0;
        char* dollar = strchr(outerBuf, '$');
        if (dollar) *dollar = 0;  // Strip inner class name
        // Replace '/' with '.' for FindClass
        // Actually FindClass uses '/' separators
        fprintf(stderr, "[TZD] ghost_class: trying privateLookupIn(%s)\n", outerBuf);
        fflush(stderr);
        jclass targetCls = env->FindClass(outerBuf);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (targetCls) {
            // MethodHandles.privateLookupIn(targetCls, baseLookup)
            jmethodID privateLookupMid = env->GetStaticMethodID(mhCls,
                "privateLookupIn",
                "(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)"
                "Ljava/lang/invoke/MethodHandles$Lookup;");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (privateLookupMid) {
                lookup = env->CallStaticObjectMethod(mhCls, privateLookupMid,
                                                      targetCls, baseLookup);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (lookup) {
                    fprintf(stderr, "[TZD] ghost_class: privateLookupIn succeeded\n");
                    fflush(stderr);
                } else {
                    lookup = baseLookup;  // fallback
                }
            }
            env->DeleteLocalRef(targetCls);
        }
    }

    // Get Lookup class
    jclass lookupCls = env->FindClass("java/lang/invoke/MethodHandles$Lookup");
    if (!lookupCls) { env->DeleteLocalRef(mhCls); return nullptr; }

    // Try defineHiddenClass first (handles inner classes, nest membership)
    jmethodID hiddenMid = env->GetMethodID(lookupCls, "defineHiddenClass",
        "([BZ[Ljava/lang/invoke/MethodHandles$Lookup$ClassOption;)"
        "Ljava/lang/invoke/MethodHandles$Lookup;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (hiddenMid) {
        // Create empty ClassOption array
        jclass coCls = env->FindClass("java/lang/invoke/MethodHandles$Lookup$ClassOption");
        jobjectArray coArr = nullptr;
        if (coCls) {
            coArr = env->NewObjectArray(0, coCls, nullptr);
            env->DeleteLocalRef(coCls);
        }
        jobject hiddenLookup = env->CallObjectMethod(lookup, hiddenMid,
            bytecodes, JNI_TRUE, coArr ? coArr : nullptr);
        jthrowable exc = env->ExceptionOccurred();
        env->ExceptionClear();
        if (coArr) env->DeleteLocalRef(coArr);
        if (hiddenLookup) {
            // Get lookupClass() from the returned Lookup
            jmethodID lcMid = env->GetMethodID(lookupCls, "lookupClass",
                "()Ljava/lang/Class;");
            jclass result = (jclass)env->CallObjectMethod(hiddenLookup, lcMid);
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(hiddenLookup);
            env->DeleteLocalRef(lookupCls);
            env->DeleteLocalRef(mhCls);
            if (result) {
                fprintf(stderr, "[TZD] ghost_class: defineHiddenClass succeeded\n");
                fflush(stderr);
            }
            return result;
        }
        if (exc) {
            // Print exception message for debugging
            jclass excCls = env->GetObjectClass(exc);
            jmethodID toStringMid = env->GetMethodID(excCls, "toString",
                "()Ljava/lang/String;");
            if (toStringMid) {
                jstring msg = (jstring)env->CallObjectMethod(exc, toStringMid);
                if (msg) {
                    const char* msgStr = env->GetStringUTFChars(msg, nullptr);
                    fprintf(stderr, "[TZD] ghost_class: defineHiddenClass exception: %s\n", msgStr);
                    fflush(stderr);
                    env->ReleaseStringUTFChars(msg, msgStr);
                    env->DeleteLocalRef(msg);
                }
            }
            env->DeleteLocalRef(exc);
            env->DeleteLocalRef(excCls);
        }
    }

    // Fallback: try defineClass(byte[])
    jmethodID defineMid = env->GetMethodID(lookupCls, "defineClass",
        "([B)Ljava/lang/Class;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (defineMid) {
        jclass result = (jclass)env->CallObjectMethod(lookup, defineMid, bytecodes);
        jthrowable exc = env->ExceptionOccurred();
        env->ExceptionClear();
        env->DeleteLocalRef(lookupCls);
        env->DeleteLocalRef(mhCls);
        if (result) {
            fprintf(stderr, "[TZD] ghost_class: defineClass succeeded\n");
            fflush(stderr);
            return result;
        }
        if (exc) {
            jclass excCls = env->GetObjectClass(exc);
            jmethodID toStringMid = env->GetMethodID(excCls, "toString",
                "()Ljava/lang/String;");
            if (toStringMid) {
                jstring msg = (jstring)env->CallObjectMethod(exc, toStringMid);
                if (msg) {
                    const char* msgStr = env->GetStringUTFChars(msg, nullptr);
                    fprintf(stderr, "[TZD] ghost_class: defineClass exception: %s\n", msgStr);
                    fflush(stderr);
                    env->ReleaseStringUTFChars(msg, msgStr);
                    env->DeleteLocalRef(msg);
                }
            }
            env->DeleteLocalRef(exc);
            env->DeleteLocalRef(excCls);
        }
    } else {
        env->DeleteLocalRef(lookupCls);
        env->DeleteLocalRef(mhCls);
    }

    log_msg("ghost_class: both defineClass and defineHiddenClass failed");
    return nullptr;
}

// ─── Main entry point ────────────────────────────────────────────────
extern "C"
jclass create_ghost_class(JNIEnv* env, jbyteArray bytecodes, jclass templateClass) {
    if (!env || !bytecodes) return nullptr;

    // 1. Parse class file
    jsize blen = env->GetArrayLength(bytecodes);
    jbyte* bbuf = env->GetByteArrayElements(bytecodes, nullptr);
    if (!bbuf) return nullptr;
    ClassFile cf;
    bool parsed = parse_class_file((const unsigned char*)bbuf, blen, &cf);
    env->ReleaseByteArrayElements(bytecodes, bbuf, JNI_ABORT);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!parsed) { log_msg("ghost_class: parsing failed"); return nullptr; }

    // 2. Extract class name
    const char* userClassName = nullptr;
    if (cf.this_class > 0 && cf.this_class <= cf.cp_count) {
        CPEntry* clsEntry = &cf.cp[cf.this_class - 1];
        if (clsEntry->tag == 7 && clsEntry->index1 > 0 && clsEntry->index1 <= cf.cp_count) {
            CPEntry* nameEntry = &cf.cp[clsEntry->index1 - 1];
            if (nameEntry->tag == 1) userClassName = nameEntry->utf8;
        }
    }
    if (!userClassName) { log_msg("ghost_class: can't get class name"); return nullptr; }

    fprintf(stderr, "[TZD] ghost_class: class name = %s (hostClass=%s)\n",
            userClassName, templateClass ? "provided" : "NULL");
    fflush(stderr);

    long long ik = 0;
    jclass foundJcls = nullptr;

    if (templateClass) {
        // ── Mode A: hostClass provided — FindClass (original working approach) ──
        // The class must be on the classpath. FindClass loads it if needed
        // (with proper bytecode rewriting) and returns a JNI reference.
        fprintf(stderr, "[TZD] ghost_class: FindClass(%s) [mode A]\n", userClassName);
        fflush(stderr);
        foundJcls = env->FindClass(userClassName);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (foundJcls) {
            ik = get_ik_from_class_mirror(env, foundJcls);
        }
    } else {
        // ── Mode B: hostClass is NULL — walk CLD list (NO FindClass) ──
        ik = find_ik_by_name(env, userClassName);
    }

    if (ik && foundJcls) {
        // ── Mode A: set HIDDEN flag, return the jclass from FindClass ──
        DWORD op = 0;
        if (VirtualProtect((void*)(ik + IK_ACCESS_FLAGS), 4, PAGE_READWRITE, &op)) {
            jint oldFlags = *(jint*)(ik + IK_ACCESS_FLAGS);
            *(jint*)(ik + IK_ACCESS_FLAGS) = oldFlags | JVM_ACC_HIDDEN;
            VirtualProtect((void*)(ik + IK_ACCESS_FLAGS), 4, op, &op);
            fprintf(stderr, "[TZD] ghost_class: HIDDEN set on ik=0x%llx (0x%x->0x%x)\n",
                    ik, oldFlags, oldFlags | JVM_ACC_HIDDEN);
            fflush(stderr);
        }
        fprintf(stderr, "[TZD] ghost_class: COMPLETE (mode A, FindClass jclass)\n");
        fflush(stderr);
        for (int i = 0; i < cf.cp_count - 1; i++) if (cf.cp[i].utf8) free(cf.cp[i].utf8);
        for (int i = 0; i < cf.method_count; i++) if (cf.methods[i].code) free((void*)cf.methods[i].code);
        return foundJcls;
    }

    if (ik && !foundJcls) {
        // ── Mode B: set HIDDEN flag, create jclass from IK's OopHandle ──
        DWORD op = 0;
        if (VirtualProtect((void*)(ik + IK_ACCESS_FLAGS), 4, PAGE_READWRITE, &op)) {
            jint oldFlags = *(jint*)(ik + IK_ACCESS_FLAGS);
            *(jint*)(ik + IK_ACCESS_FLAGS) = oldFlags | JVM_ACC_HIDDEN;
            VirtualProtect((void*)(ik + IK_ACCESS_FLAGS), 4, op, &op);
            fprintf(stderr, "[TZD] ghost_class: HIDDEN set on ik=0x%llx (0x%x->0x%x)\n",
                    ik, oldFlags, oldFlags | JVM_ACC_HIDDEN);
            fflush(stderr);
        }

        // Read the Class mirror from IK._java_mirror (OopHandle = oop*).
        // When g_handle_indir=true, jobject is also oop*, so the OopHandle
        // IS a valid jobject handle. When g_handle_indir=false, jobject IS
        // the oop, so we pass the raw oop.
        if (!detect_klass_offset_gc(env)) {
            log_msg("ghost_class: can't detect _klass_offset for mirror creation");
        } else {
            long long oopHandle = rq((void*)(ik + IK_JAVA_MIRROR));
            long long classOop = rq((void*)oopHandle);
            jobject ref = nullptr;
            if (g_handle_indir && oopHandle) {
                // OopHandle (oop*) is a valid jobject handle
                ref = env->NewLocalRef((jobject)oopHandle);
            } else if (classOop) {
                // Direct: jobject IS the oop
                ref = env->NewLocalRef((jobject)classOop);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (ref) {
                fprintf(stderr, "[TZD] ghost_class: COMPLETE (mode B, NewLocalRef mirror)\n");
                fflush(stderr);
                for (int i = 0; i < cf.cp_count - 1; i++) if (cf.cp[i].utf8) free(cf.cp[i].utf8);
                for (int i = 0; i < cf.method_count; i++) if (cf.methods[i].code) free((void*)cf.methods[i].code);
                return (jclass)ref;
            }
        }
        // Fallback: use FindClass just to create a JNI reference
        // (class is already loaded, FindClass doesn't load anything new)
        fprintf(stderr, "[TZD] ghost_class: NewLocalRef failed, using FindClass for reference\n");
        fflush(stderr);
        foundJcls = env->FindClass(userClassName);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (foundJcls) {
            fprintf(stderr, "[TZD] ghost_class: COMPLETE (mode B, FindClass ref)\n");
            fflush(stderr);
            for (int i = 0; i < cf.cp_count - 1; i++) if (cf.cp[i].utf8) free(cf.cp[i].utf8);
            for (int i = 0; i < cf.method_count; i++) if (cf.methods[i].code) free((void*)cf.methods[i].code);
            return foundJcls;
        }
        log_msg("ghost_class: found IK but can't create jclass reference");
    }

    // ── Mode C: class not found — create from scratch (NO JVM API) ──
    fprintf(stderr, "[TZD] ghost_class: class not found, creating from scratch\n");
    fflush(stderr);

    jclass newCls = create_class_from_scratch_v2(env, bytecodes, &cf, userClassName);

    // Free parsed data
    for (int i = 0; i < cf.cp_count - 1; i++) if (cf.cp[i].utf8) free(cf.cp[i].utf8);
    for (int i = 0; i < cf.method_count; i++) if (cf.methods[i].code) free((void*)cf.methods[i].code);

    if (newCls) {
        fprintf(stderr, "[TZD] ghost_class: COMPLETE (mode C)\n");
        fflush(stderr);
        return newCls;
    }

    log_msg("ghost_class: FAILED (can't find or create class)");
    return nullptr;
}
