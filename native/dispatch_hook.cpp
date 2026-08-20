// Architect: tzdwindows 7
#include "dispatch_hook.h"
#include "jvm_deopt.h"
#include "protect_class.h"
#include "interpreter_hook.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

static void log_msg(const char *m)
{
    fprintf(stderr, "[TZD] %s\n", m);
    fflush(stderr);
}

// ─── Constants ───────────────────────────────────────────────────────
static const int NUM_STATES = 10;
static const int TABLE_LENGTH = 256;
static const int TABLE_SIZE = NUM_STATES * TABLE_LENGTH * 8; // 20480
static const int TOS_FTOS = 6;
static const int TOS_ITOS = 4;
static const int TOS_LTOS = 5;
static const int TOS_DTOS = 7;
static const int TOS_ATOS = 8;
static const int TOS_VTOS = 9;
static const int FRAME_METHOD_OFFSET = -24;

// Bytecode opcodes for return instructions
static const int OP_IRETURN = 0xAC;
static const int OP_LRETURN = 0xAD;
static const int OP_FRETURN = 0xAE;
static const int OP_DRETURN = 0xAF;
static const int OP_ARETURN = 0xB0;
static const int OP_RETURN = 0xB1;

// ─── State ──────────────────────────────────────────────────────────
static bool g_inited = false;
static bool g_dispatch_mode = false;
static CRITICAL_SECTION g_cs;
static bool g_csInited = false;

static long long g_active_table = 0;
static long long g_normal_table = 0;
static long long g_safept_table = 0;
static long long g_orig_freturn = 0;
static long long g_orig_ireturn = 0;
static void *g_freturn_stub = nullptr;
static void *g_ireturn_stub = nullptr;
static bool g_freturn_patched = false;
static bool g_ireturn_patched = false;

// jvm.dll image range
static long long g_jvm_base = 0;
static long long g_jvm_end = 0;

enum RetType
{
    RET_FLOAT = 0,
    RET_INT = 1,
    RET_VOID = 2,
    RET_LONG = 3,
    RET_DOUBLE = 4,
    RET_OBJECT = 5,
    RET_OTHER = 6
};

struct HookEntry
{
    long long methodPtr;
    RetType retType;
    long long origFromInterp;
    long long origFromCompiled;
    void *stubPage;
    bool useFallback;
    long long retValueBits; // 存储目标方法的实际返回值比特位
};
static std::vector<HookEntry> g_hooks;

// ─── Helpers ─────────────────────────────────────────────────────────
static long long rq(void *a)
{
    if (!a)
        return 0;
    if (!jvm_safe_read(a, 8))
        return 0;
    return *(long long *)a;
}

static bool is_executable(long long val)
{
    if (val < 0x10000LL || val > 0x7FFFFFFFFFFFLL)
        return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void *)val, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool is_code_cache_ptr(long long val)
{
    if (!is_executable(val))
        return false;
    if (g_jvm_base && val >= g_jvm_base && val < g_jvm_end)
        return false;
    return true;
}

static void init_jvm_range()
{
    if (g_jvm_base)
        return;
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
        return;
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (GetModuleInformation(GetCurrentProcess(), hJvm, &mi, sizeof(mi)))
    {
        g_jvm_base = (long long)mi.lpBaseOfDll;
        g_jvm_end = g_jvm_base + (long long)mi.SizeOfImage;
    }
}

// ─── Find the dispatch table via code pattern scan ───────────────────
static long long find_dispatch_subtable()
{
    HMODULE hJvm = GetModuleHandleA("jvm.dll");
    if (!hJvm)
        return 0;
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (!GetModuleInformation(GetCurrentProcess(), hJvm, &mi, sizeof(mi)))
        return 0;
    unsigned char *base = (unsigned char *)mi.lpBaseOfDll;
    DWORD size = mi.SizeOfImage;

    for (DWORD off = 3; off + 1 < size; off++)
    {
        unsigned char *p = base + off;
        bool hasRex = false;
        unsigned char *jmpStart = nullptr;

        if (off >= 2 && p[-2] == 0x41 && p[-1] == 0xFF && p[0] == 0x24)
        {
            hasRex = true;
            jmpStart = p - 2;
        }
        else if (p[-1] == 0xFF && p[0] == 0x24)
        {
            hasRex = false;
            jmpStart = p - 1;
        }
        else
            continue;

        unsigned char sib = *(jmpStart + (hasRex ? 3 : 2));
        if ((sib & 0xF8) != 0xD8)
            continue;

        long long tableAddr = 0;
        for (int back = 7; back <= 20; back++)
        {
            if (jmpStart - base < (DWORD)back)
                break;
            unsigned char *lp = jmpStart - back;
            if (back >= 7 && (lp[0] == 0x4C || lp[0] == 0x48) && lp[1] == 0x8D)
            {
                unsigned char modrm = lp[2];
                if ((modrm & 0xC7) == 0x05)
                {
                    int disp32;
                    memcpy(&disp32, lp + 3, 4);
                    tableAddr = (long long)(intptr_t)(lp + 7) + disp32;
                    break;
                }
            }
            if (back >= 10 && (lp[0] == 0x49 || lp[0] == 0x48) && (lp[1] & 0xF8) == 0xB8)
            {
                memcpy(&tableAddr, lp + 2, 8);
                break;
            }
        }
        if (!tableAddr)
            continue;

        long long frEntry = rq((void *)(tableAddr + OP_FRETURN * 8));
        long long irEntry = rq((void *)(tableAddr + OP_IRETURN * 8));
        long long nopEntry = rq((void *)(tableAddr));
        if (!is_code_cache_ptr(frEntry))
            continue;
        if (!is_code_cache_ptr(irEntry))
            continue;
        if (!is_code_cache_ptr(nopEntry))
            continue;
        if (frEntry == irEntry)
            continue;

        fprintf(stderr, "[TZD] dispatch_hook: found subtable at 0x%llx (off=0x%x)\n",
                tableAddr, (int)(off - (hasRex ? 2 : 1)));
        fflush(stderr);
        return tableAddr;
    }

    fprintf(stderr, "[TZD] dispatch_hook: code scan failed, trying data scan...\n");
    fflush(stderr);

    for (DWORD off = 0; off + TABLE_SIZE <= size; off += 8)
    {
        unsigned char *p = base + off;
        long long first = rq(p);
        if (!is_code_cache_ptr(first))
            continue;

        long long fr = rq((void *)(p + OP_FRETURN * 8));
        long long ir = rq((void *)(p + OP_IRETURN * 8));
        if (!is_code_cache_ptr(fr) || !is_code_cache_ptr(ir))
            continue;
        if (fr == ir)
            continue;

        int valid = 0;
        for (int i = 0; i < 256; i++)
        {
            long long v = rq((void *)(p + i * 8));
            if (v && is_code_cache_ptr(v))
                valid++;
        }
        if (valid < 205)
            continue;

        fprintf(stderr, "[TZD] dispatch_hook: data scan found table at 0x%llx (valid=%d/256)\n",
                (long long)(intptr_t)p, valid);
        fflush(stderr);
        return (long long)(intptr_t)p;
    }
    return 0;
}

static long long derive_active_table(long long subTable)
{
    if (!subTable)
        return 0;
    for (int state = 0; state < NUM_STATES; state++)
    {
        long long candidate = subTable - (long long)state * (TABLE_LENGTH * 8);
        long long fr = rq((void *)(candidate + TOS_FTOS * TABLE_LENGTH * 8 + OP_FRETURN * 8));
        long long ir = rq((void *)(candidate + TOS_ITOS * TABLE_LENGTH * 8 + OP_IRETURN * 8));
        if (is_code_cache_ptr(fr) && is_code_cache_ptr(ir) && fr != ir)
        {
            fprintf(stderr, "[TZD] dispatch_hook: _active_table=0x%llx (state=%d)\n",
                    candidate, state);
            fflush(stderr);
            return candidate;
        }
    }
    if (is_code_cache_ptr(rq((void *)(subTable + TOS_FTOS * TABLE_LENGTH * 8 + OP_FRETURN * 8))) && is_code_cache_ptr(rq((void *)(subTable + TOS_ITOS * TABLE_LENGTH * 8 + OP_IRETURN * 8))))
    {
        fprintf(stderr, "[TZD] dispatch_hook: using table directly as _active_table=0x%llx\n", subTable);
        fflush(stderr);
        return subTable;
    }
    return 0;
}

static bool patch_table_entry(long long tableBase, int state, int opcode, long long newHandler)
{
    long long addr = tableBase + (long long)state * (TABLE_LENGTH * 8) + (long long)opcode * 8;
    if (!jvm_safe_read((void *)addr, 8))
        return false;
    DWORD op = 0;
    if (!VirtualProtect((void *)addr, 8, PAGE_READWRITE, &op))
        return false;
    *(long long *)addr = newHandler;
    VirtualProtect((void *)addr, 8, op, &op);
    return true;
}

static long long read_table_entry(long long tableBase, int state, int opcode)
{
    return rq((void *)(tableBase + (long long)state * (TABLE_LENGTH * 8) + (long long)opcode * 8));
}

// ─── Dynamic Return Value Extractor via JNI ──────────────────────────
// 动态调用一次目标方法（假设为静态），获取其预期的返回值，避免硬编码 0/null
static long long get_method_constant_return_value(JNIEnv *env, jobject method, RetType rt)
{
    if (!env || !method)
        return 0;

    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (!methodCls)
        return 0;

    jmethodID invokeMethod = env->GetMethodID(methodCls, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (!invokeMethod)
        return 0;

    jobject resultObj = env->CallObjectMethod(method, invokeMethod, nullptr, nullptr);
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
        return 0; // 若执行失败，安全退回到 0
    }
    if (!resultObj)
        return 0;

    long long bits = 0;
    if (rt == RET_FLOAT)
    {
        jclass floatCls = env->FindClass("java/lang/Float");
        jmethodID floatValue = env->GetMethodID(floatCls, "floatValue", "()F");
        jfloat f = env->CallFloatMethod(resultObj, floatValue);
        union
        {
            float f;
            int i;
        } u;
        u.f = f;
        bits = u.i;
        env->DeleteLocalRef(floatCls);
    }
    else if (rt == RET_DOUBLE)
    {
        jclass doubleCls = env->FindClass("java/lang/Double");
        jmethodID doubleValue = env->GetMethodID(doubleCls, "doubleValue", "()D");
        jdouble d = env->CallDoubleMethod(resultObj, doubleValue);
        union
        {
            double d;
            long long l;
        } u;
        u.d = d;
        bits = u.l;
        env->DeleteLocalRef(doubleCls);
    }
    else if (rt == RET_INT)
    {
        jclass numCls = env->FindClass("java/lang/Number");
        jmethodID intValue = env->GetMethodID(numCls, "intValue", "()I");
        bits = env->CallIntMethod(resultObj, intValue);
        env->DeleteLocalRef(numCls);
    }
    else if (rt == RET_LONG)
    {
        jclass numCls = env->FindClass("java/lang/Number");
        jmethodID longValue = env->GetMethodID(numCls, "longValue", "()J");
        bits = env->CallLongMethod(resultObj, longValue);
        env->DeleteLocalRef(numCls);
    }
    else if (rt == RET_OBJECT)
    {
        bits = (long long)(intptr_t)env->NewGlobalRef(resultObj);
    }

    env->DeleteLocalRef(resultObj);
    return bits;
}

// ─── Dynamic x64 Stub Generator ─────────────────────────────────────
// 修正：支持多方法差异化返回值加载，不再一律清零。
// 汇编结构：
//   mov r11, [rbp-24]                ; 获取当前栈帧的 Method*
//   cmp r11, [rip+disp_method_i]     ; 与存储的各个 Method* 依次对比
//   je  override_i
//   jmp [rip+disp_orig]              ; 无匹配，跳回正常流程
// override_i:
//   mov rax/movss/movsd [rip+disp_val_i] ; 载入对应的动态返回值
//   jmp [rip+disp_orig]
static void *generate_stub(std::vector<long long> &methods, long long origHandler, RetType rt)
{
    int N = (int)methods.size();
    if (N == 0)
        return nullptr;

    int checkSize = 13;                                                      // cmp r11, [rip+disp] (7) + je override_i (6)
    int noMatchSize = 6;                                                     // jmp [rip+disp_orig]
    int overrideBlockSize = (rt == RET_FLOAT || rt == RET_DOUBLE) ? 14 : 13; // movss/movsd (8) 或 mov rax (7) + jmp (6)

    int totalCodeSize = 4 + N * checkSize + noMatchSize + N * overrideBlockSize;
    int dataMethodsOffset = totalCodeSize;
    int dataValuesOffset = dataMethodsOffset + N * 8;
    int dataOrigOffset = dataValuesOffset + N * 8;
    int totalSize = dataOrigOffset + 8;

    void *page = VirtualAlloc(nullptr, ((totalSize + 4095) & ~4095),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page)
        return nullptr;

    unsigned char *code = (unsigned char *)page;
    int pos = 0;

    // 1. mov r11, [rbp-24]  -> 4C 8B 5D E8
    code[pos++] = 0x4C;
    code[pos++] = 0x8B;
    code[pos++] = 0x5D;
    code[pos++] = (unsigned char)(FRAME_METHOD_OFFSET & 0xFF);

    // 2. 方法对比循环 (Checks)
    for (int i = 0; i < N; i++)
    {
        // cmp r11, [rip + disp_method_i] -> 4C 3B 1D xx xx xx xx
        int cmpNext = pos + 7;
        int targetMethodData = dataMethodsOffset + i * 8;
        int dispMethod = targetMethodData - cmpNext;
        code[pos++] = 0x4C;
        code[pos++] = 0x3B;
        code[pos++] = 0x1D;
        memcpy(code + pos, &dispMethod, 4);
        pos += 4;

        // je override_i -> 0F 84 xx xx xx xx
        int jeNext = pos + 6;
        int targetOverrideCode = 4 + N * checkSize + noMatchSize + i * overrideBlockSize;
        int dispOverride = targetOverrideCode - jeNext;
        code[pos++] = 0x0F;
        code[pos++] = 0x84;
        memcpy(code + pos, &dispOverride, 4);
        pos += 4;
    }

    // 3. 无匹配默认跳转: jmp [rip + disp_orig] -> FF 25 xx xx xx xx
    int noMatchNext = pos + 6;
    int dispOrigNoMatch = dataOrigOffset - noMatchNext;
    code[pos++] = 0xFF;
    code[pos++] = 0x25;
    memcpy(code + pos, &dispOrigNoMatch, 4);
    pos += 4;

    // 4. 重写分支块 (Overrides)
    for (int i = 0; i < N; i++)
    {
        int targetValData = dataValuesOffset + i * 8;

        if (rt == RET_FLOAT)
        {
            // movss xmm0, [rip + disp_val_i] -> F3 0F 10 05 xx xx xx xx (8 bytes)
            int loadNext = pos + 8;
            int dispVal = targetValData - loadNext;
            code[pos++] = 0xF3;
            code[pos++] = 0x0F;
            code[pos++] = 0x10;
            code[pos++] = 0x05;
            memcpy(code + pos, &dispVal, 4);
            pos += 4;
        }
        else if (rt == RET_DOUBLE)
        {
            // movsd xmm0, [rip + disp_val_i] -> F2 0F 10 05 xx xx xx xx (8 bytes)
            int loadNext = pos + 8;
            int dispVal = targetValData - loadNext;
            code[pos++] = 0xF2;
            code[pos++] = 0x0F;
            code[pos++] = 0x10;
            code[pos++] = 0x05;
            memcpy(code + pos, &dispVal, 4);
            pos += 4;
        }
        else
        {
            // mov rax, [rip + disp_val_i] -> 48 8B 05 xx xx xx xx (7 bytes)
            int loadNext = pos + 7;
            int dispVal = targetValData - loadNext;
            code[pos++] = 0x48;
            code[pos++] = 0x8B;
            code[pos++] = 0x05;
            memcpy(code + pos, &dispVal, 4);
            pos += 4;
        }

        // jmp [rip + disp_orig] -> FF 25 xx xx xx xx (6 bytes)
        int jmpNext = pos + 6;
        int dispOrig = dataOrigOffset - jmpNext;
        code[pos++] = 0xFF;
        code[pos++] = 0x25;
        memcpy(code + pos, &dispOrig, 4);
        pos += 4;
    }

    // 5. 填充数据段
    // 填充 Method*
    for (int i = 0; i < N; i++)
    {
        memcpy(code + pos, &methods[i], 8);
        pos += 8;
    }
    // 填充动态返回值 Bits
    for (int i = 0; i < N; i++)
    {
        long long valBits = 0;
        for (auto &h : g_hooks)
        {
            if (h.methodPtr == methods[i])
            {
                valBits = h.retValueBits;
                break;
            }
        }
        memcpy(code + pos, &valBits, 8);
        pos += 8;
    }
    // 填充原方法处理器地址
    memcpy(code + pos, &origHandler, 8);
    pos += 8;

    FlushInstructionCache(GetCurrentProcess(), page, totalSize);
    return page;
}

static void rebuild_stub_for_type(RetType rt)
{
    std::vector<long long> methods;
    for (auto &h : g_hooks)
        if (h.retType == rt)
            methods.push_back(h.methodPtr);

    int opcode, tosState;
    void **stubPtr;
    bool *patchedFlag;
    long long *origHandler;

    switch (rt)
    {
    case RET_FLOAT:
        opcode = OP_FRETURN;
        tosState = TOS_FTOS;
        stubPtr = &g_freturn_stub;
        patchedFlag = &g_freturn_patched;
        origHandler = &g_orig_freturn;
        break;
    case RET_INT:
        opcode = OP_IRETURN;
        tosState = TOS_ITOS;
        stubPtr = &g_ireturn_stub;
        patchedFlag = &g_ireturn_patched;
        origHandler = &g_orig_ireturn;
        break;
    default:
        return;
    }

    if (methods.empty())
    {
        if (*patchedFlag && g_active_table)
        {
            patch_table_entry(g_active_table, tosState, opcode, *origHandler);
            if (g_normal_table)
                patch_table_entry(g_normal_table, tosState, opcode, *origHandler);
            if (g_safept_table)
                patch_table_entry(g_safept_table, tosState, opcode, *origHandler);
            *patchedFlag = false;
        }
        if (*stubPtr)
        {
            VirtualFree(*stubPtr, 0, MEM_RELEASE);
            *stubPtr = nullptr;
        }
        return;
    }

    void *old = *stubPtr;
    *stubPtr = generate_stub(methods, *origHandler, rt);
    if (!*stubPtr)
    {
        *stubPtr = old;
        return;
    }
    if (old)
        VirtualFree(old, 0, MEM_RELEASE);

    if (g_active_table)
        patch_table_entry(g_active_table, tosState, opcode, (long long)(intptr_t)*stubPtr);
    if (g_normal_table)
        patch_table_entry(g_normal_table, tosState, opcode, (long long)(intptr_t)*stubPtr);
    if (g_safept_table)
        patch_table_entry(g_safept_table, tosState, opcode, (long long)(intptr_t)*stubPtr);
    *patchedFlag = true;
}

static void *make_entry_stub(RetType rt)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page)
        return nullptr;
    unsigned char *c = (unsigned char *)page;
    int p = 0;
    switch (rt)
    {
    case RET_FLOAT:
    case RET_DOUBLE:
        c[p++] = 0x0F;
        c[p++] = 0x57;
        c[p++] = 0xC0;
        c[p++] = 0xC3;
        break;
    case RET_INT:
    case RET_LONG:
    case RET_OBJECT:
        c[p++] = 0x33;
        c[p++] = 0xC0;
        c[p++] = 0xC3;
        break;
    case RET_VOID:
        c[p++] = 0xC3;
        break;
    default:
        c[p++] = 0xC3;
        break;
    }
    return page;
}

static bool install_entry_stub(long long methodPtr, RetType rt)
{
    void *stub = make_entry_stub(rt);
    if (!stub)
        return false;
    int offFI = jvm_deopt_get_offset("from_interp");
    int offFC = jvm_deopt_get_offset("from_compiled");
    if (offFI < 0 || offFC < 0)
    {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    long long origFI = rq((void *)(methodPtr + offFI));
    long long origFC = rq((void *)(methodPtr + offFC));
    jvm_force_interpreter(methodPtr);

    DWORD op = 0;
    if (!VirtualProtect((void *)methodPtr, 256, PAGE_READWRITE, &op))
    {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }
    long long addr = (long long)(intptr_t)stub;
    *(long long *)(methodPtr + offFI) = addr;
    *(long long *)(methodPtr + offFC) = addr;
    VirtualProtect((void *)methodPtr, 256, op, &op);
    FlushInstructionCache(GetCurrentProcess(), (void *)methodPtr, 256);

    for (auto &h : g_hooks)
    {
        if (h.methodPtr == methodPtr)
        {
            h.origFromInterp = origFI;
            h.origFromCompiled = origFC;
            h.stubPage = stub;
            h.useFallback = true;
            break;
        }
    }
    fprintf(stderr, "[TZD] dispatch_hook: entry-stub installed method=0x%llx rt=%d\n", methodPtr, rt);
    fflush(stderr);
    return true;
}

static bool remove_entry_stub(long long methodPtr)
{
    for (auto &h : g_hooks)
    {
        if (h.methodPtr == methodPtr && h.useFallback)
        {
            int offFI = jvm_deopt_get_offset("from_interp");
            int offFC = jvm_deopt_get_offset("from_compiled");
            DWORD op = 0;
            if (VirtualProtect((void *)methodPtr, 256, PAGE_READWRITE, &op))
            {
                if (offFI >= 0)
                    *(long long *)(methodPtr + offFI) = h.origFromInterp;
                if (offFC >= 0)
                    *(long long *)(methodPtr + offFC) = h.origFromCompiled;
                VirtualProtect((void *)methodPtr, 256, op, &op);
                FlushInstructionCache(GetCurrentProcess(), (void *)methodPtr, 256);
            }
            if (h.stubPage)
                VirtualFree(h.stubPage, 0, MEM_RELEASE);
            return true;
        }
    }
    return false;
}

static RetType detect_ret_type(JNIEnv *env, jobject method)
{
    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (!methodCls)
        return RET_OTHER;
    jmethodID getRT = env->GetMethodID(methodCls, "getReturnType", "()Ljava/lang/Class;");
    env->DeleteLocalRef(methodCls);
    if (!getRT)
        return RET_OTHER;

    jclass rt = (jclass)env->CallObjectMethod(method, getRT);
    if (!rt || env->ExceptionCheck())
    {
        if (env->ExceptionCheck())
            env->ExceptionClear();
        return RET_OTHER;
    }

    jclass classCls = env->FindClass("java/lang/Class");
    jmethodID getName = env->GetMethodID(classCls, "getName", "()Ljava/lang/String;");
    env->DeleteLocalRef(classCls);
    if (!getName)
    {
        env->DeleteLocalRef(rt);
        return RET_OTHER;
    }

    jstring rtName = (jstring)env->CallObjectMethod(rt, getName);
    if (!rtName || env->ExceptionCheck())
    {
        if (env->ExceptionCheck())
            env->ExceptionClear();
        env->DeleteLocalRef(rt);
        return RET_OTHER;
    }
    const char *nameStr = env->GetStringUTFChars(rtName, nullptr);

    RetType result = RET_OTHER;
    if (strcmp(nameStr, "float") == 0)
        result = RET_FLOAT;
    else if (strcmp(nameStr, "double") == 0)
        result = RET_DOUBLE;
    else if (strcmp(nameStr, "int") == 0)
        result = RET_INT;
    else if (strcmp(nameStr, "long") == 0)
        result = RET_LONG;
    else if (strcmp(nameStr, "short") == 0 || strcmp(nameStr, "byte") == 0 ||
             strcmp(nameStr, "char") == 0 || strcmp(nameStr, "boolean") == 0)
        result = RET_INT;
    else if (strcmp(nameStr, "void") == 0)
        result = RET_VOID;
    else
        result = RET_OBJECT;

    env->ReleaseStringUTFChars(rtName, nameStr);
    env->DeleteLocalRef(rtName);
    env->DeleteLocalRef(rt);
    return result;
}

// ─── Public API ──────────────────────────────────────────────────────
bool dispatch_hook_init(JNIEnv *env)
{
    if (!g_csInited)
    {
        InitializeCriticalSection(&g_cs);
        g_csInited = true;
    }
    if (g_inited)
        return true;
    g_inited = true;
    init_jvm_range();
    jvm_deopt_init(env);

    long long subTable = find_dispatch_subtable();
    if (subTable)
    {
        g_active_table = derive_active_table(subTable);
        if (g_active_table)
        {
            g_normal_table = g_active_table + TABLE_SIZE;
            g_safept_table = g_active_table + 2 * TABLE_SIZE;
            if (!is_code_cache_ptr(read_table_entry(g_normal_table, TOS_FTOS, OP_FRETURN)))
                g_normal_table = 0;
            if (!is_code_cache_ptr(read_table_entry(g_safept_table, TOS_FTOS, OP_FRETURN)))
                g_safept_table = 0;
            g_orig_freturn = read_table_entry(g_active_table, TOS_FTOS, OP_FRETURN);
            g_orig_ireturn = read_table_entry(g_active_table, TOS_ITOS, OP_IRETURN);
            if (!is_code_cache_ptr(g_orig_freturn) || !is_code_cache_ptr(g_orig_ireturn) || g_orig_freturn == g_orig_ireturn)
            {
                fprintf(stderr, "[TZD] dispatch_hook: orig handlers invalid, disabling dispatch mode\n");
                fflush(stderr);
                g_active_table = 0;
                g_normal_table = 0;
                g_safept_table = 0;
                g_dispatch_mode = false;
            }
            else
            {
                g_dispatch_mode = true;
                fprintf(stderr, "[TZD] dispatch_hook: DISPATCH MODE active=0x%llx normal=0x%llx "
                                "safept=0x%llx fr=0x%llx ir=0x%llx\n",
                        g_active_table, g_normal_table, g_safept_table, g_orig_freturn, g_orig_ireturn);
                fflush(stderr);
            }
        }
    }
    if (!g_dispatch_mode)
    {
        fprintf(stderr, "[TZD] dispatch_hook: dispatch table NOT found — entry-point stub mode\n");
        fflush(stderr);
    }
    return true;
}

bool dispatch_hook_freturn(JNIEnv *env, long long src, long long tgt)
{
    if (!env || !src || !tgt)
        return false;
    if (!g_inited)
        dispatch_hook_init(env);

    EnterCriticalSection(&g_cs);
    for (auto &h : g_hooks)
    {
        if (h.methodPtr == src)
        {
            LeaveCriticalSection(&g_cs);
            return true;
        }
    }

    RetType rt = detect_ret_type(env, (jobject)tgt);
    // 动态提取目标方法返回值的底层二进制位
    long long retValBits = get_method_constant_return_value(env, (jobject)tgt, rt);

    fprintf(stderr, "[TZD] dispatch_hook: install src=0x%llx rt=%d val=0x%llx mode=%s\n",
            src, rt, retValBits, g_dispatch_mode ? "dispatch" : "fallback");
    fflush(stderr);

    HookEntry he;
    memset(&he, 0, sizeof(he));
    he.methodPtr = src;
    he.retType = rt;
    he.retValueBits = retValBits;
    he.useFallback = false; // 初始设为 false，回退路径中会被改为 true
    g_hooks.push_back(he);

    bool ok = false;
    if (g_dispatch_mode && (rt == RET_FLOAT || rt == RET_INT))
    {
        if (rt == RET_FLOAT)
            rebuild_stub_for_type(RET_FLOAT);
        else
            rebuild_stub_for_type(RET_INT);
        ok = true;
    }
    else
    {
        int ihRetType;
        switch (rt)
        {
        case RET_FLOAT:
            ihRetType = 0;
            break;
        case RET_DOUBLE:
            ihRetType = 1;
            break;
        case RET_INT:
            ihRetType = 2;
            break;
        case RET_LONG:
            ihRetType = 3;
            break;
        case RET_OBJECT:
            ihRetType = 4;
            break;
        case RET_VOID:
            ihRetType = 5;
            break;
        default:
            ihRetType = 5;
            break;
        }
        // 修正点 1：将动态返回值 retValBits 传入，不再写死 0
        ok = interp_hook_stub(src, ihRetType, retValBits);
        if (!ok)
        {
            g_hooks.pop_back();
        }
        else
        {
            // 修正点 2：标记成功回退，以保证后续 remove 动作可以正确恢复字节码
            g_hooks.back().useFallback = true;
        }
    }

    LeaveCriticalSection(&g_cs);
    return ok;
}

bool dispatch_hook_remove(long long src)
{
    if (!src || !g_csInited)
        return false;
    EnterCriticalSection(&g_cs);

    bool found = false;
    RetType rt = RET_OTHER;
    bool wasFallback = false;
    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it)
    {
        if (it->methodPtr == src)
        {
            rt = it->retType;
            wasFallback = it->useFallback;
            if (wasFallback)
            {
                // 成功触发：移除由 interp_hook_stub 修改的字节码，恢复原样
                interp_hook_remove(src);
            }
            g_hooks.erase(it);
            found = true;
            break;
        }
    }
    if (found && !wasFallback && g_dispatch_mode)
    {
        if (rt == RET_FLOAT)
            rebuild_stub_for_type(RET_FLOAT);
        else if (rt == RET_INT)
            rebuild_stub_for_type(RET_INT);
    }
    LeaveCriticalSection(&g_cs);
    return found;
}