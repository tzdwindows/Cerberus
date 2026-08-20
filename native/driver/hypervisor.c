// Architect: tzdwindows 7
// hypervisor.c: Thin Hypervisor (Intel VT-x + EPT) — Fix Final
#include <ntddk.h>
#include <intrin.h>

// ─── 不可用内联函数的机器码 stub ───────────────────────────────────────
static unsigned char g_vmxon_code[] = {
    0x48, 0x89, 0xC8,       // mov rax, rcx
    0xF3, 0x0F, 0xC7, 0x30, // vmxon [rax]
    0x0F, 0x92, 0xC0,       // setb al
    0xC3};
static unsigned char g_vmxoff_code[] = {
    0x0F, 0x01, 0xC4, // vmxoff
    0x0F, 0x92, 0xC0, // setb al   (CF=1 → al=1，即失败)
    0xC3};
static unsigned char g_invept_code[] = {
    0x66, 0x0F, 0x38, 0x80, 0x0A, // invept rcx, [rdx]
    0x0F, 0x92, 0xC0,             // setb al  (CF=1 → invept 失败)
    0xC3};

static unsigned char g_sgdt_code[] = {0x0F, 0x01, 0x01, 0xC3}; // sgdt [rcx]; ret
static unsigned char g_sidt_code[] = {0x0F, 0x01, 0x09, 0xC3}; // sidt [rcx]; ret

typedef unsigned char (*vmxon_fn)(void *);
typedef unsigned char (*vmxoff_fn)(void);
typedef unsigned char (*invept_fn)(ULONG64 type, void *descriptor);
static invept_fn g_invept = NULL;
typedef void (*store_dt_fn)(void *);
static ULONG_PTR NTAPI hv_ipi_arm_callback(ULONG_PTR context);
static volatile LONG g_hv_armed_cpu_count = 0;
typedef struct _GUEST_REGS
{
    ULONG64 r15;
    ULONG64 r14;
    ULONG64 r13;
    ULONG64 r12;
    ULONG64 r11;
    ULONG64 r10;
    ULONG64 r9;
    ULONG64 r8;
    ULONG64 rdi;
    ULONG64 rsi;
    ULONG64 rbp;
    ULONG64 rdx;
    ULONG64 rcx;
    ULONG64 rbx;
    ULONG64 rax;
} GUEST_REGS, *PGUEST_REGS;

typedef struct
{
    ULONG64 eptp;
    ULONG64 rsvd;
} INVEPT_DESC;

typedef struct
{
    ULONG32 index;
    ULONG32 rsvd;
    ULONG64 value;
} MSR_LIST_ENTRY;

static vmxon_fn g_vmxon = NULL;
static vmxoff_fn g_vmxoff = NULL;
static store_dt_fn g_sgdt = NULL;
static store_dt_fn g_sidt = NULL;
static PVOID g_ept_pd_pool = NULL;
static PVOID g_ept_restricted_pd_pool = NULL;
static PVOID g_hypercall_page = NULL;

static void *alloc_exec_stub(const unsigned char *code, SIZE_T len)
{
    PVOID va = ExAllocatePoolWithTag(NonPagedPoolExecute, len, 'TZDH');
    if (!va)
        return NULL;
    RtlCopyMemory(va, code, len);
    return va;
}

// ─── 常量 ──────────────────────────────────────────────────────────────
#define IA32_FEATURE_CONTROL_MSR 0x3A
#define IA32_VMX_BASIC_MSR 0x480
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS 0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS 0x490
#define CR4_VMXE_BIT 13
#define EPT_RWX 7u
#define EPT_LP (1u << 7)

#pragma pack(push, 1)
typedef struct
{
    USHORT limit;
    ULONG64 base;
} DT_STATE;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct
{
    USHORT cs;
    USHORT ss;
    USHORT ds;
    USHORT es;
    USHORT fs;
    USHORT gs;
} SEG_SELS;
#pragma pack(pop)

// ─── Per-CPU 状态 ─────────────────────────────────────────────────────
#define MAX_CPUS 64
typedef struct
{
    void *vmxon_region;
    PHYSICAL_ADDRESS vmxon_pa;
    void *vmcs_region;
    PHYSICAL_ADDRESS vmcs_pa;
    void *host_stack;
    BOOLEAN vmx_active;
    MSR_LIST_ENTRY *msr_list;
    PHYSICAL_ADDRESS msr_list_pa;
    DT_STATE gdt_state;
    DT_STATE idt_state;
    ULONG64 tr_base;
    BOOLEAN tr_base_valid;
} VMX_CPU_STATE;

static VMX_CPU_STATE g_vmx_cpu[MAX_CPUS] = {0};
volatile BOOLEAN g_hv_fallback_vmxoff_done[MAX_CPUS] = {0};
volatile ULONG g_hv_step[MAX_CPUS] = {0};
volatile LONG g_hv_abort = 0;
// ★ 诊断全局 (handler 写, WinDbg dd 看; 不用 DbgPrint, VMX root 下 DbgPrint 死锁 spin lock)
volatile ULONG g_hv_last_exit_reason = 0;
volatile ULONG64 g_hv_last_exit_rip = 0;
volatile LONG64 g_hv_exit_count = 0;

// ★ vmresume 诊断 (asm 写; WinDbg dd 看; vmresume 卡 = count 增但 post=0)
volatile LONG g_hv_vmresume_count = 0;
volatile LONG g_hv_post_vmresume = 0; // 1 = vmresume 失败(到 fail path)
// ★ 异常诊断：拦截 #UD(6)/#CP(21) 后，记录最后一个异常的向量与故障 RIP
volatile ULONG g_hv_last_exc_vec = 0;
volatile ULONG64 g_hv_last_exc_rip = 0;
volatile ULONG g_hv_last_exc_err = 0;
volatile LONG g_hv_exc_count = 0;

typedef struct
{
    ULONG64 entry;
} EPT_PTE;

static EPT_PTE *g_ept_pdpt = NULL;
static EPT_PTE *g_ept_pml4 = NULL;
static ULONG64 g_eptp = 0;
static ULONG g_ept_pml4_entries_built = 0;
static PVOID g_msr_bitmap = NULL;
static PVOID g_io_bitmap_a = NULL;
static PVOID g_io_bitmap_b = NULL;

static PVOID g_apic_mmio_va = NULL;
static ULONG g_msr_list_count = 0;
static BOOLEAN g_vmx_enabled = FALSE;
static ULONG g_vmx_revision_id = 0;

static EPT_PTE *g_ept_restricted_pdpt = NULL;
static EPT_PTE *g_ept_restricted_pml4 = NULL;

static volatile LONG g_hv_disarmed_cpu_count = 0;
static volatile LONG g_hv_disarm_fail_count = 0;

extern unsigned char AsmVmLaunch(void);
extern void AsmExitHandler(void);
extern USHORT AsmGetTr(void);
extern void AsmGetSegmentSelectors(SEG_SELS *sels);

volatile ULONG g_hv_vminstr_err[MAX_CPUS] = {0};
volatile UCHAR g_hv_launch_result[MAX_CPUS] = {0}; // 0=未跑, 1=fail, 2=success

// ═══════════════════════════════════════════════════════════════════════
// ─── Phase 3: 被武装进程状态 + EPT 控制 ──────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static volatile ULONG g_hv_armed_pid = 0;
static volatile ULONG64 g_hv_armed_cr3 = 0;
static volatile ULONG64 g_hv_jvm_base = 0;
static volatile SIZE_T g_hv_jvm_size = 0;
static volatile LONG g_hv_compromised = 0;

#define EXIT_REASON_EPT_VIOLATION 48
#define EXIT_REASON_CR_ACCESS 28
#define EXIT_REASON_MTF 37
#define EXIT_REASON_RDTSCP 16

#define GUEST_PHYSICAL_ADDR 0x2400u
#define EXIT_QUALIFICATION 0x6400u
#define VM_EXIT_INSTR_LEN 0x440Cu
#define VM_EXIT_INTERRUPTION_INFO 0x4404u
#define VM_EXIT_INTERRUPTION_ERROR 0x4406u
#define VM_ENTRY_INTERRUPTION_INFO 0x4016u
#define VM_ENTRY_EXCEPTION_ERROR 0x4018u
// ★ GUEST_LINEAR_ADDRESS: EPT violation 时提供导致违规的线性地址(GVA)
//   Exit Qualification bit7=1 时有效。用于区分"写 JIT 代码缓存" vs 其他写。
#define GUEST_LINEAR_ADDRESS 0x06C0u
// ★ EPT Violation Exit Qualification 位定义
//   bit0=read, bit1=write, bit2=instruction fetch, bit7=gla valid
#define EPT_VIOL_QUAL_READ 0x1u
#define EPT_VIOL_QUAL_WRITE 0x2u
#define EPT_VIOL_QUAL_INST 0x4u
#define EPT_VIOL_QUAL_GVA_VALID 0x80u
// ★ EPT 页表项权限位: bit0=R, bit1=W, bit2=X
//   EPT_RWX=7, EPT_RX=5 (read+execute, 无 write — 用于 JIT 写保护)
#define EPT_RX 5u

static ULONG64 g_eptp_restricted = 0;
static volatile BOOLEAN g_hv_in_restricted_mode = FALSE;

static volatile BOOLEAN g_hv_mtf_pending = FALSE;
static volatile ULONG64 g_hv_mtf_page_va = 0;

// ═════════════════════════════════════════════════════════════════════════
// ─── Phase 4: JIT 代码缓存写保护 (区分 JIT 合法写 vs 恶意篡改) ──────────────
//   JDK20 HotSpot 代码缓存行为 (E:\jdk20u-master 源码确认):
//   • 代码缓存永久 PAGE_EXECUTE_READWRITE (os_windows.cpp:3476), 永不翻 RX
//   • JVM 用直接指针写修改代码缓存 (nativeInst_x86.hpp:86 set_int_at),
//     不调 VirtualProtect — 故写者 RIP 必在 jvm.dll/java.exe 原生代码段内
//   • JIT 编译的 Java 应用代码(含 Unsafe.putByte)的 RIP 在代码缓存内, 不在
//     JVM 原生段 — 可据此区分合法 JIT 补丁 vs 恶意篡改
//   • 代码缓存有 3 个堆 (NonNMethod/Profiled/NonProfiled), 可注册多个范围
//   合法写: RIP ∈ JVM 原生段 → 允许 (MTF 单步: 临时 RWX → 写 → 恢复 R-X)
//   恶意写: RIP ∉ JVM 原生段 → 阻止 (跳过写指令, 设 compromised)
// ═════════════════════════════════════════════════════════════════════════
#define MAX_JIT_RANGES 8
static volatile ULONG64 g_hv_jit_gva_base[MAX_JIT_RANGES] = {0};
static volatile ULONG64 g_hv_jit_gva_size[MAX_JIT_RANGES] = {0};
static volatile LONG g_hv_jit_range_count = 0;

// JVM 原生写者范围 (jvm.dll / java.exe 代码段; JIT 编译器/IC 补丁的 RIP 必在此内)
static volatile ULONG64 g_hv_jvm_writer_base = 0;
static volatile SIZE_T g_hv_jvm_writer_size = 0;

// JIT 篡改检测与统计
static volatile LONG g_hv_jit_tampered = 0;     // 1 = 检测到非 JVM 写 JIT
static volatile LONG64 g_hv_jit_tamper_rip = 0; // 被阻止写者的 RIP
static volatile LONG64 g_hv_jit_tamper_va = 0;  // 被写的 JIT GVA
static volatile LONG g_hv_jit_blocks = 0;       // 累计阻止写次数
static volatile LONG g_hv_jit_allows = 0;       // 累计允许 JVM 写次数

// ─── 工具 ──────────────────────────────────────────────────────────────

static ULONG get_ept_mem_type_for_2mb(ULONG64 phys_2mb_base)
{
    ULONG64 phys_2mb_end = phys_2mb_base + (2 * 1024 * 1024);
    ULONG64 apic_base = __readmsr(0x1B) & 0xFFFFF000ULL;
    if (phys_2mb_base <= apic_base && apic_base < phys_2mb_end)
        return 0; // UC
    if (phys_2mb_base < 0xFF000000ULL && phys_2mb_end > 0xFEC00000ULL)
        return 0;

    // ★ 3. 低 1MB 以上、真正物理内存範囲以外的空洞(PCI BAR、显卡/NVMe MMIO 等)
    //    用 MmGetPhysicalMemoryRanges() 拿真实 RAM 区间,不在范围内的一律 UC
    static PHYSICAL_MEMORY_RANGE *ranges = NULL;
    if (!ranges)
        ranges = MmGetPhysicalMemoryRanges(); // 只探测一次,缓存结果

    BOOLEAN is_ram = FALSE;
    if (ranges)
    {
        for (int i = 0; ranges[i].BaseAddress.QuadPart != 0 || ranges[i].NumberOfBytes.QuadPart != 0; i++)
        {
            ULONG64 base = (ULONG64)ranges[i].BaseAddress.QuadPart;
            ULONG64 size = (ULONG64)ranges[i].NumberOfBytes.QuadPart;
            if (phys_2mb_base >= base && phys_2mb_end <= base + size)
            {
                is_ram = TRUE;
                break;
            }
        }
    }

    return is_ram ? 6 : 0; // RAM 用 WB, 其余一律 UC(宁可保守也别错标 WB)
}

static BOOLEAN safe_clear_cr4_vmxe(void)
{
    BOOLEAN ok = TRUE;
    __try
    {
        __writecr4(__readcr4() & ~(1ULL << CR4_VMXE_BIT));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 常见于嵌套虚拟化环境：L0 不允许清除 VMXE，
        // 这不是致命错误——保留 VMXE=1，后续不再尝试 VMXON 即可
        ok = FALSE;
    }
    return ok;
}

// ★ 新增：现场给指定 GPA 所在的 2MB 页在 g_ept_pml4 里建立/修正恒等映射。
//   只处理"entry 不存在"的情况(PML4/PDPT 缺失或 PD entry present=0)，
//   不处理"存在但权限不足"的情况(那种应视为真正的越权访问)。
static BOOLEAN ept_try_fixup_2mb(ULONG64 gpa)
{
    ULONG pml4_idx = (ULONG)((gpa >> 39) & 0x1FF);
    ULONG pdpt_idx = (ULONG)((gpa >> 30) & 0x1FF);
    ULONG pd_idx = (ULONG)((gpa >> 21) & 0x1FF);

    if (pml4_idx >= g_ept_pml4_entries_built || !g_ept_pml4[pml4_idx].entry)
        return FALSE; // 超出了 arm 阶段预建的范围，判定为真正异常访问

    EPT_PTE *pdpt = (EPT_PTE *)((PUCHAR)g_ept_pdpt + pml4_idx * PAGE_SIZE);
    EPT_PTE *pd = (EPT_PTE *)((PUCHAR)g_ept_pd_pool +
                              (pml4_idx * 512ULL + pdpt_idx) * PAGE_SIZE);

    if (pd[pd_idx].entry & 1) // 已经是 present，说明不是"缺失映射"问题
        return FALSE;

    ULONG64 pfn = (pml4_idx * 512ULL * 512ULL) + (pdpt_idx * 512ULL) + pd_idx;
    ULONG64 phys_base = pfn << 21;
    ULONG mem_type = get_ept_mem_type_for_2mb(phys_base);
    pd[pd_idx].entry = (pfn << 21) | EPT_RWX | EPT_LP | ((ULONG64)mem_type << 3);
    return TRUE;
}

static BOOLEAN hv_already_virtualized(void)
{
    int info[4] = {0};
    __cpuid(info, 1);
    if (!(info[2] & (1u << 31))) // ECX bit31 = hypervisor-present
        return FALSE;

    int hv_info[4] = {0};
    __cpuid(hv_info, 0x40000000);
    char sig[13] = {0};
    RtlCopyMemory(sig, &hv_info[1], 4);
    RtlCopyMemory(sig + 4, &hv_info[2], 4);
    RtlCopyMemory(sig + 8, &hv_info[3], 4);

    DbgPrint("[tzd-hv] 检测到本机已运行在另一个 Hypervisor 之下: vendor=\"%s\"\n", sig);
    DbgPrint("[tzd-hv] 这通常意味着 Windows 的 Hyper-V / VBS / 内存完整性(HVCI) 已启用，"
             "VT-x 已被占用，本驱动的 VMXON 将必然失败。\n");
    return TRUE;
}

// ★ 新增：单 context INVEPT，修改 EPT entry 后必须调用，否则各核心的
//   EPT TLB(缓存的 GPA→HPA 翻译)可能还是旧值，导致映射修复了但依然读到
//   脏数据/依然 violation，这也是一种会被误判为"随机性卡死"的原因。
static void invept_single_context(ULONG64 eptp)
{
    INVEPT_DESC desc = {eptp, 0};
    if (g_invept)
        g_invept(1 /* single-context */, &desc); // type=1
}

// ★ 限制 EPT 刷新 (restricted EPT 专用)
static void invept_restricted(void)
{
    if (g_invept && g_eptp_restricted)
    {
        INVEPT_DESC desc = {g_eptp_restricted, 0};
        g_invept(1, &desc);
    }
}

// ★ 检查 GVA 是否在已注册的 JIT 代码缓存范围内
//   JDK 代码缓存有 3 个堆 (NonNMethod/Profiled/NonProfiled), 注册为多个 GVA 范围
static BOOLEAN hv_gva_in_jit_range(ULONG64 gva)
{
    LONG count = g_hv_jit_range_count;
    for (LONG i = 0; i < count && i < MAX_JIT_RANGES; i++)
    {
        ULONG64 base = g_hv_jit_gva_base[i];
        ULONG64 size = g_hv_jit_gva_size[i];
        if (base != 0 && gva >= base && gva < base + size)
            return TRUE;
    }
    return FALSE;
}

// ★ 检查 RIP 是否为合法的 JVM 原生写者
//   JDK20 HotSpot 的 JIT 补丁 (set_int_at / Atomic::store / set_destination_mt_safe)
//   均从 JVM 原生代码(jvm.dll/java.exe 代码段)发起, RIP 必在以下范围内:
//   1. g_hv_jvm_writer_base (用户显式设置的 JVM 写者范围, 精确到 jvm.dll 代码段)
//   2. g_hv_jvm_base (armed process 的整体 JVM 范围, 回退)
//
//   ★★ 三层检查 (修复 Unsafe.putByte + JIT 内部函数 误判) ★★
//   1. RIP 在 JIT 代码缓存范围内 → 拒绝 (JIT 编译代码不是 JVM 原生写者)
//      覆盖: JIT 编译的 Java 代码直接 MOV 写代码缓存 / JIT 内部函数调用修改
//      原理: 合法 JIT 补丁(set_int_at 等)的 RIP 在 jvm.dll, 不在代码缓存
//   2. RIP 在 JVM 原生范围(jvm.dll) → 允许, 但标记脏页待周期扫描验证
//      覆盖: Unsafe.putByte 的原生实现 Unsafe.c 在 jvm.dll 内 → RIP 通过检查
//      但写的内容可能非 JIT → 由 tzd_is_jit_code 内容校验捕获 (周期扫描层)
//   3. RIP 在其他位置 → 拒绝 (shellcode / 内核 / 匿名区)
static BOOLEAN hv_is_legitimate_jvm_writer(ULONG64 rip)
{
    // ★ 层 1: RIP 在 JIT 代码缓存范围内 → 拒绝
    //   JIT 编译代码 (RIP 在代码缓存) 写代码缓存 = 非法:
    //   - Unsafe.putByte 从 JIT 编译的 Java 代码发起 (call 进 JNI 前 RIP 在代码缓存)
    //   - JIT 内部函数直接 MOV 写代码缓存 (自修改代码)
    //   合法 JIT 补丁的写者 RIP 永远在 jvm.dll, 不在代码缓存
    if (hv_gva_in_jit_range(rip))
        return FALSE;

    // ★ 层 2: RIP 在 JVM 原生范围 → 允许 (但可能含 Unsafe.putByte, 由扫描层验证)
    // 优先检查精确的 JVM 写者范围
    if (g_hv_jvm_writer_base != 0 && g_hv_jvm_writer_size != 0)
    {
        if (rip >= g_hv_jvm_writer_base &&
            rip < g_hv_jvm_writer_base + g_hv_jvm_writer_size)
            return TRUE;
    }
    // 回退: 检查整体 JVM 范围 (armed process 设置的 jvmBase/jvmSize)
    //   注意: 若 jvmBase/jvmSize 涵盖了代码缓存, 层 1 已先行拒绝代码缓存内 RIP
    if (g_hv_jvm_base != 0 && g_hv_jvm_size != 0)
    {
        if (rip >= g_hv_jvm_base &&
            rip < g_hv_jvm_base + (ULONG64)g_hv_jvm_size)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN safe_vmxoff(void)
{
    BOOLEAN failed = TRUE;
    __try
    {
        unsigned char cf = g_vmxoff();
        failed = (cf != 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        failed = TRUE; // VMXOFF 指令自身就 #GP 了，同样按失败处理
    }
    return !failed;
}

static void *alloc_page(PHYSICAL_ADDRESS *out_pa)
{
    PHYSICAL_ADDRESS zero = {0}, max;
    max.QuadPart = (LONGLONG)-1;
    PVOID va = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, zero, max, zero, MmCached);
    if (!va)
        return NULL;
    RtlZeroMemory(va, PAGE_SIZE);
    if (out_pa)
        *out_pa = MmGetPhysicalAddress(va);
    return va;
}

static ULONG32 get_segment_ar(ULONG64 gdt_base, USHORT selector)
{
    if ((selector & ~3) == 0)
        return 0x10000; // Null 选择子必须置位 Unusable (Bit 16)

    PUCHAR d = (PUCHAR)(gdt_base + (selector & ~7));
    // d[5] 包含 P, DPL, S, Type；d[6] 的高 4 位包含 G, D/B, L, AVL
    ULONG32 ar = d[5] | ((d[6] & 0xF0) << 8);

    // 如果是 Type=9 (Available 64-bit TSS)，强制修正为 Type=11 (Busy)
    // 虚拟化环境要求 TR 必须是 Busy 状态
    if ((ar & 0x1F) == 0x09)
    {
        ar |= 0x02;
    }
    return ar;
}

static ULONG32 get_segment_limit(ULONG64 gdt_base, USHORT selector)
{
    if ((selector & ~3) == 0)
        return 0;

    PUCHAR d = (PUCHAR)(gdt_base + (selector & ~7));
    ULONG32 limit = d[0] | (d[1] << 8) | ((d[6] & 0x0F) << 16);

    if (d[6] & 0x80) // 检查 Granularity (G) 位是否为 1
    {
        limit = (limit << 12) | 0xFFF;
    }
    return limit;
}

static BOOLEAN vmx_prepare_cpu_resources(ULONG cpu)
{
    if (cpu >= MAX_CPUS)
        return FALSE;
    VMX_CPU_STATE *s = &g_vmx_cpu[cpu];

    if (!s->vmxon_region)
    {
        s->vmxon_region = alloc_page(&s->vmxon_pa);
        if (!s->vmxon_region)
            return FALSE;
        *(ULONG *)s->vmxon_region = g_vmx_revision_id;
    }

    if (!s->vmcs_region)
    {
        s->vmcs_region = alloc_page(&s->vmcs_pa);
        if (!s->vmcs_region)
            return FALSE;
        *(ULONG *)s->vmcs_region = g_vmx_revision_id;
    }

    if (!s->host_stack)
    {
        s->host_stack = ExAllocatePoolWithTag(NonPagedPool, 1024 * 32 + 16, 'TZHS');
        if (!s->host_stack)
            return FALSE;
    }

    return TRUE;
}

static NTSTATUS vmx_prepare_all_cpu_resources(void)
{
    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (count > MAX_CPUS)
        count = MAX_CPUS;

    for (ULONG cpu = 0; cpu < count; cpu++)
    {
        PROCESSOR_NUMBER proc_num;
        GROUP_AFFINITY new_affinity = {0}, old_affinity;

        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(cpu, &proc_num)))
            return STATUS_UNSUCCESSFUL;

        new_affinity.Group = proc_num.Group;
        new_affinity.Mask = (KAFFINITY)1 << proc_num.Number;

        // 切到目标核，PASSIVE_LEVEL 下分配，这里内存管理器调用是合法的
        KeSetSystemGroupAffinityThread(&new_affinity, &old_affinity);

        VMX_CPU_STATE *s = &g_vmx_cpu[cpu];
        if (!s->vmxon_region)
            s->vmxon_region = alloc_page(&s->vmxon_pa);
        if (!s->vmcs_region)
            s->vmcs_region = alloc_page(&s->vmcs_pa);
        if (!s->host_stack)
            s->host_stack = ExAllocatePoolWithTag(NonPagedPool, 1024 * 32 + 16, 'TZHS');

        if (!s->tr_base_valid)
        {
            g_sgdt(&s->gdt_state);
            g_sidt(&s->idt_state);

            USHORT tr_sel = AsmGetTr(); // ★ 使用汇编实现的 AsmGetTr()
            s->tr_base = 0;
            __try
            {
                PUCHAR d = (PUCHAR)(s->gdt_state.base + (tr_sel & ~7));

                ULONG64 base0_23 = (ULONG64)d[2] | ((ULONG64)d[3] << 8) | ((ULONG64)d[4] << 16);
                ULONG64 base24_31 = (ULONG64)d[7] << 24; // 包含了之前漏掉的 d[7]
                ULONG64 base32_63 = (ULONG64) * (ULONG32 *)(d + 8) << 32;

                s->tr_base = base0_23 | base24_31 | base32_63;
                s->tr_base_valid = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                s->tr_base_valid = FALSE;
            }
        }

        KeRevertToUserGroupAffinityThread(&old_affinity);

        if (!s->vmxon_region || !s->vmcs_region || !s->host_stack || !s->tr_base_valid)
        {
            DbgPrint("[tzd-hv] prepare resources FAILED cpu=%u\n", cpu);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return STATUS_SUCCESS;
}

static ULONG64 get_vmx_msr(ULONG basic_msr, ULONG true_msr)
{
    ULONG64 vmx_basic = __readmsr(IA32_VMX_BASIC_MSR);
    // 判断 Bit 55 是否支持 True MSR
    if (vmx_basic & (1ULL << 55))
        return __readmsr(true_msr);
    return __readmsr(basic_msr);
}

static void free_page(void *va)
{
    if (va)
        MmFreeContiguousMemory(va);
}

// ─── EPT ───────────────────────────────────────────────────────────────
static BOOLEAN ept_create_identity_map(void)
{
    int info[4];
    __cpuid(info, 0x80000008);
    ULONG phys_bits = info[0] & 0xFF;
    if (phys_bits == 0 || phys_bits > 52)
        phys_bits = 48; // 保守兜底

    // 每个 PML4 entry 覆盖 512GB；总共需要覆盖 2^phys_bits 字节
    ULONG64 total_span = (phys_bits >= 39) ? (1ULL << phys_bits) : (1ULL << 39);
    ULONG pml4_entries_needed = (ULONG)((total_span + (512ULL * 1024 * 1024 * 1024 - 1)) / (512ULL * 1024 * 1024 * 1024));
    if (pml4_entries_needed > 512)
        pml4_entries_needed = 512;
    if (pml4_entries_needed < 1)
        pml4_entries_needed = 1;
    g_ept_pml4_entries_built = pml4_entries_needed;
    g_ept_pml4 = (EPT_PTE *)alloc_page(NULL);
    if (!g_ept_pml4)
        return FALSE;

    // ★ 关键改动：PDPT 和 PD 池按需要的 PML4 entry 数量整体放大，
    //   而不是只建 1 份 PDPT（原来的 512GB 硬上限就是这里来的）
    g_ept_pdpt = (EPT_PTE *)ExAllocatePoolWithTag(NonPagedPool, pml4_entries_needed * PAGE_SIZE, 'TZEQ');
    g_ept_pd_pool = ExAllocatePoolWithTag(NonPagedPool, pml4_entries_needed * 512ULL * PAGE_SIZE, 'TZEP');
    if (!g_ept_pdpt || !g_ept_pd_pool)
        return FALSE;

    RtlZeroMemory(g_ept_pdpt, pml4_entries_needed * PAGE_SIZE);
    RtlZeroMemory(g_ept_pd_pool, pml4_entries_needed * 512ULL * PAGE_SIZE);

    for (ULONG p4 = 0; p4 < pml4_entries_needed; p4++)
    {
        EPT_PTE *pdpt = (EPT_PTE *)((PUCHAR)g_ept_pdpt + p4 * PAGE_SIZE);
        PHYSICAL_ADDRESS pdpt_pa = MmGetPhysicalAddress(pdpt);
        g_ept_pml4[p4].entry = (pdpt_pa.QuadPart & 0xFFFFFFFFF000ULL) | EPT_RWX;

        for (int i = 0; i < 512; i++)
        {
            EPT_PTE *pd = (EPT_PTE *)((PUCHAR)g_ept_pd_pool + (p4 * 512ULL + i) * PAGE_SIZE);
            PHYSICAL_ADDRESS pd_pa = MmGetPhysicalAddress(pd);
            pdpt[i].entry = (pd_pa.QuadPart & 0xFFFFFFFFF000ULL) | EPT_RWX;

            for (int j = 0; j < 512; j++)
            {
                ULONG64 pfn = (p4 * 512ULL * 512ULL) + (i * 512ULL) + j;
                ULONG64 phys_base = pfn << 21;
                ULONG mem_type = get_ept_mem_type_for_2mb(phys_base);
                pd[j].entry = (pfn << 21) | EPT_RWX | EPT_LP | ((ULONG64)mem_type << 3);
            }
        }
    }

    PHYSICAL_ADDRESS pml4_pa = MmGetPhysicalAddress(g_ept_pml4);
    g_eptp = 6 | (3 << 3) | (pml4_pa.QuadPart & 0xFFFFFFFFF000ULL);

    DbgPrint("[tzd-hv] EPT 覆盖 %u 个 PML4 entry (~%llu GB) eptp=0x%llx\n",
             pml4_entries_needed, (ULONG64)pml4_entries_needed * 512, g_eptp);
    return TRUE;
}

static BOOLEAN alloc_bitmaps(void)
{
    g_msr_bitmap = alloc_page(NULL);
    g_io_bitmap_a = alloc_page(NULL);
    g_io_bitmap_b = alloc_page(NULL);
    if (!g_msr_bitmap || !g_io_bitmap_a || !g_io_bitmap_b)
        return FALSE;

    RtlFillMemory(g_msr_bitmap, PAGE_SIZE, 0x00);
    RtlFillMemory(g_io_bitmap_a, PAGE_SIZE, 0x00);
    RtlFillMemory(g_io_bitmap_b, PAGE_SIZE, 0x00);

    DbgPrint("[tzd-hv] bitmaps OK (msr/io all-permit)\n");
    return TRUE;
}

// ─── VMX 检测 ─────────────────────────────────────────────────────────
static BOOLEAN vmx_detect(void)
{
    int info[4];
    __cpuid(info, 1);
    if (!((info[2] >> 5) & 1))
    {
        DbgPrint("[tzd-hv] vmx_detect FAILED: CPUID.1:ECX.VMX flag not present!\n");
        return FALSE;
    }

    if (hv_already_virtualized())
    {
        DbgPrint("[tzd-hv] vmx_detect FAILED: 检测到已有 Hypervisor 运行，"
                 "请先关闭 Hyper-V/VBS/内存完整性后重启再试。\n");
        return FALSE;
    }

    ULONG64 fc = __readmsr(IA32_FEATURE_CONTROL_MSR);
    if (!(fc & 1))
    {
        fc |= (1ULL << 2) | 1;
        __writemsr(IA32_FEATURE_CONTROL_MSR, fc);
    }
    else if (!((fc >> 2) & 1))
    {
        DbgPrint("[tzd-hv] vmx_detect FAILED: IA32_FEATURE_CONTROL MSR locked without VMX enabled! Check BIOS settings.\n");
        return FALSE;
    }

    g_vmx_revision_id = (ULONG)(__readmsr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFF);
    DbgPrint("[tzd-hv] VMX rev=0x%x\n", g_vmx_revision_id);
    return TRUE;
}

// ─── VMXON/VMXOFF (stub) ──────────────────────────────────────────────
static BOOLEAN vmx_vmxon_cpu(void)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= MAX_CPUS)
        return FALSE;
    VMX_CPU_STATE *s = &g_vmx_cpu[cpu];

    if (!s->vmxon_region)
        return FALSE;

    __writecr4(__readcr4() | (1ULL << CR4_VMXE_BIT));

    if (g_vmxon(&s->vmxon_pa))
    {
        __writecr4(__readcr4() & ~(1ULL << CR4_VMXE_BIT));
        return FALSE;
    }
    s->vmx_active = TRUE;
    return TRUE;
}

static BOOLEAN vmx_vmxoff_cpu(void)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= MAX_CPUS)
        return FALSE;
    VMX_CPU_STATE *s = &g_vmx_cpu[cpu];
    if (!s->vmx_active)
        return TRUE;

    BOOLEAN off_ok = TRUE;
    if (!g_hv_fallback_vmxoff_done[cpu])
    {
        off_ok = safe_vmxoff();
        DbgPrint("[tzd-hv] VMXOFF %s cpu %u\n", off_ok ? "OK" : "FAILED(#GP捕获)", cpu);
    }
    else
    {
        g_hv_fallback_vmxoff_done[cpu] = FALSE;
    }

    if (!off_ok)
        return FALSE;

    s->vmx_active = FALSE;
    if (s->vmxon_region)
    {
        free_page(s->vmxon_region);
        s->vmxon_region = NULL;
        s->vmxon_pa.QuadPart = 0; // ★ 增加：清空 PA
    }
    if (s->vmcs_region)
    {
        free_page(s->vmcs_region);
        s->vmcs_region = NULL;
        s->vmcs_pa.QuadPart = 0; // ★ 增加：清空 PA
    }
    if (s->host_stack)
    {
        ExFreePool(s->host_stack); // ★ 修正：ExAllocatePoolWithTag 对应的正确释放函数是 ExFreePool
        s->host_stack = NULL;
    }

    if (!safe_clear_cr4_vmxe())
    {
        DbgPrint("[tzd-hv] 警告: cpu %u 清除CR4.VMXE被拒绝。\n", cpu);
    }
    else
    {
        DbgPrint("[tzd-hv] VMXOFF+CR4清除 cpu %u 完成\n", cpu);
    }

    return TRUE;
}

// ─── VMCS 字段编码 ─────────────────────────────────────────────────────
#define G_CR0 0x6800u
#define G_CR3 0x6802u
#define G_CR4 0x6804u
#define G_DR7 0x681Au
#define G_RIP 0x681Eu
#define G_RSP 0x681Cu
#define G_RFLAGS 0x6820u
#define G_CS_SEL 0x0802u
#define G_SS_SEL 0x0804u
#define G_DS_SEL 0x0806u
#define G_ES_SEL 0x0800u
#define G_FS_SEL 0x0808u
#define G_GS_SEL 0x080Au
#define G_TR_SEL 0x080Eu
#define G_LDTR_SEL 0x080Cu
#define G_ES_BASE 0x6806u
#define G_CS_BASE 0x6808u
#define G_SS_BASE 0x680Au
#define G_DS_BASE 0x680Cu
#define G_FS_BASE 0x680Eu
#define G_GS_BASE 0x6810u
#define G_LDTR_BASE 0x6812u
#define G_TR_BASE 0x6814u
#define G_GDTR_B 0x6816u
#define G_IDTR_B 0x6818u
#define G_CS_LIM 0x4802u
#define G_SS_LIM 0x4804u
#define G_DS_LIM 0x4806u
#define G_ES_LIM 0x4800u
#define G_FS_LIM 0x4808u
#define G_GS_LIM 0x480Au
#define G_TR_LIM 0x480Eu
#define G_GDTR_L 0x4810u
#define G_IDTR_L 0x4812u
#define G_CS_AR 0x4816u
#define G_SS_AR 0x4818u
#define G_DS_AR 0x481Au
#define G_ES_AR 0x4814u
#define G_FS_AR 0x481Cu
#define G_GS_AR 0x481Eu
#define G_TR_AR 0x4822u
#define G_LDTR_AR 0x4820u
#define G_SE_CS 0x482Au
#define G_SE_ESP 0x6824u
#define G_SE_EIP 0x6826u
#define H_CR0 0x6C00u
#define H_CR3 0x6C02u
#define H_CR4 0x6C04u
#define H_RSP 0x6C14u
#define H_RIP 0x6C16u
#define H_CS 0x0C02u
#define H_SS 0x0C04u
#define H_DS 0x0C06u
#define H_ES 0x0C00u
#define H_FS 0x0C08u
#define H_GS 0x0C0Au
#define H_TR 0x0C0Cu
#define H_FS_B 0x6C06u
#define H_GS_B 0x6C08u
#define H_TR_B 0x6C0Au
#define H_GDTR 0x6C0Cu
#define H_IDTR 0x6C0Eu
#define H_SE_CS 0x4C00u
#define H_SE_ESP 0x6C10u
#define H_SE_EIP 0x6C12u
#define C_PIN 0x4000u
#define C_PROC 0x4002u
#define C_PROC2 0x401Eu
#define C_EXCBMP 0x4004u
#define C_EXIT 0x400Cu
#define C_ENTRY 0x4012u
#define IO_BITMAP_A 0x2000u
#define IO_BITMAP_B 0x2002u
#define MSR_BITMAP 0x2004u
#define VM_EXIT_MSR_STORE_COUNT 0x400Eu
#define VM_EXIT_MSR_STORE_ADDR 0x2006u
#define VM_ENTRY_MSR_LOAD_COUNT 0x4014u
#define VM_ENTRY_MSR_LOAD_ADDR 0x200Au
#define C_CR0M 0x6000u
#define C_CR4M 0x6002u
#define C_CR0S 0x6004u
#define C_CR4S 0x6006u
#define C_EPTP 0x201Au
#define C_VMERR 0x4400u
#define C_EXIT_REASON 0x4402u
#define MSR_PIN 0x481u
#define MSR_PROC 0x482u
#define MSR_EXIT 0x483u
#define MSR_ENTRY 0x484u
#define MSR_PROC2 0x48Bu
#define MSR_FS 0xC0000100u
#define MSR_GS 0xC0000101u
#define G_VMCS_LINK_PTR 0x2800u
#define CPU_BASED_ENABLE_2ND (1u << 31)
#define CPU_BASED_CR3_LOAD_EXIT (1u << 15)
#define CPU_BASED_USE_MTF (1u << 27)
#define CPU_BASED_USE_IO_BITMAPS (1u << 25)
#define CPU_BASED_USE_MSR_BITMAPS (1u << 28)
#define SEC_EXEC_ENABLE_EPT (1u << 1)
#define CPU_BASED2_RDTSCP (1u << 3)          // secondary: RDTSCP exiting
#define CPU_BASED2_ENABLE_INVPCID (1u << 12) // enable INVPCID —— 之前写成了 bit 11
#define EXIT_CTRL_HOST_ADDR_64 (1u << 9)
#define ENTRY_CTRL_IA32E_MODE (1u << 9)
#define EXC_UD (1u << 6)
#define EXC_DF (1u << 8)
#define EXC_GP (1u << 13)
#define EXC_PF (1u << 14)
#define EXC_CP (1u << 21) // CET 控制流保护异常
#define PIN_BASED_NMI_EXITING (1u << 3)
#define PIN_BASED_VIRTUAL_NMIS (1u << 5)

static BOOLEAN vmw(ULONG64 field, ULONG64 value)
{
    unsigned char r = __vmx_vmwrite((size_t)field, (size_t)value);
    if (r)
    {
        return FALSE;
    }
    return TRUE;
}

static ULONG64 vmr(ULONG64 field)
{
    size_t val = 0;
    __vmx_vmread((size_t)field, &val);
    return (ULONG64)val;
}

static ULONG64 adjust_cr_fixed(ULONG64 cr, ULONG64 fixed0_msr, ULONG64 fixed1_msr)
{
    return (cr & fixed1_msr) | fixed0_msr;
}

static ULONG64 vmx_adjust(ULONG64 msr, ULONG64 desired)
{
    ULONG32 allowed0 = (ULONG32)msr;
    ULONG32 allowed1 = (ULONG32)(msr >> 32);
    return (ULONG64)(allowed0 | ((ULONG32)desired & allowed1));
}

static PULONG64 get_guest_reg_by_index(PGUEST_REGS regs, ULONG reg_idx)
{
    switch (reg_idx)
    {
    case 0:
        return &regs->rax;
    case 1:
        return &regs->rcx;
    case 2:
        return &regs->rdx;
    case 3:
        return &regs->rbx;
    case 4:
        return (PULONG64)NULL; // RSP 由 VMCS G_RSP 管理
    case 5:
        return &regs->rbp;
    case 6:
        return &regs->rsi;
    case 7:
        return &regs->rdi;
    case 8:
        return &regs->r8;
    case 9:
        return &regs->r9;
    case 10:
        return &regs->r10;
    case 11:
        return &regs->r11;
    case 12:
        return &regs->r12;
    case 13:
        return &regs->r13;
    case 14:
        return &regs->r14;
    case 15:
        return &regs->r15;
    default:
        return NULL;
    }
}

// ─── VMCS Setup + VMLAUNCH ─────────────────────────────────────────────
static BOOLEAN vmx_setup_vmcs_and_launch(void)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= MAX_CPUS)
        return FALSE;
    VMX_CPU_STATE *s = &g_vmx_cpu[cpu];

    if (!s->vmcs_region || !s->host_stack)
        return FALSE;

    if (__vmx_vmclear((unsigned __int64 *)&s->vmcs_pa))
        return FALSE;
    if (__vmx_vmptrld((unsigned __int64 *)&s->vmcs_pa))
        return FALSE;

    ULONG64 host_rsp = ((ULONG64)s->host_stack + 1024 * 32 - 0x200) & ~0xFULL;

    ULONG64 cr0 = __readcr0(), cr3 = __readcr3(), cr4 = __readcr4();
    ULONG64 rflags = (__readeflags() | 0x2ULL | 0x200ULL) & ~0x4000ULL;
    ULONG64 fs_base = __readmsr(MSR_FS), gs_base = __readmsr(MSR_GS);

    cr0 = adjust_cr_fixed(cr0, (ULONG32)__readmsr(0x486), (ULONG32)__readmsr(0x487));
    cr4 = adjust_cr_fixed(cr4, (ULONG32)__readmsr(0x488), (ULONG32)__readmsr(0x489));

    // ★ 修复点 1：动态获取当前核正在使用的真实段选择子，千万不能硬编码！
    SEG_SELS sels;
    AsmGetSegmentSelectors(&sels);

    ULONG64 tr = AsmGetTr();
    ULONG64 cs = sels.cs, ss = sels.ss, ds = sels.ds, es = sels.es, fs = sels.fs, gs = sels.gs;

    // Host 态强行保证是 Kernel 选择子 (去掉底部的 RPL 权限位)
    ULONG64 h_cs = cs & ~3, h_ss = ss & ~3, h_tr = tr & ~3;
    ULONG64 h_ds = ds & ~3, h_es = es & ~3, h_fs = fs & ~3, h_gs = gs & ~3;

    // =========================================================================
    // ★ 蓝屏修复：在这个 CPU 核心上现场动态获取 GDT 和 IDT，拒绝使用未初始化的变量
    // =========================================================================
    DT_STATE gdt = {0};
    DT_STATE idt = {0};
    g_sgdt(&gdt);
    g_sidt(&idt);

    // 现场动态解析该核心真正的 TR_BASE
    ULONG64 tr_base = 0;
    if (tr != 0)
    {
        PUCHAR d_tr = (PUCHAR)(gdt.base + (tr & ~7));

        ULONG64 base0_7 = (ULONG64)d_tr[2];
        ULONG64 base8_15 = (ULONG64)d_tr[3] << 8;
        ULONG64 base16_23 = (ULONG64)d_tr[4] << 16;
        ULONG64 base24_31 = (ULONG64)d_tr[7] << 24;
        ULONG64 base32_63 = (ULONG64) * (ULONG32 *)(d_tr + 8) << 32;

        tr_base = base0_7 | base8_15 | base16_23 | base24_31 | base32_63;
    }

    // ----------- Guest state -----------
    if (!vmw(G_CR0, cr0))
        return FALSE;
    if (!vmw(G_CR3, cr3))
        return FALSE;
    if (!vmw(G_CR4, cr4))
        return FALSE;
    if (!vmw(G_DR7, 0x400))
        return FALSE;
    if (!vmw(G_RFLAGS, rflags))
        return FALSE;

    if (!vmw(G_CS_SEL, cs))
        return FALSE;
    if (!vmw(G_SS_SEL, ss))
        return FALSE;
    if (!vmw(G_DS_SEL, ds))
        return FALSE;
    if (!vmw(G_ES_SEL, es))
        return FALSE;
    if (!vmw(G_FS_SEL, fs))
        return FALSE;
    if (!vmw(G_GS_SEL, gs))
        return FALSE;
    if (!vmw(G_TR_SEL, tr))
        return FALSE;

    if (!vmw(G_CS_BASE, 0))
        return FALSE;
    if (!vmw(G_SS_BASE, 0))
        return FALSE;
    if (!vmw(G_DS_BASE, 0))
        return FALSE;
    if (!vmw(G_ES_BASE, 0))
        return FALSE;
    if (!vmw(G_FS_BASE, fs_base))
        return FALSE;
    if (!vmw(G_GS_BASE, gs_base))
        return FALSE;
    if (!vmw(G_TR_BASE, tr_base))
        return FALSE;

    if (!vmw(G_GDTR_B, gdt.base))
        return FALSE;
    if (!vmw(G_IDTR_B, idt.base))
        return FALSE;

    if (!vmw(G_GDTR_L, gdt.limit))
        return FALSE;
    if (!vmw(G_IDTR_L, idt.limit))
        return FALSE;

    // ★ 修复点 2：使用 GDT 动态解析，拒绝硬编码 Limit
    if (!vmw(G_CS_LIM, get_segment_limit(gdt.base, (USHORT)cs)))
        return FALSE;
    if (!vmw(G_SS_LIM, get_segment_limit(gdt.base, (USHORT)ss)))
        return FALSE;
    if (!vmw(G_DS_LIM, get_segment_limit(gdt.base, (USHORT)ds)))
        return FALSE;
    if (!vmw(G_ES_LIM, get_segment_limit(gdt.base, (USHORT)es)))
        return FALSE;
    if (!vmw(G_FS_LIM, get_segment_limit(gdt.base, (USHORT)fs)))
        return FALSE;
    if (!vmw(G_GS_LIM, get_segment_limit(gdt.base, (USHORT)gs)))
        return FALSE;
    if (!vmw(G_TR_LIM, get_segment_limit(gdt.base, (USHORT)tr)))
        return FALSE;

    // ★ 修复点 3：使用 GDT 动态解析，拒绝硬编码 AR 字节，防止 VMware 断言奔溃！
    if (!vmw(G_CS_AR, get_segment_ar(gdt.base, (USHORT)cs)))
        return FALSE;
    if (!vmw(G_SS_AR, get_segment_ar(gdt.base, (USHORT)ss)))
        return FALSE;
    if (!vmw(G_DS_AR, get_segment_ar(gdt.base, (USHORT)ds)))
        return FALSE;
    if (!vmw(G_ES_AR, get_segment_ar(gdt.base, (USHORT)es)))
        return FALSE;
    if (!vmw(G_FS_AR, get_segment_ar(gdt.base, (USHORT)fs)))
        return FALSE;
    if (!vmw(G_GS_AR, get_segment_ar(gdt.base, (USHORT)gs)))
        return FALSE;
    if (!vmw(G_TR_AR, get_segment_ar(gdt.base, (USHORT)tr)))
        return FALSE;

    if (!vmw(G_LDTR_SEL, 0))
        return FALSE;
    if (!vmw(G_LDTR_BASE, 0))
        return FALSE;
    if (!vmw(G_LDTR_AR, 0x10000))
        return FALSE; // 0x10000 = Unusable 标志

    if (!vmw(G_SE_CS, __readmsr(0x174)))
        return FALSE;
    if (!vmw(G_SE_ESP, __readmsr(0x175)))
        return FALSE;
    if (!vmw(G_SE_EIP, __readmsr(0x176)))
        return FALSE;

    // ----------- Host state -----------
    if (!vmw(H_CR0, cr0))
        return FALSE;
    if (!vmw(H_CR3, cr3))
        return FALSE;
    if (!vmw(H_CR4, cr4))
        return FALSE;
    if (!vmw(H_RSP, host_rsp))
        return FALSE;
    if (!vmw(H_RIP, (ULONG64)AsmExitHandler))
        return FALSE;

    if (!vmw(H_CS, h_cs))
        return FALSE;
    if (!vmw(H_SS, h_ss))
        return FALSE;
    if (!vmw(H_DS, h_ds))
        return FALSE;
    if (!vmw(H_ES, h_es))
        return FALSE;
    if (!vmw(H_FS, h_fs))
        return FALSE;
    if (!vmw(H_GS, h_gs))
        return FALSE;
    if (!vmw(H_TR, h_tr))
        return FALSE;

    if (!vmw(H_FS_B, fs_base))
        return FALSE;
    if (!vmw(H_GS_B, gs_base))
        return FALSE;
    if (!vmw(H_TR_B, tr_base))
        return FALSE;
    if (!vmw(H_GDTR, gdt.base))
        return FALSE;
    if (!vmw(H_IDTR, idt.base))
        return FALSE;

    if (!vmw(H_SE_CS, __readmsr(0x174)))
        return FALSE;
    if (!vmw(H_SE_ESP, __readmsr(0x175)))
        return FALSE;
    if (!vmw(H_SE_EIP, __readmsr(0x176)))
        return FALSE;

    if (!vmw(G_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFFULL))
        return FALSE;

    // ----------- Control state -----------
    ULONG64 pin_msr = get_vmx_msr(MSR_PIN, IA32_VMX_TRUE_PINBASED_CTLS);
    if (!vmw(C_PIN, vmx_adjust(pin_msr, PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS)))
        return FALSE;

    ULONG64 proc_msr = get_vmx_msr(MSR_PROC, IA32_VMX_TRUE_PROCBASED_CTLS);
    if (!vmw(C_PROC, vmx_adjust(proc_msr,
                                CPU_BASED_USE_MSR_BITMAPS | CPU_BASED_USE_IO_BITMAPS |
                                    CPU_BASED_ENABLE_2ND)))
        return FALSE;

    if (!vmw(IO_BITMAP_A, MmGetPhysicalAddress(g_io_bitmap_a).QuadPart))
        return FALSE;
    if (!vmw(IO_BITMAP_B, MmGetPhysicalAddress(g_io_bitmap_b).QuadPart))
        return FALSE;
    if (!vmw(MSR_BITMAP, MmGetPhysicalAddress(g_msr_bitmap).QuadPart))
        return FALSE;

    ULONG64 proc2_msr = __readmsr(MSR_PROC2);
    ULONG64 proc2_val = vmx_adjust(proc2_msr, CPU_BASED2_RDTSCP | CPU_BASED2_ENABLE_INVPCID);
    if (!(proc2_val & CPU_BASED2_ENABLE_INVPCID))
    {
        DbgPrint("[tzd-hv] WARNING: CPU 不支持 enable-INVPCID，guest 执行 INVPCID 仍会 #UD\n");
    }
    if (!vmw(C_PROC2, proc2_val))
        return FALSE;
    if (!vmw(C_EXCBMP, EXC_UD | EXC_CP))
        return FALSE;

    if (!vmw(C_CR0M, 0))
        return FALSE;
    if (!vmw(C_CR4M, 0))
        return FALSE;
    if (!vmw(C_CR0S, cr0))
        return FALSE;
    if (!vmw(C_CR4S, cr4))
        return FALSE;

    ULONG64 exit_msr = get_vmx_msr(MSR_EXIT, IA32_VMX_TRUE_EXIT_CTLS);
    if (!vmw(C_EXIT, vmx_adjust(exit_msr, EXIT_CTRL_HOST_ADDR_64)))
        return FALSE;

    ULONG64 entry_msr = get_vmx_msr(MSR_ENTRY, IA32_VMX_TRUE_ENTRY_CTLS);
    if (!vmw(C_ENTRY, vmx_adjust(entry_msr, ENTRY_CTRL_IA32E_MODE)))
        return FALSE;

    unsigned char r = AsmVmLaunch();
    return (r == 0);
}

// ─── Public API ────────────────────────────────────────────────────────
NTSTATUS hypervisor_arm(void)
{
    if (g_vmx_enabled)
        return STATUS_SUCCESS;

    DbgPrint("[tzd-hv] === Arming All CPUs ===\n");

    if (hv_already_virtualized())
    {
        DbgPrint("[tzd-hv] 中止：请先执行\n"
                 "    bcdedit /set hypervisorlaunchtype off\n"
                 "并在 Windows 安全中心 -> 设备安全性 -> 核心隔离 中关闭"
                 "\"内存完整性\"，重启后再加载本驱动。\n");
        return STATUS_HV_ACCESS_DENIED; // 或自定义状态码
    }

    if (!g_vmxon)
        g_vmxon = (vmxon_fn)alloc_exec_stub(g_vmxon_code, sizeof(g_vmxon_code));
    if (!g_vmxoff)
        g_vmxoff = (vmxoff_fn)alloc_exec_stub(g_vmxoff_code, sizeof(g_vmxoff_code));
    if (!g_sgdt)
        g_sgdt = (store_dt_fn)alloc_exec_stub(g_sgdt_code, sizeof(g_sgdt_code));
    if (!g_sidt)
        g_sidt = (store_dt_fn)alloc_exec_stub(g_sidt_code, sizeof(g_sidt_code));
    if (!g_invept)
        g_invept = (invept_fn)alloc_exec_stub(g_invept_code, sizeof(g_invept_code));
    if (!g_vmxon || !g_vmxoff || !g_sgdt || !g_sidt || !g_invept)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (!vmx_detect())
        return STATUS_NOT_SUPPORTED;
    if (!ept_create_identity_map())
        return STATUS_INSUFFICIENT_RESOURCES;
    if (!alloc_bitmaps())
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG total_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (ULONG i = 0; i < total_cpus && i < MAX_CPUS; i++)
    {
        if (!vmx_prepare_cpu_resources(i))
        {
            DbgPrint("[tzd-hv] Failed to pre-allocate memory for CPU %u\n", i);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (!g_hypercall_page)
    {
        g_hypercall_page = alloc_page(NULL);
        if (g_hypercall_page)
        {
            // 填入 vmmcall (0x0F, 0x01, 0xC1) + ret (0xC3)
            PUCHAR p = (PUCHAR)g_hypercall_page;
            p[0] = 0x0F;
            p[1] = 0x01;
            p[2] = 0xC1;
            p[3] = 0xC3;
        }
    }
    if (!g_apic_mmio_va)
    {
        PHYSICAL_ADDRESS apic_pa;
        apic_pa.QuadPart = __readmsr(0x1B) & ~0xFFFULL;
        if (apic_pa.QuadPart == 0)
        {
            apic_pa.QuadPart = 0xFEE00000ULL;
        }
        g_apic_mmio_va = MmMapIoSpace(apic_pa, PAGE_SIZE, MmNonCached);
    }

    InterlockedExchange(&g_hv_armed_cpu_count, 0);

    // ★ 修复：用 KeIpiGenericCall 在所有核上同时 arm。
    //   旧的 affinity 循环（KeSetSystemGroupAffinityThread 紧接着 KeRaiseIrqlToDpcLevel）
    //   不会同步迁移线程——拉到 DPC 后调度器无法抢占，4 次循环全落在同一个核上跑，
    //   实测 vmx_active=[1,0,0,0]、armed_cpu_count=1：只有 BSP 被武装，其余 3 核裸奔。
    //   这造成"1 核 CPUID 被 hide、3 核 CPUID 真实"的分裂态，被 ntoskrnl 的
    //   HalpIsMicrosoftCompatibleHvLoaded(cpuid 0x40000001) 探测到跨核不一致 → bugcheck。
    //   KeIpiGenericCall 在 IPI_LEVEL 把回调在所有核上同时执行，是 per-CPU 武装的标准做法，
    //   不依赖线程迁移。资源已在上方 vmx_prepare_cpu_resources 循环里为每个核预分配好。
    KeIpiGenericCall(hv_ipi_arm_callback, 0);

    if (g_hv_armed_cpu_count == (LONG)total_cpus && total_cpus > 0)
    {
        g_vmx_enabled = TRUE;
        DbgPrint("[tzd-hv] All %u CPUs Armed Successfully!\n", total_cpus);
        return STATUS_SUCCESS;
    }
    else
    {
        DbgPrint("[tzd-hv] VMX Arm Failed! Armed %ld/%u CPUs.\n", g_hv_armed_cpu_count, total_cpus);
        return STATUS_UNSUCCESSFUL;
    }
}

static ULONG_PTR NTAPI hv_ipi_disarm_callback(ULONG_PTR context)
{
    UNREFERENCED_PARAMETER(context);
    if (vmx_vmxoff_cpu())
        InterlockedIncrement(&g_hv_disarmed_cpu_count);
    else
        InterlockedIncrement(&g_hv_disarm_fail_count);
    return 0;
}

void hypervisor_disarm(void)
{
    if (!g_vmx_enabled)
        return;

    ULONG total_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    InterlockedExchange(&g_hv_disarmed_cpu_count, 0);
    InterlockedExchange(&g_hv_disarm_fail_count, 0);

    KeIpiGenericCall(hv_ipi_disarm_callback, 0);

    if (g_hv_disarm_fail_count > 0 || g_hv_disarmed_cpu_count != (LONG)total_cpus)
    {
        DbgPrint("[tzd-hv] disarm 部分失败(%ld/ %u)，保留共享资源\n",
                 g_hv_disarmed_cpu_count, total_cpus);
        return;
    }

    // 释放全局 EPT 与页表资源
    if (g_ept_pml4)
    {
        free_page(g_ept_pml4);
        g_ept_pml4 = NULL;
    }
    if (g_invept)
    {
        ExFreePool(g_invept);
        g_invept = NULL;
    }
    if (g_ept_pdpt)
    {
        free_page(g_ept_pdpt);
        g_ept_pdpt = NULL;
    }
    if (g_ept_pd_pool)
    {
        ExFreePool(g_ept_pd_pool);
        g_ept_pd_pool = NULL;
    }
    if (g_ept_restricted_pml4)
    {
        free_page(g_ept_restricted_pml4);
        g_ept_restricted_pml4 = NULL;
    }
    if (g_ept_restricted_pdpt)
    {
        free_page(g_ept_restricted_pdpt);
        g_ept_restricted_pdpt = NULL;
    }
    if (g_ept_restricted_pd_pool)
    {
        ExFreePool(g_ept_restricted_pd_pool);
        g_ept_restricted_pd_pool = NULL;
    }

    if (g_msr_bitmap)
    {
        free_page(g_msr_bitmap);
        g_msr_bitmap = NULL;
    }
    if (g_io_bitmap_a)
    {
        free_page(g_io_bitmap_a);
        g_io_bitmap_a = NULL;
    }
    if (g_io_bitmap_b)
    {
        free_page(g_io_bitmap_b);
        g_io_bitmap_b = NULL;
    }

    if (g_apic_mmio_va)
    {
        MmUnmapIoSpace(g_apic_mmio_va, PAGE_SIZE);
        g_apic_mmio_va = NULL;
    }

    if (g_vmxon)
    {
        ExFreePool(g_vmxon);
        g_vmxon = NULL;
    }
    if (g_vmxoff)
    {
        ExFreePool(g_vmxoff);
        g_vmxoff = NULL;
    }
    if (g_sgdt)
    {
        ExFreePool(g_sgdt);
        g_sgdt = NULL;
    }
    if (g_sidt)
    {
        ExFreePool(g_sidt);
        g_sidt = NULL;
    }

    // ★ 重置全局 EPTP 与逻辑状态，方便下次二次 arm
    g_ept_pml4_entries_built = 0;
    g_eptp = 0;
    g_eptp_restricted = 0;
    g_hv_in_restricted_mode = FALSE;
    g_hv_armed_pid = 0;
    g_hv_armed_cr3 = 0;
    g_hv_jvm_base = 0;
    g_hv_jvm_size = 0;
    g_hv_jvm_writer_base = 0;
    g_hv_jvm_writer_size = 0;
    g_hv_mtf_pending = FALSE;
    g_hv_mtf_page_va = 0;
    InterlockedExchange(&g_hv_compromised, 0);
    // ★ 清除 JIT 写保护状态
    InterlockedExchange(&g_hv_jit_range_count, 0);
    for (int i = 0; i < MAX_JIT_RANGES; i++)
    {
        g_hv_jit_gva_base[i] = 0;
        g_hv_jit_gva_size[i] = 0;
    }
    InterlockedExchange(&g_hv_jit_tampered, 0);
    InterlockedExchange64(&g_hv_jit_tamper_rip, 0);
    InterlockedExchange64(&g_hv_jit_tamper_va, 0);
    InterlockedExchange(&g_hv_jit_blocks, 0);
    InterlockedExchange(&g_hv_jit_allows, 0);

    InterlockedExchange(&g_hv_abort, 0);
    g_vmx_enabled = FALSE;
    DbgPrint("[tzd-hv] Disarmed (全部 %ld 核确认并完全重置状态)\n", g_hv_disarmed_cpu_count);
}

static ULONG_PTR NTAPI hv_ipi_arm_callback(ULONG_PTR context)
{
    UNREFERENCED_PARAMETER(context);

    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu < MAX_CPUS)
    {
        if (vmx_vmxon_cpu())
        {
            if (vmx_setup_vmcs_and_launch())
            {
                InterlockedIncrement(&g_hv_armed_cpu_count);
            }
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── C Exit Handler (由 AsmExitHandler 调用) ─────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

void hypervisor_exit_handler_c(PGUEST_REGS regs)
{
    // 清空上一轮 VM Entry 注入标志
    __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, 0);

    size_t exit_reason_raw = 0;
    if (__vmx_vmread((size_t)C_EXIT_REASON, &exit_reason_raw) != 0)
        return;

    ULONG exit_reason = (ULONG)(exit_reason_raw & 0xFFFF);

    // 写诊断全局变量
    size_t guest_rip = 0;
    __vmx_vmread((size_t)G_RIP, &guest_rip);
    g_hv_last_exit_reason = exit_reason;
    g_hv_last_exit_rip = guest_rip;
    // g_hv_exit_count++;
    InterlockedIncrement64(&g_hv_exit_count);
    // 防 Exit 风暴
    // if (g_hv_exit_count > 200000)
    //{
    //    if (g_vmxoff)
    //        g_vmxoff();
    //    KeBugCheckEx(0xDEAD0050, (ULONG64)exit_reason, (ULONG64)g_hv_last_exit_rip, (ULONG64)g_hv_exit_count, 0);
    //}

    switch (exit_reason)
    {
    case 0: // Exception or NMI
    {
        size_t info = 0;
        __vmx_vmread((size_t)VM_EXIT_INTERRUPTION_INFO, &info);
        ULONG type = (ULONG)((info >> 8) & 7);
        ULONG vec = (ULONG)(info & 0xFF);

        g_hv_last_exc_vec = vec;
        g_hv_last_exc_rip = guest_rip;
        if (info & (1ULL << 11))
        {
            size_t ec = 0;
            __vmx_vmread((size_t)VM_EXIT_INTERRUPTION_ERROR, &ec);
            g_hv_last_exc_err = (ULONG)ec;
        }
        g_hv_exc_count++;

        if (type == 2) // ★ 新增：NMI，开了 NMI-exiting 后必须自己重新注入回 guest
        {
            ULONG64 inject = (1ULL << 31) | (2ULL << 8) | 2; // type=2 NMI, vector=2
            __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, inject);
            break;
        }

        // 只有硬件/软件异常(3/6)才重新注入
        if ((info & (1ULL << 31)) && (type == 3 || type == 6))
        {
            __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, info & 0x80000FFFULL);
            if (info & (1ULL << 11))
            {
                size_t ec = 0;
                __vmx_vmread((size_t)VM_EXIT_INTERRUPTION_ERROR, &ec);
                __vmx_vmwrite((size_t)VM_ENTRY_EXCEPTION_ERROR, ec);
            }
        }
        break;
    }

    case 1: // External Interrupt (外部中断已被 Host 接收，直接放行)
        break;

    case 10: // CPUID 模拟
    {
        if (regs->rax == 0x13371337)
        {
            regs->rax = 0x545A4448; // 'TZDH'
            regs->rbx = 0x11223344;
            regs->rcx = 0x55667788;
            regs->rdx = 0x99AABBCC;
        }
        else
        {
            int cpu_info[4] = {0};
            ULONG32 leaf = (ULONG32)regs->rax;

            __cpuidex(cpu_info, (int)regs->rax, (int)regs->rcx);

            // ★ 对所有 CPL 一致地隐藏 hypervisor 特征（ring-0 也隐藏）。
            //   关键：必须 4 核一致（Fix1 的 KeIpiGenericCall 保证），否则
            //   HalpIsMicrosoftCompatibleHvLoaded 在不同核返回不同值→跨核不一致→bugcheck。
            //   一致隐藏后，Windows 运行时探测到"无 HV"→回退原生 APIC/INVLPG 路径，
            //   不再使用本驱动未实现的 Hyper-V hypercall/TSC-page 等接口，
            //   从而避免 incomplete-HV 触发的 #UD（曾导致 idle 循环 bugcheck）。
            //   注：不按 CPL 区分——之前 Fix2 对 ring-0 透传会让 Windows 以为有完整 HV，
            //   进而走 HV 路径并触发 #UD。一致隐藏是最安全的折中。
            if (leaf == 1)
            {
                cpu_info[2] &= ~(1u << 31); // 清 hypervisor-present 位
            }
            else if (leaf >= 0x40000000 && leaf <= 0x400000FF)
            {
                cpu_info[0] = 0;
                cpu_info[1] = 0;
                cpu_info[2] = 0;
                cpu_info[3] = 0;
            }
            else if (leaf == 0x80000001)
            {
                // ★ 清 RDTSCP 位(EDX bit27)：VMX non-root 下 RDTSCP 会 #UD
                //   (驱动未启用 secondary controls，RDTSCP 被当不支持)。
                //   清掉后 Windows 若运行时重查 CPUID 会改用 lfence+RDTSC 分支，
                //   不再 RDTSCP→不再 #UD→无 exit 风暴。case0 的 RDTSCP 模拟作兜底。
                cpu_info[3] &= ~(1u << 27);
            }

            regs->rax = (ULONG32)cpu_info[0];
            regs->rbx = (ULONG32)cpu_info[1];
            regs->rcx = (ULONG32)cpu_info[2];
            regs->rdx = (ULONG32)cpu_info[3];
        }

        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 16: // RDTSCP (EXIT_REASON_RDTSCP) — VMX non-root 下 RDTSCP 被拦截
    {
        // ★ 启用 CPU_BASED2_RDTSCP 后，RDTSCP 走 VM-exit(reason16) 而非 #UD。
        //   模拟：rax/rdx = TSC, rcx = IA32_TSC_AUX(MSR 0xC0000103), 步进 RIP 3。
        //   这样不触发 #UD 路径，不需要读 guest 指令字节（避免用户态地址 0xD1）。
        ULONG64 tsc = __rdtsc();
        regs->rax = (ULONG32)(tsc & 0xFFFFFFFFu);
        regs->rdx = (ULONG32)(tsc >> 32);
        regs->rcx = (ULONG32)__readmsr(0xC0000103); // IA32_TSC_AUX
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + 3));
        break;
    }

    case 28: // CR Access 暂不适用
    {
        size_t qual = 0;
        __vmx_vmread((size_t)EXIT_QUALIFICATION, &qual);

        ULONG cr_num = (ULONG)(qual & 0xF);           // 0=CR0, 3=CR3, 4=CR4, 8=CR8
        ULONG access_type = (ULONG)((qual >> 4) & 3); // 0=mov to CR, 1=mov from CR
        ULONG reg_idx = (ULONG)((qual >> 8) & 0xF);   // 通用寄存器索引

        PULONG64 reg_ptr = get_guest_reg_by_index(regs, reg_idx);
        ULONG64 reg_val = 0;

        if (reg_ptr)
        {
            reg_val = *reg_ptr;
        }
        else if (reg_idx == 4) // RSP
        {
            __vmx_vmread((size_t)G_RSP, &reg_val);
        }

        if (cr_num == 3) // CR3 读写
        {
            if (access_type == 0) // mov cr3, reg
            {
                __vmx_vmwrite((size_t)G_CR3, reg_val);

                BOOLEAN is_armed = (g_hv_armed_cr3 != 0 && reg_val == g_hv_armed_cr3);
                if (is_armed && !g_hv_in_restricted_mode)
                {
                    if (g_eptp_restricted)
                    {
                        __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp_restricted);
                        g_hv_in_restricted_mode = TRUE;
                    }
                }
                else if (!is_armed && g_hv_in_restricted_mode)
                {
                    if (g_eptp)
                    {
                        __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp);
                        g_hv_in_restricted_mode = FALSE;
                    }
                }
            }
            else if (access_type == 1) // mov reg, cr3
            {
                ULONG64 guest_cr3 = 0;
                __vmx_vmread((size_t)G_CR3, &guest_cr3);
                if (reg_ptr)
                    *reg_ptr = guest_cr3;
            }
        }
        else if (cr_num == 0) // CR0 读写
        {
            if (access_type == 0)
            {
                ULONG64 new_cr0 = adjust_cr_fixed(reg_val, (ULONG32)__readmsr(0x486), (ULONG32)__readmsr(0x487));
                __vmx_vmwrite((size_t)G_CR0, new_cr0);
            }
            else if (access_type == 1)
            {
                ULONG64 guest_cr0 = 0;
                __vmx_vmread((size_t)G_CR0, &guest_cr0);
                if (reg_ptr)
                    *reg_ptr = guest_cr0;
            }
        }
        else if (cr_num == 4) // CR4 读写
        {
            if (access_type == 0)
            {
                ULONG64 new_cr4 = adjust_cr_fixed(reg_val, (ULONG32)__readmsr(0x488), (ULONG32)__readmsr(0x489));
                __vmx_vmwrite((size_t)G_CR4, new_cr4);
            }
            else if (access_type == 1)
            {
                ULONG64 guest_cr4 = 0;
                __vmx_vmread((size_t)G_CR4, &guest_cr4);
                if (reg_ptr)
                    *reg_ptr = guest_cr4;
            }
        }
        else if (cr_num == 8) // CR8 读写 (控制 IRQL / Local APIC TPR)
        {
            if (access_type == 0) // mov cr8, reg
            {
                __writecr8(reg_val);
            }
            else if (access_type == 1) // mov reg, cr8
            {
                ULONG64 val = __readcr8();
                if (reg_ptr)
                    *reg_ptr = val;
            }
        }

        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 31: // RDMSR
    {
        ULONG32 msr_id = (ULONG32)regs->rcx;
        ULONG64 val = 0;
        BOOLEAN fault = FALSE;

        if (msr_id == 0xC0000100) // MSR_FS_BASE
        {
            __vmx_vmread((size_t)G_FS_BASE, (size_t *)&val);
        }
        else if (msr_id == 0xC0000101) // MSR_GS_BASE
        {
            __vmx_vmread((size_t)G_GS_BASE, (size_t *)&val);
        }
        else if (msr_id == 0x40000072) // HV_X64_MSR_TPR
        {
            val = (ULONG64)__readcr8();
        }
        else if (msr_id == 0x40000073) // HV_X64_MSR_VP_INDEX
        {
            ULONG64 apic_base = __readmsr(0x1B);
            if (apic_base & (1ULL << 10))
            {
                val = (ULONG32)__readmsr(0x802); // x2APIC ID
            }
            else if (g_apic_mmio_va)
            {
                val = (*(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0x20)) >> 24; // xAPIC ID
            }
            else
            {
                val = KeGetCurrentProcessorNumber();
            }
        }
        else if (msr_id >= 0x40000000 && msr_id <= 0x400000FF)
        {
            val = 0; // 其他 Hyper-V MSR 安全返回 0
        }
        else
        {
            __try
            {
                val = __readmsr(msr_id);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                fault = TRUE;
            }
        }

        if (fault)
        {
            ULONG64 inject = (1ULL << 31) | (3ULL << 8) | (1ULL << 11) | 13; // #GP(0)
            __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, inject);
            __vmx_vmwrite((size_t)VM_ENTRY_EXCEPTION_ERROR, 0);
        }
        else
        {
            regs->rax = (ULONG32)(val & 0xFFFFFFFF);
            regs->rdx = (ULONG32)(val >> 32);
            size_t len = 0;
            __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
            __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        }
        break;
    }

    case 32: // WRMSR
    {
        ULONG32 msr_id = (ULONG32)regs->rcx;
        ULONG64 val = ((ULONG64)regs->rdx << 32) | (ULONG32)regs->rax;
        BOOLEAN fault = FALSE;

        if (msr_id == 0xC0000100) // MSR_FS_BASE
        {
            __vmx_vmwrite((size_t)G_FS_BASE, val);
        }
        else if (msr_id == 0xC0000101) // MSR_GS_BASE
        {
            __vmx_vmwrite((size_t)G_GS_BASE, val);
        }
        else if (msr_id == 0x40000070) // HV_X64_MSR_EOI
        {
            ULONG64 apic_base = __readmsr(0x1B);
            if (apic_base & (1ULL << 10))
            {
                __writemsr(0x80B, 0); // x2APIC EOI
            }
            else if (g_apic_mmio_va)
            {
                *(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0xB0) = 0; // xAPIC EOI
            }
        }
        else if (msr_id == 0x40000071) // HV_X64_MSR_ICR (发送 IPI)
        {
            ULONG64 apic_base = __readmsr(0x1B);
            if (apic_base & (1ULL << 10))
            {
                __writemsr(0x830, val); // x2APIC ICR
            }
            else if (g_apic_mmio_va)
            {
                // ★ 修正：APIC ID 必须精确左移 24 位到 ICR 高 32 位的 Bit 24-31！
                ULONG32 dest_apic_id = (ULONG32)(val >> 32);
                *(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0x310) = (dest_apic_id & 0xFF) << 24;
                *(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0x300) = (ULONG32)(val & 0xFFFFFFFF);
            }
        }
        else if (msr_id == 0x40000072) // HV_X64_MSR_TPR
        {
            __writecr8((ULONG)(val & 0xF)); // 翻译为 CR8 (TPR)
        }
        else if (msr_id >= 0x40000000 && msr_id <= 0x400000FF)
        {
            // 其他 Hyper-V MSR 静默放行
        }
        else
        {
            __try
            {
                __writemsr(msr_id, val);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                fault = TRUE;
            }
        }

        if (fault)
        {
            ULONG64 inject = (1ULL << 31) | (3ULL << 8) | (1ULL << 11) | 13; // #GP(0)
            __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, inject);
            __vmx_vmwrite((size_t)VM_ENTRY_EXCEPTION_ERROR, 0);
        }
        else
        {
            size_t len = 0;
            __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
            __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        }
        break;
    }

    case 37: // EXIT_REASON_MTF
    {
        if (g_hv_mtf_pending)
        {
            size_t proc_ctls = 0;
            __vmx_vmread((size_t)C_PROC, &proc_ctls);
            __vmx_vmwrite((size_t)C_PROC, (size_t)(proc_ctls & ~CPU_BASED_USE_MTF));

            if (g_eptp_restricted && g_hv_in_restricted_mode)
            {
                __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp_restricted);
                // ★ 刷新 restricted EPT TLB: 确保 R-X 权限在单步后立即恢复
                //   无 INVEPT 则 CPU 可能缓存旧 RWX entry → 下次写不再触发 violation
                invept_restricted();
            }
            g_hv_mtf_pending = FALSE;
        }
        break;
    }

    case 48: // EXIT_REASON_EPT_VIOLATION
    {
        size_t gpa = 0;
        size_t qual = 0;
        __vmx_vmread((size_t)GUEST_PHYSICAL_ADDR, &gpa);
        __vmx_vmread((size_t)EXIT_QUALIFICATION, &qual);

        // ★ JIT 写保护核心: 解析 EPT violation 的访问类型与目标地址
        //   EXIT_QUALIFICATION: bit1=write, bit7=gla_valid
        //   GUEST_LINEAR_ADDRESS: 导致违规的线性地址(GVA), bit7=1 时有效
        BOOLEAN is_write = (qual & EPT_VIOL_QUAL_WRITE) != 0;
        BOOLEAN gva_valid = (qual & EPT_VIOL_QUAL_GVA_VALID) != 0;

        ULONG64 gva = 0;
        if (gva_valid)
        {
            size_t gla = 0;
            __vmx_vmread((size_t)GUEST_LINEAR_ADDRESS, &gla);
            gva = (ULONG64)gla;
        }

        // ★★★ JIT 代码缓存写检测: 写 JIT 页 + GVA 有效 + GVA 在已注册 JIT 范围内 ★★★
        //   restricted EPT 将 JIT 2MB 页设为 R-X (无 W), 写操作触发 EPT violation
        //   参见 hypervisor_restrict_jit_physical(): 修改 restricted EPT PD 条目
        BOOLEAN is_jit_write = is_write && gva_valid && hv_gva_in_jit_range(gva);

        if (is_jit_write)
        {
            // ★ 新增：熔断保护，防止 INVEPT/权限切换异常时无限重入同一条指令
            static volatile LONG s_jit_violation_burst = 0;
            if (InterlockedIncrement(&s_jit_violation_burst) > 100000)
            {
                if (g_vmxoff)
                    g_vmxoff();
                break;
            }
            // 写 JIT 代码缓存页 — 区分合法 JIT 补丁 vs 恶意篡改
            if (hv_is_legitimate_jvm_writer(guest_rip))
            {
                // ★ 合法: JVM 原生代码写代码缓存 (JIT 编译器 / IC 补丁 / nmethod 翻译)
                //   JDK20 HotSpot 用直接指针写修改代码缓存:
                //     - nativeInst_x86.hpp:86  set_int_at: *(jint*)addr = i
                //     - nativeInst_x86.cpp:280 set_destination_mt_safe → set_int_at
                //     - nmethod.cpp:1347       patch_verified_entry → Atomic::store
                //     - compiledIC.cpp:133      internal_set_ic_destination
                //   写者 RIP 必在 jvm.dll/java.exe 原生代码段内 (非 JIT 编译代码)
                //   允许: 切到正常 EPT (RWX), MTF 单步一条指令, MTF 后切回 restricted (R-X)
                if (g_eptp)
                    __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp);
                size_t proc_ctls = 0;
                __vmx_vmread((size_t)C_PROC, &proc_ctls);
                __vmx_vmwrite((size_t)C_PROC, (size_t)(proc_ctls | CPU_BASED_USE_MTF));
                g_hv_mtf_pending = TRUE;
                g_hv_mtf_page_va = (ULONG64)gpa;
                InterlockedIncrement(&g_hv_jit_allows);
            }
            else
            {
                // ★★★ 恶意: 非 JVM 代码写 JIT 代码缓存 → 阻止 ★★★
                //   写者 RIP 不在 JVM 原生段:
                //   - shellcode (RIP 在匿名可执行区, 含被篡改的 JIT 页)
                //   - Unsafe.putByte 从 JIT 编译的 Java 代码 (RIP 在代码缓存内)
                //   - 外部进程通过 RMM/驱动写 (RIP 在内核)
                //   JDK 的 JIT 补丁永远从 JVM 原生代码发起, RIP 不可能在代码缓存或匿名区
                //   → 写者不在 JVM 原生段 = 必为篡改
                InterlockedExchange(&g_hv_jit_tampered, 1);
                InterlockedExchange64(&g_hv_jit_tamper_rip, (LONG64)guest_rip);
                InterlockedExchange64(&g_hv_jit_tamper_va, (LONG64)gva);
                InterlockedIncrement(&g_hv_jit_blocks);

                // 阻止写: 跳过写指令 (推进 RIP), 写操作不执行
                //   等效于"指令被 NOP" — JIT 代码缓存保持原样, 篡改未生效
                size_t len = 0;
                __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
                if (len > 0 && len <= 15)
                {
                    __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
                }
                else
                {
                    // 无法确定指令长度 (复杂指令/REP 前缀) → 注入 #GP 强制阻断
                    ULONG64 inject = (1ULL << 31) | (3ULL << 8) | (1ULL << 11) | 13;
                    __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, inject);
                    __vmx_vmwrite((size_t)VM_ENTRY_EXCEPTION_ERROR, 0);
                }
                break; // 不进入下方通用路径
            }
        }
        else
        {
            // 非 JIT 写违规 — 使用原有逻辑处理 (未映射页 / JVM 读执行等)
            BOOLEAN is_jvm = (g_hv_jvm_base != 0 &&
                              guest_rip >= g_hv_jvm_base &&
                              guest_rip < g_hv_jvm_base + (ULONG64)g_hv_jvm_size);

            if (is_jvm)
            {
                if (g_eptp)
                    __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp);
                size_t proc_ctls = 0;
                __vmx_vmread((size_t)C_PROC, &proc_ctls);
                __vmx_vmwrite((size_t)C_PROC, (size_t)(proc_ctls | CPU_BASED_USE_MTF));
                g_hv_mtf_pending = TRUE;
                g_hv_mtf_page_va = (ULONG64)gpa;
            }
            else
            {
                // ★ 修复：原来这里只是切回同一个 eptp 就 break，
                //   如果这个 GPA 本来就不在恒等映射范围内（比如落在超出预建 PML4 范围
                //   的大 BAR MMIO 上），guest 会用同一条指令、同一个未映射地址
                //   立刻再次触发一模一样的 EPT violation —— 形成无限 VM-exit 死循环，
                //   这正是"运行中某次访问到特定地址才卡死"的根本原因。
                //   这里改成：尝试现场给这个 2MB 大页建立恒等映射(RWX + 正确内存类型)，
                //   建立失败才算真正异常，交给 g_hv_compromised 兜底。
                BOOLEAN fixed = ept_try_fixup_2mb((ULONG64)gpa);
                if (fixed)
                {
                    invept_single_context(g_eptp);
                }
                else
                {
                    // 真正无法修复的情况(比如 phys addr 超过了硬件支持的最大位宽)，
                    // 才走"标记 compromised"，并且必须给风暴保护兜底，不能无限重试。
                    InterlockedExchange(&g_hv_compromised, 1);
                    if (InterlockedIncrement64(&g_hv_exit_count) > 5000000)
                    {
                        if (g_vmxoff)
                            g_vmxoff();
                        break;
                    }
                }
                if (g_eptp)
                    __vmx_vmwrite((size_t)C_EPTP, (size_t)g_eptp);
            }
        }
        break;
    }

    case 55: // XSETBV
    {
        if (regs->rcx == 0)
            _xsetbv(0, (regs->rdx << 32) | (regs->rax & 0xFFFFFFFF));
        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 57: // EXIT_REASON_RDRAND
    {
        ULONG64 val = 0;
        int cf = _rdrand64_step((unsigned __int64 *)&val);
        regs->rax = (ULONG32)(val & 0xFFFFFFFF);
        regs->rdx = (ULONG32)(val >> 32);
        size_t rflags = 0;
        __vmx_vmread((size_t)G_RFLAGS, &rflags);
        if (cf)
            rflags |= 0x1;
        else
            rflags &= ~0x1ULL;                    // 正确设置 CF
        rflags &= ~(0x4ULL | 0x80ULL | 0x800ULL); // 清 ZF/SF/OF 等，RDRAND 只影响 CF
        __vmx_vmwrite((size_t)G_RFLAGS, rflags);
        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 13: // INVD
    {
        __wbinvd();
        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 18: // VMCALL (Hyper-V Cluster IPI 超级调用)
    {
        ULONG32 call_code = (ULONG32)(regs->rcx & 0xFFFF);

        // 一致隐藏 HV 后，Windows 回退原生路径，理论上不会发 VMCALL。
        // 若仍有 VMCALL 到达（残留的 cached enlightenment），对 ClusterIpi 模拟，
        // 其余静默返回成功(rax=0)。不再注入 #GP——之前 Fix3 的 #GP 会让
        // Windows 的 HvlInvokeHypercall 走异常恢复路径，叠加 idle 循环上下文
        // 触发 KeCheckStackAndTargetAddress → bugcheck。
        if (call_code == 0x0002) // HvCallSendSyntheticClusterIpi
        {
            ULONG64 apic_base = __readmsr(0x1B);
            if (apic_base & (1ULL << 10))
            {
                // x2APIC 广播 IPI (Shorthand=11b all-but-self, Vector=0xFD)
                __writemsr(0x830, 0x000C40FDULL);
            }
            else if (g_apic_mmio_va)
            {
                // xAPIC MMIO 广播 IPI
                *(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0x310) = 0;
                *(volatile ULONG32 *)((PUCHAR)g_apic_mmio_va + 0x300) = 0x000C40FD;
            }
        }

        regs->rax = 0; // HV_STATUS_SUCCESS
        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        break;
    }

    case 49: // EPT Misconfig
        KeBugCheckEx(0xDEAD4949, 0, 0, 0, 0);
        break;

    default:
    {
        size_t len = 0;
        __vmx_vmread((size_t)VM_EXIT_INSTR_LEN, &len);
        if (len > 0)
        {
            __vmx_vmwrite((size_t)G_RIP, (size_t)(guest_rip + len));
        }
        else
        {
            // len=0 大概率是不该发生的 exit reason，注入 #UD 让 guest 自己处理，
            // 好过卡死在同一条指令上被 exit 风暴计数器最终 KeBugCheckEx
            ULONG64 inject = (1ULL << 31) | (6ULL << 8) | 6; // #UD, type=6 hw exception
            __vmx_vmwrite((size_t)VM_ENTRY_INTERRUPTION_INFO, inject);
        }
        break;
    }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Restricted EPT 创建 ─────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

static BOOLEAN ept_create_restricted_map(void)
{
    g_ept_restricted_pml4 = (EPT_PTE *)alloc_page(NULL);
    g_ept_restricted_pdpt = (EPT_PTE *)alloc_page(NULL);
    g_ept_restricted_pd_pool = ExAllocatePoolWithTag(NonPagedPool, 512 * PAGE_SIZE, 'TZER');

    if (!g_ept_restricted_pml4 || !g_ept_restricted_pdpt || !g_ept_restricted_pd_pool)
        goto fail;

    RtlZeroMemory(g_ept_restricted_pd_pool, 512 * PAGE_SIZE);

    for (int i = 0; i < 512; i++)
    {
        EPT_PTE *pd = (EPT_PTE *)((PUCHAR)g_ept_restricted_pd_pool + i * PAGE_SIZE);
        PHYSICAL_ADDRESS pd_pa = MmGetPhysicalAddress(pd);
        g_ept_restricted_pdpt[i].entry = (pd_pa.QuadPart & 0xFFFFFFFFF000ULL) | EPT_RWX;

        for (int j = 0; j < 512; j++)
        {
            ULONG64 pfn = (i * 512ULL) + j;
            ULONG64 phys_base = pfn << 21; // 2MB 对齐的物理地址
            ULONG mem_type = get_ept_mem_type_for_2mb(phys_base);
            pd[j].entry = (pfn << 21) | EPT_RWX | EPT_LP | ((ULONG64)mem_type << 3);
        }
    }

    PHYSICAL_ADDRESS pdpt_pa = MmGetPhysicalAddress(g_ept_restricted_pdpt);
    g_ept_restricted_pml4[0].entry = (pdpt_pa.QuadPart & 0xFFFFFFFFF000ULL) | EPT_RWX;

    PHYSICAL_ADDRESS pml4_pa = MmGetPhysicalAddress(g_ept_restricted_pml4);
    g_eptp_restricted = 6 | (3 << 3) | (pml4_pa.QuadPart & 0xFFFFFFFFF000ULL);

    DbgPrint("[tzd-hv] Restricted EPT eptp=0x%llx\n", g_eptp_restricted);
    return TRUE;
fail:
    if (g_ept_restricted_pml4)
    {
        free_page(g_ept_restricted_pml4);
        g_ept_restricted_pml4 = NULL;
    }
    if (g_ept_restricted_pdpt)
    {
        free_page(g_ept_restricted_pdpt);
        g_ept_restricted_pdpt = NULL;
    }
    if (g_ept_restricted_pd_pool)
    {
        ExFreePool(g_ept_restricted_pd_pool);
        g_ept_restricted_pd_pool = NULL;
    }
    return FALSE;
}

// ★ 前向声明: hypervisor_set_armed_process 调用 hypervisor_register_jit_range
void hypervisor_register_jit_range(ULONG64 gvaBase, ULONG64 gvaSize);

void hypervisor_set_armed_process(ULONG pid, ULONG64 cr3,
                                  ULONG64 jvmBase, SIZE_T jvmSize,
                                  ULONG64 ccVa, SIZE_T ccSize)
{
    g_hv_armed_pid = pid;
    g_hv_armed_cr3 = cr3;
    g_hv_jvm_base = jvmBase;
    g_hv_jvm_size = jvmSize;

    // ★ 注册代码缓存范围为 JIT 范围 (GVA)
    //   JDK20 有 3 个代码堆 (NonNMethod/Profiled/NonProfiled), ccVa/ccSize 是主缓存
    //   额外范围可通过 hypervisor_register_jit_range 单独注册
    if (ccVa != 0 && ccSize != 0)
    {
        hypervisor_register_jit_range(ccVa, ccSize);
    }

    if (!g_eptp_restricted)
    {
        ept_create_restricted_map();
    }

    DbgPrint("[tzd-hv] armed: pid=%lu cr3=0x%llx jvm=0x%llx+0x%llx cc=0x%llx+0x%llx jit_ranges=%ld\n",
             pid, (unsigned long long)cr3,
             (unsigned long long)jvmBase, (unsigned long long)jvmSize,
             (unsigned long long)ccVa, (unsigned long long)ccSize,
             g_hv_jit_range_count);
}

// ═════════════════════════════════════════════════════════════════════════
// ─── JIT 代码缓存写保护: 公共 API ──────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════

// 注册一个 JIT 代码缓存 GVA 范围 (JVM 可有多个代码堆)
//   范围以 GVA (线性地址) 存储; EPT violation 时通过 GUEST_LINEAR_ADDRESS 匹配
void hypervisor_register_jit_range(ULONG64 gvaBase, ULONG64 gvaSize)
{
    if (gvaBase == 0 || gvaSize == 0)
        return;

    // 检查重复注册 (同基址同大小 → 已注册, 跳过)
    LONG cur_count = g_hv_jit_range_count;
    for (LONG i = 0; i < cur_count && i < MAX_JIT_RANGES; i++)
    {
        if (g_hv_jit_gva_base[i] == gvaBase &&
            g_hv_jit_gva_size[i] == gvaSize)
        {
            DbgPrint("[tzd-hv] JIT range already registered: base=0x%llx (skip)\n", gvaBase);
            return;
        }
    }

    LONG idx = InterlockedIncrement(&g_hv_jit_range_count) - 1;
    if (idx >= MAX_JIT_RANGES)
    {
        InterlockedDecrement(&g_hv_jit_range_count);
        DbgPrint("[tzd-hv] JIT range table full (max %d)\n", MAX_JIT_RANGES);
        return;
    }

    g_hv_jit_gva_base[idx] = gvaBase;
    g_hv_jit_gva_size[idx] = gvaSize;

    DbgPrint("[tzd-hv] JIT GVA range registered: base=0x%llx size=0x%llx (idx=%ld/%d)\n",
             gvaBase, gvaSize, idx, MAX_JIT_RANGES);
}

// 设置 JVM 原生写者范围 (jvm.dll/java.exe 代码段)
//   合法 JIT 补丁的写者 RIP 必在此范围内; 范围外的写者 → 判定为恶意篡改
void hypervisor_set_jvm_writer_range(ULONG64 base, SIZE_T size)
{
    g_hv_jvm_writer_base = base;
    g_hv_jvm_writer_size = size;
    DbgPrint("[tzd-hv] JVM writer range set: base=0x%llx size=0x%llx\n",
             (unsigned long long)base, (unsigned long long)size);
}

// ★ 限制物理 2MB 页的写权限 (在 restricted EPT 中设 R-X)
//   将指定物理地址所在 2MB 大页的 EPT PD 条目从 RWX 改为 R-X
//   写操作 → EPT violation → handler 检查写者 RIP → 允许(JVM)/阻止(非 JVM)
//   由 tzd_ppl_drv IOCTL handler 在附着目标进程后调用 (需走页表翻译 GVA→GPA)
void hypervisor_restrict_jit_physical(ULONG64 physBase, ULONG64 size)
{
    if (!g_ept_restricted_pd_pool || !g_eptp_restricted)
    {
        DbgPrint("[tzd-hv] restrict_jit_physical: restricted EPT not initialized\n");
        return;
    }

    // 按 2MB 对齐
    ULONG64 start = physBase & ~0x1FFFFFULL;                      // 向下对齐到 2MB
    ULONG64 end = (physBase + size + 0x1FFFFFULL) & ~0x1FFFFFULL; // 向上对齐
    ULONG count = 0;

    for (ULONG64 pa = start; pa < end; pa += (2 * 1024 * 1024))
    {
        ULONG pdpt_idx = (ULONG)((pa >> 30) & 0x1FF);
        ULONG pd_idx = (ULONG)((pa >> 21) & 0x1FF);

        if (pdpt_idx >= 512)
            continue;

        EPT_PTE *pd = (EPT_PTE *)((PUCHAR)g_ept_restricted_pd_pool +
                                  pdpt_idx * PAGE_SIZE);
        if (pd[pd_idx].entry & 1) // present
        {
            // 清 Write 位 (bit 1): RWX(7) → RX(5)
            pd[pd_idx].entry &= ~2ULL;
            count++;
        }
    }

    // 刷新 restricted EPT TLB (当前 CPU; 其他 CPU 在下次 EPT 切换时自动刷新)
    invept_restricted();

    DbgPrint("[tzd-hv] JIT physical restricted: phys=0x%llx size=0x%llx (%u x 2MB pages set R-X)\n",
             physBase, size, count);
}

// 清除所有 JIT 范围并恢复 restricted EPT 为全 RWX
void hypervisor_clear_jit_ranges(void)
{
    InterlockedExchange(&g_hv_jit_range_count, 0);
    for (int i = 0; i < MAX_JIT_RANGES; i++)
    {
        g_hv_jit_gva_base[i] = 0;
        g_hv_jit_gva_size[i] = 0;
    }

    // 恢复 restricted EPT 所有 PD 条目为 RWX
    if (g_ept_restricted_pd_pool && g_eptp_restricted)
    {
        for (int i = 0; i < 512; i++)
        {
            EPT_PTE *pd = (EPT_PTE *)((PUCHAR)g_ept_restricted_pd_pool + i * PAGE_SIZE);
            for (int j = 0; j < 512; j++)
            {
                if (pd[j].entry & 1)
                    pd[j].entry |= 2ULL; // 恢复 Write 位
            }
        }
        invept_restricted();
    }

    // 清除篡改状态
    InterlockedExchange(&g_hv_jit_tampered, 0);
    InterlockedExchange64(&g_hv_jit_tamper_rip, 0);
    InterlockedExchange64(&g_hv_jit_tamper_va, 0);
    InterlockedExchange(&g_hv_jit_blocks, 0);
    InterlockedExchange(&g_hv_jit_allows, 0);

    DbgPrint("[tzd-hv] JIT ranges cleared, restricted EPT restored to RWX\n");
}

// 查询 JIT 篡改告警状态
void hypervisor_query_jit_alert(ULONG *tampered, ULONG *blocks, ULONG *allows,
                                ULONG *rangeCount, ULONG64 *tamperRip,
                                ULONG64 *tamperVa)
{
    if (tampered)
        *tampered = (ULONG)g_hv_jit_tampered;
    if (blocks)
        *blocks = (ULONG)g_hv_jit_blocks;
    if (allows)
        *allows = (ULONG)g_hv_jit_allows;
    if (rangeCount)
        *rangeCount = (ULONG)g_hv_jit_range_count;
    if (tamperRip)
        *tamperRip = (ULONG64)g_hv_jit_tamper_rip;
    if (tamperVa)
        *tamperVa = (ULONG64)g_hv_jit_tamper_va;
}