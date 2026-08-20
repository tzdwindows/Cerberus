// Architect: tzdwindows 7
// protect_class: Mark a Java class as hidden, remove it from the JVMTI class
// load list, protect its InstanceKlass memory pages from modification, AND
// protect every Method* of the class from the JIT exploit (attacker modifies
// Method._code / _from_compiled_entry to redirect execution).
//
// This is a pure-native (no JVMTI) class + method protection engine:
//   1. Resolve the InstanceKlass* from a java.lang.Class mirror by detecting
//      the java_lang_Class::_klass_offset at runtime (it is injected by the VM
//      and not a compile-time constant).
//   2. Detect the Klass::_access_flags offset at runtime by matching known
//      Java access flags (lower 16 bits) of a reference class.
//   3. Set JVM_ACC_IS_HIDDEN_CLASS (0x04000000) in _access_flags — this makes
//      the class invisible to JVMTI GetLoadedClasses / ClassFileLoadHook /
//      RetransformClasses (JVMTI filters hidden classes from all those APIs).
//   4. Detect and walk the ClassLoaderData::_klasses list (chained via
//      Klass::_next_link) and physically unlink the protected InstanceKlass so
//      JVMTI's class enumeration (which walks the same list) never sees it.
//   5. VirtualProtect the InstanceKlass memory pages to PAGE_READONLY so the
//      class metadata cannot be modified by any other agent, including
//      RetransformClasses / RedefineClasses that would rewrite field layouts.
//
//   === Method-level protection (fixes the JIT exploit) ===
//   6. Enumerate ALL declared methods + constructors via JNI reflection.
//   7. Back up every critical Method* field: _constMethod (offset 8),
//      _access_flags (40), _flags (50), _i2i_entry (56),
//      _from_compiled_entry (64), _code (72), _from_interpreted_entry (80).
//   8. Back up ConstMethod bytecodes (CRC32) for tamper detection.
//   9. Back up nmethod compiled code (if method was already JIT-compiled).
//  10. Call jvm_force_interpreter() on each method — clears _code, nulls
//      _from_compiled_entry, sets _dont_inline + NOT_C1/C2_COMPILABLE.
//      This ELIMINATES the nmethod attack surface: no compiled code exists,
//      so the attacker cannot patch compiled machine code.
//  11. Set PAGE_READONLY on Method*/ConstMethod* pages. Writes trigger
//      ACCESS_VIOLATION → the method write-guard VEH checks if the writer
//      is jvm.dll (legitimate JIT/deopt) or an attacker. Attacker writes
//      output "你好伙计，你改你妈的方法呢" and are restored from backup.
//  12. The periodic integrity thread (every 100ms) CRC32-checks ALL Method*
//      fields, ConstMethod bytecodes, and nmethod compiled code. Any
//      tampering is detected, restored, and the message is output.
//
// Layout references (JDK 20, confirmed via E:\jdk20u-master source):
//   Klass : public Metadata  (Metadata has a vptr at offset 0)
//     +0   vptr
//     +8   _layout_helper      (jint)
//     +12  _kind               (KlassKind, 4 bytes)
//     +16  _modifier_flags     (jint)
//     +20  _super_check_offset (juint)
//     +24  _name               (Symbol*)
//     +32  _secondary_super_cache (Klass*)
//     +40  _secondary_supers   (Array<Klass*>*)
//     +48  _primary_supers[8] (64 bytes)
//     +112 _java_mirror        (OopHandle = 1 pointer)
//     +120 _super              (Klass*)
//     +128 _subklass           (Klass* volatile)
//     +136 _next_sibling       (Klass* volatile)
//     +144 _next_link          (Klass*)         *** class-list chain ***
//     +152 _class_loader_data  (ClassLoaderData*) *** list head owner ***
//     +160 _vtable_len         (int)
//     +164 _access_flags       (AccessFlags = jint) *** hidden flag lives here ***
//   ClassLoaderData:
//     +0   vtable
//     +8   ... (is_unsafe_anonymous, etc.)
//     +140 _klasses             (Klass* volatile) *** list head ***
//
// All offsets are runtime-detected and verified — never hardcoded into
// production paths (the layout can shift between product/debug builds).
#pragma once
#include <windows.h>
#include <jni.h>

// Protect a class: multi-layer R3 defense (hardware + software + kernel-level).
//   1. JVM_ACC_IS_HIDDEN_CLASS flag
//   2. Unlink from ClassLoaderData::_klasses list (invisible to class enumeration)
//   3. Deep encrypt _access_flags (PAGE_GUARD + VEH decrypt-on-access)
//   4. NtQueryVirtualMemory IAT hook (Metaspace pages → MEM_PRIVATE)
//   5. Anti-debug IAT hooks (IsDebuggerPresent etc.)
//   6. Periodic CRC32 integrity thread (re-applies all protections)
//   7. Method-level protection: backup + force interpreter + PAGE_READONLY
//      + write-guard VEH (outputs "你好伙计，你改你妈的方法呢" on ALL writes
//      to protected fields — NO WHITELIST, even jvm.dll is blocked)
//   8. ConstMethod bytecode + nmethod compiled-code CRC32 integrity checking
//   9. CPU hardware breakpoints (DR0-DR3):
//      DR0: Class._klass (prevent klass swap)
//      DR1: IK._constants (prevent class replacement)
//      DR2: Method._code (prevent JIT exploit — fake nmethod)
//      DR3: Method._from_compiled_entry (prevent entry redirect)
//  10. Direct syscalls (bypass ALL user-mode hooks — IAT, inline, VEH)
//  11. 3 unkillable watchdog threads: mutual respawn + thread hiding +
//      re-apply DR on ALL threads every 500ms + new thread detection
//  12. Lock-free flat arrays for VEH-safe access (no deadlock possible)
// This covers EVERY attack vector: klass swap, method field tampering,
// JIT exploit (fake nmethod), bytecode patching, compiled code patching,
// thread killing, hook bypassing (direct syscalls), and DR clearing.
bool protect_class(JNIEnv* env, jclass clazz);

// Undo protection.
bool unprotect_class(JNIEnv* env, jclass clazz);

// Debug: return a detailed protection status report as a string.
const char* debug_check_protection(JNIEnv* env, jclass clazz);

// Block Java-level class replacement attacks:
// 1. Close Attach API pipe (prevent VirtualMachine.attach().loadAgent())
// 2. Bytecode patch Module.addOpens/addReads/addUses → no-op
//    (prevent reflection bypass of module encapsulation)
void patch_module_bypass(JNIEnv* env);
