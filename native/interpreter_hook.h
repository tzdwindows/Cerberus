// Architect: tzdwindows 7
// Interpreter hook: intercepts bytecode dispatch to modify method behavior.
// This is a SEPARATE mechanism from method_replace.cpp (which redirects
// Method* entry points). Here we modify the interpreter's _active_table
// dispatch table directly, making it undetectable via Method* inspection.
//
// Method* entry points → UNCHANGED (no suspicious redirect)
// Bytecodes           → UNCHANGED (no bytecode modification)
// Only the interpreter's internal dispatch table is modified.
//
// For JIT-compiled methods: we set _code=NULL (deoptimize) so the
// method goes through the interpreter where our dispatch hook applies.
#pragma once
#include <windows.h>
#include <jni.h>

// Initialize: find the interpreter dispatch table in jvm.dll
// Returns true on success.
bool interp_hook_init();

// ─── New (src, target) API — entry-point copy (NO constMethod swap) ──
// Hook src → target by copying target's _from_interpreted_entry /
// _from_compiled_entry to src. _constMethod is NEVER touched, so the JIT
// compiler's Method→ConstMethod→ConstantPool→InstanceKlass chain stays
// intact (this is the fix for the C1/C2 segfault that the constMethod-swap
// caused). Only non-zero target entries are copied (a zero entry would
// crash interpreted callers). src is forced to interpreter mode + anti-inline.
//
// tgtMethodPtr: a resolved Method* (use resolveMethodPtrExt).
bool interp_hook_java(long long srcMethodPtr, long long tgtMethodPtr);

// Alias — same core, explicit name for the "replace" semantics.
bool interp_hook_replace(long long srcMethodPtr, long long tgtMethodPtr);

// ─── Stub-based API (preferred) ─────────────────────────────────────
// Allocate a tiny executable stub that returns a captured constant and
// redirect src's _from_interpreted_entry / _from_compiled_entry to it.
// No constMethod swap, no bytecode modification. The stub is generated
// at install time based on the captured return value.
//   retType: 0 = float (xmm0), 1 = int (eax), 2 = void (no return value)
//   retValueBits: the return value as raw bits (float bits for RT_FLOAT,
//                 int value for RT_INT, ignored for RT_VOID)
bool interp_hook_stub(long long srcMethodPtr, int retType, long long retValueBits);

// Remove hook: restore src's original _constMethod + entry points.
bool interp_hook_remove(long long srcMethodPtr);

// Guard: verify constMethod + entries still point at target, re-apply if
// overwritten by JVM (link_method, RetransformClasses, clear_code).
void interp_hook_guard();

// Fast guard thread (anti-tamper): re-applies every hook every ~1ms so an
// adversary's direct Method* write is reverted in microseconds.
void interp_hook_start_guard();
void interp_hook_stop_guard();

// Test helper: simulate an adversary reverting src._constMethod to its
// original. The guard thread should re-apply within ~1ms.
bool interp_hook_test_tamper(long long srcMethodPtr);

// Install a hook on bytecode 'freturn' (0xAE) that checks if the
// current method (rbx = Method*) matches targetMethodPtr.
// If match: replaces xmm0 (float TOS) with replacementValue.
// If no match: jumps to original handler (transparent passthrough).
// targetMethodPtr: the resolved Method* (use resolveMethodPtr from
//                  method_replace.cpp or jmethodID resolution)
// replacementValue: the float bits to return (e.g. FLT_MAX = 0x7F7FFFFF)
// Returns true on success.
bool interp_hook_freturn(long long targetMethodPtr, int replacementValueBits);

// Remove the freturn hook (restore original dispatch entries)
void interp_hook_freturn_remove();

// Deoptimize a method: set _code = NULL to force interpreter mode
// methodPtr: the resolved Method* address
// codeOffset: offset of _code field (use method_replace offset detection)
void interp_hook_deoptimize(long long methodPtr, int codeOffset);

// Get dispatch table info (for debugging)
long interp_hook_get_dispatch_table();
int interp_hook_get_number_of_states();
