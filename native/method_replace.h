// Architect: tzdwindows 7
// Method replacement via interpreter/JIT entry-point redirection.
// Does NOT modify bytecodes — redirects Method* entry-point fields
// so execution flows through our code while bytecodes stay pristine.
#pragma once
#include <windows.h>
#include <jni.h>

// Opaque handle for a replaced method (stores original state for restore)
struct ReplacedMethod;

// Find a Method* from a jclass + method name + signature (no JVMTI needed).
// Returns a handle that can be used with method_redirect / method_restore.
ReplacedMethod* method_find(JNIEnv* env, jclass clazz, const char* name, const char* sig);

// Redirect a method's entry point to replacementFunc.
// - Forces the method to interpreter mode (clears _code/nmethod)
// - Sets _from_interpreted_entry and _from_compiled_entry to replacementFunc
// - Bytecodes in code_base() remain unchanged
// - JVMTI GetBytecodes sees the original bytes
bool method_redirect(ReplacedMethod* rm, void* replacementFunc);

// Restore the original entry point
bool method_restore(ReplacedMethod* rm);

// Guard: verify redirect is still in place, re-apply if overwritten
bool method_verify_and_reapply(ReplacedMethod* rm, void* replacementFunc);

// Get the Method* pointer (raw, for advanced use)
void* method_get_raw(ReplacedMethod* rm);

// ─── New (src, target) API ──────────────────────────────────
// Copy target's entry points to src. Forces src into interpreter mode.
bool method_replace_java(long long srcMethodPtr, long long tgtMethodPtr);

// Scan jvm.dll for interpreter code region (signature-based)
// Returns [base, end) of the interpreter's dispatch code area.
intptr_t method_scan_interpreter_region(intptr_t* outEnd);

// Detect Method* field offsets at runtime by probing a known method.
// Stores results for use by method_redirect.
void method_detect_offsets(JNIEnv* env);
