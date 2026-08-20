// Architect: tzdwindows 7
// jvm_deopt: Universal anti-inlining & deoptimization engine.
// Forces methods into interpreter mode by clearing _code (nmethod*),
// setting _dont_inline flag, and marking as NOT_C1/C2_COMPILABLE.
// Shared by both method_replace and interpreter_hook frameworks.
#pragma once
#include <windows.h>
#include <jni.h>

// JDK 20 Method* field offsets (confirmed by runtime detection):
//   +8 : _constMethod            (ConstMethod*, 8 bytes) — bytecodes live here
//   +40: _access_flags  (jint, 4 bytes)
//   +50: _flags          (u2, 2 bytes) — contains _dont_inline bit
//   +56: _i2i_entry      (address, 8 bytes)
//   +64: _from_compiled_entry (address, 8 bytes)
//   +72: _code           (CompiledMethod*, 8 bytes)
//   +80: _from_interpreted_entry (address, 8 bytes)
//
// ConstMethod layout (no vtable — confirmed by constMethod.hpp comment):
//   +0 : _fingerprint (u8)
//   +8 : _constants (ConstantPool*)
//   +16: _stackmap_data
//   +24: _constMethod_size, +28 _flags, +30 _result_type, +32 _code_size ...
//   bytecodes at (ConstMethod* + sizeof(ConstMethod))
// ConstantPool layout (has vtable):
//   +0 vtable, +8 _tags, +16 _cache, +24 _pool_holder (InstanceKlass*)
// InstanceKlass: +? _dep_context (nmethodBucket* volatile)
// nmethodBucket: +0 _nmethod (or +8 if CHeapObj vtable), _next @ +16
// nmethod: _state(signed char, in_use=0/not_entrant=2), _verified_entry_point,
//          _method (in CompiledMethod)
//
// Flag values (from JDK 20 source):
//   _dont_inline            = 0x04 (bit 2 in _flags)
//   JVM_ACC_NOT_C2_COMPILABLE = 0x02000000 (in _access_flags)
//   JVM_ACC_NOT_C1_COMPILABLE = 0x04000000 (in _access_flags)

// Initialize: detect Method* offsets at runtime
void jvm_deopt_init(JNIEnv* env);

// Set the JVMTI env used for SAFE (safepoint-based) deoptimization of inliners
// via DeoptimizeMethod. Must be called from JNI_OnLoad once JVMTI is acquired.
void jvm_deopt_set_jvmti(void* jvmti);

// Prevent inlining: set _dont_inline + NOT_C1/C2_COMPILABLE
void jvm_prevent_inlining(long long methodPtr);

// Deoptimize: clear _code (nmethod*), null _from_compiled_entry
void jvm_deoptimize_method(long long methodPtr);

// Combined: deoptimize + prevent re-compilation + force interpreter
void jvm_force_interpreter(long long methodPtr);

// ─── Tier 2: invalidate nmethods that inlined src (no JVMTI) ───
// Walks src.holder._dep_context nmethodBucket list; for each dependent
// nmethod: set _state=not_entrant + _mark_for_deoptimization_status=deoptimize
// + unlink _method._code. If a wrong-method stub is harvested, also patches
// the verified entry with a 5-byte jmp so baked direct calls bounce to deopt.
// Returns number of nmethods deoptimized. Best-effort; degrades to 0 on
// detection failure (never crashes).
int jvm_deopt_inlined_callers(long long srcMethodPtr);

// Get detected offsets (for other modules)
int jvm_deopt_get_offset(const char* name);

// Safe memory read check
bool jvm_safe_read(const void* addr, size_t size);
