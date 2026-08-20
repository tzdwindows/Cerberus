// Architect: tzdwindows 7
// TRUE interpreter dispatch table hook (resolution-safe, Method*-independent).
//
// HotSpot's template interpreter dispatches each bytecode via a computed
// jump:  jmp  [table_base + opcode * 8]   (x86_64)
// where table_base = TemplateInterpreter::_active_table._table[tos_state].
// The table is a static array of `address` (code pointers) laid out as
// _table[number_of_states=10][length=256], i.e. states-outer, codes-inner
// (confirmed: templateInterpreter.hpp:71, globalDefinitions.hpp:958).
//
//   freturn  = bytecode 0xAE, dispatched from tos_state ftos=6
//   ireturn  = bytecode 0xAC, dispatched from tos_state itos=4
//   Method*  = *(rbp - 24)  (interpreter_frame_method_offset = -3 words;
//                             confirmed: frame_x86.hpp:55-76)
//
// We patch the dispatch-table slot so that when ANY thread's interpreter
// reaches freturn/ireturn, our stub runs first. The stub reads the current
// Method* from the interpreter frame (rbp-24), compares it against each
// hooked method, and if it matches, overwrites the return value register
// (xmm0 for float, eax for int) with 0 before jumping to the original
// handler. Non-matching methods pass through transparently.
//
// The Method* is NEVER written, and bytecodes/ConstMethod are NEVER touched —
// the JIT compiler's Method→ConstMethod→ConstantPool→InstanceKlass chain
// stays intact, eliminating the C1/C2 crash that the constMethod-swap caused.
//
// Both _normal_table and _safept_table are patched (the VM swaps _active_table
// between them at safepoints), plus _active_table for immediate effect.
//
// Fallback: if the dispatch table cannot be located, dispatch_hook_freturn
// falls back to entry-point stub replacement (allocates a tiny executable
// stub that returns 0 and redirects _from_interpreted_entry/_from_compiled_entry).
#pragma once
#include <windows.h>
#include <jni.h>

// Initialize: locate the interpreter dispatch table in jvm.dll.
// Returns true on success (dispatch-table mode active).
bool dispatch_hook_init(JNIEnv* env);

// Install a hook: when `srcMethodPtr`'s freturn (or ireturn) executes,
// override the return value to 0 (float→0.0f in xmm0, int→0 in eax).
// The target method's return type is auto-detected from its descriptor.
bool dispatch_hook_freturn(JNIEnv* env, long long srcMethodPtr, long long tgtMethodObj);

// Remove a hook by src Method*.
bool dispatch_hook_remove(long long srcMethodPtr);
