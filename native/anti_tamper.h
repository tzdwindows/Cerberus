// Architect: tzdwindows 7
// Anti-tamper: patch the shared JVMTI interface table so that
// RetransformClasses / RedefineClasses (the two JVMTI paths an adversary
// uses to revert our method hooks) re-apply our constMethod swap AFTER the
// call returns. The window is zero: when the JVMTI call returns to the
// adversary, our hooks are already back in place.
//
// All jvmtiEnv* point to the SAME jvmtiInterface_1_ table (a singleton in
// jvm.dll), so patching it once covers every agent — including the JPLIS
// agent backing java.lang.instrument and any competitor env.
//
// No JVMTI Retransform/Redefine is blocked (legit tools keep working); the
// redefinition is simply overwritten synchronously.
#pragma once
#include <windows.h>
#include <jni.h>
#include <jvmti.h>

// Patch the JVMTI table (RetransformClasses + RedefineClasses slots).
// Returns true on success.
bool anti_tamper_install(jvmtiEnv* env);

// Restore the original JVMTI table entries.
void anti_tamper_uninstall();
