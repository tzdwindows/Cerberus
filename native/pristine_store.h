// Architect: tzdwindows 7
// Pristine store: fetch & cache original bytes of jvm.dll critical exports.
// Expanded to cover all JVMTI/JNI entry points + memory API functions.
#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>

struct PristineEntry {
    void*   funcAddr;
    BYTE*   pristineBytes;
    SIZE_T  size;
};

void pristine_init();
const PristineEntry* pristine_get(const char* funcName);
BOOL pristine_restore(const char* funcName);
void pristine_scan_and_repair_all();
SIZE_T pristine_count();
intptr_t pristine_get_jvm_base();
