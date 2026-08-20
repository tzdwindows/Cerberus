// Architect: tzdwindows 7
// Memory guard: inline-hook VirtualProtect / VirtualProtectEx /
// WriteProcessMemory / NtProtectVirtualMemory to block all memory
// modifications originating from non-JVM-default modules.
#pragma once
#include <windows.h>

void memguard_install();
void memguard_uninstall();
DWORD memguard_get_block_count();
intptr_t memguard_get_jvm_base();
