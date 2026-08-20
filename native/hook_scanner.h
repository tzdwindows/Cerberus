// Architect: tzdwindows 7
// Hook scanner: periodic background thread scanning for inline hooks,
// IAT tampering, and function prologue modifications across all JVM
// critical exports. Auto-repairs detected hooks using pristine bytes.
#pragma once
#include <windows.h>

void scanner_start();
void scanner_stop();
DWORD scanner_get_repair_count();
int scanner_scan_now();
