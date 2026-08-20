// Architect: tzdwindows 7
// syscall_hook: Universal R3 syscall interception engine.
//
// Patches ALL ntdll syscall stubs (Nt*/Zw*) by replacing the `syscall`
// instruction (0F 05) with `ud2` (0F 0B). A VEH handler catches the
// resulting EXCEPTION_ILLEGAL_INSTRUCTION and redirects execution to
// a private `syscall; ret` stub — transparent pass-through with full
// interception capability.
//
// Only our DLL's direct syscall stubs (in VirtualAlloc'd memory) bypass
// the interception entirely — they have their own `syscall` instruction
// that is NOT patched. All other code goes through ntdll → intercepted.
//
// Driver communication (optional): if \\.\SyscallGuard device exists,
// registers our PID + trusted stub region for kernel-level enforcement.
//
// IOCTL protocol (for the user to implement the driver side):
//   IOCTL_SYSCALLGUARD_REGISTER  — register PID + trusted stub range
//   IOCTL_SYSCALLGUARD_UNREGISTER — unregister
//   IOCTL_SYSCALLGUARD_QUERY     — query interception stats
#pragma once
#include <windows.h>

// ─── IOCTL protocol (for driver communication) ───
#define SYSCALLGUARD_DEVICE_NAME  "\\\\.\\SyscallGuard"

#define IOCTL_SYSCALLGUARD_REGISTER    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSCALLGUARD_UNREGISTER  CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSCALLGUARD_QUERY       CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Data sent to driver via IOCTL_SYSCALLGUARD_REGISTER
#pragma pack(push, 8)
typedef struct _SYSCALLGUARD_REGISTER_DATA {
    ULONG  ProcessId;           // PID to protect
    ULONG64 TrustedStubBase;   // start of our direct syscall stubs
    ULONG64 TrustedStubEnd;    // end of our direct syscall stubs
    ULONG  NumPatchedStubs;    // how many ntdll stubs we patched
} SYSCALLGUARD_REGISTER_DATA, *PSYSCALLGUARD_REGISTER_DATA;

typedef struct _SYSCALLGUARD_QUERY_DATA {
    ULONG64 TotalIntercepted;   // total syscalls intercepted by driver
    ULONG64 BlockedCount;       // syscalls blocked by driver
    ULONG  Active;              // is driver enforcement active?
} SYSCALLGUARD_QUERY_DATA, *PSYSCALLGUARD_QUERY_DATA;
#pragma pack(pop)

// ─── Public API ───

// Initialize: enumerate ntdll syscall stubs, create private syscall;ret stub,
// register VEH handler. Does NOT enable interception yet.
void syscall_hook_init();

// Enable: patch ALL ntdll syscall stubs (0F 05 → 0F 0B).
// After this, all syscalls through ntdll are intercepted.
// Our DLL's direct stubs are unaffected (they don't go through ntdll).
void syscall_hook_enable();

// Disable: restore original ntdll stub bytes.
void syscall_hook_disable();

// Check if interception is currently enabled.
bool syscall_hook_is_enabled();

// Thread-local bypass flag: set by our DLL before calling CRT functions
// that might go through ntdll. When set, the VEH handler allows the
// syscall without logging/blocking (even dangerous ones).
void syscall_hook_set_bypass(int flag);
int  syscall_hook_get_bypass();

// Scan for direct syscall stubs (0F 05) in non-module executable memory.
// Patches any found with 0F 0B (same ud2 interception).
// Called by the watchdog thread every 500ms.
// Returns count of stubs patched.
int syscall_hook_scan_direct();

// Re-apply ud2 patches on ntdll stubs (called by watchdog if tampered).
// Returns count of re-patched stubs.
int syscall_hook_reapply_patches();

// Try to connect to the optional kernel driver. If present, register our
// PID and trusted stub region for R0-level enforcement.
// Returns true if driver connected, false if R3-only mode.
bool syscall_hook_driver_connect();

// Get statistics: total intercepted, blocked, etc.
void syscall_hook_get_stats(long long* intercepted, long long* blocked);
