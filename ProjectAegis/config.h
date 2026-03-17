#pragma once

//
// Project Aegis - Config header
// Protected process names, feature flags, debug macros.
//

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------
// Protected processes (e.g. simulated game client)
// Match by image name, case-insensitive; can extend to PID/path later.
// -----------------------------------------------
#define AEGIS_MAX_PROTECTED_NAMES  8
#define AEGIS_MAX_PROTECTED_PIDS   64  // max PIDs that can be added via IOCTL
#define AEGIS_MAX_IMAGE_NAME_LEN  260

// Default protected names (defined in driver.c; can switch to IOCTL later)
extern const wchar_t* AegisDefaultProtectedNames[];
extern const ULONG AegisDefaultProtectedCount;

// -----------------------------------------------
// Feature flags (for staged development and debugging)
// -----------------------------------------------
#define AEGIS_PROTECT_READ   1   // Block reads into protected process
#define AEGIS_PROTECT_WRITE  1   // Block writes into protected process
#define AEGIS_PROTECT_INJECT 1   // Block DLL/code injection (e.g. LoadLibrary image notify)

// -----------------------------------------------
// Debug
// -----------------------------------------------
#define AEGIS_DEBUG_PRINT 1
#if defined(AEGIS_DEBUG_PRINT) && (defined(DBG) || defined(_DEBUG))
#define AegisDbgPrint(_x_) DbgPrint _x_
#else
#define AegisDbgPrint(_x_) ((void)0)
#endif

#ifdef __cplusplus
}
#endif
