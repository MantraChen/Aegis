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
#define AEGIS_MAX_BLACKLIST_NAMES  16  // process names to block (e.g. cheat tools)
#define AEGIS_MAX_WHITELIST_NAMES  24  // process names allowed to open protected process with full access (Phase 3)

// Bloom filter for O(1) DLL / feature matching (succinct probabilistic structure)
#define AEGIS_BLOOM_BITS           1024   // bit array size (power of 2)
#define AEGIS_BLOOM_HASHES         7      // number of hash functions (Kirsch–Mitzenmacher)
#define AEGIS_MAX_BLACKLIST_DLL    32     // max blacklisted DLL names to add to filter

// Default protected names (defined in driver.c; can switch to IOCTL later)
extern const wchar_t* AegisDefaultProtectedNames[];
extern const ULONG AegisDefaultProtectedCount;

// Blacklist: processes that are blocked from starting (Phase 2 - process notify)
extern const wchar_t* AegisBlacklistProcessNames[];
extern const ULONG AegisBlacklistProcessCount;

// Whitelist: processes allowed to open protected process with full access (Phase 3 - Ob callbacks)
// Narrow string to match PsGetProcessImageFileName() output (ASCII, may be truncated to 15 chars on some builds)
extern const char* AegisWhitelistProcessNames[];
extern const ULONG AegisWhitelistProcessCount;

// Blacklist DLL names (hashed into Bloom filter at init; checked in LoadImageNotify)
extern const wchar_t* AegisBlacklistDllNames[];
extern const ULONG AegisBlacklistDllCount;

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
