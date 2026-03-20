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
#define AEGIS_MAX_RANGE_CONTEXTS  64  // max (PID -> interval tree) entries for memory range protection
#define AEGIS_MAX_RANGES_PER_PID  256 // max intervals per process (cap for O(log N) tree depth)
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
// Hypervisor / EPT integration
// -----------------------------------------------
// 未来如果 Project Aegis 进化为 Hypervisor，可以把 AEGIS_HAS_HYPERVISOR 置为 1，
// 并在驱动或外部组件中实现基于 EPT 的 PTE 查询逻辑，取代纯 Guest PTE Walk。
#define AEGIS_HAS_HYPERVISOR 0

// -----------------------------------------------
// EPROCESS -> DirectoryTableBase (CR3) offset
// -----------------------------------------------
// 当你通过特征码扫描/符号信息确定 EPROCESS 中 DirectoryTableBase 的偏移后，
// 可以把 AEGIS_HAS_EPROCESS_CR3_OFFSET 设为 1，并设置正确的 AEGIS_EPROCESS_CR3_OFFSET，
// 这样 AegisGetProcessCr3 就会直接从 EPROCESS 读取 CR3，而不再使用 KeStackAttachProcess。
// 注意：该偏移与系统版本强相关，Windows 小版本/补丁都可能变化。生产环境建议：
// 1) 动态解析偏移（符号/特征码）；
// 2) 保留运行时校验与安全回退路径（当前 driver.c 已包含回退到 attach 读 CR3 的逻辑）。
#define AEGIS_HAS_EPROCESS_CR3_OFFSET   0
#define AEGIS_EPROCESS_CR3_OFFSET       0x0

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
