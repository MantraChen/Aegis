#pragma once

//
// Project Aegis - IOCTL codes and structures shared between driver (Ring 0) and client (Ring 3).
// Include this from both kernel and user mode; use _KERNEL_MODE to switch includes.
//

#ifndef AEGIS_SHARED_IOCTL_H
#define AEGIS_SHARED_IOCTL_H

#ifdef _KERNEL_MODE
#include <wdm.h>
#elif defined(_WIN32)
#include <Windows.h>
#else
/* Non-Windows (e.g. macOS/IDE): minimal types so the header parses without Windows SDK */
typedef unsigned long ULONG;
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN  0x00000022
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED      0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS      0
#endif
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#endif

// -----------------------------------------------
// IOCTL codes (METHOD_BUFFERED: kernel copies in/out buffers)
// -----------------------------------------------
#define IOCTL_AEGIS_PROTECT_PID    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_UNPROTECT_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_GET_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_SCAN_VAD      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_ADD_RANGE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_REMOVE_RANGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_SET_POLICY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -----------------------------------------------
// Input: protect / unprotect by PID
// -----------------------------------------------
typedef struct _AEGIS_PID_INPUT {
    ULONG Pid;
} AEGIS_PID_INPUT, *PAEGIS_PID_INPUT;

// -----------------------------------------------
// Input: add/remove protected memory range [Low, High) for a process (interval tree)
// -----------------------------------------------
typedef struct _AEGIS_RANGE_INPUT {
    ULONG    Pid;
    ULONG_PTR Low;   // inclusive
    ULONG_PTR High;  // exclusive: interval [Low, High)
} AEGIS_RANGE_INPUT, *PAEGIS_RANGE_INPUT;

// -----------------------------------------------
// Output: status (e.g. after GET_STATUS or returned in buffer for PROTECT/UNPROTECT)
// -----------------------------------------------
typedef struct _AEGIS_STATUS_OUTPUT {
    ULONG StatusCode;      // 0 = success; otherwise error (e.g. NTSTATUS lower 32 bits)
    ULONG ProtectedCount;  // number of PIDs currently protected (for GET_STATUS)
} AEGIS_STATUS_OUTPUT, *PAEGIS_STATUS_OUTPUT;

// -----------------------------------------------
// Phase 4: VAD scan – one suspicious region (unbacked RWX)
// -----------------------------------------------
#define AEGIS_MAX_VAD_SCAN_ENTRIES  64

typedef struct _AEGIS_VAD_ENTRY {
    ULONG_PTR BaseAddress;
    SIZE_T    RegionSize;
    ULONG     Protect;     // e.g. PAGE_EXECUTE_READWRITE
    ULONG     Type;        // MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE
} AEGIS_VAD_ENTRY, *PAEGIS_VAD_ENTRY;

// PTE-VAD discrepancy: one record (VAD said non-executable, but PTE allows execute)
#define AEGIS_MAX_PTE_DISCREPANCY  16
typedef struct _AEGIS_PTE_DISCREPANCY {
    ULONG_PTR Va;        // virtual address of the page
    ULONG     VadProtect; // protection from ZwQueryVirtualMemory
    ULONG64   PteValue;   // raw PTE from page table walk
} AEGIS_PTE_DISCREPANCY, *PAEGIS_PTE_DISCREPANCY;

typedef struct _AEGIS_VAD_SCAN_OUTPUT {
    ULONG                 StatusCode;   // 0 = success
    ULONG                 Count;       // number of entries in Entries[]
    ULONG                 DiscrepancyCount;  // PTE vs VAD mismatch (VAD says no-exec, PTE has NX clear)
    AEGIS_VAD_ENTRY       Entries[AEGIS_MAX_VAD_SCAN_ENTRIES];
    AEGIS_PTE_DISCREPANCY Discrepancies[AEGIS_MAX_PTE_DISCREPANCY];
} AEGIS_VAD_SCAN_OUTPUT, *PAEGIS_VAD_SCAN_OUTPUT;

// -----------------------------------------------
// Dynamic policy (Phase 5): blacklist/whitelist from Ring 3 (no encryption in this version)
// Layout must match config.h limits (AEGIS_MAX_BLACKLIST_NAMES, AEGIS_MAX_WHITELIST_NAMES, AEGIS_MAX_BLACKLIST_DLL).
// Optional: layer HMAC/signature verification on top for production.
// -----------------------------------------------
#define AEGIS_POLICY_MAX_BLACKLIST   16
#define AEGIS_POLICY_MAX_WHITELIST   24
#define AEGIS_POLICY_MAX_DLL_BLACK   32
#define AEGIS_POLICY_IMAGE_LEN       260   /* WCHAR count for process/DLL names */
#define AEGIS_POLICY_WHITELIST_LEN   16    /* CHAR count for PsGetProcessImageFileName (often 15) */

typedef struct _AEGIS_POLICY_INPUT {
    ULONG ProcessBlacklistCount;
    ULONG ProcessWhitelistCount;
    ULONG DllBlacklistCount;
    /* Process blacklist: Unicode names to block from starting (process notify) */
    WCHAR ProcessBlacklist[AEGIS_POLICY_MAX_BLACKLIST][AEGIS_POLICY_IMAGE_LEN];
    /* Process whitelist: ASCII names allowed full handle access to protected process/thread */
    CHAR  ProcessWhitelist[AEGIS_POLICY_MAX_WHITELIST][AEGIS_POLICY_WHITELIST_LEN];
    /* DLL blacklist: Unicode names to treat as blacklisted in LoadImageNotify (Bloom + exact match) */
    WCHAR DllBlacklist[AEGIS_POLICY_MAX_DLL_BLACK][AEGIS_POLICY_IMAGE_LEN];
} AEGIS_POLICY_INPUT, *PAEGIS_POLICY_INPUT;

#endif
