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

// -----------------------------------------------
// Input: protect / unprotect by PID
// -----------------------------------------------
typedef struct _AEGIS_PID_INPUT {
    ULONG Pid;
} AEGIS_PID_INPUT, *PAEGIS_PID_INPUT;

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

typedef struct _AEGIS_VAD_SCAN_OUTPUT {
    ULONG           StatusCode;   // 0 = success
    ULONG           Count;       // number of entries in Entries[]
    AEGIS_VAD_ENTRY Entries[AEGIS_MAX_VAD_SCAN_ENTRIES];
} AEGIS_VAD_SCAN_OUTPUT, *PAEGIS_VAD_SCAN_OUTPUT;

#endif
