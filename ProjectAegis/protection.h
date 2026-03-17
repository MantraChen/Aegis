#pragma once

//
// Project Aegis - Protection API
// Process protection: block read, write, injection.
//

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------
// Protected list (internal use)
// -----------------------------------------------
NTSTATUS AegisProtectionInitialize(void);
void AegisProtectionUninitialize(void);

// True if the given process is in the protected set (by object, PID, or image name)
BOOLEAN AegisIsProcessProtected(PEPROCESS Process);
BOOLEAN AegisIsProcessProtectedByPid(HANDLE Pid);
BOOLEAN AegisIsProcessProtectedByImageName(PCUNICODE_STRING ImageName);

// True if (Pid, Address) falls inside any registered protected range (interval tree, O(log N))
BOOLEAN AegisIsAddressInProtectedRange(ULONG Pid, ULONG_PTR Address);

// -----------------------------------------------
// Callback registration (called from driver.c in DriverEntry/Unload)
// -----------------------------------------------
NTSTATUS AegisRegisterCallbacks(void);
void AegisUnregisterCallbacks(void);

#ifdef __cplusplus
}
#endif
