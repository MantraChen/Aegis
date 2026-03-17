//
// Project Aegis - Kernel driver main module
// Minimal anti-cheat: protect designated processes from read, write, and injection.
// Target: Windows 10/11 x64. Must be developed and tested in a VM.
//

#include <ntddk.h>
#include "config.h"
#include "protection.h"

// -----------------------------------------------
// Default protected process name list (matches extern in config.h)
// -----------------------------------------------
const wchar_t* AegisDefaultProtectedNames[] = {
    L"GameClient.exe",
    L"TestProtected.exe",
};
const ULONG AegisDefaultProtectedCount = sizeof(AegisDefaultProtectedNames) / sizeof(AegisDefaultProtectedNames[0]);

// -----------------------------------------------
// Process create/exit notify (for protected list and future hooks)
// -----------------------------------------------
static void AegisProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static BOOLEAN g_AegisCallbacksRegistered = FALSE;

// -----------------------------------------------
// DriverEntry / Unload
// -----------------------------------------------
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    AegisDbgPrint(("[Aegis] DriverEntry\n"));

    status = AegisProtectionInitialize();
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] AegisProtectionInitialize failed: 0x%X\n", status));
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status));
        AegisProtectionUninitialize();
        return status;
    }
    g_AegisCallbacksRegistered = TRUE;

    status = AegisRegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] AegisRegisterCallbacks failed: 0x%X\n", status));
        if (g_AegisCallbacksRegistered) {
            PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, TRUE);
            g_AegisCallbacksRegistered = FALSE;
        }
        AegisProtectionUninitialize();
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    AegisDbgPrint(("[Aegis] DriverEntry OK\n"));
    return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    AegisDbgPrint(("[Aegis] DriverUnload\n"));

    AegisUnregisterCallbacks();

    if (g_AegisCallbacksRegistered) {
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, TRUE);
        g_AegisCallbacksRegistered = FALSE;
    }

    AegisProtectionUninitialize();
    AegisDbgPrint(("[Aegis] DriverUnload done\n"));
}

// -----------------------------------------------
// Protection logic (skeleton; extend with Ob callbacks, memory/injection hooks)
// -----------------------------------------------
NTSTATUS AegisProtectionInitialize(void)
{
    // Currently uses default list only; later: registry or IOCTL config
    return STATUS_SUCCESS;
}

void AegisProtectionUninitialize(void)
{
    // Release protected list etc. (no dynamic allocation in this skeleton)
}

BOOLEAN AegisIsProcessProtected(PEPROCESS Process)
{
    HANDLE pid;
    if (Process == NULL) return FALSE;
    pid = PsGetProcessId(Process);
    return AegisIsProcessProtectedByPid(pid);
}

BOOLEAN AegisIsProcessProtectedByPid(HANDLE Pid)
{
    UNREFERENCED_PARAMETER(Pid);
    // Skeleton: full impl would maintain PID <-> image name mapping
    return FALSE;
}

BOOLEAN AegisIsProcessProtectedByImageName(PCUNICODE_STRING ImageName)
{
    ULONG i;
    if (ImageName == NULL || ImageName->Buffer == NULL) return FALSE;
    for (i = 0; i < AegisDefaultProtectedCount; i++) {
        UNICODE_STRING u;
        RtlInitUnicodeString(&u, AegisDefaultProtectedNames[i]);
        if (RtlCompareUnicodeString(ImageName, &u, TRUE) == 0)
            return TRUE;
    }
    return FALSE;
}

NTSTATUS AegisRegisterCallbacks(void)
{
    // Stub: ObRegisterCallbacks (handle restrict), PsSetLoadImageNotifyRoutine (DLL inject), etc.
    return STATUS_SUCCESS;
}

void AegisUnregisterCallbacks(void)
{
    // Paired with AegisRegisterCallbacks
}

// -----------------------------------------------
// Process notify implementation
// -----------------------------------------------
static void AegisProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo != NULL && CreateInfo->ImageFileName != NULL) {
        if (AegisIsProcessProtectedByImageName(CreateInfo->ImageFileName)) {
            AegisDbgPrint(("[Aegis] Protected process created: %wZ\n", CreateInfo->ImageFileName));
            // Optional: extra init here (Ob callbacks, memory protection, etc.)
        }
    }
}
