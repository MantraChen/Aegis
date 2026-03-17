//
// Project Aegis - Kernel driver main module
// Phase 1: IOCTL; Phase 2: process/thread/image callbacks (no SSDT hook).
// Target: Windows 10/11 x64. Develop and test in a VM; use dual-machine debugging.
//

#include <ntddk.h>
#include <ntifs.h>
#include "config.h"
#include "protection.h"
#include "shared_ioctl.h"

/* Phase 4: VAD-style scan – unbacked RWX detection */
#define PAGE_EXECUTE_READWRITE  0x40
#define MEM_IMAGE               0x100000

/* Task 2 (optional): CR3 / page table – see docs/Phase4-CR3-PageTables.md.
 * To read current process CR3 when attached: KeStackAttachProcess(Process, &apcState); cr3 = __readcr3(); KeUnstackDetachProcess(&apcState). */

#define AEGIS_DEVICE_NAME   L"\\Device\\ProjectAegis"
#define AEGIS_LINK_NAME     L"\\DosDevices\\ProjectAegis"

// -----------------------------------------------
// Default protected process name list (matches extern in config.h)
// -----------------------------------------------
const wchar_t* AegisDefaultProtectedNames[] = {
    L"GameClient.exe",
    L"TestProtected.exe",
};
const ULONG AegisDefaultProtectedCount = sizeof(AegisDefaultProtectedNames) / sizeof(AegisDefaultProtectedNames[0]);

// -----------------------------------------------
// Blacklist: cheat/debug tools to block from starting (Phase 2 - process notify)
// -----------------------------------------------
const wchar_t* AegisBlacklistProcessNames[] = {
    L"cheatengine-x86_64.exe",
    L"cheatengine-i386.exe",
    L"Cheat Engine.exe",
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"ollydbg.exe",
};
const ULONG AegisBlacklistProcessCount = sizeof(AegisBlacklistProcessNames) / sizeof(AegisBlacklistProcessNames[0]);

// -----------------------------------------------
// Whitelist: processes allowed to open protected process with full access (Phase 3 - Ob callbacks)
// ASCII to match PsGetProcessImageFileName(); system + anti-cheat service
// -----------------------------------------------
const char* AegisWhitelistProcessNames[] = {
    "System",
    "csrss.exe",
    "services.exe",
    "wininit.exe",
    "lsass.exe",
    "svchost.exe",
    "AegisClient.exe",
    "GameClient.exe",   /* game itself may open its own handle in some flows */
    "TestProtected.exe",
};
const ULONG AegisWhitelistProcessCount = sizeof(AegisWhitelistProcessNames) / sizeof(AegisWhitelistProcessNames[0]);

// -----------------------------------------------
// PID list (dynamic via IOCTL); protected PIDs added by user-mode client
// -----------------------------------------------
static ULONG g_ProtectedPids[AEGIS_MAX_PROTECTED_PIDS];
static ULONG g_ProtectedPidCount = 0;
static KSPIN_LOCK g_PidListLock;

// -----------------------------------------------
// Device and IRP dispatch
// -----------------------------------------------
static PDEVICE_OBJECT g_AegisDeviceObject = NULL;

static NTSTATUS AegisDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
static NTSTATUS AegisDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
static NTSTATUS AegisDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

static void AegisProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);
static void AegisThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
static void AegisLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);
static BOOLEAN g_AegisProcessNotifyRegistered = FALSE;
static BOOLEAN g_AegisThreadNotifyRegistered = FALSE;
static BOOLEAN g_AegisImageNotifyRegistered = FALSE;
static PVOID g_ObCallbackHandle = NULL;

static BOOLEAN AegisIsProcessBlacklisted(PCUNICODE_STRING ImageName);
static BOOLEAN AegisIsProcessWhitelisted(PEPROCESS Process);
static NTSTATUS AegisScanProcessVad(_In_ ULONG Pid, _Out_ PAEGIS_VAD_SCAN_OUTPUT Output);
static OB_PREOP_CALLBACK_STATUS AegisObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

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
    UNICODE_STRING deviceName;
    UNICODE_STRING linkName;

    AegisDbgPrint(("[Aegis] DriverEntry - Hello World\n"));

    status = AegisProtectionInitialize();
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] AegisProtectionInitialize failed: 0x%X\n", status));
        return status;
    }

    RtlInitUnicodeString(&deviceName, AEGIS_DEVICE_NAME);
    RtlInitUnicodeString(&linkName, AEGIS_LINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_AegisDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] IoCreateDevice failed: 0x%X\n", status));
        AegisProtectionUninitialize();
        return status;
    }

    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] IoCreateSymbolicLink failed: 0x%X\n", status));
        IoDeleteDevice(g_AegisDeviceObject);
        g_AegisDeviceObject = NULL;
        AegisProtectionUninitialize();
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AegisDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisDispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status));
        IoDeleteSymbolicLink(&linkName);
        IoDeleteDevice(g_AegisDeviceObject);
        g_AegisDeviceObject = NULL;
        AegisProtectionUninitialize();
        return status;
    }
    g_AegisProcessNotifyRegistered = TRUE;

    status = AegisRegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] AegisRegisterCallbacks failed: 0x%X\n", status));
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, TRUE);
        g_AegisProcessNotifyRegistered = FALSE;
        IoDeleteSymbolicLink(&linkName);
        IoDeleteDevice(g_AegisDeviceObject);
        g_AegisDeviceObject = NULL;
        AegisProtectionUninitialize();
        return status;
    }

    AegisDbgPrint(("[Aegis] DriverEntry OK; device \\Device\\ProjectAegis\n"));
    return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING linkName;

    AegisDbgPrint(("[Aegis] DriverUnload\n"));

    AegisUnregisterCallbacks();
    if (g_AegisProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyCallback, TRUE);
        g_AegisProcessNotifyRegistered = FALSE;
    }

    RtlInitUnicodeString(&linkName, AEGIS_LINK_NAME);
    IoDeleteSymbolicLink(&linkName);
    if (g_AegisDeviceObject) {
        IoDeleteDevice(g_AegisDeviceObject);
        g_AegisDeviceObject = NULL;
    }

    AegisProtectionUninitialize();
    AegisDbgPrint(("[Aegis] DriverUnload done\n"));
}

// -----------------------------------------------
// IRP dispatch: Create, Close
// -----------------------------------------------
static NTSTATUS AegisDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS AegisDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// -----------------------------------------------
// IRP dispatch: DeviceControl (IOCTL)
// -----------------------------------------------
static NTSTATUS AegisDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG code;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inSize, outSize;
    PVOID inBuf, outBuf;
    AEGIS_STATUS_OUTPUT outData;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    code  = stack->Parameters.DeviceIoControl.IoControlCode;
    inSize  = stack->Parameters.DeviceIoControl.InputBufferLength;
    outSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    inBuf   = Irp->AssociatedIrp.SystemBuffer;
    outBuf  = Irp->AssociatedIrp.SystemBuffer;

    RtlZeroMemory(&outData, sizeof(outData));

    switch (code) {
    case IOCTL_AEGIS_PROTECT_PID: {
        PAEGIS_PID_INPUT in = (PAEGIS_PID_INPUT)inBuf;
        if (inSize < sizeof(AEGIS_PID_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        KeAcquireSpinLock(&g_PidListLock, &oldIrql);
        if (g_ProtectedPidCount >= AEGIS_MAX_PROTECTED_PIDS) {
            KeReleaseSpinLock(&g_PidListLock, oldIrql);
            status = STATUS_TOO_MANY_NAMES;
            outData.StatusCode = (ULONG)status;
            break;
        }
        g_ProtectedPids[g_ProtectedPidCount++] = in->Pid;
        outData.ProtectedCount = g_ProtectedPidCount;
        outData.StatusCode = 0;
        KeReleaseSpinLock(&g_PidListLock, oldIrql);
        AegisDbgPrint(("[Aegis] IOCTL protect PID %u; total %u\n", in->Pid, g_ProtectedPidCount));
        break;
    }
    case IOCTL_AEGIS_UNPROTECT_PID: {
        PAEGIS_PID_INPUT in = (PAEGIS_PID_INPUT)inBuf;
        ULONG i, j;
        BOOLEAN found = FALSE;
        if (inSize < sizeof(AEGIS_PID_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        KeAcquireSpinLock(&g_PidListLock, &oldIrql);
        for (i = 0; i < g_ProtectedPidCount; i++) {
            if (g_ProtectedPids[i] == in->Pid) {
                for (j = i; j + 1 < g_ProtectedPidCount; j++)
                    g_ProtectedPids[j] = g_ProtectedPids[j + 1];
                g_ProtectedPidCount--;
                found = TRUE;
                break;
            }
        }
        outData.ProtectedCount = g_ProtectedPidCount;
        outData.StatusCode = found ? 0 : (ULONG)STATUS_NOT_FOUND;
        KeReleaseSpinLock(&g_PidListLock, oldIrql);
        AegisDbgPrint(("[Aegis] IOCTL unprotect PID %u; total %u\n", in->Pid, g_ProtectedPidCount));
        break;
    }
    case IOCTL_AEGIS_GET_STATUS:
        KeAcquireSpinLock(&g_PidListLock, &oldIrql);
        outData.ProtectedCount = g_ProtectedPidCount;
        outData.StatusCode = 0;
        KeReleaseSpinLock(&g_PidListLock, oldIrql);
        if (outSize < sizeof(AEGIS_STATUS_OUTPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(outBuf, &outData, sizeof(outData));
        Irp->IoStatus.Information = sizeof(AEGIS_STATUS_OUTPUT);
        break;
    case IOCTL_AEGIS_SCAN_VAD: {
        PAEGIS_PID_INPUT in = (PAEGIS_PID_INPUT)inBuf;
        PAEGIS_VAD_SCAN_OUTPUT out = (PAEGIS_VAD_SCAN_OUTPUT)outBuf;
        if (inSize < sizeof(AEGIS_PID_INPUT) || in == NULL || outSize < sizeof(AEGIS_VAD_SCAN_OUTPUT) || out == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(out, sizeof(AEGIS_VAD_SCAN_OUTPUT));
        status = AegisScanProcessVad(in->Pid, out);
        if (NT_SUCCESS(status))
            Irp->IoStatus.Information = sizeof(AEGIS_VAD_SCAN_OUTPUT);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        outData.StatusCode = (ULONG)status;
        break;
    }

    if (code != IOCTL_AEGIS_GET_STATUS && code != IOCTL_AEGIS_SCAN_VAD && outSize >= sizeof(AEGIS_STATUS_OUTPUT)) {
        RtlCopyMemory(outBuf, &outData, sizeof(outData));
        Irp->IoStatus.Information = sizeof(AEGIS_STATUS_OUTPUT);
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// -----------------------------------------------
// Phase 4: VAD-style scan – enumerate VM regions, flag unbacked RWX (manual map heuristic)
// -----------------------------------------------
static NTSTATUS AegisScanProcessVad(_In_ ULONG Pid, _Out_ PAEGIS_VAD_SCAN_OUTPUT Output)
{
    NTSTATUS status;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    PVOID baseAddress = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T retLen;
    ULONG count = 0;

    if (Output == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Output, sizeof(AEGIS_VAD_SCAN_OUTPUT));

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)Pid;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        Output->StatusCode = (ULONG)status;
        return status;
    }

    for (;;) {
        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            processHandle,
            baseAddress,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &retLen
        );
        if (!NT_SUCCESS(status))
            break;

        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_EXECUTE_READWRITE &&
            mbi.Type != MEM_IMAGE) {
            /* Unbacked RWX – typical manual map / shellcode injection */
            if (count < AEGIS_MAX_VAD_SCAN_ENTRIES) {
                Output->Entries[count].BaseAddress = (ULONG_PTR)mbi.BaseAddress;
                Output->Entries[count].RegionSize = mbi.RegionSize;
                Output->Entries[count].Protect = mbi.Protect;
                Output->Entries[count].Type = mbi.Type;
                count++;
            }
            AegisDbgPrint(("[Aegis] VAD scan PID %u: suspicious RWX unbacked at %p size %Iu\n",
                Pid, mbi.BaseAddress, mbi.RegionSize));
        }

        baseAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)baseAddress < (ULONG_PTR)mbi.BaseAddress || (ULONG_PTR)baseAddress > 0x7FFFFFFFFFFFULL)
            break;
    }

    ZwClose(processHandle);
    Output->StatusCode = 0;
    Output->Count = count;
    return STATUS_SUCCESS;
}

// -----------------------------------------------
// Protection logic: PID list + name list
// -----------------------------------------------
NTSTATUS AegisProtectionInitialize(void)
{
    KeInitializeSpinLock(&g_PidListLock);
    g_ProtectedPidCount = 0;
    return STATUS_SUCCESS;
}

void AegisProtectionUninitialize(void)
{
    g_ProtectedPidCount = 0;
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
    ULONG i;
    ULONG pidVal = (ULONG)(ULONG_PTR)Pid;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    for (i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPids[i] == pidVal) {
            KeReleaseSpinLock(&g_PidListLock, oldIrql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_PidListLock, oldIrql);
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
    NTSTATUS status;
    UNICODE_STRING altitude;
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION obOpReg[1];

    status = PsSetCreateThreadNotifyRoutine(AegisThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", status));
        return status;
    }
    g_AegisThreadNotifyRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(AegisLoadImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status));
        PsRemoveCreateThreadNotifyRoutine(AegisThreadNotifyCallback);
        g_AegisThreadNotifyRegistered = FALSE;
        return status;
    }
    g_AegisImageNotifyRegistered = TRUE;

    /* Phase 3: ObRegisterCallbacks for process handle create/duplicate */
    RtlInitUnicodeString(&altitude, L"320000.123");
    obOpReg[0].ObjectType = PsProcessType;
    obOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg[0].PreOperation = AegisObPreOperationCallback;
    obOpReg[0].PostOperation = NULL;
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    obReg.Altitude = altitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = obOpReg;

    status = ObRegisterCallbacks(&obReg, &g_ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        AegisDbgPrint(("[Aegis] ObRegisterCallbacks failed: 0x%X\n", status));
        PsRemoveLoadImageNotifyRoutine(AegisLoadImageNotifyCallback);
        g_AegisImageNotifyRegistered = FALSE;
        PsRemoveCreateThreadNotifyRoutine(AegisThreadNotifyCallback);
        g_AegisThreadNotifyRegistered = FALSE;
        return status;
    }

    return STATUS_SUCCESS;
}

void AegisUnregisterCallbacks(void)
{
    if (g_ObCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }
    if (g_AegisImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(AegisLoadImageNotifyCallback);
        g_AegisImageNotifyRegistered = FALSE;
    }
    if (g_AegisThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(AegisThreadNotifyCallback);
        g_AegisThreadNotifyRegistered = FALSE;
    }
}

// -----------------------------------------------
// Phase 3: Ob pre-callback – strip handle rights for non-whitelisted openers of protected process
// -----------------------------------------------
static BOOLEAN AegisIsProcessWhitelisted(PEPROCESS Process)
{
    ULONG i;
    const char* imageName;

    if (Process == NULL) return FALSE;
    imageName = PsGetProcessImageFileName(Process);
    if (imageName == NULL) return FALSE;

    for (i = 0; i < AegisWhitelistProcessCount; i++) {
        ANSI_STRING aCur, aList;
        RtlInitAnsiString(&aCur, imageName);
        RtlInitAnsiString(&aList, (PCHAR)AegisWhitelistProcessNames[i]);
        if (RtlCompareString(&aCur, &aList, TRUE) == 0)
            return TRUE;
    }
    return FALSE;
}

static OB_PREOP_CALLBACK_STATUS AegisObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    PEPROCESS targetProcess;
    PEPROCESS creatorProcess;
    PACCESS_MASK pDesiredAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->ObjectType != PsProcessType)
        return OB_PREOP_SUCCESS;

    targetProcess = (PEPROCESS)OperationInformation->Object;
    if (!AegisIsProcessProtected(targetProcess))
        return OB_PREOP_SUCCESS;

    creatorProcess = PsGetCurrentProcess();
    if (AegisIsProcessWhitelisted(creatorProcess))
        return OB_PREOP_SUCCESS;

    /* Non-whitelisted process opening/duplicating handle to protected process – strip to query-only */
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        pDesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    *pDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
    AegisDbgPrint(("[Aegis] Ob: stripped handle access for PID %p -> protected process\n", PsGetCurrentProcessId()));

    return OB_PREOP_SUCCESS;
}

// -----------------------------------------------
// Task 1: Process notify – blacklist and block; log protected process creation
// -----------------------------------------------
static BOOLEAN AegisIsProcessBlacklisted(PCUNICODE_STRING ImageName)
{
    ULONG i;
    if (ImageName == NULL || ImageName->Buffer == NULL) return FALSE;
    for (i = 0; i < AegisBlacklistProcessCount; i++) {
        UNICODE_STRING u;
        RtlInitUnicodeString(&u, AegisBlacklistProcessNames[i]);
        if (RtlCompareUnicodeString(ImageName, &u, TRUE) == 0)
            return TRUE;
    }
    return FALSE;
}

static void AegisProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == NULL)
        return;

    if (CreateInfo->ImageFileName != NULL) {
        if (AegisIsProcessBlacklisted(CreateInfo->ImageFileName)) {
            AegisDbgPrint(("[Aegis] Blocking blacklisted process: %wZ\n", CreateInfo->ImageFileName));
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
        if (AegisIsProcessProtectedByImageName(CreateInfo->ImageFileName)) {
            AegisDbgPrint(("[Aegis] Protected process created: %wZ\n", CreateInfo->ImageFileName));
        }
    }
}

// -----------------------------------------------
// Task 2: Thread notify – detect and terminate remote threads in protected processes
// -----------------------------------------------
static void AegisThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    HANDLE threadHandle = NULL;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;

    if (!Create)
        return;
    if (!AegisIsProcessProtectedByPid(ProcessId))
        return;
    /* Remote thread: creator is not the process that owns the new thread. */
    if (PsGetCurrentProcessId() == ProcessId)
        return;

    AegisDbgPrint(("[Aegis] Remote thread in protected process PID %p TID %p – terminating\n", ProcessId, ThreadId));

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = ThreadId;

    if (!NT_SUCCESS(ZwOpenThread(&threadHandle, THREAD_TERMINATE, &oa, &cid)))
        return;
    ZwTerminateThread(threadHandle, STATUS_ACCESS_DENIED);
    ZwClose(threadHandle);
}

// -----------------------------------------------
// Task 3: Load image notify – log DLL loads into protected process
// -----------------------------------------------
static void AegisLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    if (FullImageName == NULL || ImageInfo == NULL)
        return;
    if (!AegisIsProcessProtectedByPid(ProcessId))
        return;
    /* Log any image load (exe or DLL) into protected process; typical injection is DLL. */
    AegisDbgPrint(("[Aegis] Image loaded into protected PID %p: %wZ (base %p)\n",
        ProcessId, FullImageName, ImageInfo->ImageBase));
}
