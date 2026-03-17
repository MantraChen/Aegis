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
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_WRITECOPY  0x80
#define MEM_IMAGE               0x100000

/* PTE walk: x64 four-level paging (PML4 -> PDPT -> PD -> PT); NX = bit 63 */
#define AEGIS_PAGE_SIZE         0x1000
#define AEGIS_PTE_NX            (1ULL << 63)
#define AEGIS_PTE_PRESENT       1ULL
#define AEGIS_PDE_PS            (1ULL << 7)   /* 2MB page */
#define AEGIS_PFN_MASK          0x000FFFFFFFFFF000ULL
#define AEGIS_VA_PML4_I(va)     (((va) >> 39) & 0x1FF)
#define AEGIS_VA_PDPT_I(va)     (((va) >> 30) & 0x1FF)
#define AEGIS_VA_PD_I(va)       (((va) >> 21) & 0x1FF)
#define AEGIS_VA_PT_I(va)       (((va) >> 12) & 0x1FF)
#define AEGIS_USER_VA_MAX       0x00007FFFFFFFFFFFULL

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
// Blacklist DLL names – hashed into Bloom filter at init; O(1) check in LoadImageNotify (config.h extern)
// -----------------------------------------------
const wchar_t* AegisBlacklistDllNames[] = {
    L"cheat.dll",
    L"inject.dll",
    L"hook.dll",
    L"speedhack.dll",
    L"gamehack.dll",
    L"bypass.dll",
};
const ULONG AegisBlacklistDllCount = sizeof(AegisBlacklistDllNames) / sizeof(AegisBlacklistDllNames[0]);

// -----------------------------------------------
// Bloom filter – succinct probabilistic set; ~128 bytes, O(k) query/add (k = 7)
// -----------------------------------------------
#define AEGIS_BLOOM_MASK  (AEGIS_BLOOM_BITS - 1)
static UCHAR g_BloomFilter[AEGIS_BLOOM_BITS / 8];

static ULONG AegisBloomHash(_In_reads_bytes_(Len) const UCHAR* Data, ULONG Len, ULONG Seed)
{
    ULONG h = (Seed != 0) ? Seed : 0x811c9dc5u;  /* FNV-1a offset */
    ULONG i;
    for (i = 0; i < Len; i++) {
        h ^= Data[i];
        h *= 0x01000193u;  /* FNV prime */
    }
    return h;
}

static void AegisBloomSetBit(ULONG Index)
{
    ULONG byteIdx = Index / 8;
    ULONG bitIdx = Index % 8;
    if (byteIdx < (AEGIS_BLOOM_BITS / 8))
        g_BloomFilter[byteIdx] |= (UCHAR)(1u << bitIdx);
}

static BOOLEAN AegisBloomTestBit(ULONG Index)
{
    ULONG byteIdx = Index / 8;
    ULONG bitIdx = Index % 8;
    if (byteIdx >= (AEGIS_BLOOM_BITS / 8)) return FALSE;
    return (g_BloomFilter[byteIdx] & (UCHAR)(1u << bitIdx)) != 0;
}

static void AegisBloomAdd(_In_reads_bytes_(Len) const UCHAR* Data, ULONG Len)
{
    ULONG h1 = AegisBloomHash(Data, Len, 0);
    ULONG h2 = AegisBloomHash(Data, Len, 0x9e3779b9u);
    ULONG i;
    for (i = 0; i < AEGIS_BLOOM_HASHES; i++) {
        ULONG idx = (h1 + i * h2) & AEGIS_BLOOM_MASK;
        AegisBloomSetBit(idx);
    }
}

/* Returns TRUE if key is *possibly* in the set (may have false positives). */
static BOOLEAN AegisBloomQuery(_In_reads_bytes_(Len) const UCHAR* Data, ULONG Len)
{
    ULONG h1 = AegisBloomHash(Data, Len, 0);
    ULONG h2 = AegisBloomHash(Data, Len, 0x9e3779b9u);
    ULONG i;
    for (i = 0; i < AEGIS_BLOOM_HASHES; i++) {
        ULONG idx = (h1 + i * h2) & AEGIS_BLOOM_MASK;
        if (!AegisBloomTestBit(idx))
            return FALSE;
    }
    return TRUE;
}

static void AegisBloomReset(void)
{
    RtlZeroMemory(g_BloomFilter, sizeof(g_BloomFilter));
}

/* Exact match (case-insensitive) against blacklist – used after Bloom filter hit to avoid FP. */
static BOOLEAN AegisIsDllBlacklisted(PCUNICODE_STRING DllName)
{
    ULONG i;
    if (DllName == NULL || DllName->Buffer == NULL) return FALSE;
    for (i = 0; i < AegisBlacklistDllCount; i++) {
        UNICODE_STRING u;
        RtlInitUnicodeString(&u, AegisBlacklistDllNames[i]);
        if (RtlCompareUnicodeString(DllName, &u, TRUE) == 0)
            return TRUE;
    }
    return FALSE;
}

// -----------------------------------------------
// PID list (dynamic via IOCTL) – lock-free for read path (Ob/thread/image callbacks)
// Writers (IOCTL) use InterlockedCompareExchange; readers just read the array (no lock).
// -----------------------------------------------
static volatile ULONG g_ProtectedPids[AEGIS_MAX_PROTECTED_PIDS];
static volatile LONG g_ProtectedPidCount = 0;

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
static ULONG64 AegisGetProcessCr3(_In_ PEPROCESS Process);
static ULONG64 AegisReadPhysical(ULONG64 Pa);
static ULONG64 AegisPteWalk(ULONG64 Pml4Pa, ULONG_PTR Va);
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
        ULONG i;
        BOOLEAN inserted = FALSE;
        if (inSize < sizeof(AEGIS_PID_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        /* Already in list? (lock-free read) */
        for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++) {
            if (g_ProtectedPids[i] == in->Pid) {
                outData.ProtectedCount = (ULONG)InterlockedOr(&g_ProtectedPidCount, 0);
                outData.StatusCode = 0;
                inserted = TRUE;
                break;
            }
        }
        if (!inserted) {
            for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++) {
                if (InterlockedCompareExchange((LONG*)&g_ProtectedPids[i], (LONG)in->Pid, 0) == 0) {
                    InterlockedIncrement(&g_ProtectedPidCount);
                    outData.ProtectedCount = (ULONG)InterlockedOr(&g_ProtectedPidCount, 0);
                    outData.StatusCode = 0;
                    inserted = TRUE;
                    break;
                }
            }
        }
        if (!inserted) {
            status = STATUS_TOO_MANY_NAMES;
            outData.StatusCode = (ULONG)status;
            outData.ProtectedCount = (ULONG)InterlockedOr(&g_ProtectedPidCount, 0);
        }
        AegisDbgPrint(("[Aegis] IOCTL protect PID %u; total %u\n", in->Pid, outData.ProtectedCount));
        break;
    }
    case IOCTL_AEGIS_UNPROTECT_PID: {
        PAEGIS_PID_INPUT in = (PAEGIS_PID_INPUT)inBuf;
        ULONG i;
        BOOLEAN found = FALSE;
        if (inSize < sizeof(AEGIS_PID_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++) {
            if (InterlockedCompareExchange((LONG*)&g_ProtectedPids[i], 0, (LONG)in->Pid) == (LONG)in->Pid) {
                InterlockedDecrement(&g_ProtectedPidCount);
                found = TRUE;
                break;
            }
        }
        outData.ProtectedCount = (ULONG)InterlockedOr(&g_ProtectedPidCount, 0);
        outData.StatusCode = found ? 0 : (ULONG)STATUS_NOT_FOUND;
        AegisDbgPrint(("[Aegis] IOCTL unprotect PID %u; total %u\n", in->Pid, outData.ProtectedCount));
        break;
    }
    case IOCTL_AEGIS_GET_STATUS:
        outData.ProtectedCount = (ULONG)InterlockedOr(&g_ProtectedPidCount, 0);
        outData.StatusCode = 0;
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
// PTE walk: get CR3 (PML4 base) by attaching to process and reading CR3 register
// -----------------------------------------------
static ULONG64 AegisGetProcessCr3(_In_ PEPROCESS Process)
{
    KAPC_STATE apcState;
    ULONG64 cr3;

    if (Process == NULL) return 0;
    KeStackAttachProcess(Process, &apcState);
    cr3 = __readcr3();
    KeUnstackDetachProcess(&apcState);
    /* CR3 bits 12-51 = PML4 physical base (4-level paging) */
    return cr3 & AEGIS_PFN_MASK;
}

/* Map one physical page and read 8 bytes at Pa (must be 8-byte aligned). */
static ULONG64 AegisReadPhysical(ULONG64 Pa)
{
    PHYSICAL_ADDRESS phys;
    PVOID mapped;
    ULONG64 value;

    phys.QuadPart = (LONGLONG)(Pa & ~0xFFFULL);
    mapped = MmMapIoSpace(phys, AEGIS_PAGE_SIZE, MmNonCached);
    if (mapped == NULL) return 0;
    value = *(ULONG64*)((PUCHAR)mapped + (Pa & 0xFFF));
    MmUnmapIoSpace(mapped, AEGIS_PAGE_SIZE);
    return value;
}

/* Four-level walk: PML4 -> PDPT -> PD -> PT; return final PTE (or PDE for 2MB page). Returns 0 if not present. */
static ULONG64 AegisPteWalk(ULONG64 Pml4Pa, ULONG_PTR Va)
{
    ULONG64 e1, e2, e3, e4;
    ULONG64 pdpt_pa, pd_pa, pt_pa;

    if (Pml4Pa == 0 || (Va > AEGIS_USER_VA_MAX)) return 0;

    e1 = AegisReadPhysical(Pml4Pa + AEGIS_VA_PML4_I(Va) * 8);
    if (!(e1 & AEGIS_PTE_PRESENT)) return 0;
    pdpt_pa = e1 & AEGIS_PFN_MASK;

    e2 = AegisReadPhysical(pdpt_pa + AEGIS_VA_PDPT_I(Va) * 8);
    if (!(e2 & AEGIS_PTE_PRESENT)) return 0;
    pd_pa = e2 & AEGIS_PFN_MASK;

    e3 = AegisReadPhysical(pd_pa + AEGIS_VA_PD_I(Va) * 8);
    if (!(e3 & AEGIS_PTE_PRESENT)) return 0;
    if (e3 & AEGIS_PDE_PS)
        return e3;  /* 2MB page: PDE is the “PTE” for NX check */
    pt_pa = e3 & AEGIS_PFN_MASK;

    e4 = AegisReadPhysical(pt_pa + AEGIS_VA_PT_I(Va) * 8);
    return e4;
}

#define AEGIS_VAD_EXEC_MASK  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// -----------------------------------------------
// Phase 4: VAD scan + PTE walk – unbacked RWX and PTE-VAD discrepancy (hidden exec)
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
    ULONG discCount = 0;
    PEPROCESS processObject = NULL;
    ULONG64 cr3 = 0;

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

    status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_INFORMATION, PsProcessType, KernelMode, (PVOID*)&processObject, NULL);
    if (NT_SUCCESS(status) && processObject != NULL) {
        cr3 = AegisGetProcessCr3(processObject);
        ObDereferenceObject(processObject);
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

        /* PTE-VAD discrepancy: VAD says non-executable but PTE has NX clear (possible PTE tampering) */
        if (cr3 != 0 && mbi.State == MEM_COMMIT && discCount < AEGIS_MAX_PTE_DISCREPANCY) {
            if ((mbi.Protect & AEGIS_VAD_EXEC_MASK) == 0) {
                ULONG64 pte = AegisPteWalk(cr3, (ULONG_PTR)mbi.BaseAddress);
                if (pte != 0 && (pte & AEGIS_PTE_NX) == 0) {
                    Output->Discrepancies[discCount].Va = (ULONG_PTR)mbi.BaseAddress;
                    Output->Discrepancies[discCount].VadProtect = mbi.Protect;
                    Output->Discrepancies[discCount].PteValue = pte;
                    discCount++;
                    AegisDbgPrint(("[Aegis] PTE-VAD discrepancy PID %u: VA %p VAD protect 0x%X PTE 0x%llX (NX clear)\n",
                        Pid, mbi.BaseAddress, mbi.Protect, pte));
                }
            }
        }

        baseAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)baseAddress < (ULONG_PTR)mbi.BaseAddress || (ULONG_PTR)baseAddress > AEGIS_USER_VA_MAX)
            break;
    }

    ZwClose(processHandle);
    Output->StatusCode = 0;
    Output->Count = count;
    Output->DiscrepancyCount = discCount;
    return STATUS_SUCCESS;
}

// -----------------------------------------------
// Protection logic: PID list + name list
// -----------------------------------------------
NTSTATUS AegisProtectionInitialize(void)
{
    ULONG i;
    UNICODE_STRING u;

    InterlockedExchange(&g_ProtectedPidCount, 0);
    for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++)
        InterlockedExchange((LONG*)&g_ProtectedPids[i], 0);

    AegisBloomReset();
    for (i = 0; i < AegisBlacklistDllCount; i++) {
        RtlInitUnicodeString(&u, AegisBlacklistDllNames[i]);
        AegisBloomAdd((PUCHAR)u.Buffer, u.Length);
    }

    return STATUS_SUCCESS;
}

void AegisProtectionUninitialize(void)
{
    InterlockedExchange(&g_ProtectedPidCount, 0);
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
    /* Lock-free read: full array scan; each slot read is atomic (aligned ULONG on x64) */
    for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++) {
        if (g_ProtectedPids[i] == pidVal)
            return TRUE;
    }
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
// Task 3: Load image notify – O(1) Bloom filter hit, then exact blacklist check
// -----------------------------------------------
static void AegisLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    WCHAR fileBuf[AEGIS_MAX_IMAGE_NAME_LEN];
    WCHAR fileBufDown[AEGIS_MAX_IMAGE_NAME_LEN];
    UNICODE_STRING srcStr, destStr;
    PWCHAR p, last, filenameStart;
    USHORT filenameLenBytes;

    if (FullImageName == NULL || ImageInfo == NULL)
        return;
    if (!AegisIsProcessProtectedByPid(ProcessId))
        return;

    /* Extract last path component (filename) for Bloom query */
    if (FullImageName->Length == 0 || FullImageName->Buffer == NULL)
        goto log_only;
    last = (PWCHAR)((PUCHAR)FullImageName->Buffer + FullImageName->Length) - 1;
    if (last < FullImageName->Buffer)
        goto log_only;
    for (p = last; p >= FullImageName->Buffer; p--) {
        if (*p == L'\\') {
            p++;
            break;
        }
    }
    filenameStart = (p >= FullImageName->Buffer && *p != L'\\') ? p : FullImageName->Buffer;
    filenameLenBytes = (USHORT)((PUCHAR)(last + 1) - (PUCHAR)filenameStart);
    if (filenameLenBytes > (AEGIS_MAX_IMAGE_NAME_LEN - 1) * sizeof(WCHAR))
        filenameLenBytes = (USHORT)((AEGIS_MAX_IMAGE_NAME_LEN - 1) * sizeof(WCHAR));

    RtlZeroMemory(fileBuf, sizeof(fileBuf));
    RtlCopyMemory(fileBuf, filenameStart, filenameLenBytes);
    srcStr.Buffer = fileBuf;
    srcStr.Length = filenameLenBytes;
    srcStr.MaximumLength = (USHORT)sizeof(fileBuf);
    destStr.Buffer = fileBufDown;
    destStr.Length = 0;
    destStr.MaximumLength = (USHORT)sizeof(fileBufDown);
    if (RtlDowncaseUnicodeString(&destStr, &srcStr, FALSE) != STATUS_SUCCESS) {
        destStr.Buffer = fileBuf;
        destStr.Length = filenameLenBytes;
    }

    /* O(1) Bloom filter: if definitely not in set, skip blacklist check */
    if (!AegisBloomQuery((PUCHAR)destStr.Buffer, destStr.Length))
        goto log_only;

    /* Bloom said "maybe" – confirm with exact blacklist (avoids false positives) */
    if (AegisIsDllBlacklisted(&destStr)) {
        AegisDbgPrint(("[Aegis] BLACKLISTED DLL loaded into protected PID %p: %wZ (base %p)\n",
            ProcessId, FullImageName, ImageInfo->ImageBase));
        return;
    }

log_only:
    AegisDbgPrint(("[Aegis] Image loaded into protected PID %p: %wZ (base %p)\n",
        ProcessId, FullImageName, ImageInfo->ImageBase));
}
