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

/* Thread access rights for stripping (avoid THREAD_SET_CONTEXT / THREAD_SUSPEND_RESUME / APC injection) */
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION  (0x0800)
#endif

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
// Runtime policy (Phase 5): writable copy, init from defaults, updatable via IOCTL_AEGIS_SET_POLICY
// -----------------------------------------------
static AEGIS_POLICY_INPUT g_RuntimePolicy;
static KSPIN_LOCK g_PolicyLock;

static void AegisPolicyInitFromDefaults(void);
static void AegisPolicyRebuildBloom(void);

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

/* Add wide string to Bloom (length in bytes, up to first null or maxChars). */
static void AegisBloomAddWideString(const WCHAR* Buf, ULONG MaxChars)
{
    ULONG len = 0;
    while (len < MaxChars && Buf[len] != L'\0') len++;
    if (len > 0)
        AegisBloomAdd((const UCHAR*)Buf, len * sizeof(WCHAR));
}

/* Exact match (case-insensitive) against runtime DLL blacklist – used after Bloom filter hit. */
static BOOLEAN AegisIsDllBlacklisted(PCUNICODE_STRING DllName)
{
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    UNICODE_STRING u;

    if (DllName == NULL || DllName->Buffer == NULL) return FALSE;
    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    for (i = 0; i < g_RuntimePolicy.DllBlacklistCount && i < AEGIS_POLICY_MAX_DLL_BLACK; i++) {
        RtlInitUnicodeString(&u, g_RuntimePolicy.DllBlacklist[i]);
        if (u.Buffer != NULL && RtlCompareUnicodeString(DllName, &u, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
    return found;
}

static ULONG AegisWideLen(const WCHAR* s, ULONG max)
{
    ULONG i = 0;
    while (i < max && s[i] != L'\0') i++;
    return i;
}
static ULONG AegisAnsiLen(const char* s, ULONG max)
{
    ULONG i = 0;
    while (i < max && s[i] != '\0') i++;
    return i;
}

static void AegisPolicyInitFromDefaults(void)
{
    ULONG i;
    ULONG len;
    RtlZeroMemory(&g_RuntimePolicy, sizeof(g_RuntimePolicy));
    g_RuntimePolicy.ProcessBlacklistCount = (AegisBlacklistProcessCount <= AEGIS_POLICY_MAX_BLACKLIST)
        ? (ULONG)AegisBlacklistProcessCount : AEGIS_POLICY_MAX_BLACKLIST;
    for (i = 0; i < g_RuntimePolicy.ProcessBlacklistCount; i++) {
        len = AegisWideLen(AegisBlacklistProcessNames[i], AEGIS_POLICY_IMAGE_LEN - 1) + 1;
        RtlCopyMemory(g_RuntimePolicy.ProcessBlacklist[i], AegisBlacklistProcessNames[i], len * sizeof(WCHAR));
    }
    g_RuntimePolicy.ProcessWhitelistCount = (AegisWhitelistProcessCount <= AEGIS_POLICY_MAX_WHITELIST)
        ? (ULONG)AegisWhitelistProcessCount : AEGIS_POLICY_MAX_WHITELIST;
    for (i = 0; i < g_RuntimePolicy.ProcessWhitelistCount; i++) {
        len = AegisAnsiLen(AegisWhitelistProcessNames[i], AEGIS_POLICY_WHITELIST_LEN - 1) + 1;
        RtlCopyMemory(g_RuntimePolicy.ProcessWhitelist[i], AegisWhitelistProcessNames[i], len);
    }
    g_RuntimePolicy.DllBlacklistCount = (AegisBlacklistDllCount <= AEGIS_POLICY_MAX_DLL_BLACK)
        ? (ULONG)AegisBlacklistDllCount : AEGIS_POLICY_MAX_DLL_BLACK;
    for (i = 0; i < g_RuntimePolicy.DllBlacklistCount; i++) {
        len = AegisWideLen(AegisBlacklistDllNames[i], AEGIS_POLICY_IMAGE_LEN - 1) + 1;
        RtlCopyMemory(g_RuntimePolicy.DllBlacklist[i], AegisBlacklistDllNames[i], len * sizeof(WCHAR));
    }
    AegisPolicyRebuildBloom();
}

static void AegisPolicyRebuildBloom(void)
{
    ULONG i;
    AegisBloomReset();
    for (i = 0; i < g_RuntimePolicy.DllBlacklistCount && i < AEGIS_POLICY_MAX_DLL_BLACK; i++)
        AegisBloomAddWideString(g_RuntimePolicy.DllBlacklist[i], AEGIS_POLICY_IMAGE_LEN);
}

// -----------------------------------------------
// PID list (dynamic via IOCTL) – lock-free for read path (Ob/thread/image callbacks)
// Writers (IOCTL) use InterlockedCompareExchange; readers just read the array (no lock).
// -----------------------------------------------
static volatile ULONG g_ProtectedPids[AEGIS_MAX_PROTECTED_PIDS];
static volatile LONG g_ProtectedPidCount = 0;

/* x64 上自然对齐的 32-bit 读是原子的；这里避免只读路径使用总线锁指令。 */
static __forceinline ULONG AegisReadProtectedPidCount(void)
{
    return (ULONG)g_ProtectedPidCount;
}

// -----------------------------------------------
// Memory range protection: interval tree per process, O(log N) point-in-range query
// -----------------------------------------------
typedef struct _AEGIS_RANGE_NODE {
    ULONG_PTR Low;
    ULONG_PTR High;
    ULONG_PTR MaxHigh;  // max High in this subtree (augmented for interval query)
    struct _AEGIS_RANGE_NODE* Left;
    struct _AEGIS_RANGE_NODE* Right;
} AEGIS_RANGE_NODE, *PAEGIS_RANGE_NODE;

typedef struct _AEGIS_RANGE_CONTEXT {
    ULONG Pid;
    PAEGIS_RANGE_NODE Root;
    ULONG NodeCount;
} AEGIS_RANGE_CONTEXT, *PAEGIS_RANGE_CONTEXT;

#define AEGIS_RANGE_POOL_TAG 'egiA'
static AEGIS_RANGE_CONTEXT g_RangeContexts[AEGIS_MAX_RANGE_CONTEXTS];
static KSPIN_LOCK g_RangeTreeLock;

static PAEGIS_RANGE_NODE AegisRangeNodeAlloc(ULONG_PTR Low, ULONG_PTR High);
static void AegisRangeNodeFree(PAEGIS_RANGE_NODE Node);
static PAEGIS_RANGE_NODE AegisRangeInsert(PAEGIS_RANGE_NODE Root, ULONG_PTR Low, ULONG_PTR High, PULONG NodeCount);
static PAEGIS_RANGE_NODE AegisRangeRemove(PAEGIS_RANGE_NODE Root, ULONG_PTR Low, ULONG_PTR High, PULONG NodeCount);
static BOOLEAN AegisRangeQuery(PAEGIS_RANGE_NODE Root, ULONG_PTR Addr);
static void AegisRangeTreeFree(PAEGIS_RANGE_NODE Root);
static PAEGIS_RANGE_CONTEXT AegisRangeContextFind(ULONG Pid);
static PAEGIS_RANGE_CONTEXT AegisRangeContextForPid(ULONG Pid);

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
                outData.ProtectedCount = AegisReadProtectedPidCount();
                outData.StatusCode = 0;
                inserted = TRUE;
                break;
            }
        }
        if (!inserted) {
            for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++) {
                if (InterlockedCompareExchange((LONG*)&g_ProtectedPids[i], (LONG)in->Pid, 0) == 0) {
                    InterlockedIncrement(&g_ProtectedPidCount);
                    outData.ProtectedCount = AegisReadProtectedPidCount();
                    outData.StatusCode = 0;
                    inserted = TRUE;
                    break;
                }
            }
        }
        if (!inserted) {
            status = STATUS_TOO_MANY_NAMES;
            outData.StatusCode = (ULONG)status;
            outData.ProtectedCount = AegisReadProtectedPidCount();
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
        outData.ProtectedCount = AegisReadProtectedPidCount();
        outData.StatusCode = found ? 0 : (ULONG)STATUS_NOT_FOUND;
        AegisDbgPrint(("[Aegis] IOCTL unprotect PID %u; total %u\n", in->Pid, outData.ProtectedCount));
        break;
    }
    case IOCTL_AEGIS_GET_STATUS:
        outData.ProtectedCount = AegisReadProtectedPidCount();
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
    case IOCTL_AEGIS_ADD_RANGE: {
        PAEGIS_RANGE_INPUT in = (PAEGIS_RANGE_INPUT)inBuf;
        KIRQL oldIrql;
        PAEGIS_RANGE_CONTEXT ctx;
        if (inSize < sizeof(AEGIS_RANGE_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        if (in->Low >= in->High) {
            status = STATUS_INVALID_PARAMETER;
            outData.StatusCode = (ULONG)status;
            break;
        }
        KeAcquireSpinLock(&g_RangeTreeLock, &oldIrql);
        ctx = AegisRangeContextForPid(in->Pid);
        if (ctx == NULL) {
            KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);
            status = STATUS_TOO_MANY_NAMES;
            outData.StatusCode = (ULONG)status;
            break;
        }
        if (ctx->NodeCount >= AEGIS_MAX_RANGES_PER_PID) {
            KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);
            status = STATUS_TOO_MANY_NAMES;
            outData.StatusCode = (ULONG)status;
            break;
        }
        ctx->Root = AegisRangeInsert(ctx->Root, in->Low, in->High, &ctx->NodeCount);
        KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);
        outData.StatusCode = 0;
        AegisDbgPrint(("[Aegis] IOCTL add range PID %u [%p, %p)\n", in->Pid, (void*)in->Low, (void*)in->High));
        break;
    }
    case IOCTL_AEGIS_REMOVE_RANGE: {
        PAEGIS_RANGE_INPUT in = (PAEGIS_RANGE_INPUT)inBuf;
        KIRQL oldIrql;
        PAEGIS_RANGE_CONTEXT ctx;
        if (inSize < sizeof(AEGIS_RANGE_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        KeAcquireSpinLock(&g_RangeTreeLock, &oldIrql);
        ctx = AegisRangeContextFind(in->Pid);
        if (ctx != NULL)
            ctx->Root = AegisRangeRemove(ctx->Root, in->Low, in->High, &ctx->NodeCount);
        KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);
        outData.StatusCode = (ctx != NULL) ? 0 : (ULONG)STATUS_NOT_FOUND;
        AegisDbgPrint(("[Aegis] IOCTL remove range PID %u [%p, %p)\n", in->Pid, (void*)in->Low, (void*)in->High));
        break;
    }
    case IOCTL_AEGIS_SET_POLICY: {
        PAEGIS_POLICY_INPUT in = (PAEGIS_POLICY_INPUT)inBuf;
        KIRQL oldIrql;
        if (inSize < sizeof(AEGIS_POLICY_INPUT) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            outData.StatusCode = (ULONG)status;
            break;
        }
        if (in->ProcessBlacklistCount > AEGIS_POLICY_MAX_BLACKLIST ||
            in->ProcessWhitelistCount > AEGIS_POLICY_MAX_WHITELIST ||
            in->DllBlacklistCount > AEGIS_POLICY_MAX_DLL_BLACK) {
            status = STATUS_INVALID_PARAMETER;
            outData.StatusCode = (ULONG)status;
            break;
        }
        KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
        RtlCopyMemory(&g_RuntimePolicy, in, sizeof(AEGIS_POLICY_INPUT));
        AegisPolicyRebuildBloom();
        KeReleaseSpinLock(&g_PolicyLock, oldIrql);
        outData.StatusCode = 0;
        AegisDbgPrint(("[Aegis] IOCTL SET_POLICY: blacklist %u whitelist %u dll %u\n",
            g_RuntimePolicy.ProcessBlacklistCount, g_RuntimePolicy.ProcessWhitelistCount, g_RuntimePolicy.DllBlacklistCount));
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
    ULONG64 cr3;

    if (Process == NULL) return 0;

#if AEGIS_HAS_EPROCESS_CR3_OFFSET
    {
        ULONG64 candidate = *(volatile ULONG64 *)((PUCHAR)Process + AEGIS_EPROCESS_CR3_OFFSET);
        candidate &= AEGIS_PFN_MASK;
        if (candidate != 0 && (candidate & (AEGIS_PAGE_SIZE - 1)) == 0)
            return candidate;
        AegisDbgPrint(("[Aegis] EPROCESS CR3 offset read invalid (0x%llX), fallback to attach path\n", candidate));
    }
#endif

    {
        KAPC_STATE apcState;
        KeStackAttachProcess(Process, &apcState);
        cr3 = __readcr3();
        KeUnstackDetachProcess(&apcState);
        return cr3 & AEGIS_PFN_MASK;
    }
}

static ULONG64 AegisReadPhysical(ULONG64 Pa)
{
    MM_COPY_ADDRESS src;
    ULONG64 value = 0;
    SIZE_T bytesRead = 0;
    NTSTATUS status;

    src.PhysicalAddress.QuadPart = (LONGLONG)Pa;

    status = MmCopyMemory(
        &value,
        src,
        sizeof(ULONG64),
        MM_COPY_MEMORY_PHYSICAL,
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead != sizeof(ULONG64)) {
        return 0;
    }

    return value;
}

// -----------------------------------------------
// PTE backend abstraction – future Hypervisor/EPT hook point
// -----------------------------------------------

/* 统一的 PTE 查询入口：未来可在此接入 Hypervisor / EPT 视角。 */
static ULONG64 AegisQueryPteForVa(ULONG64 Pml4Pa, ULONG_PTR Va)
{
#if AEGIS_HAS_HYPERVISOR
    //
    // 预留：当有 Hypervisor 时，在这里通过 VMCall/共享内存等方式，
    // 向 Ring -1 查询 VA 对应的最终执行权限 / PTE 值。
    // 目前先退回到 Guest 内核视角的 PTE Walk。
    //
#endif
    return AegisPteWalk(Pml4Pa, Va);
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

// -----------------------------------------------
// Interval tree: [Low, High), keyed by Low then High; MaxHigh = max endpoint in subtree
// -----------------------------------------------
static PAEGIS_RANGE_NODE AegisRangeNodeAlloc(ULONG_PTR Low, ULONG_PTR High)
{
    PAEGIS_RANGE_NODE n = (PAEGIS_RANGE_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(AEGIS_RANGE_NODE), AEGIS_RANGE_POOL_TAG);
    if (n == NULL) return NULL;
    n->Low = Low;
    n->High = High;
    n->MaxHigh = High;
    n->Left = n->Right = NULL;
    return n;
}

static void AegisRangeNodeFree(PAEGIS_RANGE_NODE Node)
{
    if (Node != NULL)
        ExFreePoolWithTag(Node, AEGIS_RANGE_POOL_TAG);
}

static ULONG_PTR AegisRangeMaxHigh(PAEGIS_RANGE_NODE N)
{
    return N != NULL ? N->MaxHigh : 0;
}

/* Insert [Low, High); key = (Low, High) lexicographic; return new root. */
static PAEGIS_RANGE_NODE AegisRangeInsert(PAEGIS_RANGE_NODE Root, ULONG_PTR Low, ULONG_PTR High, PULONG NodeCount)
{
    if (Root == NULL) {
        PAEGIS_RANGE_NODE n = AegisRangeNodeAlloc(Low, High);
        if (n != NULL && NodeCount != NULL)
            (*NodeCount)++;
        return n;
    }
    if (Low < Root->Low || (Low == Root->Low && High < Root->High))
        Root->Left = AegisRangeInsert(Root->Left, Low, High, NodeCount);
    else
        Root->Right = AegisRangeInsert(Root->Right, Low, High, NodeCount);
    Root->MaxHigh = Root->High;
    if (AegisRangeMaxHigh(Root->Left) > Root->MaxHigh)  Root->MaxHigh = AegisRangeMaxHigh(Root->Left);
    if (AegisRangeMaxHigh(Root->Right) > Root->MaxHigh) Root->MaxHigh = AegisRangeMaxHigh(Root->Right);
    return Root;
}

/* Find leftmost node in subtree. */
static PAEGIS_RANGE_NODE AegisRangeLeftmost(PAEGIS_RANGE_NODE N)
{
    while (N != NULL && N->Left != NULL) N = N->Left;
    return N;
}

/* Remove node with exact (Low, High); return new root. */
static PAEGIS_RANGE_NODE AegisRangeRemove(PAEGIS_RANGE_NODE Root, ULONG_PTR Low, ULONG_PTR High, PULONG NodeCount)
{
    if (Root == NULL) return NULL;
    if (Low < Root->Low || (Low == Root->Low && High < Root->High)) {
        Root->Left = AegisRangeRemove(Root->Left, Low, High, NodeCount);
    } else if (Low > Root->Low || (Low == Root->Low && High > Root->High)) {
        Root->Right = AegisRangeRemove(Root->Right, Low, High, NodeCount);
    } else {
        PAEGIS_RANGE_NODE tmp = Root;
        if (Root->Left == NULL) {
            Root = Root->Right;
            AegisRangeNodeFree(tmp);
            if (NodeCount != NULL) (*NodeCount)--;
            return Root;
        }
        if (Root->Right == NULL) {
            Root = Root->Left;
            AegisRangeNodeFree(tmp);
            if (NodeCount != NULL) (*NodeCount)--;
            return Root;
        }
        PAEGIS_RANGE_NODE succ = AegisRangeLeftmost(Root->Right);
        Root->Low = succ->Low;
        Root->High = succ->High;
        Root->Right = AegisRangeRemove(Root->Right, succ->Low, succ->High, NodeCount);
        /* successor node was freed inside AegisRangeRemove and NodeCount decremented there */
    }
    Root->MaxHigh = Root->High;
    if (AegisRangeMaxHigh(Root->Left) > Root->MaxHigh)  Root->MaxHigh = AegisRangeMaxHigh(Root->Left);
    if (AegisRangeMaxHigh(Root->Right) > Root->MaxHigh) Root->MaxHigh = AegisRangeMaxHigh(Root->Right);
    return Root;
}

/* Query: does Addr lie in any interval [Low, High)? O(log N). */
static BOOLEAN AegisRangeQuery(PAEGIS_RANGE_NODE Root, ULONG_PTR Addr)
{
    if (Root == NULL) return FALSE;
    if (Addr >= Root->Low && Addr < Root->High)
        return TRUE;
    if (Root->Left != NULL && Addr <= Root->Left->MaxHigh)
        if (AegisRangeQuery(Root->Left, Addr)) return TRUE;
    if (Root->Right != NULL)
        return AegisRangeQuery(Root->Right, Addr);
    return FALSE;
}

static void AegisRangeTreeFree(PAEGIS_RANGE_NODE Root)
{
    if (Root == NULL) return;
    AegisRangeTreeFree(Root->Left);
    AegisRangeTreeFree(Root->Right);
    AegisRangeNodeFree(Root);
}

/* Find context for Pid (no create); caller must hold g_RangeTreeLock. */
static PAEGIS_RANGE_CONTEXT AegisRangeContextFind(ULONG Pid)
{
    ULONG i;
    for (i = 0; i < AEGIS_MAX_RANGE_CONTEXTS; i++) {
        if (g_RangeContexts[i].Pid == Pid)
            return &g_RangeContexts[i];
    }
    return NULL;
}

/* Find or create context for Pid; caller must hold g_RangeTreeLock. Returns NULL if table full. */
static PAEGIS_RANGE_CONTEXT AegisRangeContextForPid(ULONG Pid)
{
    PAEGIS_RANGE_CONTEXT ctx = AegisRangeContextFind(Pid);
    ULONG i;
    if (ctx != NULL) return ctx;
    for (i = 0; i < AEGIS_MAX_RANGE_CONTEXTS; i++) {
        if (g_RangeContexts[i].Pid == 0) {
            g_RangeContexts[i].Pid = Pid;
            g_RangeContexts[i].Root = NULL;
            g_RangeContexts[i].NodeCount = 0;
            return &g_RangeContexts[i];
        }
    }
    return NULL;
}

BOOLEAN AegisIsAddressInProtectedRange(ULONG Pid, ULONG_PTR Address)
{
    KIRQL oldIrql;
    PAEGIS_RANGE_CONTEXT ctx;
    BOOLEAN result = FALSE;

    KeAcquireSpinLock(&g_RangeTreeLock, &oldIrql);
    ctx = AegisRangeContextFind(Pid);
    if (ctx != NULL && ctx->Root != NULL)
        result = AegisRangeQuery(ctx->Root, Address);
    KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);
    return result;
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

        /* PTE-VAD discrepancy: VAD says non-executable but low-level PTE backend报告为可执行（可能的 PTE / EPT 篡改） */
        if ((mbi.Protect & AEGIS_VAD_EXEC_MASK) == 0) {
            ULONG_PTR va;
            for (va = (ULONG_PTR)mbi.BaseAddress; va < (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize; va += AEGIS_PAGE_SIZE) {
                ULONG64 pte = AegisQueryPteForVa(cr3, va);
                if (pte != 0 && (pte & AEGIS_PTE_NX) == 0) {
                    // 记录异常，并可考虑直接 break 避免单区域记录过多导致数组越界
                    Output->Discrepancies[discCount].Va = va;
                    Output->Discrepancies[discCount].VadProtect = mbi.Protect;
                    Output->Discrepancies[discCount].PteValue = pte;
                    discCount++;
                    break; 
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

    InterlockedExchange(&g_ProtectedPidCount, 0);
    for (i = 0; i < AEGIS_MAX_PROTECTED_PIDS; i++)
        InterlockedExchange((LONG*)&g_ProtectedPids[i], 0);

    KeInitializeSpinLock(&g_RangeTreeLock);
    RtlZeroMemory(g_RangeContexts, sizeof(g_RangeContexts));

    KeInitializeSpinLock(&g_PolicyLock);
    AegisPolicyInitFromDefaults();

    return STATUS_SUCCESS;
}

void AegisProtectionUninitialize(void)
{
    ULONG i;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_RangeTreeLock, &oldIrql);
    for (i = 0; i < AEGIS_MAX_RANGE_CONTEXTS; i++) {
        if (g_RangeContexts[i].Root != NULL) {
            AegisRangeTreeFree(g_RangeContexts[i].Root);
            g_RangeContexts[i].Root = NULL;
            g_RangeContexts[i].NodeCount = 0;
        }
        g_RangeContexts[i].Pid = 0;
    }
    KeReleaseSpinLock(&g_RangeTreeLock, oldIrql);

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
    OB_OPERATION_REGISTRATION obOpReg[2];

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

    /* Phase 3 + 5: ObRegisterCallbacks for process and thread handle create/duplicate */
    RtlInitUnicodeString(&altitude, L"320000.123");
    obOpReg[0].ObjectType = PsProcessType;
    obOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg[0].PreOperation = AegisObPreOperationCallback;
    obOpReg[0].PostOperation = NULL;
    obOpReg[1].ObjectType = PsThreadType;
    obOpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg[1].PreOperation = AegisObPreOperationCallback;
    obOpReg[1].PostOperation = NULL;
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
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
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    ANSI_STRING aCur, aList;

    if (Process == NULL) return FALSE;
    imageName = PsGetProcessImageFileName(Process);
    if (imageName == NULL) return FALSE;

    RtlInitAnsiString(&aCur, imageName);
    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    for (i = 0; i < g_RuntimePolicy.ProcessWhitelistCount && i < AEGIS_POLICY_MAX_WHITELIST; i++) {
        RtlInitAnsiString(&aList, g_RuntimePolicy.ProcessWhitelist[i]);
        if (aList.Buffer != NULL && RtlCompareString(&aCur, &aList, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
    return found;
}

static OB_PREOP_CALLBACK_STATUS AegisObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    PEPROCESS targetProcess;
    PEPROCESS ownerProcess;
    PETHREAD targetThread;
    PEPROCESS creatorProcess;
    PACCESS_MASK pDesiredAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        pDesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    creatorProcess = PsGetCurrentProcess();
    if (AegisIsProcessWhitelisted(creatorProcess))
        return OB_PREOP_SUCCESS;

    if (OperationInformation->ObjectType == PsProcessType) {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        if (!AegisIsProcessProtected(targetProcess))
            return OB_PREOP_SUCCESS;
        *pDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
        AegisDbgPrint(("[Aegis] Ob: stripped process handle access for PID %p -> protected process\n", PsGetCurrentProcessId()));
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == PsThreadType) {
        targetThread = (PETHREAD)OperationInformation->Object;
        ownerProcess = PsGetThreadProcess(targetThread);
        if (ownerProcess == NULL || !AegisIsProcessProtected(ownerProcess))
            return OB_PREOP_SUCCESS;
        /* Strip to query-only to block THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, APC injection, etc. */
        *pDesiredAccess = THREAD_QUERY_LIMITED_INFORMATION;
        AegisDbgPrint(("[Aegis] Ob: stripped thread handle access for PID %p -> thread in protected process\n", PsGetCurrentProcessId()));
        return OB_PREOP_SUCCESS;
    }

    return OB_PREOP_SUCCESS;
}

// -----------------------------------------------
// Task 1: Process notify – blacklist and block; log protected process creation
// -----------------------------------------------
static BOOLEAN AegisIsProcessBlacklisted(PCUNICODE_STRING ImageName)
{
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    UNICODE_STRING u;

    if (ImageName == NULL || ImageName->Buffer == NULL) return FALSE;
    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    for (i = 0; i < g_RuntimePolicy.ProcessBlacklistCount && i < AEGIS_POLICY_MAX_BLACKLIST; i++) {
        RtlInitUnicodeString(&u, g_RuntimePolicy.ProcessBlacklist[i]);
        if (u.Buffer != NULL && RtlCompareUnicodeString(ImageName, &u, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
    return found;
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
