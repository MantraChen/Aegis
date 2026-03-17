//
// Project Aegis - User-mode client (Ring 3)
// Sends IOCTLs to the kernel driver to protect/unprotect PIDs and query status.
// Run as Administrator. Driver must be loaded (e.g. sc start ProjectAegis).
// Build on Windows only; this file parses on non-Windows (e.g. macOS) for IDE support.
//

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32

#include <Windows.h>
#include "shared_ioctl.h"

#define AEGIS_DEVICE_PATH  "\\\\.\\ProjectAegis"

static HANDLE OpenDriver(void)
{
    HANDLE h = CreateFileA(
        AEGIS_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile failed: %lu\n", GetLastError());
        return NULL;
    }
    return h;
}

static void PrintUsage(const char* prog)
{
    printf("Usage:\n");
    printf("  %s protect <PID>   - Add PID to protected list\n", prog);
    printf("  %s unprotect <PID> - Remove PID from protected list\n", prog);
    printf("  %s status         - Show protected count and driver status\n", prog);
    printf("  %s scan <PID>      - Scan process for unbacked RWX regions (Phase 4)\n", prog);
    printf("\nExample: %s protect 1234\n", prog);
}

int main(int argc, char** argv)
{
    HANDLE hDev;
    AEGIS_PID_INPUT in;
    AEGIS_STATUS_OUTPUT out;
    DWORD bytesReturned;
    BOOL ok;
    int pidArg;

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    hDev = OpenDriver();
    if (!hDev) {
        fprintf(stderr, "Run as Administrator and ensure the driver is loaded (sc start ProjectAegis).\n");
        return 1;
    }

    if (_stricmp(argv[1], "protect") == 0) {
        if (argc < 3) {
            PrintUsage(argv[0]);
            CloseHandle(hDev);
            return 1;
        }
        pidArg = atoi(argv[2]);
        if (pidArg <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", argv[2]);
            CloseHandle(hDev);
            return 1;
        }
        in.Pid = (ULONG)pidArg;
        ZeroMemory(&out, sizeof(out));
        ok = DeviceIoControl(
            hDev,
            IOCTL_AEGIS_PROTECT_PID,
            &in,
            sizeof(in),
            &out,
            sizeof(out),
            &bytesReturned,
            NULL
        );
        if (ok && out.StatusCode == 0) {
            printf("OK: PID %u is now protected. Total protected: %u\n", in.Pid, out.ProtectedCount);
        } else {
            printf("Failed: protect PID %u (status 0x%X, GetLastError %lu)\n", in.Pid, out.StatusCode, GetLastError());
        }
    } else if (_stricmp(argv[1], "unprotect") == 0) {
        if (argc < 3) {
            PrintUsage(argv[0]);
            CloseHandle(hDev);
            return 1;
        }
        pidArg = atoi(argv[2]);
        if (pidArg <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", argv[2]);
            CloseHandle(hDev);
            return 1;
        }
        in.Pid = (ULONG)pidArg;
        ZeroMemory(&out, sizeof(out));
        ok = DeviceIoControl(
            hDev,
            IOCTL_AEGIS_UNPROTECT_PID,
            &in,
            sizeof(in),
            &out,
            sizeof(out),
            &bytesReturned,
            NULL
        );
        if (ok && out.StatusCode == 0) {
            printf("OK: PID %u removed from protected list. Total protected: %u\n", in.Pid, out.ProtectedCount);
        } else {
            printf("Failed: unprotect PID %u (status 0x%X, GetLastError %lu)\n", in.Pid, out.StatusCode, GetLastError());
        }
    } else if (_stricmp(argv[1], "status") == 0) {
        ZeroMemory(&out, sizeof(out));
        ok = DeviceIoControl(
            hDev,
            IOCTL_AEGIS_GET_STATUS,
            NULL,
            0,
            &out,
            sizeof(out),
            &bytesReturned,
            NULL
        );
        if (ok) {
            printf("Driver status: 0x%X, protected PIDs count: %u\n", out.StatusCode, out.ProtectedCount);
        } else {
            printf("DeviceIoControl GET_STATUS failed: %lu\n", GetLastError());
        }
    } else if (_stricmp(argv[1], "scan") == 0) {
        AEGIS_VAD_SCAN_OUTPUT scanOut;
        ULONG i;
        if (argc < 3) {
            PrintUsage(argv[0]);
            CloseHandle(hDev);
            return 1;
        }
        pidArg = atoi(argv[2]);
        if (pidArg <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", argv[2]);
            CloseHandle(hDev);
            return 1;
        }
        in.Pid = (ULONG)pidArg;
        ZeroMemory(&scanOut, sizeof(scanOut));
        ok = DeviceIoControl(
            hDev,
            IOCTL_AEGIS_SCAN_VAD,
            &in,
            sizeof(in),
            &scanOut,
            sizeof(scanOut),
            &bytesReturned,
            NULL
        );
        if (ok && scanOut.StatusCode == 0) {
            printf("VAD scan PID %u: %u suspicious (unbacked RWX) region(s), %u PTE-VAD discrepancy(ies)\n",
                in.Pid, scanOut.Count, scanOut.DiscrepancyCount);
            for (i = 0; i < scanOut.Count; i++) {
                printf("  [%u] base %p size 0x%zX protect 0x%X type 0x%X\n",
                    i, (void*)(ULONG_PTR)scanOut.Entries[i].BaseAddress,
                    (size_t)scanOut.Entries[i].RegionSize,
                    scanOut.Entries[i].Protect, scanOut.Entries[i].Type);
            }
            for (i = 0; i < scanOut.DiscrepancyCount; i++) {
                printf("  PTE-VAD [%u] VA %p VAD protect 0x%X PTE 0x%llX\n",
                    i, (void*)(ULONG_PTR)scanOut.Discrepancies[i].Va,
                    scanOut.Discrepancies[i].VadProtect, (unsigned long long)scanOut.Discrepancies[i].PteValue);
            }
        } else {
            printf("VAD scan failed: status 0x%X, GetLastError %lu\n", scanOut.StatusCode, GetLastError());
        }
    } else {
        PrintUsage(argv[0]);
        CloseHandle(hDev);
        return 1;
    }

    CloseHandle(hDev);
    return 0;
}

#else

/* Stub when built or parsed on non-Windows (e.g. macOS IDE); real build is on Windows with MSVC. */
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    printf("AegisClient is a Windows application. Build and run it on Windows (Visual Studio, x64).\n");
    return 1;
}

#endif
