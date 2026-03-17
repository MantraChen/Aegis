# Project Aegis

**A minimal Windows kernel anti-cheat framework** that protects designated processes (e.g. simulated game clients) from **read**, **write**, and **injection**.

This project is for **training my own project and systems programming skills** (kernel-mode development, WDK, process protection). It is not intended for production or commercial use.

- **Target platform**: Windows 10 / 11 (x64)
- **Stack**: C / C++
- **Tools**: Visual Studio, WDK (Windows Driver Kit), WinDbg, VMware/VirtualBox

> **Important**: Develop and test **only inside a VM**. Running or testing this driver on a physical machine can cause BSODs or unbootable systems.

---

## Layout

```
Project Aegis/
├── README.md
├── ProjectAegis.sln              # Visual Studio solution
├── Shared/
│   └── shared_ioctl.h            # IOCTL codes and structs (driver + client)
├── docs/
│   └── Phase1-DualMachineDebug.md # Dual-machine kernel debugging setup
├── ProjectAegis/                 # Kernel driver (Ring 0)
│   ├── ProjectAegis.vcxproj
│   ├── ProjectAegis.inf
│   ├── driver.c                  # Entry, unload, device, IOCTL, protection
│   ├── config.h
│   └── protection.h
└── AegisClient/                  # User-mode console (Ring 3)
    ├── AegisClient.vcxproj
    └── main.c                    # Sends protect/unprotect/status IOCTLs
```

---

## Requirements

1. **Windows 10/11 x64** (ideally in a VM)
2. **Visual Studio 2022** with “Desktop development with C++”
3. **Windows Driver Kit (WDK)** matching your Windows SDK  
   - Install the WDK VSIX so Visual Studio has the driver build targets

---

## Build

1. Open `ProjectAegis.sln` in the VM.
2. Select **Debug | x64** or **Release | x64**.
3. **Build → Build Solution** (Ctrl+Shift+B).
4. Output: `bin\Debug\` or `bin\Release\` → `ProjectAegis.sys` (and `ProjectAegis.inf` if configured).

From “x64 Native Tools Command Prompt for VS 2022”:

```bat
msbuild ProjectAegis.sln /p:Configuration=Debug /p:Platform=x64
```

---

## Deploy and test (VM only)

1. **Disable driver signature enforcement** (test only):  
   - F8 or Advanced startup → “Disable driver signature enforcement”, or  
   - `bcdedit /set testsigning on` and reboot.

2. **Install/register the driver**:  
   - Right‑click the INF → Install, or  
   - Use `sc create` + `NtLoadDriver` (or similar) with admin rights.

3. **Load/unload**:  
   - Load: `sc start ProjectAegis` (or your service name)  
   - Unload: `sc stop ProjectAegis`, then remove the driver package if needed.

4. **Debug**:  
   - Set up WinDbg kernel debugging (VM serial/pipe or network KD), then break and watch `DbgPrint` output.

---

## Phase 1: Environment and “Hello World” driver

**Task 1 – Dual-machine debugging**  
- **Host (physical)**: Visual Studio + WinDbg.  
- **Guest (VM)**: Test Windows where the driver runs.  
Step-by-step: [docs/Phase1-DualMachineDebug.md](docs/Phase1-DualMachineDebug.md).

**Task 2 – Minimal driver**  
- **DriverEntry**: Creates device `\Device\ProjectAegis`, symbolic link `\DosDevices\ProjectAegis`, registers IRP dispatch (Create, Close, DeviceControl), then process notify and protection init.  
- **DriverUnload**: Unregisters callbacks, deletes link and device.

**Task 3 – IOCTL and Ring 3 client**  
- **Driver**: Handles `IOCTL_AEGIS_PROTECT_PID`, `IOCTL_AEGIS_UNPROTECT_PID`, `IOCTL_AEGIS_GET_STATUS` (see `Shared/shared_ioctl.h`).  
- **AegisClient**: Console app that opens `\\.\ProjectAegis` and sends commands.  
  - Build the solution (driver + AegisClient).  
  - On the **guest**, load the driver (`sc start ProjectAegis`).  
  - Run **AegisClient.exe** as Administrator:

```bat
AegisClient.exe protect 1234
AegisClient.exe unprotect 1234
AegisClient.exe status
```

---

## Phase 2: Process and thread monitoring (system callbacks)

No SSDT hooking (PatchGuard/KPP); only official callback APIs.

**Task 1 – Process notify (`PsSetCreateProcessNotifyRoutineEx`)**  
- **Blacklist**: Cheat/debug tools (e.g. Cheat Engine, x64dbg) are listed in `AegisBlacklistProcessNames` in `driver.c`.  
- When a blacklisted image starts, the callback sets `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` so the process is blocked.  
- **Note**: The driver is linked with `/INTEGRITYCHECK` so the kernel allows this “deny” usage of the Ex callback.

**Task 2 – Thread notify (`PsSetCreateThreadNotifyRoutine`)**  
- When a thread is created in a **protected** process and the creating process is **different** (i.e. remote thread, e.g. `CreateRemoteThread` for injection), the driver terminates that thread with `ZwTerminateThread`.  
- This detects and stops classic DLL injection via remote thread into the game process.

**Task 3 – Load image notify (`PsSetLoadImageNotifyRoutine`)**  
- When any image (exe or DLL) is loaded into a protected process, the driver logs it (path and base) via `DbgPrint`.  
- Used to monitor (and later extend to block) unsigned or unwanted DLLs loading into the game.

---

## Phase 3: Object protection and handle stripping (core defense)

Cheats often use `OpenProcess` with `PROCESS_VM_READ` (or `PROCESS_ALL_ACCESS`) to read game memory. Phase 3 uses **ObRegisterCallbacks** to strip those rights for untrusted openers.

**Task 1 – ObRegisterCallbacks**  
- The driver registers an **ObjectPreCallback** for **process** handle operations: **OB_OPERATION_HANDLE_CREATE** and **OB_OPERATION_HANDLE_DUPLICATE**.  
- Altitude used: `320000.123` (third-party range).

**Task 2 – Handle stripping**  
- When a **non-whitelisted** process opens or duplicates a handle to a **protected** process, the pre-callback sets the granted access to **PROCESS_QUERY_LIMITED_INFORMATION** only (no `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_TERMINATE`, etc.).  
- Kernel handles (`KernelHandle == TRUE`) are left unchanged.  
- Result: user-mode cheats that call `OpenProcess(PROCESS_ALL_ACCESS)` get a handle that cannot read/write memory or terminate the game.

**Task 3 – Whitelist**  
- **Whitelisted** processes are allowed to receive full requested access when opening the protected process.  
- Whitelist (by image name, ASCII, from `PsGetProcessImageFileName`) includes: **System**, **csrss.exe**, **services.exe**, **wininit.exe**, **lsass.exe**, **svchost.exe**, **AegisClient.exe**, and the game images **GameClient.exe** / **TestProtected.exe**.  
- Any other process (e.g. a cheat or unknown tool) gets stripped access as above.

---

## Current implementation (Phase 1 + Phase 2 + Phase 3)

- **Driver**: Device, IOCTL, protected PID list, process/thread/image callbacks, **Ob process callbacks**.
- **Process**: Blacklist block + protected-process creation log.
- **Thread**: Remote threads in protected processes are terminated.
- **Image**: All image loads into protected processes are logged.
- **Ob**: Process handle create/duplicate are intercepted; non-whitelisted openers of protected process get **query-only** handle (no VM read/write/terminate).

---

## Possible extensions

- **Thread handles**: Register Ob callbacks for `PsThreadType` to restrict thread handle rights (e.g. block `THREAD_SET_CONTEXT` from untrusted processes).
- **Image load**: Block specific DLLs (e.g. unsigned) loading into protected process (e.g. via CI or custom logic).
- **Dynamic lists**: Add/remove protected or whitelist names/PIDs via registry or IOCTL.

---

## Disclaimer and compliance

This project is for **learning and personal skill training** only. Deploying unsigned kernel drivers on a real system may violate Windows licensing and local laws. Use only in an isolated VM and comply with applicable regulations.
