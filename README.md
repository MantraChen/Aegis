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
│   ├── Phase1-DualMachineDebug.md   # Dual-machine kernel debugging setup
│   └── Phase4-CR3-PageTables.md     # CR3 / page table (optional, Phase 4 Task 2)
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

## Phase 4: Memory protection and hidden-scan (advanced)

**Task 1 – VAD-style scan (unbacked RWX)**  
- The driver does **not** walk the internal VAD tree (undocumented); it uses **ZwQueryVirtualMemory** in a loop to enumerate virtual memory regions of a target process (by PID).  
- It looks for regions that are **committed**, have protection **PAGE_EXECUTE_READWRITE (RWX)**, and **type ≠ MEM_IMAGE** (i.e. not backed by a mapped image file). Such regions are a common signature of **manual map** injection or shellcode.  
- **IOCTL**: `IOCTL_AEGIS_SCAN_VAD`. Input: PID (`AEGIS_PID_INPUT`). Output: `AEGIS_VAD_SCAN_OUTPUT` (count + array of `AEGIS_VAD_ENTRY`: base, size, protect, type). Suspicious regions are also logged via `DbgPrint`.  
- The client can send “scan PID” and display the list of suspicious ranges.

**Task 2 – CR3 and page tables (optional / advanced)**  
- **Documentation**: [docs/Phase4-CR3-PageTables.md](docs/Phase4-CR3-PageTables.md) explains virtual-to-physical translation, CR3, the four-level page walk, and how a rootkit could modify a game’s page table (e.g. clear NX, change R/W).  
- **Detection** of such modifications from another driver is advanced (OS-version dependent, PTE layout, VBS/HVCI); the doc describes the idea and does **not** implement full PTE-walk or integrity checks.  
- A short comment in the driver points to the doc; reading CR3 (e.g. after `KeStackAttachProcess`) is left as an optional exercise.

---

## Current implementation (Phase 1 + Phase 2 + Phase 3 + Phase 4)

- **Driver**: Device, IOCTL, protected PID list (**lock-free**), process/thread/image callbacks, Ob process callbacks, **VAD-style scan**.
- **Concurrent PID list**: The protected-PID set is updated with **InterlockedCompareExchange** (CAS) and **InterlockedIncrement/Decrement**; **no spinlock** is taken on the read path. Callbacks (Ob, thread, image) only read the array, so handle create/duplicate no longer contend on a global lock.
- **Process**: Blacklist block + protected-process creation log.
- **Thread**: Remote threads in protected processes are terminated.
- **Image**: All image loads into protected processes are logged.
- **Ob (process + thread)**: Process and **thread** handle create/duplicate intercepted. Non-whitelisted openers of a **protected process** get **PROCESS_QUERY_LIMITED_INFORMATION** only; non-whitelisted openers of a **thread belonging to a protected process** get **THREAD_QUERY_LIMITED_INFORMATION** only (blocks **THREAD_SET_CONTEXT**, **THREAD_SUSPEND_RESUME**, APC injection, etc.).
- **VAD scan**: `IOCTL_AEGIS_SCAN_VAD` enumerates VM via `ZwQueryVirtualMemory` and reports **unbacked RWX** regions (manual map heuristic). **PTE walk**: the driver reads the target process **CR3** (via **KeStackAttachProcess** + **`__readcr3()`**), then performs a **four-level page table walk** (PML4→PDPT→PD→PT) using **MmMapIoSpace** to read physical table entries. For each committed region, if **VAD says non-executable** but the **PTE has NX clear**, a **PTE–VAD discrepancy** is recorded (possible PTE tampering). The scan output includes **DiscrepancyCount** and **Discrepancies[]** (VA, VadProtect, PteValue).
- **Memory range spatial index**: An **interval tree** per process stores protected address ranges `[Low, High)` with **O(log N)** point-in-range query. Use `AegisIsAddressInProtectedRange(Pid, Address)` in future memory read/write interception or hidden scans. **IOCTLs**: `IOCTL_AEGIS_ADD_RANGE` / `IOCTL_AEGIS_REMOVE_RANGE` (input: Pid, Low, High). **Client**: `addrange <PID> <Low_hex> <High_hex>`, `removerange <PID> <Low_hex> <High_hex>`.
- **Bloom filter**: A **succinct probabilistic** set (~128 bytes, 1024 bits, 7 hashes) holds hashes of **blacklisted DLL names** (from runtime policy). In **LoadImageNotify** we do an **O(1)** Bloom query on the loaded image filename; on "maybe present" we confirm with an exact blacklist check to avoid false positives.
- **Dynamic policy**: Blacklist/whitelist and DLL blacklist are no longer hardcoded only. At load the driver initializes from built-in defaults; **IOCTL_AEGIS_SET_POLICY** accepts an **AEGIS_POLICY_INPUT** (process blacklist, process whitelist, DLL blacklist) from Ring 3 and updates the in-kernel policy; the Bloom filter is rebuilt when the DLL list changes. **Client**: `setpolicy` pushes the default policy (same as driver defaults). Optional: layer HMAC/signature verification on the policy buffer for production.

---

## Possible extensions

- **Image load**: Block specific DLLs (e.g. unsigned) loading into protected process (e.g. via CI or custom logic).
- **Policy encryption**: Sign or encrypt the policy buffer from Ring 3 so only a trusted service can update the driver’s blacklist/whitelist.

---

## Disclaimer and compliance

This project is for **learning and personal skill training** only. Deploying unsigned kernel drivers on a real system may violate Windows licensing and local laws. Use only in an isolated VM and comply with applicable regulations.
