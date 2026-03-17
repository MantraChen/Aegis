# Phase 4 – Task 2 (Optional): CR3 and Page Table Basics

This document explains the role of **CR3** and page tables in x64 Windows, and how malicious drivers could theoretically modify a game’s page table attributes. It is for learning only; implementing full detection is advanced and often OS-version dependent.

---

## 1. Virtual to physical address translation (x64)

On x86-64, each process has its own **page tables**. The CPU uses them to translate **virtual addresses (VA)** to **physical addresses (PA)**.

- **CR3** (Control Register 3) holds the **physical** address of the **PML4 table** (Page Map Level 4) for the **current** logical processor. When the OS switches to a process, it loads that process’s PML4 physical address into CR3.
- Translation is a **four-level walk** (on standard 4-level paging):
  1. **PML4** (Page Map Level 4) – index from bits 39–47 of VA  
  2. **PDPT** (Page Directory Pointer Table) – index from bits 30–38  
  3. **PD** (Page Directory) – index from bits 21–29  
  4. **PT** (Page Table) – index from bits 12–20  

  The low 12 bits of the VA are the **page offset** (4 KB page). The final **PTE (Page Table Entry)** gives the **physical page frame** and **attributes** (R/W, U/S, NX, etc.).

- **NX (No-Execute)** is bit 63 of the PTE. If set, the page is non-executable. Normal code pages have NX clear; data/heap often have NX set. **RWX (Read-Write-Execute)** pages have both write and execute enabled and are suspicious when they are not backed by a known image.

---

## 2. Where the process CR3 lives

- For the **current** process, the effective “process CR3” is simply **CR3** (the register). Reading it in the driver (e.g. in a context where you are running in the target process) gives that process’s PML4 physical address.
- For an **arbitrary** process (e.g. the game), the kernel stores the **directory table base** (same value that gets loaded into CR3 when that process runs) in the process object. On Windows this is in **EPROCESS** (or the internal **KPROCESS**). The exact **offset** is **undocumented** and can change between Windows builds. Many anti-cheat and research projects resolve it at runtime (e.g. by pattern or by reading from a known process that has just been scheduled).
- **Do not** hardcode EPROCESS offsets; they differ per OS version and patch level.

---

## 3. What “page table manipulation” by a rootkit could do

A malicious driver with access to physical memory (e.g. via **MDL**, **MmMapIoSpace**, or other means) could in principle:

- **Locate** the game process’s page tables (using its CR3 / directory base).
- **Walk** VA → PA using the PML4/PDPT/PD/PT and find the **PTE** for a given virtual page.
- **Change** the PTE:
  - Clear **NX** to make a data page executable (for shellcode).
  - Set **R/W** to allow writing to code pages (for hooks).
  - Remap a physical page (e.g. swap the PFN) to replace code or data.

Such changes are **hard to detect** from another kernel driver because:

- You would need to **read** the same PTEs and compare them to an expected value (e.g. “this VA should be NX”), which requires a correct VA→PA walk and handling of large pages, etc.
- The layout and semantics of PTEs (and sometimes table formats) can change with OS versions and with **VBS/HVCI** (e.g. with **Kernel VA Shadowing** and **second-level paging**).
- **PatchGuard** restricts many kernel modifications; a rootkit that tampers with critical structures risks detection or crash.

So in practice, **detecting** “someone modified the game’s page tables” is **advanced**: it usually involves either a **trusted reference** (e.g. expected PTE attributes per VA range) or lower-level components (e.g. hypervisor or VBS-based integrity).

## 4. Implementation in Project Aegis (PTE walk + discrepancy)

The driver **implements** the following (see `driver.c`):

1. **CR3 for an arbitrary process**  
   - Use **ObReferenceObjectByHandle** on the process handle to get **PEPROCESS**, then **KeStackAttachProcess** and **`__readcr3()`** to read the PML4 physical base. Mask to 4-level: `cr3 & 0x000FFFFFFFFFF000`.

2. **Physical read**  
   - **MmMapIoSpace**(physical page, PAGE_SIZE, MmNonCached) to get a kernel VA, read the 8-byte table entry at the correct offset, then **MmUnmapIoSpace**.

3. **Four-level walk (PML4 → PDPT → PD → PT)**  
   - For a user VA, compute indices from bits 39–47, 30–38, 21–29, 12–20. At each level read the entry; if Present=0, abort. If at PD level the **PS (Page Size)** bit is set, treat the PDE as a 2MB page and use it for the NX check. Otherwise continue to PT and read the final PTE.

4. **PTE–VAD discrepancy**  
   - For each **committed** region from **ZwQueryVirtualMemory**, if the **VAD protection** says non-executable (no execute bits) but the **PTE** has **NX bit clear** (page is executable), record a **discrepancy**. This indicates possible PTE tampering (e.g. NX stripped to run shellcode). The scan output includes **DiscrepancyCount** and an array of **Discrepancies** (VA, VadProtect, PteValue).

**Caveats**: Behaviour with **VBS/HVCI** or **5-level paging** may differ. Use in a test (e.g. VM) environment.

---

## 5. Memory range spatial index (interval tree)

To support **fine-grained** protection (e.g. protecting a game’s anti-cheat `.text` section by address range), the driver maintains an **interval tree** per process:

- **Structure**: For each PID that has at least one protected range, the driver keeps a BST keyed by `[Low, High)` with an augmented **MaxHigh** in each node. This allows **point-in-interval** queries in **O(log N)**.
- **API**: `AegisIsAddressInProtectedRange(Pid, Address)` returns TRUE if the given virtual address falls inside any registered range for that process. Use this in future memory read/write interception or hidden scans.
- **IOCTLs**: `IOCTL_AEGIS_ADD_RANGE` and `IOCTL_AEGIS_REMOVE_RANGE` (input: `Pid`, `Low`, `High`) add or remove one interval. Limits: `AEGIS_MAX_RANGE_CONTEXTS` (PIDs with ranges), `AEGIS_MAX_RANGES_PER_PID` (intervals per process).
- **Client**: `addrange <PID> <Low_hex> <High_hex>` and `removerange <PID> <Low_hex> <High_hex>` for testing.
