# PS5 XOM Bypass & Hypervisor Structure Research
## Target: FW 4.03 | Tools: kstuff + idlesauce/umtx2 jailbreak

---

## The Hard Truth About XOM

**Reading kernel .text = kernel panic. Every single time. No exceptions.**

XOM is enforced by the hypervisor through AMD SVM nested page tables (NPT). The
xotext bit (bit 58) in nested PTEs marks kernel .text as execute-only. When the CPU
executes a memory LOAD instruction targeting an XOM-protected physical page, the nested
page table walk fails, a #NPF (nested page fault) fires, the HV catches it, and the
system panics. This happens for:

- `kread8()` on .text addresses — **PANIC**
- `copyout()` on .text addresses — **PANIC**
- `rep movsb` (used by kelf.asm `cmpb` macro) on .text — **PANIC**
- DMAP reads of .text physical addresses — **PANIC**
- ANY CPU load instruction targeting XOM physical pages — **PANIC**

**Critically: #NPF is handled by the HV, NOT the guest.** The guest kernel cannot
install a fault handler that catches nested page faults. There is no try/catch for
NPF. If the HV decides to panic, you panic. Period.

---

## What Does NOT Panic (Proven by kstuff)

These operations have been executed thousands of times by kstuff/porting_tool without
any panics:

### 1. Reading kernel .data
`kread8()` and `copyout()` on kernel .data addresses work perfectly. The NPT maps
.data pages as readable. kstuff dumps ~134MB of kernel .data this way.

**Proven at:** `prosper0gdb/r0gdb.c:56` (kread8), `prosper0gdb/r0gdb.c:134` (copyout)
**Used by:** porting_tool `dump_kernel()` at `main.py:78-114`

### 2. Walking guest page tables through DMAP
The DMAP (direct map) gives kernel virtual addresses for physical memory. Guest page
table pages are stored in physical memory that IS mapped readable in the NPT. Reading
them through DMAP is safe.

**Proven at:** `ps5-kstuff/main.c:262` (virt2phys reads DMAP+pml)
**Proven at:** `ps5-kstuff/main.c:327` (reads entire PML4 through DMAP)
**Used by:** porting_tool `virt2phys()` at `main.py:289`

### 3. Reading CR3
`r0gdb_read_cr3()` executes `mov rax, cr3` in kernel mode. The HV either doesn't
intercept CR3 reads or returns the guest CR3. This works.

**Proven at:** `prosper0gdb/r0gdb.c:483`
**Used by:** `ps5-kstuff/main.c:258`, `main.c:325`

### 4. Reading/writing MSR 0xC0000084 (SFMASK)
The porting_tool reads and writes this MSR during trace setup. It is NOT in the HV's
MSRPM protection bitmap (or is allowed to pass through).

**Proven at:** `prosper0gdb/r0gdb.c:538`

### 5. Single-step tracing kernel .text
Setting the TF (trap flag) and executing kernel code one instruction at a time is
safe. The CPU EXECUTES the instruction (allowed by XOM — execute is permitted), then
the debug trap captures the register state AFTER each instruction. No read of .text
memory occurs.

**Proven at:** Entire porting_tool offset discovery system
**Example:** `main.py:357-404` finds `rdmsr_start`, `pop_all_iret`, `justreturn`
**Example:** `main.py:557-581` traces `cpu_switch` call tree

### 6. Reading/writing debug registers
Hardware debug registers (DR0-DR7) are accessible through r0gdb.

**Proven at:** `prosper0gdb/r0gdb.c:424-480`

### 7. Kernel function calls via run_in_kernel
Executing kernel instructions with controlled register values. The CPU executes
the instruction (not a read), so XOM doesn't fire.

**Proven at:** `prosper0gdb/r0gdb.c:280` (run_in_kernel)

---

## What MIGHT Panic (Unproven on FW 4.03)

### MSR reads of SVM-specific registers
The HV constructs an MSRPM (MSR Protection Map) bitmap that controls which MSRs
trigger #VMEXIT on access. MSR 0xC0000084 is proven safe. Others are unknown.

**If protected:** rdmsr triggers #VMEXIT → HV injects #GP into guest.
- If kstuff's uelf layer is running (int13_handler installed): #GP is caught cleanly
- If running in raw r0gdb mode (no int13_handler): stock kernel #GP handler runs
  in an unexpected context → likely crash

**Risk mitigation:** Only attempt SVM MSR reads AFTER kstuff uelf is fully installed,
where the `int13_handler` at `uelf/main.c:122` catches #GP. This way a protected
MSR read fails gracefully instead of panicking.

**MSRs we want to read:**
```
0xC0000080 - EFER (might be readable - guest needs to see its own EFER)
0xC0010114 - VM_CR (SVM config - likely MSRPM-protected)
0xC0010117 - VM_HSAVE_PA (host save area - almost certainly MSRPM-protected)
```

### DMAP reads of unknown physical address ranges
The DMAP maps physical RAM to kernel virtual space. For .data physical pages, the
NPT allows reads (proven). For .text physical pages, the NPT has xotext set (PANIC).
For physical pages belonging to the HV itself, we don't know — they might be:
- NPT-unmapped entirely → #NPF → HV handler → probably panic
- NPT-mapped with xotext → #NPF → panic
- NPT-mapped readable → safe (but this would be a HV design flaw)

**There is NO safe way to test this from the guest.** #NPF cannot be caught.

---

## Safe Strategy: What We Can Actually Learn Without Panicking

### Phase 1: Full Guest Page Table Dump (ZERO RISK)

Walk the entire guest page table hierarchy through DMAP. This is proven safe and
gives us:

**a) Complete physical memory map**
```
CR3 → PML4 (512 entries)
  → Each PDPT (512 entries)
    → Each PD (512 entries)
      → Each PT (512 entries) or 2MB/1GB huge pages
```
For each final entry, extract:
- Physical address
- Present bit (0), R/W bit (1), U/S bit (2), NX bit (63)
- Page size (4KB, 2MB, 1GB)

**b) Identify .text vs .data physical ranges**
We know .text virtual addresses from IDT entries and sysent pointers (readable from
.data). Use `virt2phys()` to translate them to physical addresses. This tells us
which physical address ranges to NEVER try to DMAP-read.

**c) DMAP coverage analysis**
Walk the DMAP's own PML4/PDPT/PD/PT entries to see exactly which physical address
range the DMAP covers. Any HV physical pages outside this range are completely
inaccessible (no guest mapping exists). Any HV pages inside this range but with
xotext in the NPT will panic on read.

**d) Physical address gap analysis**
Compare the full set of physical addresses referenced by guest page tables against
the total DMAP-covered range. Gaps might indicate HV-reserved physical regions.

### Phase 2: Exhaustive .data Mining (ZERO RISK)

Scan the entire kernel .data dump for HV-related artifacts:

**a) Function pointers pointing into .text**
Every 8-byte-aligned value in .data that falls in the kernel .text virtual address
range (0xFFFFFFFF80XXXXXX to 0xFFFFFFFF8XXXXXXX) is a .text pointer. Catalog ALL
of them. These form a map of what functions the kernel references, which includes:
- Syscall handler table (sysents) — already known
- Interrupt handlers (IDT) — already known
- Hypercall wrappers (VMMCALL dispatch)
- Callback tables, vtables, function pointer arrays

**b) Hypercall-related structures**
Search .data for patterns related to VMMCALL dispatch. On FW ≤2.70 the hypercall
jump table was directly in .data. On FW 4.03 it may have moved, but there should
still be guest-side structures that reference the hypercall interface:
- Array of exactly 17 function pointers (the 17 known hypercalls)
- Pointers near VMMCALL instruction addresses
- Structures containing both a function pointer and an integer ID (0x00-0x10)

**c) QA flags structure**
The QA flags are shared between HV and guest kernel. They're in .data (writable on
FW 4.03). Look for:
- A flags structure that contains bit fields
- References near known HV initialization code paths
- Values that look like debug/QA configuration

**d) VMCB / SVM pointers**
Even though the HV is separate on FW 4.03, the kernel may store references to
SVM-related structures in .data:
- Physical address values (< 2^39, page-aligned) that don't correspond to known
  kernel physical pages — could be VMCB physical address
- The VMCB is 4KB-aligned, so look for page-aligned physical addresses in .data

**e) String scanning**
Look for strings in .data that reveal HV-related functionality:
- "vmmcall", "hypercall", "hv_", "svm", "npt", "vmcb"
- "xotext", "xom", "execute"
- "qa_flag", "sl_flag", "debug"
- AMD-specific strings

### Phase 3: Blind Disassembly of Key Code Paths (ZERO RISK)

Use single-step tracing to understand kernel code without reading it:

**a) Trace VMMCALL execution**
If we find a hypercall wrapper (from Phase 2 .data mining), trace through it:
1. Set registers for a known-safe hypercall (e.g., CPUID query)
2. Single-step until VMMCALL instruction
3. VMMCALL exits to HV, HV processes it, returns to guest
4. Observe registers after VMMCALL return — shows HV return values
5. The RIP values before VMMCALL give us the wrapper code structure
6. The RIP after VMMCALL shows where the HV returns to

This is safe because VMMCALL is an intentional HV entry point — the HV expects it.

**b) Trace interrupt handlers**
The IDT entries (in .data, readable) give us entry points for all 256 interrupt
handlers. Trace them to understand:
- What #PF (IDT[14]) does — the page fault handler's logic
- What #GP (IDT[13]) does — how the kernel handles protection faults
- What #DB (IDT[1]) does — the debug handler
- These reveal the kernel's internal flow and structure offsets

**c) Trace known system calls**
The porting_tool already traces syscalls. Extend this to trace:
- mmap/mprotect — understand page table manipulation code
- ioctl — understand device interaction, potentially GPU commands
- Any syscall that might interact with the HV internally

**d) Instruction semantics recovery**
For any .text address found as a pointer in .data, recover the instruction at that
address by:
1. Set controlled register values
2. Execute one instruction at the target address
3. Observe register/memory changes
4. Deduce the instruction

Example (already done by porting_tool, main.py:614-632):
```python
# Set rdi = rsp, write known value to [rsp+0xea], set ebx = known value
# Execute instruction at target
# Check if [rsp+0xea] changed → proves it's "add [rdi+0xea], ebx"
```

### Phase 4: Safe MSR Probing (LOW RISK — with #GP handler)

After kstuff uelf is fully installed (int13_handler active), probe MSRs:

**a) Read EFER (0xC0000080)**
This is likely readable — the guest needs to see EFER for normal operation. It tells
us:
- Bit 12: SVME — is SVM enabled? (should be 1)
- Bit 16: xotext/nda feature — is the custom AMD xotext feature enabled?
- Bit 11: NXE — NX bit enabled?

**b) Probe VM_CR (0xC0010114)**
May be MSRPM-protected. If #GP is caught by int13_handler, we know it's protected
(which itself is information). If readable:
- Bit 3: LOCK — SVM config locked
- Bit 4: SVMDIS — SVM disabled

**c) Probe VM_HSAVE_PA (0xC0010117)**
Almost certainly MSRPM-protected. The #GP catch tells us it's protected. If somehow
readable, it gives us the physical address of the host save area (near the VMCB).

**d) Systematic MSR enumeration**
Iterate through all known AMD MSRs, attempting rdmsr on each. With int13_handler
catching #GP, this is safe. Result: a complete map of which MSRs the guest can read
(MSRPM bitmap reverse-engineered from the guest side).

### Phase 5: VMMCALL Probing (LOW RISK)

Issue VMMCALL with different function numbers and observe behavior:

**a) Find VMMCALL gadget**
Trace a known hypercall path to find the address of the `vmmcall` instruction.
Or search .data for code patterns near known hypercall wrappers.

**b) Probe all 17 hypercalls**
```
For each hypercall_id in 0x00..0x10:
  Set RAX = hypercall_id
  Set safe/neutral arguments in RDI, RSI, RDX, RCX
  Execute VMMCALL
  Record: return value (RAX), modified registers, timing
```
This is safe because VMMCALL is the designed HV interface — the HV expects to receive
these calls. Invalid function numbers should return an error code, not panic.

**c) Deep probing of interesting hypercalls**
For hypercalls that return data (rather than just error codes), systematically vary
the arguments and observe how return values change. This reverse-engineers the
HV API from the outside.

---

## Implementation: hv_probe.py

**Tool:** `ps5-kstuff/porting_tool/hv_probe.py`

This is a concrete Python tool that plugs into the existing porting_tool
infrastructure. No new payload required — it uses the same gdb_rpc/r0gdb
mechanism that already works.

### Step 1: Find the HV boundary

```python
import hv_probe
result = hv_probe.find_hv_boundary(gdb, r0gdb, symbols, kdata_base)
```

This traces mmap+mlock of a signed SELF using `fix_mmap_self` as the trace
program. Since `fix_mmap_self` only patches 2 addresses, every instruction
inside sceSblServiceMailbox gets recorded — including the VMMCALL or MMIO
that crosses into the HV.

The tool identifies the HV boundary by looking for:
- **#VMEXIT gaps**: consecutive frames where RIP jumps >15 bytes but the
  control flow isn't a call/ret. This happens because VMMCALL causes #VMEXIT
  which preempts #DB, so the trap for the VMMCALL instruction is "eaten."
- **Polling loops**: repeated short instruction sequences (spin-wait after
  MMIO doorbell write)
- **Subcall analysis**: if VMMCALL is in a helper function called by
  sceSblServiceMailbox, the tool finds it there too.

Output: VMMCALL address, register state before/after, calling convention.

### Step 2: Probe the mailbox interface

```python
handle = result['mailbox_handle']
hv_probe.probe_mailbox_commands(gdb, r0gdb, symbols, kdata_base, handle)
```

This calls `sceSblServiceMailbox` directly through `r0gdb_kfncall` with
crafted 128-byte messages. For each command ID:
1. Allocates kernel buffer, writes command ID at offset 0
2. Calls `sceSblServiceMailbox(handle, buf, buf)` through the kernel wrapper
3. Reads back the response (status at offset 4, full 128 bytes)

This is safe because:
- The kernel wrapper handles VMMCALL setup/teardown properly
- The HV is designed to receive mailbox messages
- Invalid command IDs should return error codes, not crash

### Step 3: Deep probe known commands

```python
hv_probe.probe_known_commands(gdb, r0gdb, symbols, kdata_base, handle)
```

Tests specific command IDs from Byepervisor research (SM_VERIFY_HEADER,
SM_LOAD_SELF_SEGMENT, SM_DECRYPT_SELF_BLOCK, etc.) to map which commands
the HV recognizes and what error codes it returns.

### What this gives us:
- The VMMCALL/MMIO instruction address and register convention
- Which mailbox commands the HV accepts (command enumeration)
- Error codes for invalid/malformed commands
- Response data for valid commands
- The handle value needed to invoke sceSblServiceMailbox
- Full instruction trace of sceSblServiceMailbox internals

### What to do with the results:
1. **Command fuzzing**: for commands that accept arguments, vary the argument
   fields and look for crashes, unexpected responses, or data leaks
2. **Argument overflow**: test oversized/undersized messages
3. **Race conditions**: call multiple commands concurrently from different CPUs
4. **State confusion**: call commands out of expected order
5. **Handle manipulation**: try different RDI handle values

---

## Implementation: xom_bypass.py

**Tool:** `ps5-kstuff/porting_tool/xom_bypass.py`
**Runner:** `ps5-kstuff/porting_tool/run_xom_bypass.py`

This is the integrated XOM bypass toolkit that implements all five research
phases in a single tool. It plugs into the same porting_tool infrastructure
as hv_probe.py — no new payload required.

### Usage

```bash
# Full run (requires porting_tool offsets + kernel .data cache)
python3 run_xom_bypass.py database.json <ps5_ip> [port] [kdata_cache.bin]

# Or from Python:
import xom_bypass
results = xom_bypass.run_full_bypass(gdb, r0gdb, kdata_base, symbols, kernel_data)
```

### What it does

**Phase 1: Guest Page Table Dump** (`dump_guest_page_tables`)
- Walks PML4 → PDPT → PD → PT through DMAP (zero risk)
- Maps all physical memory regions with flags (R/W/X/NX)
- Identifies .text physical ranges (XOM-protected) via IDT cross-reference
- Finds physical address gaps (potential HV-reserved regions)

**Phase 2: Kernel .data Mining** (`scan_kdata_for_hv_artifacts`)
- Catalogs ALL function pointers from .data → .text
- Finds consecutive pointer arrays (potential hypercall dispatch tables)
- Searches for QA flags structure (small flag words near kernel_pmap_store)
- Finds page-aligned physical addresses (potential VMCB pointers)
- Scans for HV-related strings

**Phase 3: Instruction Recovery** (`recover_instructions`)
- Single-step executes .text instructions with controlled register state
- Deduces instruction semantics from register/memory side effects
- Targets addresses found in Phase 2 (hypercall table entries)

**Phase 4: MSR Probing** (`probe_msrs`)
- Reads EFER (SVME bit, potential xotext control in high bits)
- Probes VM_CR (SVM lock state)
- Probes VM_HSAVE_PA (HV save area physical address → VMCB location)
- Enumerates all readable vs MSRPM-protected MSRs
- Safe: #GP caught by kstuff int13_handler

**Phase 5: Sleep/Resume Attack** (`attempt_sleep_resume_attack`)
- Locates QA flags candidates from Phase 2
- Writes debug/QA bits to flag locations
- Tests if XOM enforcement changes
- Provides instructions for manual suspend/resume cycle

### Output files

- `xom_full_results.json` — all phase results combined
- `xom_page_tables.json` — guest physical memory map
- `xom_data_mining.json` — HV artifact scan results
- `xom_msr_results.json` — MSR accessibility map

### Key attack vectors detected

The tool analyzes results across all phases and identifies:
1. **Shared function pointer tables** — if a .data array of .text pointers is
   used by the HV as a dispatch table, overwriting entries redirects HV execution
2. **VM_HSAVE_PA leak** — if readable, reveals VMCB physical address; if the VMCB
   page is DMAP-accessible, NPT entries can be modified to clear xotext
3. **QA flag persistence** — if QA flags survive sleep/resume without HV
   reinitialization, XOM can be disabled through the QA interface
4. **EFER high bits** — custom AMD bits above bit 15 may control xotext; if EFER
   is writable (or modifiable via VMCB), xotext can be toggled

---

## What This Won't Give Us (Limitations)

- **HV code disassembly** — we cannot read HV code. We can only observe its external
  behavior (hypercall returns, MSR interception decisions, XOM enforcement patterns).
- **NPT structure** — nested page table entries are at HV-private physical addresses.
  We cannot read them from the guest without risking #NPF → panic.
- **VMCB contents** — the VMCB is at a physical address we likely can't read.
- **HV internal data structures** — unless they're shared with the guest (like QA flags
  were on ≤2.50), we can't access them.

**The path forward after this research:**
The goal is to find enough information from the safe probing to identify a vulnerability
in the HV's guest-facing interface (hypercalls, MSR handling, interrupt handling,
page table management) that allows escalation to HV code execution or XOM disablement.
Byepervisor found two such vulnerabilities on ≤2.50:
1. Shared jump table in .data (FW ≤2.70)
2. QA flags not reinitialized on sleep resume

Similar guest-facing attack surface exists on FW 4.03 — we just need to find it.

---

## References

- [PS5 Wiki - Hypervisor](https://ps5dev.github.io/ps5-wiki/hypervisor)
- [PS5 Wiki - XOM](https://ps5dev.github.io/ps5-wiki/xom)
- [PS5Dev Wiki - Hypervisor](https://www.psdevwiki.com/ps5/Hypervisor)
- [PS5Dev Wiki - Vulnerabilities](https://www.psdevwiki.com/ps5/Vulnerabilities)
- [Byepervisor (FW ≤2.50)](https://github.com/PS5Dev/Byepervisor)
- [PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak)
- [idlesauce/umtx2](https://github.com/idlesauce/umtx2)
- [Byepervisor talk at hardwear.io NL 2024](https://hardwear.io/netherlands-2024/speakers/specter.php)
- [AMD SVM Architecture Reference](https://www.0x04.net/doc/amd/33047.pdf)
- [Google Project Zero - KVM VMCB escape](https://projectzero.google/2021/06/an-epyc-escape-case-study-of-kvm.html)
