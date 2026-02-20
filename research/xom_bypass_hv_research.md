# PS5 XOM Bypass & Hypervisor Structure Research
## Target: FW 4.03 | Tools: kstuff + idlesauce/umtx2 jailbreak

### The Problem

On PS5 FW 4.03, after umtx2 jailbreak we have:
- **Kernel arbitrary read/write** (via pktopts/pipe primitives in r0gdb.c)
- **Kernel .data is fully readable AND writable** (no .data write protection until FW 6.00)
- **Kernel .text is XOM-protected** — any read attempt triggers a nested page fault, the hypervisor catches it, and the system panics
- **No decrypted firmware dump available**

The hypervisor enforces XOM through AMD SVM nested page tables (NPT). The xotext
bit (bit 58) in nested PTEs marks kernel .text as execute-only. The HV also intercepts
CR0/CR4 writes and blocks EFER bit 16 (xotext enable), bit 12 (SVME), and bit 11 (NXE)
changes via masked EFER writes.

We need to understand the hypervisor structure to eventually break it, **without
triggering kernel panics**.

---

## What kstuff Already Gives Us (Panic-Free)

### 1. Kernel .data dump (r0gdb `copyout`)
`prosper0gdb/r0gdb.c:134` — `copyout()` can bulk-copy kernel .data to userspace.
The porting_tool (`main.py:78-114`) dumps ~134 MB of kernel .data this way. This
region contains:
- **Function pointer tables** (sysents, sysents_ps4) pointing into .text
- **IDT entries** — 256 interrupt descriptors, each containing .text handler addresses
- **GDT/TSS arrays** — processor descriptor tables
- **PCPU array** — per-CPU data structures
- **Hypercall-related structures** — on FW ≤2.70 the jump table was in .data; on 4.03
  the HV is separate but there may still be guest-side data structures
- **kernel_pmap_store** — the kernel page map, containing physical address mappings
- **QA flags** — shared between HV and guest kernel
- **String references** — xrefs to known strings leak structure offsets

### 2. Single-step execution tracing (r0gdb trace)
`prosper0gdb/r0gdb.c:531` — `r0gdb_trace()` sets up the TF (trap flag) to single-step
kernel instructions. At each step it captures a full frame:
```
{rip, cs, eflags, rsp, ss, rax, rcx, rdx, rbx, pad, rbp, rsi, rdi, r8-r15}
```
This is the **core XOM bypass technique**: the CPU EXECUTES each instruction (allowed
by XOM), and the debug trap captures the state AFTER each instruction. By observing:
- **RIP delta** → instruction length
- **Register changes** → instruction semantics
- **RSP changes** → calls/returns/pushes/pops
- **Memory side effects** (via subsequent kread8) → stores

You effectively disassemble code **through execution** without ever reading it.

### 3. Register/MSR/CR access (r0gdb)
- `r0gdb_rdmsr(ecx)` / `r0gdb_wrmsr(ecx, value)` — read/write MSRs
- `r0gdb_read_cr3()` / `r0gdb_write_cr3()` — read/write CR3
- `r0gdb_read_dbregs()` / `r0gdb_write_dbregs()` — hardware debug registers
- `run_in_kernel(regs)` — execute arbitrary kernel instructions with controlled registers

### 4. Instrumented tracing (trace_prog callbacks)
`prosper0gdb/r0gdb.c:646` — `r0gdb_instrument()` installs a custom callback that
fires at every single-stepped instruction. The porting_tool uses this extensively:
- `trace_skip_scheduler_only` — trace syscalls skipping context switches
- `trace_calls` — trace function call trees
- `do_jprog` — programmable trace with register injection
- `leak_rep_movsq` — find gadgets by observing execution side effects

---

## Strategies to Research the Hypervisor (Panic-Free)

### Strategy 1: Mine Kernel .data for HV Artifacts
**Risk: NONE — purely reads .data**

The kernel .data section contains a wealth of information about the hypervisor:

**a) Hypercall table pointers**
The PS5 has only ~17 hypercalls (VMMCALL 0x0-0x10). On FW 4.03, the HV is a separate
component, but the guest-side dispatch table or function pointers may still reside in
kernel .data. Scan for:
- Arrays of 17 code pointers (values in kernel .text range, i.e., 0xFFFFFFFF8XXXXXXX)
- VMMCALL wrapper functions referenced from sysent or other dispatch tables
- Strings like "vmmcall", "hypercall", "hv_" in the .data region

**b) VMCB pointer / VM_HSAVE_PA**
The VMCB (Virtual Machine Control Block) is a 4KB page that controls the VM. Its
physical address may be referenced in kernel .data. Look for:
- The VM_HSAVE_PA MSR (0xC0010117) — read it via `r0gdb_rdmsr(0xC0010117)` to get
  the VMCB host save area physical address
- Pointers to page-aligned physical addresses in low memory (VMCB is typically in
  low physical memory)

**c) QA flags location**
The QA flags are shared between HV and guest kernel. On Byepervisor, setting the SL
(System Level) debug flag causes the HV to skip setting the xotext bit on NPT entries
during initialization. Even on FW 4.03 (where the sleep/resume trick may not work the
same way), finding the QA flags structure is valuable:
- Search .data for known flag patterns
- Look for references near HV initialization code paths

**d) kernel_pmap_store → NPT root**
The kernel_pmap_store (found by the porting_tool at `main.py:248`) contains the
physical address mapping for kernel virtual addresses. From this you can:
- Calculate the direct-map (DMAP) base address
- Walk the guest page tables to find all .text/.data regions
- Look for NPT-related pointers stored alongside kernel pmap data

**e) IDT handler analysis**
All 256 IDT entries are in .data and point into .text. These are extremely valuable:
- IDT[1] = #DB (debug exception) — the core of r0gdb
- IDT[6] = #UD (undefined opcode)
- IDT[13] = #GP (general protection fault)
- IDT[14] = #PF (page fault) — triggers on XOM violation before HV intercept
- IDT[244+] = system-specific handlers (LAPIC, timers, etc.)
Each IDT entry leaks a .text address. Combined with tracing, you can map the entire
interrupt handling flow.

### Strategy 2: Blind Disassembly via Single-Step Tracing
**Risk: NONE — only executes code (allowed by XOM), never reads it**

This is the most powerful technique already proven by the porting_tool:

**a) Instruction length oracle**
Single-step from a known address. `RIP_after - RIP_before = instruction_length`.
x86 instruction lengths range from 1-15 bytes. Combined with register deltas, this
often uniquely identifies the instruction.

**b) Controlled-input execution**
Set specific register values via r0gdb, execute one instruction, observe changes:
```
Example from porting_tool main.py:614-618:
  Set rdi = rsp, {int}(rsp+0xea) = 123456789, ebx = 987654321
  Execute instruction at resumectx+192
  Check: {int}(rsp+0xea) == 1111111110
  → This proves the instruction is "add [rdi+0xea], ebx"
```
By controlling inputs and observing outputs, you can determine instruction semantics
for ANY kernel .text address without reading it.

**c) Full function tracing**
Trace an entire function call tree:
```python
# From porting_tool: trace a syscall to find cpu_switch
trace = Trace(r0gdb.trace('trace_calls', 'nanosleep', ...))
for i in range(1, len(trace)):
    if trace.is_jump(i-1) and trace[i].rsp not in range(...):
        # Found a function call boundary
```
This builds a call graph of kernel execution without reading any code.

**d) Systematic sweep of .text region**
Given that we know .text addresses from .data pointers (IDT entries, sysent handlers,
etc.), we can:
1. Start at each known .text address
2. Single-step through the function
3. Record all executed paths
4. Build a map of the entire reachable code

### Strategy 3: VMMCALL Probing (Hypercall Fuzzing)
**Risk: LOW — worst case is a clean VM exit, not a panic**

The PS5 has ~17 documented hypercalls. Using `run_in_kernel()` we can:

**a) Enumerate hypercall interface**
```c
struct regs r = {0};
r.rip = <address_of_vmmcall_gadget>;  // find via trace
r.rax = hypercall_number;  // 0x0 through 0x10
r.rdi = arg1;
r.rsi = arg2;
// etc.
run_in_kernel(&r);
// Check r.rax for return value, other regs for outputs
```

**b) Known PS5 hypercalls to probe:**
- 0x00-0x03: Message/loading operations
- 0x04: HV_SET_CPUID_PS4 (the one Byepervisor hijacks on ≤2.50)
- 0x05: CPUID configuration
- 0x06-0x0C: IOMMU management
- 0x0D: TMR violation handling
- 0x0E-0x10: Multi-processing operations

Each call's return values and side effects reveal HV internal behavior.

**c) VMMCALL gadget location**
Find a `vmmcall; ret` sequence by tracing code paths that are known to make
hypercalls (IOMMU setup, CPUID emulation, etc.). The porting_tool's trace
mechanism can identify the exact address.

### Strategy 4: AMD SVM MSR/CR Reconnaissance
**Risk: NONE for reads; careful with writes**

AMD SVM exposes significant HV configuration through MSRs:

**Critical MSRs to read via r0gdb_rdmsr():**
```
0xC0000080 - EFER (Extended Feature Enable Register)
  → Bit 12: SVME (SVM enable)
  → Bit 16: xotext/nda feature enable
  → Bit 11: NXE (No-Execute enable)

0xC0010114 - VM_CR (VM Configuration Register)
  → Bit 4: SVMDIS (SVM disable)
  → Bit 3: LOCK (SVM lock)
  → Reveals whether SVM can be reconfigured

0xC0010117 - VM_HSAVE_PA (Host Save Area Physical Address)
  → Physical address where host state is saved on VMRUN
  → This is adjacent to or near the VMCB

0xC0010130-0xC001013F - SMI_ON_IO_TRAP / SVM related
0xC0000101 - GS_BASE (used for PCPU pointer)
0xC0000102 - KERNEL_GS_BASE
0x00000277 - PAT (Page Attribute Table)
```

**What the reads reveal:**
- EFER tells us exactly which SVM features are enabled
- VM_HSAVE_PA gives us a physical address anchor into HV memory
- VM_CR tells us if SVM configuration is locked
- Comparing guest-visible vs actual MSR values reveals what the HV intercepts

**Note:** MSR reads from the guest may return intercepted/virtualized values. The
MSRPM (MSR Protection Map) bitmap controls which MSRs trigger #VMEXIT on access.
If a read returns a value, it's either the real value or the HV's virtualized value —
both are informative.

### Strategy 5: Page Table Archaeology
**Risk: NONE — reading .data structures**

With `r0gdb_read_cr3()` and kernel R/W, we can walk the entire page table hierarchy:

**a) Walk guest page tables (GPT)**
```
CR3 → PML4 → PDPT → PD → PT → Physical page
```
For each entry, extract:
- Present bit, R/W bit, U/S bit, XD (NX) bit
- Physical address of next level / final page
- **The xotext bit (bit 58 in NPT entries)** — but this is in nested page tables

**b) Locate the NPT root**
The nested page table root CR3 is stored in the VMCB (offset 0x008 in the VMCB
control area for nCR3). If we can find the VMCB physical address through:
- VM_HSAVE_PA MSR → nearby in physical memory
- Scanning low physical memory via DMAP for VMCB signatures
- Finding NPT root references in kernel .data

**c) Walk NPT entries to map XOM**
Once we have the NPT root, walk the nested page tables:
- Entries with bit 58 set = xotext (XOM-protected)
- Entries without bit 58 = normal access
- This gives a complete map of what's protected and what isn't

**d) DMAP base calculation**
The porting_tool already calculates this:
```python
dmem_base = deref('kernel_pmap_store', 32) - deref('kernel_pmap_store', 40)
```
The DMAP maps all physical memory into kernel virtual space, so:
- `dmap_base + physical_addr` = kernel virtual address
- This lets us read ANY physical page (that isn't XOM-protected)
- The HV's own code pages (separate binary on FW 4.03) might be readable
  if they're only XOM-protected via NPT and we access through DMAP

### Strategy 6: HV Code Through DMAP (HIGH VALUE)
**Risk: MEDIUM — may panic if HV pages are also NPT-protected from DMAP reads**

On FW 4.03, the HV is a separate binary loaded at a specific physical address range.
The kernel .text is XOM-protected via NPT, but:

**Critical question: Is the HV's own code XOM-protected from the guest?**

If the HV only XOM-protects kernel .text pages (which is what the documentation
suggests — "kernel .text pages are marked as eXecute Only Memory"), then:
- The HV's own code lives at different physical pages
- Those physical pages might be readable through the DMAP
- Reading them wouldn't trigger XOM because XOM is only enforced on kernel .text PTEs

**How to test safely:**
1. Read CR3 and walk guest page tables to find all mapped regions
2. Walk NPT (if accessible) to find non-XOM physical pages
3. Identify physical address ranges that correspond to the HV binary
4. Attempt a **small** read (1 byte) of a candidate HV page via DMAP
5. If it doesn't panic → we can dump the entire HV

**Why this might work:**
- The HV intercepts are set up to protect kernel .text integrity
- The HV's own code runs at a higher privilege level (host mode)
- NPT mappings for guest access may not cover HV-private physical pages at all
  (they'd simply be unmapped in the guest NPT, causing #NPF → not a panic,
  just a fault that could be caught)

**Why this might not work:**
- Sony may have mapped the HV physical pages as inaccessible in the guest NPT
- An NPF on unmapped pages might still crash (depends on how the HV handles it)

**Safe testing approach:**
- Set up r0gdb with a controlled trap handler
- Install a custom #PF handler that catches faults gracefully
- Attempt the DMAP read inside the trap handler
- If it faults, the handler returns cleanly without panic

### Strategy 7: Speculative / Timing Side Channels
**Risk: NONE — passive observation**

Even without reading code, timing differences reveal information:

**a) Performance counters via MSR**
AMD CPUs expose performance monitoring counters. Read them before/after executing
a code path to count:
- Retired instructions
- Branch mispredictions
- Cache hits/misses
- TLB misses

This reveals code complexity and branching behavior.

**b) Cache side channels (FLUSH+RELOAD / PRIME+PROBE)**
After executing a kernel function, probe cache lines to determine:
- Which code pages were accessed (revealing execution path)
- Which data structures were touched
- Whether specific branches were taken

**c) TSC (Time Stamp Counter) measurements**
Measure execution time of hypercalls or kernel functions to:
- Distinguish fast-path vs slow-path execution
- Identify which hypercall numbers are valid vs invalid
- Detect internal branching within the HV

### Strategy 8: IOMMU/GPU DMA as a Read Oracle
**Risk: MEDIUM — requires GPU programming expertise**

On FW 4.03, the IOMMU is managed by the HV. However:
- The GPU has DMA access that goes through the IOMMU
- If the IOMMU doesn't enforce XOM the same way NPT does...
- A GPU compute shader could potentially DMA-read kernel .text pages

This is the technique used on FW 6.00+ to bypass .data write protection.
On 4.03 where .data is already writable, the same DMA mechanism could
potentially be used for .text READS instead.

**Implementation path:**
1. Find GPU command buffer submission interfaces in kernel .data
2. Craft a GPU compute shader that reads from a physical address
3. Submit via kernel R/W into GPU command buffers
4. GPU DMA reads bypass CPU-side NPT (goes through IOMMU instead)
5. If IOMMU doesn't enforce XOM → full kernel .text dump

---

## Recommended Execution Order

### Phase 1: Information Gathering (Zero Risk)
1. **Dump kernel .data** — get the full ~134MB kdata dump
2. **Read all SVM-related MSRs** — EFER, VM_CR, VM_HSAVE_PA, etc.
3. **Read CR3** — get the guest page table root
4. **Walk guest page tables** — map all virtual→physical translations
5. **Extract all IDT entries** — get all .text handler addresses
6. **Locate kernel_pmap_store** — get DMAP base and physical layout

### Phase 2: Page Table Analysis (Zero Risk)
7. **Analyze guest page tables** — identify all .text vs .data regions
8. **Attempt to find NPT root** — via VMCB location or .data scanning
9. **Walk NPT if accessible** — map XOM bits across all physical pages
10. **Identify HV physical address range** — from NPT or physical memory scan

### Phase 3: Controlled Probing (Low Risk)
11. **Probe DMAP reads of HV pages** — with fault handling in place
12. **Trace VMMCALL wrapper** — find the gadget address via single-step
13. **Enumerate all 17 hypercalls** — probe each with safe parameters
14. **Single-step key interrupt handlers** — IDT[14] (#PF), IDT[13] (#GP)

### Phase 4: Deep Analysis (Low-Medium Risk)
15. **Build full trace of VMMCALL paths** — how does the kernel invoke each call?
16. **Trace IOMMU setup code** — understand GPU DMA configuration
17. **Attempt GPU DMA read of .text** — if IOMMU allows it
18. **Map QA flags structure** — for potential sleep/resume approaches

---

## Implementation Notes for ELF Payload

The ELF payload should be built with PS5 Payload SDK and sent via the idlesauce
host to 192.168.0.88. The payload should:

1. Initialize r0gdb (reuse kstuff's `r0gdb_init()`)
2. Set up socket connection back to Mac at 192.168.0.99 for data exfiltration
3. Implement each probe as a separate function callable via kekcall
4. Send results back over the socket in a structured format
5. Include fault handling (r0gdb's IDT manipulation) to catch #PF/#GP gracefully

Key files to base the payload on:
- `prosper0gdb/r0gdb.c` — kernel R/W, MSR, CR3, debug register primitives
- `ps5-kstuff/main.c` — ELF loading, IDT/GDT/TSS manipulation
- `ps5-kstuff/porting_tool/main.py` — offset discovery techniques (reference)
- `gdb_stub/ring0.c` — ring0 execution framework

---

## Key Constraints

- **NEVER use kread8/copyout on .text addresses** — instant panic
- **The comparison_table mechanism (cmpb in kelf.asm) uses rep movsb** — this is a
  CPU read operation and WILL trigger XOM on .text pages
- **Single-stepping is safe** — the CPU executes instructions (allowed), then traps
- **All .data reads are safe** — the HV only protects .text
- **MSR reads from guest may return virtualized values** — still informative
- **Hypercall probing should use known-valid parameters first** — validate the
  interface before fuzzing

---

## References

- [PS5 Wiki - Hypervisor](https://ps5dev.github.io/ps5-wiki/hypervisor)
- [PS5 Wiki - XOM](https://ps5dev.github.io/ps5-wiki/xom)
- [PS5Dev Wiki - Hypervisor](https://www.psdevwiki.com/ps5/Hypervisor)
- [PS5Dev Wiki - Vulnerabilities](https://www.psdevwiki.com/ps5/Vulnerabilities)
- [Byepervisor (FW ≤2.50)](https://github.com/PS5Dev/Byepervisor)
- [PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak)
- [idlesauce/umtx2](https://github.com/idlesauce/umtx2)
- [Cryptogenic/PS5-IPV6-Kernel-Exploit](https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit)
- [Byepervisor talk at hardwear.io NL 2024](https://hardwear.io/netherlands-2024/speakers/specter.php)
- [AMD SVM Architecture Reference](https://www.0x04.net/doc/amd/33047.pdf)
