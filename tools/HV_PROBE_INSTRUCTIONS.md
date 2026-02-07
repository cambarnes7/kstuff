# PS5 Hypervisor Probe — Phases 1-3 Instructions

## Overview

This tooling probes the PS5 hypervisor from kernel context using kstuff as a
research platform. It maps which MSRs and control registers the HV intercepts,
blocks, or filters — building a picture of the HV's attack surface without
needing to break XOM or read kernel .text.

## Architecture

```
┌─────────────────┐         TCP:9020          ┌──────────────────┐
│   PC             │ ◄───────────────────────► │   PS5             │
│   hv_probe.py    │    binary protocol        │   hv_probe_server │
│   (controller)   │                           │   (userspace)     │
│                  │                           │        │          │
│   checkpoint.json│                           │    kekcall(nr)    │
└─────────────────┘                           │        │          │
                                               │   ┌────▼────┐    │
                                               │   │ kstuff   │    │
                                               │   │ uelf     │    │
                                               │   │ kekcall.c│    │
                                               │   │ hv_probe │    │
                                               │   └────┬────┘    │
                                               │        │          │
                                               │   rdmsr/wrmsr    │
                                               │   run_gadget()   │
                                               │   (ring 0)       │
                                               └──────────────────┘
```

## Components

### Kernel-side (built into kstuff automatically)

- **`ps5-kstuff/uelf/hv_probe.c`** — Probe functions wrapping existing
  `rdmsr()`/`wrmsr()`/`read_cr0()`/`write_cr0()` from `utils.c` with
  proper fault detection via kstuff's #GP handler.

- **`ps5-kstuff/uelf/kekcall.c`** (modified) — New kekcall handlers:

  | Nr | Operation | Args | Returns |
  |----|-----------|------|---------|
  | 3  | rdmsr (existing) | RDI=msr | RAX=value, EFAULT on #GP |
  | 4  | wrmsr (new) | RDI=msr, RSI=value | 0 on success, EFAULT on #GP |
  | 30 | CR read | RDI=cr_num (0=CR0) | RAX=value |
  | 31 | CR write+readback | RDI=cr_num, RSI=value | RAX=readback |
  | 32 | MSR write+readback | RDI=msr, RSI=value | RAX=readback |

### Userspace (PS5-side probe server)

- **`tools/hv_probe_server.c`** — Standalone ELF that listens on TCP port
  9020 and dispatches probe commands via kekcalls. Compile with the PS5
  Payload SDK and load onto the PS5 after kstuff is active.

### PC-side controller

- **`tools/hv_probe.py`** — Python 3 script that connects to the probe
  server, drives all probes, checkpoints results to JSON, and survives
  panics with automatic reconnection.

---

## Build Instructions

### 1. Build kstuff with HV probe support

The new files `hv_probe.c` and `hv_probe.h` in `ps5-kstuff/uelf/` are
picked up automatically by the Makefile wildcard (`uelf/*.c`). Just rebuild
kstuff as usual:

```bash
cd ps5-kstuff && make clean && make
cd ../ps5-kstuff-ldr && make clean && make
```

The resulting `kstuff.elf` now includes kekcall handlers for MSR write,
CR access, and MSR write+readback.

### 2. Build the probe server

With the PS5 Payload SDK:

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
source $PS5_PAYLOAD_SDK/toolchain/prospero.env  # if applicable
$CC -o hv_probe_server.elf tools/hv_probe_server.c
```

Or if compiling manually with clang:

```bash
clang --target=x86_64-sie-ps5 -o hv_probe_server.elf tools/hv_probe_server.c
```

### 3. PC-side (no build needed)

```bash
pip install --user  # no dependencies, stdlib only
python3 tools/hv_probe.py --help
```

---

## Usage

### Step 1: Load kstuff on PS5

Use your existing workflow:
1. Host the webkit exploit
2. PS5 browser visits it → code execution
3. Kernel exploit runs → kernel r/w
4. Load the rebuilt `kstuff.elf` (now with HV probe kekcalls)

### Step 2: Load the probe server on PS5

After kstuff is active, load `hv_probe_server.elf` using your ELF loader.
It will listen on TCP port 9020.

### Step 3: Run the PC-side controller

```bash
# Run all phases:
python3 tools/hv_probe.py <PS5_IP>

# Run a specific phase:
python3 tools/hv_probe.py <PS5_IP> --phase 1    # Priority MSRs only
python3 tools/hv_probe.py <PS5_IP> --phase 2    # Full MSR sweep
python3 tools/hv_probe.py <PS5_IP> --phase 3    # CR analysis

# Resume after a panic (automatic — reads checkpoint):
python3 tools/hv_probe.py <PS5_IP> --resume hv_probe_checkpoint.json
```

---

## Phase 1: Priority MSR Reads

**Goal**: Read high-value MSRs to establish what the HV exposes vs hides.

**What happens**: For each MSR, the probe server calls kekcall(3) which
runs `rdmsr()` in kernel context via an IRET-based gadget chain. If the
MSR causes #GP, kstuff's IDT handler catches it, and `rdmsr()` returns
failure (RIP doesn't advance past the gadget). No panic.

**MSRs probed (in order)**:

| MSR | Name | Why It Matters |
|-----|------|----------------|
| 0xC0000101 | GS_BASE | Baseline — kstuff already uses this, guaranteed safe |
| 0xC0000080 | EFER | Bit 12 = SVME (SVM enable). If readable, check if HV hides the SVM bit |
| 0x0000001B | APIC_BASE | Physical address of LAPIC — gives you an MMIO starting point |
| 0x00000277 | PAT | Page Attribute Table — compare with expected Zen 2 defaults |
| 0xC0000082 | LSTAR | Syscall entry point — should match known kernel address |
| 0xC0000081 | STAR | Syscall selector values |
| 0xC0000084 | SYSCALL_MASK | RFLAGS mask for syscall |
| 0xC0010114 | VM_CR | SVM lock register — **may cause HV termination** |
| 0xC0010117 | VM_HSAVE_PA | HV save area physical address — **HIGH VALUE TARGET** |
| 0xC0010058 | MMIO_CFG_BASE | PCI ECAM base — reveals PCIe config space location |
| 0xC0010010 | SYSCFG | System configuration |
| 0xC001001A | TOP_MEM | Top of memory below 4GB |
| 0xC001001D | TOP_MEM2 | Top of memory above 4GB |

**Expected results**:
- GS_BASE, LSTAR, STAR, SYSCALL_MASK → should succeed (kernel uses these)
- EFER → likely succeeds but the SVM bit (bit 12) may be cleared by the HV
- VM_CR, VM_HSAVE_PA → most likely #GP (HV blocks) or may cause panic
- APIC_BASE, MMIO_CFG_BASE → likely succeeds, gives physical addresses

**What to look for**:
- If EFER is readable and SVME (bit 12) is 0: HV is filtering the value
- If VM_HSAVE_PA is readable: you get the physical address of HV state (!!)
- If APIC_BASE is readable: you get an MMIO address to probe in Phase 4+
- Any MSR that causes a panic (timeout) is logged and blacklisted

---

## Phase 2: Full MSR Sweep

**Goal**: Enumerate all accessible MSRs across AMD architectural ranges.

**Ranges scanned**:
- 0x00000000 - 0x00000400 (Architectural MSRs)
- 0x00000200 - 0x00000280 (MTRR/PAT)
- 0x00000800 - 0x00000840 (x2APIC)
- 0xC0000000 - 0xC0000200 (AMD Extended)
- 0xC0010000 - 0xC0010200 (AMD SVM/platform)

**This is the slow phase.** Each MSR read is a separate kekcall round-trip.
Expect ~2-5 probes/second depending on network latency. The full sweep
of ~2000 MSRs takes roughly 10-15 minutes if nothing panics.

**Checkpointing**: Every successful probe is saved to `hv_probe_checkpoint.json`.
If the PS5 panics mid-sweep, just reboot, reload kstuff + probe server, and
re-run `hv_probe.py` — it will resume from where it left off.

**What to look for in results**:
- Compare accessible MSR values against AMD PPR (Processor Programming Reference)
  for Zen 2. Any value that differs from the documented default may be
  HV-filtered.
- MSRs that #GP but shouldn't (according to AMD docs) are HV-intercepted.
- Any MSR that panics the system is especially interesting — the HV chose
  to kill the guest rather than return an error, suggesting it's
  security-critical.

---

## Phase 3: Control Register Analysis

**Goal**: Read CR0, test if the HV enforces specific CR bits.

**What happens**:
1. Read CR0 via kekcall(30) → report all bits
2. Try toggling the WP (Write Protect) bit in CR0
3. Write modified CR0 via kekcall(31) → read back → compare
4. Restore original CR0

**Interpretation**:
- If WP toggle sticks (readback matches written value): HV allows CR0.WP changes
- If readback differs from written value: HV silently restores/modifies the bit
- If the operation panics: HV blocks CR0 writes entirely

**CR4 is not yet available.** The offset table has no `mov rax, cr4` / `mov cr4, rax`
gadget. To add CR4 support:
1. Use the single-step tracing methodology from sleirsgoevy's OnOffsets gist
2. Trace `pmap_activate_sw` or another function that accesses CR4
3. When you see a single-step where RAX changes to a value with known CR4 bits
   (SMEP, SMAP, FSGSBASE, etc.), that instruction is `mov rax, cr4`
4. Add the address to `prosper0gdb/offset_list.txt` and `offsets.c`
5. Add `read_cr4()` / `write_cr4()` to `utils.c` following the CR0 pattern
6. Add CR4 support to `hv_probe.c` and kekcall handlers

---

## Kekcall Calling Convention (for custom tools)

From PS5 userspace, kekcalls are invoked by executing the `syscall` instruction
with RAX set to `(kekcall_nr << 32) | SYS_getppid`. The kernel resolves
`SYS_getppid` to its sysent entry, and kstuff's syscall hook extracts the
kekcall number from the upper 32 bits of the original RAX (saved on the
kernel stack).

```c
static int64_t kekcall(uint32_t nr, uint64_t arg1, uint64_t arg2)
{
    register uint64_t rax __asm__("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi __asm__("rdi") = arg1;
    register uint64_t rsi __asm__("rsi") = arg2;
    __asm__ volatile("syscall"
        : "+r"(rax), "+r"(rdi), "+r"(rsi)
        : : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory");
    return (int64_t)rax;
}

/* Examples: */
int64_t efer = kekcall(3, 0xC0000080, 0);   /* rdmsr EFER */
int64_t err  = kekcall(4, 0xC0010114, 0);   /* wrmsr VM_CR = 0 */
int64_t cr0  = kekcall(30, 0, 0);           /* read CR0 */
```

Return value:
- On success: the value (MSR value, CR value, etc.) — always >= 0
- On failure: 0 with the syscall returning an error code

---

## Panic Recovery

If a probe causes a kernel panic:
1. The PS5 reboots
2. The Python script detects a timeout (no response within 5 seconds)
3. The script logs which operation caused the panic
4. The script enters wait mode, polling for the probe server to come back
5. After you re-exploit and reload kstuff + probe server, the script
   automatically reconnects and resumes from the checkpoint

**The checkpoint file (`hv_probe_checkpoint.json`) stores**:
- All MSR read results (status + value)
- All MSR write results (written + readback + status)
- All CR read/write results
- A blacklist of operations that caused panics

**Important**: The MSRs most likely to panic are VM_CR (0xC0010114) and
VM_HSAVE_PA (0xC0010117). These are probed last in Phase 1 for this reason.
If they do panic, they are blacklisted and skipped on resume.

---

## What Comes Next (Phase 4+)

After Phases 1-3, you will have:
- A list of all accessible MSRs and their values
- Knowledge of which MSRs the HV blocks or filters
- CR0 behavior under writes
- A list of operations that crash the system

This data tells you:
1. **Which VMEXIT handlers exist** (every blocked MSR = a handler)
2. **What the HV hides** (filtered values = active emulation)
3. **Physical address leads** (APIC_BASE, MMIO_CFG_BASE, VM_HSAVE_PA)
4. **Security-critical boundaries** (operations that panic = HV considers them threats)

Phase 4 (NPT permission mapping) and Phase 5 (physical memory survey)
build on these findings. The physical addresses from MSR reads become
starting points for probing what the HV protects in physical memory.

**Critical prerequisite for Phase 4**: Hook int 14 (#PF) in the IDT
following the `ist_ercc` pattern in `kelf.asm`. Without this, any NPT
violation crashes the kernel (confirmed: kread8 on .text always panics).
