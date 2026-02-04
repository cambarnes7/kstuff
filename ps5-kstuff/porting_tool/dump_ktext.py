#!/usr/bin/env python3
"""
PS5 Kernel .text Section Dumper

Dumps the kernel's executable .text section for offline analysis using
firmware-specific offsets. The dump can be loaded into reverse engineering
tools (Ghidra, IDA Pro, Binary Ninja) for disassembly and analysis.

The key insight is that in the PS5 kernel offset tables, negative offsets
relative to kdata_base point into the .text section. By using these offsets
as landmarks combined with page table walking via kernel_pmap_store, we can
determine the exact .text boundaries and dump the section safely.

For FW 4.03, known .text offsets range from:
  -0x9d6f80 (cpu_switch, ~10.3 MB below kdata_base) to
  -0xa9b00  (malloc, ~676 KB below kdata_base)

Usage:
    python3 dump_ktext.py <offsets.json> <ps5_ip> [loader_port] [output_file]

Arguments:
    offsets.json  - JSON file with firmware offsets (must have allproc,
                    kernel_pmap_store; negative offsets help determine range)
    ps5_ip        - IP address of the PS5
    loader_port   - Port for the payload loader (default: 9019)
    output_file   - Output file path (default: ktext_dump.bin)

Required offsets in JSON:
    allproc              - Process list head offset (for r0gdb init)
    kernel_pmap_store    - Kernel page map store (for page table walking)

Output:
    <output_file>          - Raw binary dump of kernel .text
    <output_file>_meta.json - Metadata (base address, size, fw version)

    Load the raw binary in Ghidra at the text_base address from the metadata.
"""

import sys
import json
import struct
import os
import time

if 'linux' not in sys.platform:
    print('This tool only supports GNU/Linux. Use Docker or WSL on other OSes.')
    sys.exit(1)

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(0)

import gdb_rpc

# --- Argument Parsing ---

offsets_path = sys.argv[1]
ps5_ip = sys.argv[2]
loader_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9019
output_path = sys.argv[4] if len(sys.argv) > 4 else 'ktext_dump.bin'

with open(offsets_path) as f:
    symbols = json.load(f)

if 'allproc' not in symbols:
    print('error: offsets.json must contain "allproc"')
    sys.exit(1)

if 'kernel_pmap_store' not in symbols:
    print('error: offsets.json must contain "kernel_pmap_store"')
    print('       (needed for page table walking to find .text boundaries)')
    sys.exit(1)

gdb = gdb_rpc.GDB(ps5_ip, loader_port)

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']


def ostr(x):
    """Convert to unsigned 64-bit string for GDB expression evaluation."""
    return str(x % 2**64)


# --- Page Table Walking ---
#
# x86-64 uses 4-level page tables:
#   PML4 (bits 47:39) -> PDPT (bits 38:30) -> PD (bits 29:21) -> PT (bits 20:12)
#
# We walk the kernel's page tables through the direct memory map (dmap),
# which maps all physical memory at a fixed virtual offset. This lets us
# safely check if a virtual address is mapped without risking a panic from
# accessing unmapped memory.
#
# Page table entry flags:
#   Bit 0 (P)   - Present
#   Bit 7 (PS)  - Page Size (2MB huge page at PD level, 1GB at PDPT level)
#   Bit 63 (NX) - No-Execute (0 = executable, i.e. .text)

def read_pte(dmap_base, phys_addr):
    """Read a page table entry from its physical address via the dmap."""
    return gdb.ieval('{void*}%d' % (dmap_base + phys_addr))


def is_page_mapped(addr, dmap_base, cr3):
    """
    Check if a kernel virtual address is mapped by walking the page tables.

    Reads page table entries through the dmap (always safe since the page
    table pages themselves are always mapped). Returns False if any level
    has a non-present entry.
    """
    pml = cr3
    for shift in (39, 30, 21, 12):
        idx = (addr >> shift) & 0x1FF
        entry = read_pte(dmap_base, pml + idx * 8)
        if not (entry & 1):  # Present bit not set
            return False
        if (entry & 0x80) or shift == 12:  # Huge page or final PT level
            return True
        pml = entry & ((1 << 52) - (1 << 12))  # Physical addr of next level
    return False


def is_page_executable(addr, dmap_base, cr3):
    """
    Check if a kernel virtual address is mapped as executable.

    Walks the page table and checks the NX bit (bit 63) at the final level.
    Kernel .text pages should have NX=0 (executable), while .data/.bss will
    have NX=1 (non-executable).
    """
    pml = cr3
    for shift in (39, 30, 21, 12):
        idx = (addr >> shift) & 0x1FF
        entry = read_pte(dmap_base, pml + idx * 8)
        if not (entry & 1):
            return False
        if (entry & 0x80) or shift == 12:
            # Check NX bit: 0 means executable
            return not bool(entry & (1 << 63))
        pml = entry & ((1 << 52) - (1 << 12))
    return False


def find_text_boundaries(kdata_base, dmap_base, cr3):
    """
    Find the kernel .text section boundaries via page table walking.

    Strategy:
    1. Use the most negative known offset as a guaranteed .text address
    2. Scan backward from there in 2MB steps until we hit unmapped memory
    3. Binary search between the last unmapped and first mapped address
       to find the exact boundary at page (4KB) granularity
    4. Verify contiguity with spot checks

    Returns (text_start, text_end) or (None, None) on failure.
    """
    # Find the most negative offset in our symbols - this is the deepest
    # known point in the .text section relative to kdata_base
    most_negative = 0
    for key, value in symbols.items():
        if isinstance(value, int) and value < most_negative:
            most_negative = value

    if most_negative == 0:
        # No negative offsets found - use a conservative default
        # Most PS5 kernels have .text extending ~10MB below kdata_base
        most_negative = -0xA00000
        print('  warning: no negative offsets in JSON, using default range')

    # Page-align the known code address (round down)
    known_code = (kdata_base + most_negative) & ~0xFFF
    print('  deepest known .text offset: %s (%s)' % (
        hex(most_negative),
        next((k for k, v in symbols.items() if v == most_negative), '?')
    ))
    print('  known code address: %s' % hex(known_code))

    # Verify the known address is actually mapped
    if not is_page_mapped(known_code, dmap_base, cr3):
        print('  ERROR: known code address is not mapped - check offsets')
        return None, None

    # Phase 1: Coarse scan backward in 2MB steps
    print('  phase 1: coarse scan (2MB steps)...')
    step = 0x200000  # 2MB
    max_scan = 0x2000000  # 32MB safety limit
    addr = known_code
    unmapped_addr = None

    while kdata_base - addr < max_scan:
        addr -= step
        if not is_page_mapped(addr, dmap_base, cr3):
            unmapped_addr = addr
            break

    if unmapped_addr is None:
        # Everything mapped for 32MB - use the scan limit
        print('  warning: no unmapped boundary found within 32MB, using limit')
        text_start = kdata_base - max_scan
    else:
        # Phase 2: Binary search for exact boundary (4KB precision)
        print('  phase 2: binary search for exact boundary...')
        lo = unmapped_addr  # known unmapped
        hi = unmapped_addr + step  # known mapped

        while hi - lo > 0x1000:
            mid = ((lo + hi) // 2) & ~0xFFF
            if is_page_mapped(mid, dmap_base, cr3):
                hi = mid
            else:
                lo = mid + 0x1000

        text_start = hi

    text_end = kdata_base

    # Phase 3: Spot-check contiguity
    print('  phase 3: verifying contiguity...')
    check_addrs = [
        text_start,
        text_start + 0x1000,
        (text_start + known_code) // 2,
        known_code,
        kdata_base - 0x1000,
    ]
    for cp in check_addrs:
        cp = cp & ~0xFFF
        if text_start <= cp < text_end:
            if not is_page_mapped(cp, dmap_base, cr3):
                print('  WARNING: gap at %s - .text may not be contiguous' % hex(cp))

    return text_start, text_end


# --- Main Dump Logic ---

def dump_ktext():
    """
    Dump the kernel .text section.

    Workflow:
    1. Initialize r0gdb for kernel memory access
    2. Read kernel_pmap_store to get dmap_base and CR3
    3. Walk page tables to find .text boundaries
    4. Stream .text via copyout over a socket connection
    5. Save raw dump + metadata
    """
    print('=== PS5 Kernel .text Dumper ===')
    print()

    # Step 1: Initialize r0gdb
    print('[1/5] Initializing r0gdb...')
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    print('  kdata_base = %s' % hex(kdata_base))

    # Set allproc for kernel R/W initialization
    gdb.eval('offsets.allproc = ' + ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'):
        gdb.eval('r0gdb_init_with_offsets()')
    print('  kernel R/W initialized')

    # Step 2: Get page table info from kernel_pmap_store
    print()
    print('[2/5] Reading kernel page map...')
    kpms_addr = kdata_base + symbols['kernel_pmap_store']

    # kernel_pmap_store layout (FreeBSD pmap structure):
    #   +32: pm_pml4  (virtual address of PML4 via dmap)
    #   +40: pm_cr3   (physical address of PML4)
    # dmap_base = pm_pml4 - pm_cr3
    dmap_virt = gdb.ieval('{void*}%d' % (kpms_addr + 32))
    cr3 = gdb.ieval('{void*}%d' % (kpms_addr + 40))
    dmap_base = dmap_virt - cr3

    print('  dmap_base = %s' % hex(dmap_base))
    print('  cr3       = %s' % hex(cr3))

    # Step 3: Find .text boundaries
    print()
    print('[3/5] Finding .text section boundaries...')
    text_start, text_end = find_text_boundaries(kdata_base, dmap_base, cr3)
    if text_start is None:
        print('FAILED: could not determine .text boundaries')
        return

    text_size = text_end - text_start
    print()
    print('  .text range: %s - %s' % (hex(text_start), hex(text_end)))
    print('  .text size:  %d bytes (%.1f MB)' % (text_size, text_size / (1024 * 1024)))

    # Check if any pages in the range are executable (as expected for .text)
    sample_addr = text_start + text_size // 2
    if is_page_executable(sample_addr, dmap_base, cr3):
        print('  executable:  yes (NX=0 confirmed at midpoint)')
    else:
        print('  note: midpoint page is not marked executable (NX=1)')
        print('        (this is expected on some FW versions with W^X)')

    # Step 4: Dump the .text section via copyout + socket
    print()
    print('[4/5] Dumping .text section...')

    local_buf = bytearray()
    with gdb_rpc.BlobReceiver(gdb, local_buf, '  transferring') as addr:
        remote_fd = gdb.ieval('r0gdb_open_socket("%s", %d)' % addr)
        remote_buf = gdb.ieval('malloc(1048576)')
        one_second = gdb.ieval('(void*)(uint64_t[2]){1, 0}')
        total_sent = 0

        while total_sent < text_size:
            chunk = min(1048576, text_size - total_sent)
            src = text_start + total_sent
            chk0 = gdb.ieval('copyout(%d, %d, %d)' % (remote_buf, src, chunk))
            if chk0 <= 0:
                print('\n  WARNING: copyout returned %d at offset %s' % (
                    chk0, hex(total_sent)))
                break
            assert not gdb.ieval(
                'r0gdb_sendall(%d, %d, %d)' % (remote_fd, remote_buf, chk0))
            total_sent += chk0

        # Wait for all data to arrive
        while len(local_buf) != total_sent:
            gdb.eval('(int)nanosleep(%d)' % one_second)
        gdb.eval('(int)close(%d)' % remote_fd)

    print('  received %d bytes' % len(local_buf))

    # Step 5: Save output files
    print()
    print('[5/5] Saving dump...')

    # Get firmware version if possible
    try:
        fw_version = gdb.ieval('r0gdb_get_fw_version()') >> 16
    except Exception:
        fw_version = 0

    # Save raw binary dump
    with open(output_path, 'wb') as f:
        f.write(local_buf)

    # Save metadata as companion JSON
    meta_path = os.path.splitext(output_path)[0] + '_meta.json'
    metadata = {
        'format': 'ps5_ktext_dump_v1',
        'text_base': hex(text_start),
        'text_end': hex(text_end),
        'text_size': text_size,
        'kdata_base': hex(kdata_base),
        'dmap_base': hex(dmap_base),
        'cr3': hex(cr3),
        'fw_version': hex(fw_version) if fw_version else 'unknown',
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print('  raw dump: %s (%d bytes)' % (output_path, len(local_buf)))
    print('  metadata: %s' % meta_path)

    # Print load instructions
    print()
    print('=== Load Instructions ===')
    print('  Ghidra:  File > Import > Raw Binary')
    print('           Language: x86:LE:64:default')
    print('           Base Address: %s' % hex(text_start))
    print()
    print('  IDA Pro: Load as "Binary file"')
    print('           Processor: metapc (x86-64)')
    print('           Loading segment: %s' % hex(text_start))

    # Validate against known offsets
    print()
    print('=== Offset Validation ===')
    validated = 0
    total_negative = 0
    for key, value in sorted(symbols.items()):
        if not isinstance(value, int) or value >= 0:
            continue
        total_negative += 1
        func_addr = kdata_base + value
        file_offset = func_addr - text_start
        if 0 <= file_offset < len(local_buf):
            preview = local_buf[file_offset:file_offset + 8].hex()
            print('  %-45s addr=%s off=0x%x [%s]' % (
                key, hex(func_addr), file_offset, preview))
            validated += 1
        else:
            print('  %-45s addr=%s OFF OUT OF RANGE' % (key, hex(func_addr)))

    if total_negative > 0:
        print()
        print('  %d/%d known .text offsets validated in dump' % (
            validated, total_negative))

    return bytes(local_buf), text_start


# --- Entry Point ---

if __name__ == '__main__':
    try:
        result = dump_ktext()
        if result:
            print()
            print('Done.')
    except gdb_rpc.DisconnectedException:
        print()
        print('PS5 disconnected. The console may have panicked.')
        print('Restart the PS5 and try again.')
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        print('Aborted.')
        sys.exit(1)
