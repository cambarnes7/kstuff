#!/usr/bin/env python3
"""
PS5 Kernel .text Section Dumper (Brute-Force)

Dumps the kernel's executable .text section for offline analysis using
firmware-specific offsets.  Employs a page-by-page brute-force strategy
that tries multiple read methods per page so that a partial dump is
always produced even when some pages are protected by XOM (execute-only
memory enforced by the PS5 hypervisor via EPT).

Read methods tried per page, in order:
  1. copyout from DMAP+physical  (page-table walk, then read through
     the direct physical memory mapping -- bypasses first-level XOM)
  2. copyout from the .text virtual address directly
     (works if the page is RX rather than XO)
  3. kread8 from virtual address  (setsockopt/getsockopt path --
     different kernel code path from pipe-based copyout)
  4. kread8 from DMAP+physical

Pages that cannot be read by any method are filled with a 0xDEADC0DE
pattern so the dump is still loadable and the gaps are obvious.

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
    <output_file>              - Raw binary dump of kernel .text
    <output_file>_bitmap.bin   - 1 byte per page (0=fail, 1-4=method)
    <output_file>_meta.json    - Metadata (base address, size, stats)

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
    sys.exit(1)

gdb = gdb_rpc.GDB(ps5_ip, loader_port)

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']

DEAD_PATTERN = b'\xDE\xAD\xC0\xDE' * 4  # 16 bytes, tiled to fill page
PAGE_SIZE = 0x1000


def ostr(x):
    """Convert to unsigned 64-bit string for GDB expression evaluation."""
    return str(x % 2**64)


# --- Page Table Walking ---

def read_pte(dmap_base, phys_addr):
    """Read a page table entry from its physical address via the dmap."""
    return gdb.ieval('{void*}%d' % (dmap_base + phys_addr))


def virt2phys(addr, dmap_base, cr3):
    """Walk x86-64 page tables to translate virtual -> physical.
    Returns physical address or None if unmapped."""
    pml = cr3
    for shift in (39, 30, 21, 12):
        idx = (addr >> shift) & 0x1FF
        entry = read_pte(dmap_base, pml + idx * 8)
        if not (entry & 1):
            return None
        if (entry & 0x80) or shift == 12:
            mask = (1 << shift) - 1
            phys_base = entry & ((1 << 52) - (1 << shift))
            return phys_base | (addr & mask)
        pml = entry & ((1 << 52) - (1 << 12))
    return None


def is_page_mapped(addr, dmap_base, cr3):
    """Check if a kernel virtual address is mapped."""
    return virt2phys(addr, dmap_base, cr3) is not None


# --- Brute-Force Page Reader ---

def try_copyout_page(remote_buf, src_addr, one_sec):
    """Try to copyout a full page from src_addr via r0gdb.
    Returns PAGE_SIZE bytes or None."""
    try:
        got = gdb.ieval('copyout(%d, %d, %d)' % (remote_buf, src_addr, PAGE_SIZE))
        if got != PAGE_SIZE:
            return None
        # read the remote_buf back to local memory
        local = bytearray()
        with gdb_rpc.BlobReceiver(gdb, local, None) as addr:
            fd = gdb.ieval('r0gdb_open_socket("%s", %d)' % addr)
            assert not gdb.ieval('r0gdb_sendall(%d, %d, %d)' % (fd, remote_buf, PAGE_SIZE))
            while len(local) < PAGE_SIZE:
                gdb.eval('(int)nanosleep(%d)' % one_sec)
            gdb.eval('(int)close(%d)' % fd)
        if len(local) >= PAGE_SIZE:
            return bytes(local[:PAGE_SIZE])
    except Exception:
        pass
    return None


def try_kread8_page(addr):
    """Read a page 8 bytes at a time via kread8.
    Returns PAGE_SIZE bytes or None (None if all zeros)."""
    result = bytearray(PAGE_SIZE)
    any_nonzero = False
    for off in range(0, PAGE_SIZE, 8):
        try:
            val = gdb.ieval('kread8(%d)' % (addr + off))
        except Exception:
            val = 0
        struct.pack_into('<Q', result, off, val)
        if val:
            any_nonzero = True
    return bytes(result) if any_nonzero else None


def bruteforce_read_page(vaddr, dmap_base, cr3, remote_buf, one_sec):
    """Try every method to read a single 4KB page.
    Returns (data_bytes, method_number) or (None, 0)."""

    phys = virt2phys(vaddr, dmap_base, cr3)

    # Method 1: copyout from DMAP+physical
    if phys is not None:
        data = try_copyout_page(remote_buf, dmap_base + phys, one_sec)
        if data:
            return data, 1

    # Method 2: copyout from virtual address directly
    data = try_copyout_page(remote_buf, vaddr, one_sec)
    if data:
        return data, 2

    # Method 3: kread8 from virtual address
    data = try_kread8_page(vaddr)
    if data:
        return data, 3

    # Method 4: kread8 from DMAP+physical
    if phys is not None:
        data = try_kread8_page(dmap_base + phys)
        if data:
            return data, 4

    return None, 0


# --- Boundary Scanner ---

def find_text_boundaries(kdata_base, dmap_base, cr3):
    """Find .text boundaries using all negative offsets + backward scanning."""

    # Collect all negative offsets
    negative_offsets = {}
    for key, value in symbols.items():
        if isinstance(value, int) and value < 0:
            negative_offsets[key] = value

    if not negative_offsets:
        print('  warning: no negative offsets in JSON, using -0xA00000 default')
        negative_offsets['(default)'] = -0xA00000

    most_negative = min(negative_offsets.values())
    deepest_sym = [k for k, v in negative_offsets.items() if v == most_negative][0]
    print('  %d negative offsets found' % len(negative_offsets))
    print('  deepest: %s = %s' % (deepest_sym, hex(most_negative)))

    known_code = (kdata_base + most_negative) & ~0xFFF

    if not is_page_mapped(known_code, dmap_base, cr3):
        print('  ERROR: deepest known address %s is not mapped' % hex(known_code))
        return None, None

    # Scan backward from deepest known offset to find actual .text start
    print('  scanning backward from %s...' % hex(known_code))
    text_start = known_code
    consecutive_unmapped = 0
    addr = known_code
    pages_scanned = 0

    while pages_scanned < 8192:  # up to 32 MB
        addr -= PAGE_SIZE
        pages_scanned += 1
        if is_page_mapped(addr, dmap_base, cr3):
            consecutive_unmapped = 0
            text_start = addr
        else:
            consecutive_unmapped += 1
            if consecutive_unmapped >= 4:
                break

        # progress
        if pages_scanned % 512 == 0:
            sys.stdout.write('\r  scanned %d pages backward...' % pages_scanned)
            sys.stdout.flush()

    if pages_scanned >= 512:
        print()

    text_end = kdata_base
    text_size = text_end - text_start
    n_pages = text_size // PAGE_SIZE

    print('  scanned %d pages backward' % pages_scanned)
    print('  .text range: %s - %s (%d bytes, %.1f MB, %d pages)' % (
        hex(text_start), hex(text_end), text_size,
        text_size / (1024 * 1024), n_pages))

    return text_start, text_end


# --- Main Dump Logic ---

def dump_ktext():
    """Brute-force dump of the kernel .text section."""

    print('=== PS5 Kernel .text Dumper (Brute-Force) ===')
    print()

    # Step 1: Initialize r0gdb
    print('[1/5] Initializing r0gdb...')
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    print('  kdata_base = %s' % hex(kdata_base))

    gdb.eval('offsets.allproc = ' + ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'):
        gdb.eval('r0gdb_init_with_offsets()')
    print('  kernel R/W initialized')

    # Step 2: Get page table info
    print()
    print('[2/5] Reading kernel page map...')
    kpms_addr = kdata_base + symbols['kernel_pmap_store']
    dmap_virt = gdb.ieval('{void*}%d' % (kpms_addr + 32))
    cr3 = gdb.ieval('{void*}%d' % (kpms_addr + 40))
    dmap_base = dmap_virt - cr3
    print('  dmap_base = %s' % hex(dmap_base))
    print('  cr3       = %s' % hex(cr3))

    # Step 3: Find boundaries
    print()
    print('[3/5] Finding .text boundaries...')
    text_start, text_end = find_text_boundaries(kdata_base, dmap_base, cr3)
    if text_start is None:
        print('FAILED: could not determine .text boundaries')
        return

    text_size = text_end - text_start
    n_pages = text_size // PAGE_SIZE

    # Allocate remote buffer for copyout
    remote_buf = gdb.ieval('malloc(4096)')
    one_second = gdb.ieval('(void*)(uint64_t[2]){1, 0}')

    # Probe methods on a known address
    print()
    print('  probing read methods...')
    negative_offsets = {k: v for k, v in symbols.items()
                       if isinstance(v, int) and v < 0}
    if negative_offsets:
        most_neg = min(negative_offsets.values())
        probe_addr = (kdata_base + most_neg) & ~0xFFF
    else:
        probe_addr = text_start

    probe_phys = virt2phys(probe_addr, dmap_base, cr3)

    methods_avail = []
    if probe_phys is not None:
        d = try_copyout_page(remote_buf, dmap_base + probe_phys, one_second)
        if d:
            methods_avail.append('dmap_copyout')
    d = try_copyout_page(remote_buf, probe_addr, one_second)
    if d:
        methods_avail.append('direct_copyout')
    try:
        v = gdb.ieval('kread8(%d)' % probe_addr)
        if v:
            methods_avail.append('kread8(nonzero)')
        else:
            methods_avail.append('kread8(zero)')
    except Exception:
        pass

    print('  available methods: %s' % (methods_avail if methods_avail else 'NONE detected'))
    if not methods_avail:
        print('  WARNING: no method succeeded on probe -- will brute-force anyway')

    # Step 4: Page-by-page brute-force dump
    print()
    print('[4/5] Brute-force dumping %d pages...' % n_pages)

    dump_data = bytearray()
    bitmap = bytearray(n_pages)
    method_counts = [0, 0, 0, 0, 0]  # [fail, dmap, direct, kr8, kr8dmap]
    pages_ok = 0
    pages_fail = 0
    t0 = time.time()

    for pg in range(n_pages):
        vaddr = text_start + pg * PAGE_SIZE

        data, method = bruteforce_read_page(
            vaddr, dmap_base, cr3, remote_buf, one_second)

        if data:
            dump_data += data
            bitmap[pg] = method
            method_counts[method] += 1
            pages_ok += 1
        else:
            # Fill with dead pattern
            dump_data += DEAD_PATTERN * (PAGE_SIZE // len(DEAD_PATTERN))
            bitmap[pg] = 0
            method_counts[0] += 1
            pages_fail += 1

        # Progress every 64 pages
        if (pg + 1) % 64 == 0 or pg == n_pages - 1:
            elapsed = time.time() - t0
            pct = (pg + 1) * 100 // n_pages
            eta = (elapsed / (pg + 1)) * (n_pages - pg - 1) if pg > 0 else 0
            sys.stdout.write(
                '\r  [%3d%%] page %d/%d  ok=%d fail=%d  '
                '(%.0fs elapsed, ~%.0fs remaining)' % (
                    pct, pg + 1, n_pages, pages_ok, pages_fail,
                    elapsed, eta))
            sys.stdout.flush()

    print()
    print('  done: %d/%d pages read (%.1f%%)' % (
        pages_ok, n_pages, pages_ok * 100.0 / max(n_pages, 1)))
    print('  methods: dmap=%d direct=%d kr8=%d kr8dmap=%d fail=%d' % (
        method_counts[1], method_counts[2], method_counts[3],
        method_counts[4], method_counts[0]))

    # Step 5: Save output
    print()
    print('[5/5] Saving dump...')

    try:
        fw_version = gdb.ieval('r0gdb_get_fw_version()') >> 16
    except Exception:
        fw_version = 0

    # Raw binary
    with open(output_path, 'wb') as f:
        f.write(dump_data)

    # Bitmap
    bitmap_path = os.path.splitext(output_path)[0] + '_bitmap.bin'
    with open(bitmap_path, 'wb') as f:
        f.write(bitmap)

    # Metadata
    meta_path = os.path.splitext(output_path)[0] + '_meta.json'
    metadata = {
        'format': 'ps5_ktext_dump_v2',
        'text_base': hex(text_start),
        'text_end': hex(text_end),
        'text_size': text_size,
        'kdata_base': hex(kdata_base),
        'dmap_base': hex(dmap_base),
        'cr3': hex(cr3),
        'fw_version': hex(fw_version) if fw_version else 'unknown',
        'total_pages': n_pages,
        'pages_ok': pages_ok,
        'pages_fail': pages_fail,
        'method_dmap': method_counts[1],
        'method_direct': method_counts[2],
        'method_kread8': method_counts[3],
        'method_kread8_dmap': method_counts[4],
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print('  raw dump:  %s (%d bytes)' % (output_path, len(dump_data)))
    print('  bitmap:    %s' % bitmap_path)
    print('  metadata:  %s' % meta_path)

    # Load instructions
    print()
    print('=== Load Instructions ===')
    print('  Ghidra:  File > Import > Raw Binary')
    print('           Language: x86:LE:64:default')
    print('           Base Address: %s' % hex(text_start))
    print()
    print('  IDA Pro: Load as "Binary file"')
    print('           Processor: metapc (x86-64)')
    print('           Loading segment: %s' % hex(text_start))

    # Validate known offsets
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
        if 0 <= file_offset < len(dump_data):
            preview = dump_data[file_offset:file_offset + 8].hex()
            is_dead = dump_data[file_offset:file_offset + 4] == b'\xDE\xAD\xC0\xDE'
            status = 'DEAD' if is_dead else 'ok'
            print('  %-40s addr=%s off=0x%06x [%s] %s' % (
                key, hex(func_addr), file_offset, preview, status))
            if not is_dead:
                validated += 1
        else:
            print('  %-40s addr=%s OUT OF RANGE' % (key, hex(func_addr)))

    if total_negative > 0:
        print()
        print('  %d/%d known .text offsets have real data in dump' % (
            validated, total_negative))

    return bytes(dump_data), text_start


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
