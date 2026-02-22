#!/usr/bin/env python3
"""
Kernel .text dumper for PS5.

Usage: dump_ktext.py <database.json> <ps5_ip> [port] [output_file]

Background: PS5 kernel .text is execute-only (XOM) enforced by the
hypervisor via AMD SVM Nested Page Tables. Prior testing confirmed:
  - kread8(.text VA)           -> kernel panic
  - copyout(.text VA)          -> kernel panic
  - kfncall(copyout, dmap+phys) -> EFAULT (dmap has no PTE for .text phys)
  - kmemcpy(dmap+phys)         -> kernel panic (no pcb_onfault)

Strategy (in order of safety):
  1. Probe with kfncall(copyout) from .text VA (pcb_onfault = safe EFAULT)
  2. Translate .text VA to physical via page table walk
  3. Check if dmap has a PTE for .text physical pages
  4. If no dmap PTE, create one via copyin + TLB flush
  5. Read through the new dmap mapping via kfncall(copyout)
  6. If all else fails, try kread8 (WARNING: likely panics)
"""

import sys, json, os, time, struct

if len(sys.argv) < 3:
    print('usage: dump_ktext.py <database.json> <ps5_ip> [port] [output_file]')
    sys.exit(0)

import gdb_rpc

db_path = sys.argv[1]
ps5_ip = sys.argv[2]
ps5_port = int(sys.argv[3]) if len(sys.argv) >= 4 else 9019
output_file = sys.argv[4] if len(sys.argv) >= 5 else 'ktext_dump.bin'

with open(db_path) as f:
    symbols = json.load(f)

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']

gdb = gdb_rpc.GDB(ps5_ip, ps5_port)

def ostr(x):
    return str(x % 2**64)

def setup_r0gdb():
    """Initialize r0gdb connection and return kdata_base."""
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    gdb.eval('offsets.allproc = ' + ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'):
        gdb.eval('r0gdb_init_with_offsets()')
    return kdata_base

def setup_r0gdb_with_retry(max_retries=2):
    """Try setup_r0gdb with retries. Probes port 1234 before connecting GDB."""
    for attempt in range(max_retries + 1):
        try:
            return setup_r0gdb()
        except gdb_rpc.DisconnectedException as e:
            stderr_msg = getattr(gdb, '_gdb_stderr', None)
            if attempt < max_retries:
                print(f'  Attempt {attempt+1} failed: {e}')
                if stderr_msg:
                    print(f'  GDB stderr: {stderr_msg}')
                delay = 2 * (attempt + 1)
                print(f'  Retrying in {delay}s...')
                time.sleep(delay)
            else:
                # Final attempt failed — provide diagnostics
                print(f'  Failed to connect: {e}')
                if stderr_msg:
                    print(f'  GDB stderr: {stderr_msg}')
                print()
                print('  Diagnosing...')
                port_open = gdb.wait_for_port(1234, timeout=5)
                if not port_open:
                    print('  Port 1234 is NOT open on the PS5.')
                    print('  The payload was sent but the GDB stub never started.')
                    print()
                    print('  Possible causes:')
                    if ps5_port != 9019:
                        print(f'  - Port {ps5_port} loader may be incompatible with')
                        print(f'    prosper0gdb payload-elfldr.elf format.')
                        print(f'    The elfldr payload uses elf_main(struct specter_args*)')
                        print(f'    but ps5-payload-dev loaders pass payload_args_t*.')
                        print(f'  - Try using port 9019 (frankenelf format) instead.')
                    print('  - The payload may have crashed during initialization.')
                    print('  - The PS5 kernel exploit state may need to be re-triggered.')
                else:
                    print('  Port 1234 IS open. GDB failed to connect to it.')
                    print('  This may be a GDB or network issue.')
                raise

def get_dmap_and_cr3(kdata_base):
    """Get dmap base and cr3 from kernel_pmap_store."""
    if 'kernel_pmap_store' not in symbols:
        print('  ERROR: kernel_pmap_store not in database')
        return None, None
    kps = kdata_base + symbols['kernel_pmap_store']
    # kernel_pmap_store+32 = pm_pml4 (VA), +40 = pm_pml4pa (PA)
    pm_pml4 = gdb.ieval('{void*}%d' % (kps + 32))
    pm_pml4pa = gdb.ieval('{void*}%d' % (kps + 40))
    dmap = (pm_pml4 - pm_pml4pa) % (2**64)
    cr3 = pm_pml4pa
    print(f'  dmap = {hex(dmap)}')
    print(f'  cr3 (PML4 phys) = {hex(cr3)}')
    return dmap, cr3

def virt2phys(addr, dmap, cr3):
    """Walk x86-64 page tables to translate VA to PA. Returns (phys, page_size) or (None, 0)."""
    pml = cr3
    for level in (39, 30, 21, 12):
        idx = (addr >> level) & 0x1FF
        entry_pa = pml + idx * 8
        entry = gdb.ieval('{void*}%d' % (dmap + entry_pa))
        if not (entry & 1):  # not present
            return None, 0
        if (entry & 0x80) or level == 12:  # large page or final PTE
            page_mask = (1 << level) - 1
            phys = (entry & ((1 << 52) - 1) & ~page_mask) | (addr & page_mask)
            return phys, 1 << level
        pml = entry & ((1 << 52) - (1 << 12))
    return None, 0

def read_pte_raw(addr, dmap, cr3):
    """Walk page tables and return the raw PTE/PDE leaf entry for addr. Returns 0 if not mapped."""
    pml = cr3
    for level in (39, 30, 21, 12):
        idx = (addr >> level) & 0x1FF
        entry_pa = pml + idx * 8
        entry = gdb.ieval('{void*}%d' % (dmap + entry_pa))
        if not (entry & 1):
            return 0  # not present
        if (entry & 0x80) or level == 12:
            return entry  # leaf entry
        pml = entry & ((1 << 52) - (1 << 12))
    return 0

def find_pte_hole(addr, dmap, cr3):
    """Walk page tables for addr, return (entry_va, level) of first not-present entry.
    Level is the shift value: 39=PML4, 30=PDPT, 21=PD, 12=PT.
    Returns (0, 0) if already fully mapped.
    """
    pml = cr3
    for level in (39, 30, 21, 12):
        idx = (addr >> level) & 0x1FF
        entry_pa = pml + idx * 8
        entry_va = dmap + entry_pa
        entry = gdb.ieval('{void*}%d' % entry_va)
        if not (entry & 1):
            return entry_va, level
        if (entry & 0x80) or level == 12:
            return 0, 0  # already mapped
        pml = entry & ((1 << 52) - (1 << 12))
    return 0, 0

def find_text_range(kdata_base):
    """Determine .text range from known offsets in database.json."""
    text_offsets = []
    for name, value in symbols.items():
        if isinstance(value, int) and value < 0:
            text_offsets.append((name, value))

    if not text_offsets:
        for name, value in symbols.items():
            if isinstance(value, int) and value > 0x7fffffff:
                signed_val = value - (1 << 64) if value >= (1 << 63) else value
                if signed_val < 0:
                    text_offsets.append((name, signed_val))

    if not text_offsets:
        print('ERROR: No .text offsets found in database.json')
        return None, None

    text_offsets.sort(key=lambda x: x[1])
    deepest_name, deepest_off = text_offsets[0]
    shallowest_name, shallowest_off = text_offsets[-1]

    # Page-align start down to 4KB
    text_start = (kdata_base + deepest_off) & ~0xFFF
    text_end = kdata_base

    size = text_end - text_start
    print(f'  .text range: {hex(text_start)} - {hex(text_end)}')
    print(f'  size: {size} bytes ({size / (1024*1024):.1f} MB)')
    print(f'  deepest: {deepest_name} = {hex(deepest_off)}')
    print(f'  shallowest: {shallowest_name} = {hex(shallowest_off)}')
    print(f'  {len(text_offsets)} .text symbols found')

    return text_start, text_end

def probe_kfncall_copyout(kdata_base, addr, label=""):
    """Probe using kfncall(copyout) -- pcb_onfault makes this safe.
    Returns (success, value).
    """
    if 'copyout' not in symbols:
        return False, 0
    prefix = f'  [{label}] ' if label else '  '
    try:
        ubuf = gdb.ieval('malloc(8)')
        ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, 8)' % (
            ostr(kdata_base + symbols['copyout']),
            ostr(addr),
            ostr(ubuf)), timeout=15)
        if ret == 0:
            val = gdb.ieval('{void*}%d' % ubuf)
            print(f'{prefix}kfncall(copyout, {hex(addr)}) = {hex(val)}')
            return True, val
        else:
            print(f'{prefix}kfncall(copyout, {hex(addr)}) = EFAULT ({ret})')
            return False, 0
    except gdb_rpc.DisconnectedException:
        print(f'{prefix}PANIC during kfncall(copyout, {hex(addr)})!')
        raise
    except Exception as e:
        print(f'{prefix}Error: {e}')
        return False, 0

def create_dmap_mapping(phys, dmap, cr3, kdata_base):
    """Create a guest PTE in the dmap page tables to map a .text physical page.

    Returns True if the mapping was created and is readable.
    """
    dmap_va = dmap + phys
    hole_va, hole_level = find_pte_hole(dmap_va, dmap, cr3)

    if not hole_va:
        print(f'  dmap already has mapping for phys {hex(phys)} (unexpected)')
        return True

    print(f'  dmap hole at level {hole_level} (va={hex(hole_va)})')

    if hole_level > 21:
        # Hole at PDPT or PML4 level -- need to allocate intermediate page table pages
        # This is more complex; allocate a zeroed page and link it in
        new_pt = gdb.ieval('r0gdb_kmalloc(4096)')
        if not new_pt:
            print('  ERROR: kmalloc failed for page table page')
            return False

        # Zero the new page table (kmalloc may not zero)
        for off in range(0, 4096, 8):
            gdb.ieval('{void*}%d = 0' % (new_pt + off))

        # Get physical address of new PT page
        new_pt_phys, _ = virt2phys(new_pt, dmap, cr3)
        if new_pt_phys is None:
            print('  ERROR: cannot translate new PT page to phys')
            return False

        # Write intermediate entry: phys | P|RW|U|A
        inter_val = (new_pt_phys & ~0xFFF) | 0x67
        if 'copyin' in symbols:
            gdb.ieval('r0gdb_kfncall(%s, %s, (void*)(uint64_t[1]){%s}, 8)' % (
                ostr(kdata_base + symbols['copyin']),
                ostr(hole_va),
                ostr(inter_val)))
        else:
            gdb.ieval('{void*}%d = %d' % (hole_va, inter_val))

        # Re-check for the next-level hole
        hole_va, hole_level = find_pte_hole(dmap_va, dmap, cr3)
        if not hole_va or hole_level > 21:
            print(f'  ERROR: still no leaf-level hole after PT allocation (level={hole_level})')
            return False

    # Create a leaf PTE/PDE at level 21 (2MB) or 12 (4KB)
    if hole_level == 21:
        # 2MB PDE: phys_base (2MB-aligned) | P|RW|A|D|PS|NX
        pte_val = (phys & ~0x1FFFFF) | 0x80000000000000E3
        print(f'  Creating 2MB PDE: phys={hex(phys & ~0x1FFFFF)}, PDE={hex(pte_val)}')
    else:
        # 4KB PTE: phys_page | P|RW|A|D|NX
        pte_val = (phys & ~0xFFF) | 0x8000000000000063
        print(f'  Creating 4KB PTE: phys={hex(phys & ~0xFFF)}, PTE={hex(pte_val)}')

    # Write the PTE via copyin (kernel write)
    if 'copyin' in symbols:
        gdb.ieval('r0gdb_kfncall(%s, %s, (void*)(uint64_t[1]){%s}, 8)' % (
            ostr(kdata_base + symbols['copyin']),
            ostr(hole_va),
            ostr(pte_val)))
    else:
        gdb.ieval('{void*}%d = %d' % (hole_va, pte_val))

    # Flush TLB by reloading CR3
    print('  Flushing TLB (reload CR3)...')
    gdb.eval('r0gdb_write_cr3(r0gdb_read_cr3())')

    # Verify the mapping exists now
    check = read_pte_raw(dmap_va, dmap, cr3)
    if check & 1:
        print(f'  Mapping created successfully (PTE={hex(check)})')
        return True
    else:
        print(f'  ERROR: Mapping creation failed (PTE={hex(check)})')
        return False

def dump_via_kfncall(text_start, text_end, kdata_base, dmap, cr3, use_dmap):
    """Dump .text via kfncall(copyout), either from .text VA or dmap+phys.

    If use_dmap is True, translates each page to physical and reads via dmap.
    Creates dmap PTEs as needed.
    """
    size = text_end - text_start
    method_name = 'kfncall(copyout) via dmap' if use_dmap else 'kfncall(copyout) direct'
    print(f'\nDumping {size} bytes ({size/(1024*1024):.1f} MB) via {method_name}...')
    print(f'Output: {output_file}')

    copyout_fn = kdata_base + symbols['copyout']
    chunk_size = 4096
    remote_buf = gdb.ieval('malloc(%d)' % chunk_size)

    local_buf = bytearray()
    start_time = time.time()
    errors = 0
    mappings_created = 0
    last_mapped_2mb = None  # track which 2MB region we last created a mapping for

    try:
        addr = text_start
        while addr < text_end:
            remaining = text_end - addr
            to_read = min(chunk_size, remaining)

            src_addr = addr  # default: read from .text VA directly

            if use_dmap:
                phys, pgsz = virt2phys(addr, dmap, cr3)
                if phys is None:
                    # .text VA not mapped in guest PT (shouldn't happen)
                    local_buf.extend(b'\xDE\xAD\xC0\xDE' * (to_read // 4))
                    errors += 1
                    addr += to_read
                    continue

                src_addr = dmap + phys

                # Check if we need to create a dmap mapping
                # Only check once per 2MB region for efficiency
                region_2mb = phys & ~0x1FFFFF
                if region_2mb != last_mapped_2mb:
                    dmap_pte = read_pte_raw(dmap + phys, dmap, cr3)
                    if not (dmap_pte & 1):
                        ok = create_dmap_mapping(phys, dmap, cr3, kdata_base)
                        if ok:
                            mappings_created += 1
                        else:
                            # Mapping creation failed, fill with error pattern
                            local_buf.extend(b'\xDE\xAD\xC0\xDE' * (to_read // 4))
                            errors += 1
                            addr += to_read
                            last_mapped_2mb = region_2mb
                            continue
                    last_mapped_2mb = region_2mb

                # Clamp to page boundary (don't cross into next physical page)
                phys_page_remaining = pgsz - (phys % pgsz)
                to_read = min(to_read, phys_page_remaining)

            try:
                ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, %s)' % (
                    ostr(copyout_fn), ostr(src_addr), ostr(remote_buf), ostr(to_read)),
                    timeout=15)

                if ret == 0:
                    # Read data from remote buffer via GDB
                    chunk = bytearray(to_read)
                    for i in range(0, to_read, 8):
                        val = gdb.ieval('{void*}%d' % (remote_buf + i))
                        n = min(8, to_read - i)
                        struct.pack_into('<Q', chunk, i, val)
                    local_buf.extend(chunk[:to_read])
                else:
                    local_buf.extend(b'\xDE\xAD\xC0\xDE' * (to_read // 4))
                    errors += 1

            except gdb_rpc.DisconnectedException:
                print(f'\nPANIC at addr {hex(addr)} (src={hex(src_addr)})')
                print('PS5 disconnected. Saving partial dump...')
                break

            addr += to_read
            offset = len(local_buf)

            # Progress every 4KB
            if offset % (64 * 1024) < to_read:
                elapsed = time.time() - start_time
                rate = offset / elapsed if elapsed > 0 else 0
                eta = (size - offset) / rate if rate > 0 else 0
                pct = 100.0 * offset / size
                sys.stdout.write(f'\r  {pct:5.1f}% | {offset//1024}/{size//1024} KB | '
                               f'ETA {eta:.0f}s | {errors} err | {mappings_created} maps')
                sys.stdout.flush()

        print()

    except KeyboardInterrupt:
        print(f'\nInterrupted. Saving partial dump...')

    offset = len(local_buf)
    elapsed = time.time() - start_time

    with open(output_file, 'wb') as f:
        f.write(struct.pack('<QQ', text_start, offset))
        f.write(local_buf)

    meta = {
        'text_start': hex(text_start),
        'text_end': hex(text_start + offset),
        'kdata_base': hex(kdata_base),
        'dump_size': offset,
        'total_expected': size,
        'complete': offset == size,
        'errors': errors,
        'mappings_created': mappings_created,
        'elapsed_seconds': round(elapsed, 1),
        'method': method_name,
    }
    meta_path = output_file.rsplit('.', 1)[0] + '_meta.json'
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nDump saved:')
    print(f'  Bytes: {offset} / {size} ({100*offset//size if size else 0}%)')
    print(f'  Errors: {errors}, Mappings created: {mappings_created}')
    print(f'  Time: {elapsed:.1f}s')
    print(f'  Files: {output_file}, {meta_path}')

    return offset == size

def dump_via_kread8(text_start, text_end, kdata_base):
    """Last resort: dump via kread8, 8 bytes at a time.
    WARNING: Prior testing shows this panics on .text VAs!
    """
    size = text_end - text_start
    print(f'\nWARNING: kread8 has been shown to panic on .text VAs in prior testing!')
    print(f'Dumping {size} bytes ({size/(1024*1024):.1f} MB) via kread8...')
    print(f'Estimated time: ~{size * 10 / (10*1024*1024):.0f} minutes (if it works)')

    buf = bytearray(size)
    errors = 0
    start_time = time.time()
    addr = text_start
    offset = 0

    try:
        while addr < text_end:
            try:
                val = gdb.ieval('kread8(%s)' % ostr(addr), timeout=15)
                struct.pack_into('<Q', buf, offset, val)
            except gdb_rpc.DisconnectedException:
                print(f'\nPANIC at {hex(addr)} — kread8 confirmed to panic on .text')
                break
            except Exception:
                struct.pack_into('<Q', buf, offset, 0xDEADC0DEDEADC0DE)
                errors += 1

            addr += 8
            offset += 8

            if offset % 4096 < 8:
                elapsed = time.time() - start_time
                rate = offset / elapsed if elapsed > 0 else 0
                eta = (size - offset) / rate if rate > 0 else 0
                pct = 100.0 * offset / size
                sys.stdout.write(f'\r  {pct:5.1f}% | {offset//1024}/{size//1024} KB | '
                               f'{rate/1024:.1f} KB/s | ETA {eta:.0f}s | {errors} err')
                sys.stdout.flush()

        print()
    except KeyboardInterrupt:
        print(f'\nInterrupted at {hex(addr)}.')

    elapsed = time.time() - start_time

    with open(output_file, 'wb') as f:
        f.write(struct.pack('<QQ', text_start, offset))
        f.write(buf[:offset])

    meta = {
        'text_start': hex(text_start),
        'text_end': hex(text_start + offset),
        'kdata_base': hex(kdata_base),
        'dump_size': offset,
        'total_expected': size,
        'complete': offset == size,
        'errors': errors,
        'elapsed_seconds': round(elapsed, 1),
        'method': 'kread8',
    }
    meta_path = output_file.rsplit('.', 1)[0] + '_meta.json'
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nDump: {offset}/{size} bytes, {errors} errors, {elapsed:.1f}s')
    return offset == size


def main():
    print('=== PS5 Kernel .text Dumper ===')
    print()
    print('Known from prior testing:')
    print('  kread8(.text VA)           -> kernel panic')
    print('  copyout(.text VA)          -> kernel panic')
    print('  kfncall(copyout, dmap+phys) -> EFAULT (no dmap PTE)')
    print('  Creating dmap PTE + read   -> UNTESTED')
    print()

    # Step 1: Connect
    print('[1/5] Connecting to PS5...')
    try:
        kdata_base = setup_r0gdb_with_retry()
    except gdb_rpc.DisconnectedException:
        return
    except Exception as e:
        print(f'  Failed to connect: {e}')
        return
    print(f'  kdata_base = {hex(kdata_base)}')

    # Step 2: Get memory layout
    print('\n[2/5] Getting memory layout...')
    dmap, cr3 = get_dmap_and_cr3(kdata_base)
    if dmap is None:
        print('  Cannot proceed without kernel_pmap_store')
        return

    text_start, text_end = find_text_range(kdata_base)
    if text_start is None:
        return

    # Pick a probe address
    probe_candidates = ['doreti_iret', 'justreturn', 'cpu_switch', 'syscall_before']
    probe_addr = None
    probe_name = None
    for name in probe_candidates:
        if name in symbols and isinstance(symbols[name], int) and symbols[name] < 0:
            probe_name = name
            probe_addr = kdata_base + symbols[name]
            break
    if probe_addr is None:
        for name, val in symbols.items():
            if isinstance(val, int) and val < 0:
                probe_name, probe_addr = name, kdata_base + val
                break
    if probe_addr is None:
        print('  ERROR: No .text symbols for probing')
        return

    # Step 3: Diagnose .text memory layout
    print(f'\n[3/5] Diagnosing .text memory ({probe_name} @ {hex(probe_addr)})...')

    # 3a: Read guest PTE for .text VA
    text_pte = read_pte_raw(probe_addr, dmap, cr3)
    print(f'  Guest PTE for .text VA: {hex(text_pte)}')
    if text_pte & 1:
        print(f'    Present={text_pte&1}, RW={text_pte>>1&1}, PS={text_pte>>7&1}, NX={text_pte>>63&1}')
    else:
        print(f'    NOT PRESENT — .text VA is not mapped in guest PT!')

    # 3b: Translate to physical
    phys, pgsz = virt2phys(probe_addr, dmap, cr3)
    if phys is not None:
        print(f'  Physical addr: {hex(phys)} (page size: {pgsz // 1024}KB)')
    else:
        print(f'  Cannot translate .text VA to physical!')
        return

    # 3c: Check dmap mapping for this physical address
    dmap_pte = read_pte_raw(dmap + phys, dmap, cr3)
    print(f'  dmap PTE for phys: {hex(dmap_pte)}')
    if dmap_pte & 1:
        print(f'    dmap already has mapping (unexpected)')
    else:
        print(f'    dmap has NO mapping for .text phys pages (dp=0, as expected)')

    # 3d: Baseline test — read .data (should always work)
    data_addr = kdata_base + symbols.get('allproc', 0)
    ok, val = probe_kfncall_copyout(kdata_base, data_addr, label='baseline .data')
    if not ok:
        print('  ERROR: Cannot even read .data! Something is wrong.')
        return

    # Step 4: Try read methods in order of safety
    print(f'\n[4/5] Probing read methods...')

    # Method A: kfncall(copyout) from .text VA directly
    # pcb_onfault should catch the fault and return EFAULT (no panic)
    # But if HV handles the #NPF before guest fault handler, it may panic
    print('\n  Method A: kfncall(copyout) from .text VA...')
    print('  (pcb_onfault should make this safe — EFAULT expected)')
    method_a_ok, method_a_val = probe_kfncall_copyout(kdata_base, probe_addr, label='method A')

    if method_a_ok:
        print('\n  Method A WORKS! .text is readable via kfncall(copyout)!')
        print('\n[5/5] Starting full dump via kfncall(copyout) direct...')
        dump_via_kfncall(text_start, text_end, kdata_base, dmap, cr3, use_dmap=False)
        return

    # Method B: Create dmap PTE and read through dmap
    print('\n  Method B: Create dmap PTE for .text physical pages...')
    mapping_ok = create_dmap_mapping(phys, dmap, cr3, kdata_base)

    if mapping_ok:
        # Test if we can read through the new mapping
        dmap_addr = dmap + phys
        method_b_ok, method_b_val = probe_kfncall_copyout(kdata_base, dmap_addr, label='method B')

        if method_b_ok:
            print(f'\n  Method B WORKS! Read via dmap+phys = {hex(method_b_val)}')
            print('\n[5/5] Starting full dump via dmap PTE creation...')
            dump_via_kfncall(text_start, text_end, kdata_base, dmap, cr3, use_dmap=True)
            return
        else:
            print('  Method B: dmap PTE created but read still blocked (NPT?)')

    # Method C: kread8 — WARNING: almost certainly panics
    print('\n  Method C: kread8 (WARNING: prior testing shows this panics!)')
    print('  Attempting single kread8 probe on .text VA...')
    print('  >>> If PS5 disconnects, kread8 is confirmed to panic <<<')
    try:
        val = gdb.ieval('kread8(%s)' % ostr(probe_addr), timeout=10)
        print(f'  kread8 returned: {hex(val)} — it works!')
        print('\n[5/5] Starting full dump via kread8...')
        dump_via_kread8(text_start, text_end, kdata_base)
        return
    except gdb_rpc.DisconnectedException:
        print('  CONFIRMED: kread8 panics on .text VAs')
    except Exception as e:
        print(f'  kread8 error: {e}')

    # All methods exhausted
    print('\n=== ALL READ METHODS FAILED ===')
    print()
    print('The PS5 hypervisor blocks all CPU load instructions on .text physical pages')
    print('at the NPT (Nested Page Table) level. No guest-side read is possible.')
    print()
    print('Remaining options:')
    print('  1. Single-step instruction recovery (trace execution, infer opcodes)')
    print('  2. Find and modify NPT entries (requires HV vulnerability)')
    print('  3. MSR probing to find HV configuration (VM_HSAVE_PA etc)')
    print('  4. Mailbox command probing to find HV interface')


if __name__ == '__main__':
    main()
