#!/usr/bin/env python3
"""
Kernel .text dumper via kread8 (8 bytes at a time).

Usage: dump_ktext.py <database.json> <ps5_ip> [port] [output_file]

Strategy:
  1. Connect to PS5, set up r0gdb with kernel R/W
  2. Determine .text range from known offsets in database.json
  3. Probe a single .text address with kread8 to test safety
  4. If probe succeeds, dump full .text 8 bytes at a time over socket
  5. Write raw dump + metadata to output file

The dump is streamed 8 bytes at a time via kread8(). This is slow
(~10 min per 10MB) but may bypass XOM where copyout fails.
"""

import sys, json, os, time, struct, socket, threading

if 'linux' not in sys.platform:
    print('This tool only supports GNU/Linux! Use Docker or WSL on other OSes.')
    sys.exit(1)

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

def find_text_range(kdata_base):
    """Determine .text range from known offsets.

    All offsets in database.json are relative to kdata_base.
    .text offsets are negative (below kdata_base).
    Returns (text_start, text_end) as absolute kernel VAs.
    """
    # Collect all negative offsets (these are .text symbols)
    text_offsets = []
    for name, value in symbols.items():
        if isinstance(value, int) and value < 0:
            text_offsets.append((name, value))

    if not text_offsets:
        # Try offsets that are large positive values (could be stored unsigned)
        for name, value in symbols.items():
            if isinstance(value, int) and value > 0x7fffffff:
                # This is likely a sign-extended negative offset
                signed_val = value - (1 << 64) if value >= (1 << 63) else value
                if signed_val < 0:
                    text_offsets.append((name, signed_val))

    if not text_offsets:
        print('ERROR: No .text offsets found in database.json')
        print('Known symbols:', list(symbols.keys())[:20])
        return None, None

    # Find the deepest (most negative) and shallowest offsets
    text_offsets.sort(key=lambda x: x[1])
    deepest_name, deepest_off = text_offsets[0]
    shallowest_name, shallowest_off = text_offsets[-1]

    # Page-align: round start down to 4KB boundary
    text_start = (kdata_base + deepest_off) & ~0xFFF
    text_end = kdata_base  # .text ends where .data begins

    size = text_end - text_start
    print(f'  .text range: {hex(text_start)} - {hex(text_end)}')
    print(f'  size: {size} bytes ({size / (1024*1024):.1f} MB)')
    print(f'  deepest offset: {deepest_name} = {hex(deepest_off)}')
    print(f'  shallowest offset: {shallowest_name} = {hex(shallowest_off)}')
    print(f'  {len(text_offsets)} .text symbols found')

    return text_start, text_end

def probe_kread8(kdata_base, text_addr):
    """Probe a single .text address with kread8.

    Returns (success, value) where success indicates no panic.
    If the PS5 panics, the GDB connection will drop.
    """
    print(f'  Probing kread8 at {hex(text_addr)}...')
    try:
        val = gdb.ieval('kread8(%s)' % ostr(text_addr), timeout=10)
        print(f'  kread8 returned: {hex(val)}')
        return True, val
    except gdb_rpc.DisconnectedException:
        print('  PANIC: PS5 disconnected during kread8 probe!')
        return False, 0
    except Exception as e:
        print(f'  ERROR during probe: {e}')
        return False, 0

def probe_kfncall_copyout(kdata_base, text_addr):
    """Probe using r0gdb_kfncall(copyout, ...) which has pcb_onfault safety.

    This should return EFAULT instead of panicking if the read is blocked.
    """
    if 'copyout' not in symbols:
        print('  copyout offset not in database, skipping kfncall probe')
        return False, 0

    print(f'  Probing kfncall(copyout) at {hex(text_addr)}...')
    try:
        # Allocate a small buffer in userspace for the result
        ubuf = gdb.ieval('malloc(8)')
        # Call kernel copyout: copyout(src_kaddr, dst_uaddr, len)
        ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, 8)' % (
            ostr(kdata_base + symbols['copyout']),
            ostr(text_addr),
            ostr(ubuf)))
        if ret == 0:
            val = gdb.ieval('{void*}%d' % ubuf)
            print(f'  kfncall(copyout) succeeded! val={hex(val)}')
            return True, val
        else:
            print(f'  kfncall(copyout) returned error: {ret} (EFAULT=14)')
            return False, 0
    except gdb_rpc.DisconnectedException:
        print('  PANIC: PS5 disconnected during kfncall(copyout) probe!')
        return False, 0
    except Exception as e:
        print(f'  ERROR during kfncall probe: {e}')
        return False, 0

def dump_via_kread8(text_start, text_end, kdata_base):
    """Dump .text using kread8, 8 bytes at a time.

    Streams results to output file. Shows progress every 4KB.
    """
    size = text_end - text_start
    print(f'\nDumping {size} bytes ({size//(1024*1024)} MB) via kread8...')
    print(f'Estimated time: ~{size * 10 / (10*1024*1024):.0f} minutes')
    print(f'Output: {output_file}')

    buf = bytearray(size)
    errors = 0
    start_time = time.time()

    # We read 8 bytes at a time via GDB eval
    # To reduce GDB round-trips, we can batch reads
    addr = text_start
    offset = 0
    last_progress = 0

    try:
        while addr < text_end:
            remaining = text_end - addr
            read_size = min(8, remaining)

            try:
                val = gdb.ieval('kread8(%s)' % ostr(addr), timeout=15)
                struct.pack_into('<Q', buf, offset, val)
            except gdb_rpc.DisconnectedException:
                print(f'\nPANIC at offset {hex(offset)} (addr {hex(addr)})')
                print('PS5 disconnected. Saving partial dump...')
                break
            except Exception as e:
                # Fill with error pattern
                struct.pack_into('<Q', buf, offset, 0xDEADC0DEDEADC0DE)
                errors += 1

            addr += 8
            offset += 8

            # Progress every 4KB
            if offset - last_progress >= 4096:
                elapsed = time.time() - start_time
                rate = offset / elapsed if elapsed > 0 else 0
                eta = (size - offset) / rate if rate > 0 else 0
                pct = 100.0 * offset / size
                sys.stdout.write(f'\r  {pct:5.1f}% | {offset/1024:.0f}/{size/1024:.0f} KB | '
                               f'{rate/1024:.1f} KB/s | ETA {eta:.0f}s | {errors} errors')
                sys.stdout.flush()
                last_progress = offset

        print()  # newline after progress

    except KeyboardInterrupt:
        print(f'\nInterrupted at offset {hex(offset)}. Saving partial dump...')

    elapsed = time.time() - start_time

    # Write output file with metadata header
    # Header: 8 bytes text_start + 8 bytes dump_size + dump_data
    with open(output_file, 'wb') as f:
        f.write(struct.pack('<QQ', text_start, offset))
        f.write(buf[:offset])

    # Write metadata JSON
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

    print(f'\nDump complete:')
    print(f'  Bytes dumped: {offset} / {size} ({100*offset//size}%)')
    print(f'  Errors: {errors}')
    print(f'  Time: {elapsed:.1f}s')
    print(f'  Output: {output_file}')
    print(f'  Metadata: {meta_path}')

    return offset == size

def dump_via_kfncall_copyout(text_start, text_end, kdata_base):
    """Dump .text using r0gdb_kfncall(copyout, ...), 4KB at a time.

    Faster than kread8 if it works (copyout does 4KB per call vs 8 bytes).
    """
    size = text_end - text_start
    print(f'\nDumping {size} bytes ({size//(1024*1024)} MB) via kfncall(copyout)...')
    print(f'Output: {output_file}')

    copyout_addr = kdata_base + symbols['copyout']
    chunk_size = 4096

    # Allocate remote buffer
    remote_buf = gdb.ieval('malloc(%d)' % chunk_size)

    local_buf = bytearray()
    start_time = time.time()
    errors = 0
    addr = text_start

    try:
        while addr < text_end:
            remaining = text_end - addr
            to_read = min(chunk_size, remaining)

            try:
                ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, %s)' % (
                    ostr(copyout_addr), ostr(addr), ostr(remote_buf), ostr(to_read)),
                    timeout=15)

                if ret == 0:
                    # Read the data from remote buffer
                    chunk = bytearray(to_read)
                    for i in range(0, to_read, 8):
                        val = gdb.ieval('{void*}%d' % (remote_buf + i))
                        struct.pack_into('<Q', chunk, i, val)
                    local_buf.extend(chunk)
                else:
                    # copyout failed (EFAULT), fill with error pattern
                    local_buf.extend(b'\xDE\xAD\xC0\xDE' * (to_read // 4))
                    errors += 1

            except gdb_rpc.DisconnectedException:
                print(f'\nPANIC at addr {hex(addr)}')
                break

            addr += to_read
            offset = len(local_buf)

            elapsed = time.time() - start_time
            rate = offset / elapsed if elapsed > 0 else 0
            eta = (size - offset) / rate if rate > 0 else 0
            pct = 100.0 * offset / size
            sys.stdout.write(f'\r  {pct:5.1f}% | {offset/1024:.0f}/{size/1024:.0f} KB | '
                           f'ETA {eta:.0f}s | {errors} errors')
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
        'elapsed_seconds': round(elapsed, 1),
        'method': 'kfncall_copyout',
    }
    meta_path = output_file.rsplit('.', 1)[0] + '_meta.json'
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f'\nDump complete: {offset}/{size} bytes, {errors} errors, {elapsed:.1f}s')
    return offset == size


def main():
    print('=== PS5 Kernel .text Dumper (kread8) ===')
    print()

    # Step 1: Connect and set up
    print('[1/4] Connecting to PS5...')
    kdata_base = setup_r0gdb()
    print(f'  kdata_base = {hex(kdata_base)}')

    # Step 2: Determine .text range
    print('\n[2/4] Determining .text range...')
    text_start, text_end = find_text_range(kdata_base)
    if text_start is None:
        return

    # Pick a known .text address for probing (use the deepest known offset)
    text_offsets = [(n, v) for n, v in symbols.items() if isinstance(v, int) and v < 0]
    if not text_offsets:
        print('ERROR: No .text offsets to probe')
        return

    # Use a well-known symbol for probing
    probe_candidates = ['doreti_iret', 'justreturn', 'cpu_switch', 'syscall_before']
    probe_name = None
    probe_addr = None
    for name in probe_candidates:
        if name in symbols and isinstance(symbols[name], int) and symbols[name] < 0:
            probe_name = name
            probe_addr = kdata_base + symbols[name]
            break

    if probe_addr is None:
        # Fall back to any .text symbol
        probe_name, probe_off = text_offsets[0]
        probe_addr = kdata_base + probe_off

    # Step 3: Safety probes
    print(f'\n[3/4] Safety probes (testing {probe_name} at {hex(probe_addr)})...')

    # Try kfncall(copyout) first - it has pcb_onfault safety, won't panic
    kfncall_ok, kfncall_val = probe_kfncall_copyout(kdata_base, probe_addr)

    # Try kread8 - this MIGHT panic if NPT blocks the read
    kread8_ok = False
    if not kfncall_ok:
        print('\n  kfncall(copyout) failed. Trying kread8 (may panic)...')
        print('  If PS5 disconnects here, kread8 is confirmed to panic on .text.')
    else:
        print('\n  kfncall(copyout) worked! Also testing kread8 for comparison...')

    kread8_ok, kread8_val = probe_kread8(kdata_base, probe_addr)

    if not kread8_ok and not kfncall_ok:
        print('\n  BOTH methods failed. .text is not readable from this context.')
        print('  The hypervisor blocks all CPU load instructions on .text pages.')
        return

    # Verify consistency if both worked
    if kread8_ok and kfncall_ok:
        if kread8_val == kfncall_val:
            print(f'\n  Both methods agree: {hex(kread8_val)}')
        else:
            print(f'\n  WARNING: methods disagree! kread8={hex(kread8_val)} kfncall={hex(kfncall_val)}')

    # Step 4: Full dump
    print('\n[4/4] Starting full .text dump...')

    if kfncall_ok:
        print('  Using kfncall(copyout) method (faster, 4KB chunks)')
        dump_via_kfncall_copyout(text_start, text_end, kdata_base)
    elif kread8_ok:
        print('  Using kread8 method (slow, 8 bytes at a time)')
        dump_via_kread8(text_start, text_end, kdata_base)


if __name__ == '__main__':
    main()
