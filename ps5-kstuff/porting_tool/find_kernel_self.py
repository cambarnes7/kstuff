#!/usr/bin/env python3
"""
PS5 Kernel SELF Finder & Extractor

Scans PS5 internal storage partitions to find the kernel SELF file,
checks if its header is readable (Prospero SELF magic: 54 14 F5 EE),
and dumps it to USB or over the network.

This is the first step toward decrypting the kernel .text section
via the SPU oracle approach (bypassing XOM).

Usage:
    python3 find_kernel_self.py <offsets.json> <ps5_ip> [port]

Requirements:
    - PS5 running firmware with kernel exploit (e.g., 4.03)
    - Offsets JSON with at least 'allproc' defined
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

offsets_path = sys.argv[1]
ps5_ip = sys.argv[2]
loader_port = int(sys.argv[3]) if len(sys.argv) > 3 else 9019

with open(offsets_path) as f:
    symbols = json.load(f)

if 'allproc' not in symbols:
    print('error: offsets.json must contain "allproc"')
    sys.exit(1)

gdb = gdb_rpc.GDB(ps5_ip, loader_port)
R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']


def ostr(x):
    return str(x % 2**64)


# PS5 Prospero SELF magic (confirmed from decrypted updatemode.elf)
SELF_PROSPERO_MAGIC = bytes([0x54, 0x14, 0xF5, 0xEE])

# PS4-style SELF magic (used by FSELF/make_fself.py)
SELF_ORBIS_MAGIC = bytes([0x4F, 0x15, 0x3D, 0x1D])

# ELF magic
ELF_MAGIC = b'\x7FELF'

# SELF ExInfo program types
PTYPE_HOST_KERNEL = 0xC
PTYPE_SECURE_KERNEL = 0xF


def parse_self_header(data):
    """Parse a PS5 Prospero SELF header and return key info."""
    if len(data) < 32:
        return None

    # Common header: magic(4) + version(1) + mode(1) + endian(1) + attribs(1) = 8 bytes
    magic = data[0:4]
    if magic != SELF_PROSPERO_MAGIC and magic != SELF_ORBIS_MAGIC:
        return None

    version = data[4]
    mode = data[5]
    endian = data[6]
    attribs = data[7]

    # Extended header: key_type(4) + header_size(2) + meta_size(2) + file_size(8) +
    #                  num_entries(2) + flags(2) + padding(4) = 24 bytes
    key_type, header_size, meta_size = struct.unpack_from('<I2H', data, 8)
    file_size, num_entries, flags = struct.unpack_from('<Q2H', data, 16)

    info = {
        'magic': magic.hex(),
        'version': version,
        'mode': mode,
        'endian': endian,
        'attribs': attribs,
        'key_type': key_type,
        'header_size': header_size,
        'meta_size': meta_size,
        'file_size': file_size,
        'num_entries': num_entries,
        'flags': flags,
    }

    # Try to find embedded ELF header and ExInfo
    # ELF header starts after the SELF entry table
    # Entry table: num_entries * 32 bytes, starting at offset 32
    entry_table_end = 32 + num_entries * 32

    if len(data) > entry_table_end + 64:
        # Look for ELF magic in the header area
        for offset in range(entry_table_end, min(len(data) - 4, header_size), 8):
            if data[offset:offset+4] == ELF_MAGIC:
                info['elf_offset'] = offset
                # Read ELF header fields
                if len(data) > offset + 64:
                    elf_type, elf_machine = struct.unpack_from('<2H', data, offset + 16)
                    elf_entry = struct.unpack_from('<Q', data, offset + 24)[0]
                    info['elf_type'] = elf_type
                    info['elf_machine'] = elf_machine
                    info['elf_entry'] = elf_entry
                    # OS/ABI is at offset 7 in ELF header
                    info['elf_osabi'] = data[offset + 7]
                break

    # Try to find ExInfo (ptype tells us if it's a kernel)
    # ExInfo is at: header area after ELF headers, aligned to 16
    # Format: paid(8) + ptype(8) + app_version(8) + fw_version(8) + digest(32) = 64 bytes
    if 'elf_offset' in info:
        # ExInfo typically follows ELF+PHdr area, aligned
        elf_off = info['elf_offset']
        # Scan for ExInfo by looking for reasonable ptype values
        for offset in range(elf_off, min(len(data) - 64, header_size), 8):
            paid, ptype = struct.unpack_from('<QQ', data, offset)
            if ptype in (PTYPE_HOST_KERNEL, PTYPE_SECURE_KERNEL):
                info['exinfo_offset'] = offset
                info['paid'] = paid
                info['ptype'] = ptype
                info['ptype_name'] = {PTYPE_HOST_KERNEL: 'HOST_KERNEL',
                                       PTYPE_SECURE_KERNEL: 'SECURE_KERNEL'}.get(ptype, hex(ptype))
                app_ver, fw_ver = struct.unpack_from('<QQ', data, offset + 16)
                info['app_version'] = app_ver
                info['fw_version'] = fw_ver
                break

    return info


def try_open_read(path, size=4096):
    """Try to open a device/file on PS5 and read bytes. Returns (fd, data) or (-1, None)."""
    # Write path string to a kernel buffer
    path_escaped = path.replace('"', '\\"')
    fd = gdb.ieval('(int)open("%s", 0)' % path_escaped, timeout=5)
    if fd < 0:
        return fd, None

    # Allocate buffer and read
    buf_addr = gdb.ieval('(long)malloc(%d)' % size)
    if buf_addr == 0:
        gdb.eval('(int)close(%d)' % fd)
        return -1, None

    n = gdb.ieval('(int)read(%d, %d, %d)' % (fd, buf_addr, size), timeout=10)

    data = None
    if n > 0:
        # Read the buffer contents via copyout-style mechanism
        # We need to copy from userspace buffer to our local script
        data = bytearray()
        remaining = n
        offset = 0
        while remaining > 0:
            chunk = min(remaining, 8)
            if chunk == 8:
                val = gdb.ieval('{long}%d' % (buf_addr + offset))
                data.extend(val.to_bytes(8, 'little'))
            else:
                for i in range(chunk):
                    val = gdb.ieval('{char}%d' % (buf_addr + offset + i))
                    data.append(val & 0xff)
            offset += chunk
            remaining -= chunk
        data = bytes(data[:n])

    gdb.eval('(int)close(%d)' % fd)
    gdb.eval('(void)free(%d)' % buf_addr)
    return fd, data


def try_open_read_fast(path, size=4096):
    """
    Fast version: open, read into kernel buffer, transfer via socket.
    Falls back to slow byte-by-byte if socket transfer isn't set up.
    """
    path_escaped = path.replace('"', '\\"')
    try:
        fd = gdb.ieval('(int)open("%s", 0)' % path_escaped, timeout=5)
    except Exception:
        return -1, None
    if fd < 0:
        return fd, None

    try:
        buf_addr = gdb.ieval('(long)malloc(%d)' % size)
        n = gdb.ieval('(int)read(%d, %d, %d)' % (fd, buf_addr, size), timeout=10)
    except Exception:
        try:
            gdb.eval('(int)close(%d)' % fd)
        except Exception:
            pass
        return -1, None

    data = None
    if n > 0:
        # Read 8 bytes at a time via GDB (faster than byte-by-byte)
        data = bytearray()
        offset = 0
        while offset < n:
            chunk = min(n - offset, 8)
            try:
                if chunk >= 8:
                    val = gdb.ieval('{long}%d' % (buf_addr + offset))
                    data.extend(val.to_bytes(8, 'little'))
                else:
                    for i in range(chunk):
                        val = gdb.ieval('{char}%d' % (buf_addr + offset + i))
                        data.append(val & 0xff)
            except Exception:
                break
            offset += chunk
        data = bytes(data[:n])

    try:
        gdb.eval('(int)close(%d)' % fd)
        gdb.eval('(void)free(%d)' % buf_addr)
    except Exception:
        pass

    return fd, data


def dump_file_to_local(path, output_path, expected_size=None):
    """Dump a file from PS5 to local disk via socket transfer."""
    path_escaped = path.replace('"', '\\"')
    fd = gdb.ieval('(int)open("%s", 0)' % path_escaped, timeout=5)
    if fd < 0:
        print('  ERROR: cannot open %s (fd=%d)' % (path, fd))
        return False

    # Get file size via lseek to end
    if expected_size is None:
        end = gdb.ieval('(long)lseek(%d, 0, 2)' % fd)  # SEEK_END = 2
        gdb.ieval('(long)lseek(%d, 0, 0)' % fd)  # SEEK_SET = 0
        if end <= 0:
            print('  ERROR: cannot determine file size (lseek=%d)' % end)
            gdb.eval('(int)close(%d)' % fd)
            return False
        expected_size = end
    print('  file size: %d bytes (%.1f MB)' % (expected_size, expected_size / (1024*1024)))

    # Transfer via socket (fast path)
    local_buf = bytearray()
    remote_buf = gdb.ieval('(long)malloc(1048576)')
    if remote_buf == 0:
        print('  ERROR: malloc failed')
        gdb.eval('(int)close(%d)' % fd)
        return False

    with gdb_rpc.BlobReceiver(gdb, local_buf, '  transferring') as addr:
        remote_fd = gdb.ieval('r0gdb_open_socket("%s", %d)' % addr)
        total = 0
        while total < expected_size:
            chunk = min(1048576, expected_size - total)
            n = gdb.ieval('(int)read(%d, %d, %d)' % (fd, remote_buf, chunk), timeout=30)
            if n <= 0:
                print('\n  WARNING: read returned %d at offset %d' % (n, total))
                break
            assert not gdb.ieval('r0gdb_sendall(%d, %d, %d)' % (remote_fd, remote_buf, n))
            total += n

        # Wait for data to arrive
        one_second = gdb.ieval('(void*)(uint64_t[2]){1, 0}')
        while len(local_buf) < total:
            gdb.eval('(int)nanosleep(%d)' % one_second)
        gdb.eval('(int)close(%d)' % remote_fd)

    gdb.eval('(void)free(%d)' % remote_buf)
    gdb.eval('(int)close(%d)' % fd)

    with open(output_path, 'wb') as f:
        f.write(local_buf)

    print('  saved: %s (%d bytes)' % (output_path, len(local_buf)))
    return True


def main():
    print('=== PS5 Kernel SELF Finder ===')
    print()

    # Step 1: Initialize r0gdb
    print('[1/4] Initializing r0gdb...')
    gdb.use_r0gdb(R0GDB_FLAGS)
    kdata_base = gdb.ieval('kdata_base')
    print('  kdata_base = %s' % hex(kdata_base))

    gdb.eval('offsets.allproc = ' + ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'):
        gdb.eval('r0gdb_init_with_offsets()')
    print('  kernel R/W initialized')

    # Step 2: Scan device paths for kernel SELF
    print()
    print('[2/4] Scanning PS5 storage for kernel SELF...')
    print()

    # Device paths to try, ordered by likelihood
    device_paths = [
        # PS5-specific named partitions (ssd0.NAME format)
        '/dev/ssd0.kernel',
        '/dev/ssd0.kernel_a',
        '/dev/ssd0.kernel_b',
        '/dev/ssd0.os0',
        '/dev/ssd0.os1',
        '/dev/ssd0.coreos',
        '/dev/ssd0.coreos_a',
        '/dev/ssd0.coreos_b',
        '/dev/ssd0.update',
        '/dev/ssd0.eap_kern',

        # Numbered partitions (GPT slice naming)
        '/dev/ssd0s1',
        '/dev/ssd0s2',
        '/dev/ssd0s3',
        '/dev/ssd0s4',
        '/dev/ssd0s5',
        '/dev/ssd0s6',
        '/dev/ssd0s7',
        '/dev/ssd0s8',
        '/dev/ssd0s9',
        '/dev/ssd0s10',
        '/dev/ssd0s11',
        '/dev/ssd0s12',
        '/dev/ssd0s13',
        '/dev/ssd0s14',
        '/dev/ssd0s15',
        '/dev/ssd0s16',

        # Alternative naming with 'p' (partition)
        '/dev/ssd0p1',
        '/dev/ssd0p2',
        '/dev/ssd0p3',
        '/dev/ssd0p4',
        '/dev/ssd0p5',
        '/dev/ssd0p6',

        # SCSI-style naming (da0)
        '/dev/da0s1',
        '/dev/da0s2',
        '/dev/da0s3',
        '/dev/da0s4',
        '/dev/da0s5',
        '/dev/da0s6',

        # NVMe naming
        '/dev/nvd0s1',
        '/dev/nvd0s2',
        '/dev/nvd0s3',
        '/dev/nvd0s4',
        '/dev/nvd0s5',
        '/dev/nvd0s6',

        # Raw device (scan beginning)
        '/dev/ssd0',
    ]

    found = []
    accessible = []

    for path in device_paths:
        sys.stdout.write('  %-35s ' % path)
        sys.stdout.flush()

        fd, data = try_open_read_fast(path, 4096)

        if fd < 0:
            print('ENOENT/EACCES (fd=%d)' % fd)
            continue

        if data is None or len(data) == 0:
            print('empty (0 bytes read)')
            accessible.append((path, 'empty'))
            continue

        accessible.append((path, '%d bytes' % len(data)))

        # Check magic bytes
        magic = data[:4]
        if magic == SELF_PROSPERO_MAGIC:
            info = parse_self_header(data)
            ptype_str = info.get('ptype_name', '?') if info else '?'
            file_size = info.get('file_size', 0) if info else 0
            print('*** SELF FOUND! ptype=%s size=%s ***' % (
                ptype_str, ('%d MB' % (file_size // (1024*1024))) if file_size else '?'))
            found.append((path, data, info))
        elif magic == SELF_ORBIS_MAGIC:
            print('PS4 SELF magic (4F 15 3D 1D)')
            found.append((path, data, parse_self_header(data)))
        elif magic == ELF_MAGIC:
            print('raw ELF (7F 45 4C 46)')
            found.append((path, data, None))
        else:
            print('data: %s ...' % data[:16].hex())

    # Step 3: Report findings
    print()
    print('[3/4] Results')
    print()
    print('  Accessible devices: %d' % len(accessible))
    for path, info in accessible:
        print('    %-35s %s' % (path, info))

    print()
    if not found:
        print('  *** No SELF or ELF files found on any partition ***')
        print()
        print('  This means either:')
        print('  a) The kernel is in a partition with a name we didn\'t try')
        print('  b) The kernel is encrypted on disk (no readable SELF header)')
        print('  c) Access to block devices is restricted')
        print()
        print('  Next steps:')
        print('  - Check the accessible device list above for clues')
        print('  - Try reading rootdevnames from kernel memory')
        print('  - Fall back to ROM key offline decryption')
        return

    print('  Found %d SELF/ELF file(s):' % len(found))
    for path, data, info in found:
        print()
        print('  Path: %s' % path)
        print('  First 64 bytes: %s' % data[:64].hex())
        if info:
            for k, v in sorted(info.items()):
                if isinstance(v, int) and k not in ('version', 'mode', 'endian'):
                    print('    %-20s = %s (%d)' % (k, hex(v), v))
                else:
                    print('    %-20s = %s' % (k, v))

    # Step 4: Dump the kernel SELF
    print()
    print('[4/4] Extracting kernel SELF...')

    # Prefer kernel-type SELF, fall back to first found
    kernel_entry = None
    for path, data, info in found:
        if info and info.get('ptype') in (PTYPE_HOST_KERNEL, PTYPE_SECURE_KERNEL):
            kernel_entry = (path, data, info)
            break
    if kernel_entry is None:
        kernel_entry = found[0]

    path, header_data, info = kernel_entry
    print('  Selected: %s' % path)

    file_size = info.get('file_size', 0) if info else 0

    # Save header for quick inspection
    with open('kernel_header.bin', 'wb') as f:
        f.write(header_data)
    print('  Saved header: kernel_header.bin (%d bytes)' % len(header_data))

    # Dump full file if we know the size
    if file_size > 0:
        print('  Dumping full SELF (%d bytes / %.1f MB)...' % (file_size, file_size/(1024*1024)))
        if dump_file_to_local(path, 'kernel_raw.self', file_size):
            print()
            print('=== SUCCESS ===')
            print('  kernel_header.bin  - first 4KB of SELF header')
            print('  kernel_raw.self    - full kernel SELF (%d bytes)' % file_size)
            print()
            print('Next steps:')
            print('  1. Try Cryptogenic\'s PS5-SELF-Decrypter on kernel_raw.self')
            print('  2. Or run decrypt_ktext.py to use SPU oracle approach')
        else:
            print('  ERROR: dump failed')
    else:
        print('  WARNING: could not determine file size from SELF header')
        print('  Attempting dump with lseek size detection...')
        if dump_file_to_local(path, 'kernel_raw.self'):
            print()
            print('=== SUCCESS ===')
        else:
            print('  ERROR: dump failed')


if __name__ == '__main__':
    try:
        main()
    except gdb_rpc.DisconnectedException:
        print()
        print('PS5 disconnected. The console may have panicked.')
        print('Restart the PS5 and try again.')
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        print('Aborted.')
        sys.exit(1)
