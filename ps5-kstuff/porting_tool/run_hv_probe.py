#!/usr/bin/env python3
"""
Run HV probe on a jailbroken PS5.

Usage:
    python3 run_hv_probe.py <database.json> <ps5_ip> [port]

Requires: porting_tool offsets already discovered (database.json populated).
The PS5 must be jailbroken with r0gdb ready (same state as porting_tool).
"""

import sys, json

if 'linux' not in sys.platform:
    print('This tool only supports GNU/Linux! Use Docker or WSL on other OSes.')
    sys.exit(1)

if len(sys.argv) not in (3, 4):
    print('usage: run_hv_probe.py <database.json> <ps5_ip> [port]')
    sys.exit(1)

import gdb_rpc, traces, hv_probe

# Connect to PS5
print('[*] connecting to PS5...')
if len(sys.argv) == 4:
    gdb = gdb_rpc.GDB(sys.argv[2], int(sys.argv[3]))
else:
    gdb = gdb_rpc.GDB(sys.argv[2])

# Load offset database
with open(sys.argv[1]) as f:
    symbols = json.load(f)

# Check required offsets exist
REQUIRED = [
    'allproc', 'doreti_iret', 'idt', 'tss_array',
    'rdmsr_start', 'wrmsr_ret',
    'sceSblServiceMailbox',
    'mmap_self_fix_1_start', 'mmap_self_fix_2_start',
    'sysents', 'syscall_after',
    'malloc', 'M_something',
]
missing = [k for k in REQUIRED if k not in symbols]
if missing:
    print('[!] missing required offsets: %s' % ', '.join(missing))
    print('[!] run the porting_tool first to discover these')
    sys.exit(1)

print('[*] %d offsets loaded from %s' % (len(symbols), sys.argv[1]))

def ostr(x):
    return str(x % 2**64)

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']
r0gdb = gdb_rpc.R0GDB(gdb, R0GDB_FLAGS)

# Initialize r0gdb (same as do_use_r0gdb_raw + do_use_r0gdb_trace)
print('[*] initializing r0gdb...')
if gdb.use_r0gdb(R0GDB_FLAGS):
    kdata_base = gdb.ieval('kdata_base')
    gdb.eval('offsets.allproc = ' + ostr(kdata_base + symbols['allproc']))
    if not gdb.ieval('rpipe'):
        gdb.eval('r0gdb_init_with_offsets()')
    gdb.eval('offsets.doreti_iret = ' + ostr(kdata_base + symbols['doreti_iret']))
    gdb.eval('offsets.add_rsp_iret = offsets.doreti_iret - 7')
    gdb.eval('offsets.swapgs_add_rsp_iret = offsets.add_rsp_iret - 3')
    gdb.eval('offsets.idt = ' + ostr(kdata_base + symbols['idt']))
    gdb.eval('offsets.tss_array = ' + ostr(kdata_base + symbols['tss_array']))
    gdb.eval('p r0gdb()')

# Set up trace infrastructure offsets
print('[*] setting up trace offsets...')
kdata_base = gdb.ieval('kdata_base')
gdb.ieval('offsets.rdmsr_start = ' + ostr(kdata_base + symbols['rdmsr_start']))
gdb.ieval('offsets.wrmsr_ret = ' + ostr(kdata_base + symbols['wrmsr_ret']))
gdb.ieval('offsets.nop_ret = ' + ostr(kdata_base + symbols['wrmsr_ret'] + 2))
if 'rep_movsb_pop_rbp_ret' in symbols:
    gdb.ieval('offsets.rep_movsb_pop_rbp_ret = ' + ostr(kdata_base + symbols['rep_movsb_pop_rbp_ret']))
if 'cpu_switch' in symbols:
    gdb.ieval('offsets.cpu_switch = ' + ostr(kdata_base + symbols['cpu_switch']))

# Set up offsets needed by r0gdb_kfncall and r0gdb_kmalloc
gdb.ieval('offsets.sysents = ' + ostr(kdata_base + symbols['sysents']))
gdb.ieval('offsets.syscall_after = ' + ostr(kdata_base + symbols['syscall_after']))
gdb.ieval('offsets.malloc = ' + ostr(kdata_base + symbols['malloc']))
gdb.ieval('offsets.M_something = ' + ostr(kdata_base + symbols['M_something']))

# Allocate trace buffer (64 MB)
print('[*] allocating trace buffer...')
assert 'void' == gdb.eval('p r0gdb_trace(%d)' % (1 << 26))

print('[*] setup complete. kdata_base = %#x' % kdata_base)
print()

# === PHASE 1: Find HV boundary ===
print('=' * 60)
print('PHASE 1: Finding HV boundary inside sceSblServiceMailbox')
print('=' * 60)
print()

result = hv_probe.find_hv_boundary(gdb, r0gdb, symbols, kdata_base)

if result is None:
    print('[!] find_hv_boundary failed')
    sys.exit(1)

# Save raw trace for offline analysis
print('\n[*] saving trace data to hv_trace.bin...')
with open('hv_trace.bin', 'wb') as f:
    f.write(result['trace']._Trace__data if hasattr(result['trace'], '_Trace__data') else b'')
print('[*] trace saved')

# Dump internals for manual review
print('\n[*] saving instruction dump to hv_internals.txt...')
with open('hv_internals.txt', 'w') as f:
    f.write('# sceSblServiceMailbox internal instruction trace\n')
    f.write('# %d frames\n\n' % len(result['internals']))
    for idx, frame in result['internals']:
        f.write('[%6d] %#018x  rax=%016x rcx=%016x rdx=%016x rdi=%016x rsi=%016x rsp=%016x\n' % (
            idx, frame.rip, frame.rax, frame.rcx, frame.rdx, frame.rdi, frame.rsi, frame.rsp))
print('[*] dump saved')

# === PHASE 2: Probe mailbox commands ===
if 'mailbox_handle' in result:
    print()
    print('=' * 60)
    print('PHASE 2: Probing mailbox commands')
    print('=' * 60)
    print()

    handle = result['mailbox_handle']

    # First, probe known commands from Byepervisor research
    print('[*] probing known SBL commands...')
    known_results = hv_probe.probe_known_commands(gdb, r0gdb, symbols, kdata_base, handle)

    # Then, enumerate a wider range
    print()
    print('[*] enumerating command IDs 0x00-0xFF...')
    enum_results = hv_probe.probe_mailbox_commands(
        gdb, r0gdb, symbols, kdata_base, handle, cmd_range=range(0x100))

    # Save results
    print('\n[*] saving probe results to hv_probe_results.json...')
    import json as _json
    save = {}
    for cmd_id, v in enum_results.items():
        save[str(cmd_id)] = {
            'ret': v['ret'],
            'status': v['status'],
            'response': [str(r) for r in v['response']],
        }
    with open('hv_probe_results.json', 'w') as f:
        _json.dump(save, f, indent=2)
    print('[*] results saved')
else:
    print('[!] no mailbox handle captured, skipping probe phase')

print()
print('=' * 60)
print('DONE')
print('=' * 60)
print()
print('Output files:')
print('  hv_internals.txt    — instruction trace inside sceSblServiceMailbox')
print('  hv_probe_results.json — mailbox command probe results')
print()
if 'vmmcall_addr' in (result or {}):
    print('VMMCALL found at %#x (offset %#x)' % (
        result['vmmcall_addr'], result['vmmcall_addr'] - kdata_base))
else:
    print('No VMMCALL identified — check hv_internals.txt for manual analysis')
    print('Look for polling loops or MMIO patterns')
