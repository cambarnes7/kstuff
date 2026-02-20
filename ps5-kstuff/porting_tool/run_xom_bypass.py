#!/usr/bin/env python3
"""
Run XOM bypass toolkit on a jailbroken PS5.

Usage:
    python3 run_xom_bypass.py <database.json> <ps5_ip> [port] [kernel_data_dump]

Requires: porting_tool offsets already discovered (database.json populated).
The PS5 must be jailbroken with r0gdb ready (same state as porting_tool).

Phases:
  1. Guest page table dump — map physical memory, identify XOM regions
  2. Kernel .data mining — find HV artifacts, QA flags, hypercall tables
  3. Instruction recovery — disassemble key .text functions blind
  4. MSR probing — enumerate readable MSRs, check SVM configuration
  5. Sleep/resume attack — attempt QA flag persistence across suspend

Output files:
  xom_page_tables.json   — full guest page table dump
  xom_data_mining.json   — .data scan results
  xom_msr_results.json   — MSR probe results
  xom_full_results.json  — all results combined
"""

import sys
import json
import os
import shutil
import subprocess

if sys.platform not in ('linux', 'darwin'):
    print('This tool supports Linux and macOS. Use WSL on Windows.')
    sys.exit(1)

if len(sys.argv) not in (3, 4, 5):
    print('usage: run_xom_bypass.py <database.json> <ps5_ip> [port] [kernel_data_dump]')
    sys.exit(1)

# On macOS, check for required cross-compilation tools
if sys.platform == 'darwin':
    missing_tools = []
    if shutil.which('x86_64-elf-gcc'):
        os.environ.setdefault('CC', 'x86_64-elf-gcc')
        os.environ.setdefault('LD', 'x86_64-elf-ld')
        os.environ.setdefault('OBJCOPY', 'x86_64-elf-objcopy')
    elif not shutil.which('gcc') or b'Mach-O' in subprocess.check_output(
            ['gcc', '-dumpmachine'], stderr=subprocess.DEVNULL):
        missing_tools.append(('x86_64-elf-gcc', 'brew install x86_64-elf-gcc'))
    if not shutil.which('yasm'):
        missing_tools.append(('yasm', 'brew install yasm'))
    if not shutil.which('gdb'):
        missing_tools.append(('gdb', 'brew install gdb'))
    if missing_tools:
        print('[!] missing required tools for macOS:')
        for tool, cmd in missing_tools:
            print('    %s  ->  %s' % (tool, cmd))
        sys.exit(1)

import gdb_rpc
import traces
import xom_bypass

# Parse arguments
db_path = sys.argv[1]
ps5_ip = sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) >= 4 and sys.argv[3].isdigit() else None
kdump_path = sys.argv[-1] if len(sys.argv) == 5 else None

# Connect to PS5
print('[*] connecting to PS5...')
if port is not None:
    gdb = gdb_rpc.GDB(ps5_ip, port)
else:
    gdb = gdb_rpc.GDB(ps5_ip)

# Load offset database
with open(db_path) as f:
    content = f.read().strip()
    symbols = json.loads(content) if content else {}

# Check required offsets
REQUIRED = [
    'allproc', 'doreti_iret', 'idt', 'tss_array',
    'rdmsr_start', 'wrmsr_ret',
    'kernel_pmap_store',
    'sysents', 'syscall_after',
    'malloc', 'M_something',
]
missing = [k for k in REQUIRED if k not in symbols]
if missing:
    print('[!] missing required offsets: %s' % ', '.join(missing))
    print('[!] run the porting_tool first to discover these')
    sys.exit(1)

print('[*] %d offsets loaded from %s' % (len(symbols), db_path))

def ostr(x):
    return str(x % 2**64)

R0GDB_FLAGS = ['-DMEMRW_FALLBACK', '-DNO_BUILTIN_OFFSETS']
r0gdb = gdb_rpc.R0GDB(gdb, R0GDB_FLAGS)

# Initialize r0gdb
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
print('[*] setting up offsets...')
kdata_base = gdb.ieval('kdata_base')
gdb.ieval('offsets.rdmsr_start = ' + ostr(kdata_base + symbols['rdmsr_start']))
gdb.ieval('offsets.wrmsr_ret = ' + ostr(kdata_base + symbols['wrmsr_ret']))
gdb.ieval('offsets.nop_ret = ' + ostr(kdata_base + symbols['wrmsr_ret'] + 2))

# Set up kernel function call infrastructure
gdb.ieval('offsets.sysents = ' + ostr(kdata_base + symbols['sysents']))
gdb.ieval('offsets.syscall_after = ' + ostr(kdata_base + symbols['syscall_after']))
gdb.ieval('offsets.malloc = ' + ostr(kdata_base + symbols['malloc']))
gdb.ieval('offsets.M_something = ' + ostr(kdata_base + symbols['M_something']))

# Optional offsets
for opt in ('rep_movsb_pop_rbp_ret', 'cpu_switch', 'mov_rax_cr3', 'mov_cr3_rax_mov_ds'):
    if opt in symbols:
        gdb.ieval('offsets.%s = %s' % (opt, ostr(kdata_base + symbols[opt])))

print('[*] setup complete. kdata_base = %#x' % kdata_base)

# Load kernel data dump if available
kernel_data = None
if kdump_path and os.path.exists(kdump_path):
    print('[*] loading kernel data dump from %s...' % kdump_path)
    with open(kdump_path, 'rb') as f:
        data = f.read()
    if len(data) >= 16 and int.from_bytes(data[8:16], 'little') == len(data) - 16:
        kernel_data = data[16:]
        print('[*] loaded %d bytes of kernel .data' % len(kernel_data))
    else:
        print('[!] invalid kernel dump format, skipping .data analysis')
else:
    # Check for cached dump
    cache_path = os.path.join(os.path.dirname(db_path) or '.', '.kdata_cache.bin')
    if os.path.exists(cache_path):
        print('[*] loading cached kernel data from %s...' % cache_path)
        with open(cache_path, 'rb') as f:
            data = f.read()
        if len(data) >= 16 and int.from_bytes(data[8:16], 'little') == len(data) - 16:
            kernel_data = data[16:]
            print('[*] loaded %d bytes of kernel .data' % len(kernel_data))
    if kernel_data is None:
        print('[*] no kernel .data dump available')
        print('[*] Phase 2 (.data mining) will be skipped')
        print('[*] run porting_tool dump_kernel() first for full analysis')

print()

# Run the full XOM bypass toolkit
results = xom_bypass.run_full_bypass(
    gdb, r0gdb, kdata_base, symbols, kernel_data)

# Save results
print()
print('[*] saving results...')

def make_serializable(obj):
    """Convert results to JSON-serializable format."""
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_serializable(i) for i in obj]
    elif isinstance(obj, int):
        if obj > 2**53:
            return '0x%x' % obj
        return obj
    elif isinstance(obj, bytes):
        return obj.hex()
    elif obj is None:
        return None
    elif isinstance(obj, bool):
        return obj
    elif isinstance(obj, str):
        return obj
    else:
        return str(obj)

serializable = make_serializable(results)

with open('xom_full_results.json', 'w') as f:
    json.dump(serializable, f, indent=2)
print('[*] full results saved to xom_full_results.json')

# Save individual phase results
if 'page_tables' in results and results['page_tables']:
    pt = make_serializable(results['page_tables'])
    # Don't save the full regions list (too large), save summary
    pt_summary = {k: v for k, v in pt.items() if k != 'regions'}
    pt_summary['num_regions'] = len(results['page_tables'].get('regions', []))
    with open('xom_page_tables.json', 'w') as f:
        json.dump(pt_summary, f, indent=2)
    print('[*] page table summary saved to xom_page_tables.json')

if 'data_mining' in results and results['data_mining']:
    dm = make_serializable(results['data_mining'])
    with open('xom_data_mining.json', 'w') as f:
        json.dump(dm, f, indent=2)
    print('[*] data mining results saved to xom_data_mining.json')

if 'msrs' in results and results['msrs']:
    msr = make_serializable(results['msrs'])
    with open('xom_msr_results.json', 'w') as f:
        json.dump(msr, f, indent=2)
    print('[*] MSR results saved to xom_msr_results.json')

print()
print('=' * 70)
print('DONE')
print('=' * 70)
print()
print('Output files:')
print('  xom_full_results.json    — all results')
print('  xom_page_tables.json     — guest page table summary')
print('  xom_data_mining.json     — .data scan results')
print('  xom_msr_results.json     — MSR probe results')
print()
print('Next steps:')
print('  1. Review xom_full_results.json for attack vectors')
print('  2. Run hv_probe.py to find VMMCALL and probe mailbox')
print('  3. If QA flags found, try: set flags -> suspend -> resume -> re-run')
print('  4. If hypercall table found, verify if writable and HV-shared')
