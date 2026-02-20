#!/usr/bin/env python3
"""
Run KCFI analysis and bypass on a jailbroken PS5.

Usage:
    python3 run_cfi_bypass.py <database.json> <ps5_ip> [port]

Requires: porting_tool offsets already discovered (database.json populated).
The PS5 must be jailbroken with r0gdb ready (same state as porting_tool).

Phases:
  1. Trace a SELF-loading code path (reuses fix_mmap_self trace infrastructure)
  2. Discover all indirect call sites in the trace
  3. Detect CFI check patterns and boundaries
  4. Identify KCFI trampolines at function entries
  5. Extract KCFI hash values for all observed call sites

Output files:
  cfi_analysis.json     — full CFI analysis results
  cfi_call_sites.txt    — human-readable call site listing
"""

import sys
import json
import shutil
import subprocess
import os
import collections

if sys.platform not in ('linux', 'darwin'):
    print('This tool supports Linux and macOS. Use WSL on Windows.')
    sys.exit(1)

if len(sys.argv) not in (3, 4):
    print('usage: run_cfi_bypass.py <database.json> <ps5_ip> [port]')
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
import cfi_bypass

# Parse arguments
db_path = sys.argv[1]
ps5_ip = sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) == 4 else None

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
    'mmap_self_fix_1_start', 'mmap_self_fix_2_start',
    'sceSblServiceMailbox',
    'sysents', 'syscall_after',
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

# Initialize r0gdb (same setup as run_hv_probe.py)
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

# Set up mmap_self offsets for tracing the SELF-loading path
gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'
          % ostr(kdata_base + symbols['mmap_self_fix_1_start']))
gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'
          % ostr(kdata_base + symbols['mmap_self_fix_2_start']))

# Allocate trace buffer (64 MB)
print('[*] allocating trace buffer...')
assert 'void' == gdb.eval('p r0gdb_trace(%d)' % (1 << 26))

print('[*] setup complete. kdata_base = %#x' % kdata_base)
print()

# =============================================================================
# PHASE 1: Capture a trace of the SELF-loading code path
# =============================================================================
print('=' * 60)
print('PHASE 1: Tracing SELF-loading code path')
print('=' * 60)
print()

# Open a signed SELF and trace the mmap+mlock path.
# This is the same approach as hv_probe.py and main.py sceSblServiceMailbox().
# fix_mmap_self only patches 2 addresses, records EVERYTHING else —
# including all CFI checks at indirect call sites.
fd = gdb.ieval('(int)open("/system_ex/common_ex/lib/libSceNKWebKit.sprx", 0)')
assert fd >= 0, "failed to open signed SELF"

print('[*] tracing mmap + mlock of signed SELF...')
raw = (
    r0gdb.trace('fix_mmap_self', 'mmap', 0, 65536, 1, 0x80001, fd, 0) +
    r0gdb.trace('fix_mmap_self', 'mlock', gdb.ieval('(void*)$rax'), 65536)
)
trace = traces.Trace(raw)
print('[*] trace captured: %d frames' % len(trace))

# Also capture a getpid trace for a simpler code path
print('[*] tracing getpid syscall for comparison...')
raw2 = r0gdb.trace('trace_skip_scheduler_only', 'getpid')
trace_getpid = traces.Trace(raw2)
print('[*] getpid trace: %d frames' % len(trace_getpid))

print()

# =============================================================================
# PHASE 2: Full CFI analysis of the SELF-loading trace
# =============================================================================
print('=' * 60)
print('PHASE 2: Analyzing CFI in SELF-loading trace')
print('=' * 60)
print()

results_self = cfi_bypass.analyze_trace_cfi(trace, kdata_base)

print()

# =============================================================================
# PHASE 3: CFI analysis of the simpler getpid trace
# =============================================================================
print('=' * 60)
print('PHASE 3: Analyzing CFI in getpid trace')
print('=' * 60)
print()

results_getpid = cfi_bypass.analyze_trace_cfi(trace_getpid, kdata_base)

print()

# =============================================================================
# PHASE 4: Extract KCFI hash catalog
# =============================================================================
print('=' * 60)
print('PHASE 4: Extracting KCFI hash catalog')
print('=' * 60)
print()

hashes_self = cfi_bypass.extract_cfi_hashes_from_trace(trace, kdata_base)
hashes_getpid = cfi_bypass.extract_cfi_hashes_from_trace(trace_getpid, kdata_base)

# Merge hash catalogs
all_hashes = {}
all_hashes.update(hashes_getpid)
all_hashes.update(hashes_self)  # SELF trace has priority (more interesting)

print()
print('[*] total unique KCFI hashes: %d' % len(all_hashes))

# =============================================================================
# PHASE 5: Identify bypass candidates
# =============================================================================
print()
print('=' * 60)
print('PHASE 5: Identifying bypass candidates')
print('=' * 60)
print()

# Calls to sceSblServiceMailbox are the most interesting — these are
# the path into the HV. If they have CFI, we need to bypass it to
# redirect them.
mailbox_addr = kdata_base + symbols['sceSblServiceMailbox']
mailbox_calls = [cs for cs in results_self['call_sites']
                 if cs.callee_rip == mailbox_addr]

if mailbox_calls:
    print('[cfi] %d calls to sceSblServiceMailbox found' % len(mailbox_calls))
    for cs in mailbox_calls:
        print('  from %#x (offset %#x)' % (
            cs.caller_rip, cs.caller_rip - kdata_base))
        if cs.cfi_boundary:
            b = cs.cfi_boundary
            print('    CFI: hash=%#x in %s, check at %#x' % (
                b.hash_value or 0, b.hash_reg or '?', b.check_rip or 0))
            print('    BYPASS: set DR at %#x, swap %s after check' % (
                b.check_rip, cs.target_reg or 'rax'))
        else:
            print('    no CFI check detected (may be direct call)')
else:
    print('[cfi] no direct calls to sceSblServiceMailbox in this trace')
    print('[cfi] the mailbox may be called through a wrapper function')

# Also check for any calls near known interesting offsets
interesting_offsets = {}
for name in ('sceSblAuthMgrSmIsLoadable2', 'sceSblServiceMailbox',
             'eventhandler_register', 'printf', 'copyin', 'copyout'):
    if name in symbols:
        interesting_offsets[kdata_base + symbols[name]] = name

interesting_calls = [cs for cs in results_self['call_sites']
                     if cs.callee_rip in interesting_offsets]
if interesting_calls:
    print('\n[cfi] calls to known functions:')
    for cs in interesting_calls:
        name = interesting_offsets[cs.callee_rip]
        cfi = 'CFI' if cs.cfi_boundary else 'no-CFI'
        print('  %s: from %#x (%s, target_reg=%s)' % (
            name, cs.caller_rip, cfi, cs.target_reg or '?'))

# =============================================================================
# Save results
# =============================================================================
print()
print('=' * 60)
print('Saving results')
print('=' * 60)
print()

def make_serializable(obj):
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_serializable(i) for i in obj]
    elif isinstance(obj, int):
        return '0x%x' % obj if obj > 2**53 else obj
    elif isinstance(obj, bytes):
        return obj.hex()
    elif obj is None or isinstance(obj, (bool, str)):
        return obj
    else:
        return str(obj)

# Build JSON-safe results
save_data = {
    'kdata_base': '0x%x' % kdata_base,
    'self_trace_frames': len(trace),
    'getpid_trace_frames': len(trace_getpid),
    'call_sites': [],
    'cfi_protected': [],
    'trampolines': [],
    'hashes': make_serializable(all_hashes),
    'mailbox_calls': [],
}

for cs in results_self['call_sites']:
    entry = {
        'caller_rip': '0x%x' % cs.caller_rip,
        'callee_rip': '0x%x' % cs.callee_rip,
        'caller_offset': '0x%x' % (cs.caller_rip - kdata_base),
        'callee_offset': '0x%x' % (cs.callee_rip - kdata_base),
        'target_reg': cs.target_reg,
        'has_cfi': cs.cfi_boundary is not None,
    }
    if cs.cfi_boundary:
        b = cs.cfi_boundary
        entry['cfi'] = {
            'check_rip': '0x%x' % b.check_rip if b.check_rip else None,
            'hash_reg': b.hash_reg,
            'hash_value': '0x%x' % b.hash_value if b.hash_value is not None else None,
            'pattern': b.pattern,
        }
        save_data['cfi_protected'].append(entry)
    save_data['call_sites'].append(entry)

for t in results_self.get('trampolines', []):
    save_data['trampolines'].append({
        'entry_rip': '0x%x' % t['entry_rip'],
        'body_rip': '0x%x' % t['body_rip'],
        'entry_offset': '0x%x' % (t['entry_rip'] - kdata_base),
        'trampoline_size': t['trampoline_size'],
    })

for cs in mailbox_calls:
    entry = {
        'caller_rip': '0x%x' % cs.caller_rip,
        'caller_offset': '0x%x' % (cs.caller_rip - kdata_base),
        'target_reg': cs.target_reg,
        'has_cfi': cs.cfi_boundary is not None,
    }
    if cs.cfi_boundary:
        b = cs.cfi_boundary
        entry['bypass'] = {
            'breakpoint_addr': '0x%x' % b.check_rip if b.check_rip else None,
            'swap_reg': cs.target_reg or 'rax',
            'hash_value': '0x%x' % b.hash_value if b.hash_value is not None else None,
        }
    save_data['mailbox_calls'].append(entry)

with open('cfi_analysis.json', 'w') as f:
    json.dump(save_data, f, indent=2)
print('[*] analysis saved to cfi_analysis.json')

# Write human-readable call site listing
with open('cfi_call_sites.txt', 'w') as f:
    f.write('# KCFI Call Site Analysis\n')
    f.write('# kdata_base = %#x\n' % kdata_base)
    f.write('# SELF trace: %d frames\n' % len(trace))
    f.write('# getpid trace: %d frames\n\n' % len(trace_getpid))

    f.write('## SELF-loading trace call sites (%d total)\n\n' % len(results_self['call_sites']))
    for cs in results_self['call_sites']:
        f.write('%#018x -> %#018x  (offset %#x -> %#x)  target_reg=%-4s  CFI=%s\n' % (
            cs.caller_rip, cs.callee_rip,
            cs.caller_rip - kdata_base, cs.callee_rip - kdata_base,
            cs.target_reg or '?',
            'YES' if cs.cfi_boundary else 'no'))
        if cs.cfi_boundary:
            b = cs.cfi_boundary
            f.write('    CFI check: %#x hash=%s in %s pattern=%s\n' % (
                b.check_rip or 0,
                '%#x' % b.hash_value if b.hash_value is not None else '?',
                b.hash_reg or '?', b.pattern or '?'))

    f.write('\n## KCFI trampolines (%d total)\n\n' % len(results_self.get('trampolines', [])))
    for t in results_self.get('trampolines', []):
        f.write('%#018x: trampoline %d bytes -> body at %#018x  (offset %#x)\n' % (
            t['entry_rip'], t['trampoline_size'], t['body_rip'],
            t['entry_rip'] - kdata_base))

    f.write('\n## KCFI hash catalog (%d entries)\n\n' % len(all_hashes))
    for rip, info in sorted(all_hashes.items()):
        f.write('call at %#018x -> %#018x: hash=%#010x in %s  target_reg=%s\n' % (
            rip, info['target'], info['hash'], info['hash_reg'],
            info.get('target_reg', '?')))

    if mailbox_calls:
        f.write('\n## sceSblServiceMailbox calls (%d)\n\n' % len(mailbox_calls))
        for cs in mailbox_calls:
            f.write('from %#018x (offset %#x)  target_reg=%s  CFI=%s\n' % (
                cs.caller_rip, cs.caller_rip - kdata_base,
                cs.target_reg or '?',
                'YES' if cs.cfi_boundary else 'no'))
            if cs.cfi_boundary:
                b = cs.cfi_boundary
                f.write('    BYPASS: DR at %#x, swap %s, hash=%#x\n' % (
                    b.check_rip or 0, cs.target_reg or 'rax',
                    b.hash_value or 0))

print('[*] call sites saved to cfi_call_sites.txt')

# =============================================================================
# Summary
# =============================================================================
print()
print('=' * 60)
print('DONE')
print('=' * 60)
print()
print('Results:')
print('  SELF trace: %d frames, %d indirect calls, %d CFI-protected' % (
    len(trace),
    len(results_self['call_sites']),
    len(results_self['cfi_protected'])))
print('  getpid trace: %d frames, %d indirect calls, %d CFI-protected' % (
    len(trace_getpid),
    len(results_getpid['call_sites']),
    len(results_getpid['cfi_protected'])))
print('  KCFI trampolines: %d' % len(results_self.get('trampolines', [])))
print('  KCFI hashes extracted: %d' % len(all_hashes))
if mailbox_calls:
    cfi_mailbox = [cs for cs in mailbox_calls if cs.cfi_boundary]
    print('  sceSblServiceMailbox calls: %d (%d CFI-protected)' % (
        len(mailbox_calls), len(cfi_mailbox)))
print()
print('Output files:')
print('  cfi_analysis.json    -- full analysis (JSON)')
print('  cfi_call_sites.txt   -- human-readable call site listing')
print()
print('To use the bypass interactively:')
print('  import cfi_bypass')
print('  # Analyze an existing trace:')
print('  results = cfi_bypass.analyze_trace_cfi(trace, kdata_base)')
print('  # Plan and execute a redirected call:')
print('  plan = cfi_bypass.plan_interposition(call_site)')
print('  cfi_bypass.execute_redirected_call(gdb, kdata_base, plan, new_target)')
