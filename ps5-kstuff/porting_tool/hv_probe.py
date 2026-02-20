"""
HV Boundary Finder & Mailbox Prober

Uses the existing r0gdb trace infrastructure to:
1. Trace THROUGH sceSblServiceMailbox (not intercepting at entry)
2. Find the VMMCALL/MMIO instruction that crosses into the HV
3. Extract the hypercall calling convention
4. Probe the HV by sending crafted mailbox messages through the
   kernel's own sceSblServiceMailbox wrapper (safe — no raw VMMCALL)

Requires: a working porting_tool setup with offsets already discovered
Usage: called from the porting_tool main.py context (needs gdb, r0gdb, traces)

Typical workflow:
    import hv_probe

    # Phase 1: find the HV boundary inside sceSblServiceMailbox
    result = hv_probe.find_hv_boundary(gdb, r0gdb, symbols, kdata_base)

    # Phase 2: probe the HV with crafted mailbox commands
    handle = result['mailbox_handle']
    hv_probe.probe_mailbox_commands(gdb, r0gdb, symbols, kdata_base, handle)
"""

import collections
import struct
import traces


def find_hv_boundary(gdb, r0gdb, symbols, kdata_base):
    """
    Trace through sceSblServiceMailbox and find where execution
    crosses into the hypervisor.

    The trace records every instruction because fix_mmap_self only
    patches 2 specific addresses. Everything else — including the
    full body of sceSblServiceMailbox — executes and gets recorded.

    Returns dict with:
      - vmmcall_addr: address of VMMCALL/MMIO instruction
      - mailbox_handle: RDI value used when calling sceSblServiceMailbox
      - mailbox_entries: trace indices of all mailbox calls
      - gaps: detected #VMEXIT gaps (VMMCALL signature)
      - subcalls: function calls made inside sceSblServiceMailbox
      - internals: all trace frames inside the first mailbox call
      - trace: the Trace object
    """

    mailbox_addr = kdata_base + symbols['sceSblServiceMailbox']

    # Set up offsets needed by fix_mmap_self trace_prog
    gdb.ieval('offsets.mmap_self_fix_1_end = (offsets.mmap_self_fix_1_start = %s) + 2'
              % ostr(kdata_base + symbols['mmap_self_fix_1_start']))
    gdb.ieval('offsets.mmap_self_fix_2_end = (offsets.mmap_self_fix_2_start = %s) + 2'
              % ostr(kdata_base + symbols['mmap_self_fix_2_start']))

    # Open a signed SELF — triggers the full loading pipeline
    fd = gdb.ieval('(int)open("/system_ex/common_ex/lib/libSceNKWebKit.sprx", 0)')
    assert fd >= 0, "failed to open signed SELF"

    # Trace mmap + mlock of the SELF
    # fix_mmap_self only patches 2 addresses, records EVERYTHING else
    print('[hv_probe] tracing mmap+mlock of signed SELF...')
    raw = (
        r0gdb.trace('fix_mmap_self', 'mmap', 0, 65536, 1, 0x80001, fd, 0) +
        r0gdb.trace('fix_mmap_self', 'mlock', gdb.ieval('(void*)$rax'), 65536)
    )
    trace = traces.Trace(raw)
    print('[hv_probe] trace captured: %d frames' % len(trace))

    # Find all calls to sceSblServiceMailbox
    mailbox_entries = []
    for i in range(1, len(trace)):
        if trace.is_jump(i-1) and trace[i].rsp == trace[i-1].rsp - 8:
            if trace[i].rip == mailbox_addr:
                mailbox_entries.append(i)

    print('[hv_probe] found %d calls to sceSblServiceMailbox' % len(mailbox_entries))
    if not mailbox_entries:
        print('[hv_probe] ERROR: no mailbox calls found!')
        print('[hv_probe] mailbox_addr = %#x' % mailbox_addr)
        # Diagnostic: show frequent call targets
        targets = collections.Counter()
        for i in range(1, len(trace)):
            if trace.is_jump(i-1) and trace[i].rsp == trace[i-1].rsp - 8:
                targets[trace[i].rip] += 1
        print('[hv_probe] frequent call targets:')
        for addr, count in targets.most_common(20):
            if count >= 4:
                print('  %#x: %d calls' % (addr, count))
        return None

    # Capture the mailbox handle (RDI at entry)
    mailbox_handle = trace[mailbox_entries[0]].rdi
    print('[hv_probe] mailbox handle (RDI) = %#x' % mailbox_handle)

    # Cross-call analysis: compare arguments across all invocations
    print('\n[hv_probe] === MAILBOX CALL ANALYSIS ===')
    handles = set()
    for idx, entry in enumerate(mailbox_entries):
        f = trace[entry]
        handles.add(f.rdi)
        print('[hv_probe] call #%d: RDI=%#x RSI=%#x RDX=%#x' % (
            idx, f.rdi, f.rsi, f.rdx))

    if len(handles) == 1:
        print('[hv_probe] all calls use same handle: %#x' % mailbox_handle)
    else:
        print('[hv_probe] WARNING: multiple handles: %s' % (
            ', '.join('%#x' % h for h in sorted(handles))))

    # Analyze internals of first mailbox call
    entry_idx = mailbox_entries[0]
    entry_rsp = trace[entry_idx].rsp
    print('\n[hv_probe] === INTERNAL ANALYSIS (first call) ===')

    internals = []
    i = entry_idx
    while i < len(trace):
        internals.append((i, trace[i]))
        # Detect function return
        if i > entry_idx and trace.is_jump(i-1):
            if trace[i].rsp == entry_rsp + 8:
                break
        i += 1

    print('[hv_probe] %d frames inside function' % len(internals))

    # === Find #VMEXIT gaps ===
    # When VMMCALL (or any #VMEXIT-causing instruction) executes with TF set,
    # #VMEXIT preempts #DB. The HV handles the exit, does VMRUN. Guest resumes
    # at VMMCALL+3 with TF still set. The next instruction executes, THEN #DB
    # fires. So one instruction is "eaten" — the trace shows a gap where
    # consecutive RIPs differ by more than one instruction length AND the
    # control flow is not a call/ret/jump.
    gaps = []
    for j in range(len(internals) - 1):
        _, fa = internals[j]
        _, fb = internals[j+1]
        rip_diff = (fb.rip - fa.rip) % 2**64

        if rip_diff >= 16:
            is_call = (fb.rsp == fa.rsp - 8)
            is_ret = (fb.rsp == fa.rsp + 8)
            if not is_call and not is_ret:
                gaps.append({
                    'idx': j,
                    'rip': fa.rip,
                    'next_rip': fb.rip,
                    'rip_diff': rip_diff,
                    'rsp_diff': fb.rsp - fa.rsp,
                    'rax_before': fa.rax,
                    'rax_after': fb.rax,
                    'before': fa,
                    'after': fb,
                })

    # === Find subcalls ===
    subcalls = []
    for j in range(len(internals) - 1):
        _, fa = internals[j]
        _, fb = internals[j+1]
        if trace.is_jump(internals[j][0]) and fb.rsp == fa.rsp - 8:
            subcalls.append({
                'caller_rip': fa.rip,
                'callee_rip': fb.rip,
                'idx': j,
            })

    # === Find polling loops ===
    loops = _find_loops(internals)

    # === Report ===
    if gaps:
        print('\n[hv_probe] %d #VMEXIT gaps found:' % len(gaps))
        for g in gaps:
            print('  RIP %#x -> %#x (diff=%d, rsp_diff=%d)' % (
                g['rip'], g['next_rip'], g['rip_diff'], g['rsp_diff']))
            print('    RAX: %#x -> %#x' % (g['rax_before'], g['rax_after']))

    if subcalls:
        print('\n[hv_probe] %d subcalls:' % len(subcalls))
        for sc in subcalls:
            print('  %#x calls %#x' % (sc['caller_rip'], sc['callee_rip']))

    if loops:
        print('\n[hv_probe] %d polling loops:' % len(loops))
        for lp in loops[:5]:
            print('  %d iterations, RIPs: %s' % (
                lp['iterations'],
                ' '.join('%#x' % r for r in lp['rips'])))

    # === Identify VMMCALL ===
    # Check gaps in the top-level function and all subcalls
    all_gaps = list(gaps)

    # Also check inside subcalls (VMMCALL is likely in a helper function)
    for sc in subcalls:
        sc_start = sc['idx'] + 1
        if sc_start >= len(internals):
            continue
        sc_rsp = internals[sc_start][1].rsp
        sc_frames = []
        for k in range(sc_start, len(internals)):
            sc_frames.append(internals[k])
            if k > sc_start and internals[k][1].rsp == sc_rsp + 8:
                break

        for k in range(len(sc_frames) - 1):
            _, fa = sc_frames[k]
            _, fb = sc_frames[k+1]
            d = (fb.rip - fa.rip) % 2**64
            if d >= 16 and fb.rsp != fa.rsp - 8 and fb.rsp != fa.rsp + 8:
                all_gaps.append({
                    'idx': sc['idx'] + 1 + k,
                    'rip': fa.rip,
                    'next_rip': fb.rip,
                    'rip_diff': d,
                    'rsp_diff': fb.rsp - fa.rsp,
                    'rax_before': fa.rax,
                    'rax_after': fb.rax,
                    'before': fa,
                    'after': fb,
                    'in_subcall': sc['callee_rip'],
                })

    result = {
        'mailbox_handle': mailbox_handle,
        'mailbox_entries': mailbox_entries,
        'gaps': all_gaps,
        'subcalls': subcalls,
        'loops': loops,
        'internals': internals,
        'trace': trace,
    }

    # Best VMMCALL candidate: gap with RAX change, reasonable RIP diff
    vmmcall = [g for g in all_gaps if g['rax_before'] != g['rax_after']
               and g['rip_diff'] < 50]
    if vmmcall:
        best = vmmcall[0]
        print('\n[hv_probe] === LIKELY VMMCALL ===')
        print('[hv_probe] addr: %#x (offset %#x)' % (
            best['rip'], best['rip'] - kdata_base))
        if 'in_subcall' in best:
            print('[hv_probe] inside subcall at %#x' % best['in_subcall'])
        print('[hv_probe] RAX before: %#x (hypercall id?)' % best['rax_before'])
        print('[hv_probe] RAX after:  %#x (return code?)' % best['rax_after'])
        print('[hv_probe] regs before:')
        _dump_regs(best['before'])
        print('[hv_probe] regs after:')
        _dump_regs(best['after'])
        result['vmmcall_addr'] = best['rip']
    elif all_gaps:
        # Might be MMIO — the gap signature is different
        print('\n[hv_probe] no clear VMMCALL (RAX unchanged in gaps)')
        print('[hv_probe] possible MMIO-based HV communication')
        for g in all_gaps:
            print('  gap at %#x: diff=%d, rsp_diff=%d' % (
                g['rip'], g['rip_diff'], g['rsp_diff']))
            sc = g.get('in_subcall')
            if sc:
                print('    (inside subcall %#x)' % sc)
    else:
        print('\n[hv_probe] no gaps found — HV boundary may be via MMIO store')
        print('[hv_probe] check polling loops for post-doorbell spin-waits')

    return result


def probe_mailbox_commands(gdb, r0gdb, symbols, kdata_base, handle,
                           cmd_range=range(0x100)):
    """
    Probe the HV by calling sceSblServiceMailbox with crafted messages.

    This is SAFE because:
    - We call through the kernel's own wrapper (proper setup/teardown)
    - The HV is designed to receive mailbox messages
    - Invalid commands should return error codes, not crash

    Arguments:
        handle: RDI value (captured from find_hv_boundary)
        cmd_range: range of command IDs to try (default 0x00-0xFF)
    """

    mailbox_fn = kdata_base + symbols['sceSblServiceMailbox']

    # Allocate a 128-byte message buffer in kernel memory
    msg_buf = gdb.ieval('r0gdb_kmalloc(256)')
    assert msg_buf, "kmalloc failed"
    print('[hv_probe] message buffer at %#x' % msg_buf)

    results = {}

    for cmd_id in cmd_range:
        # Zero the buffer
        gdb.ieval('{uint64_t[16]}%d = {}' % msg_buf)

        # Set command ID (bytes 0-3)
        gdb.ieval('{uint32_t}%d = %d' % (msg_buf, cmd_id))

        # Call sceSblServiceMailbox(handle, msg_buf, msg_buf)
        # r0gdb_kfncall sets up tracing, redirects getpid to our function,
        # and returns the function's return value
        ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, %s)' % (
            ostr(mailbox_fn), ostr(handle), ostr(msg_buf), ostr(msg_buf)))

        # Read back the status field (bytes 4-7)
        status = gdb.ieval('{uint32_t}%d' % (msg_buf + 4))

        # Read the full response
        resp = []
        for off in range(0, 128, 8):
            resp.append(gdb.ieval('{uint64_t}%d' % (msg_buf + off)))

        results[cmd_id] = {
            'ret': ret,
            'status': status,
            'response': resp,
        }

        # Report non-trivial results
        if status != 0 or ret != 0:
            print('[hv_probe] cmd %#04x: ret=%#x status=%#x' % (cmd_id, ret, status))
            if any(r != 0 for r in resp[1:]):
                print('  response: %s' % ' '.join('%016x' % r for r in resp[:8]))
        else:
            # All zeros — likely means "unknown command, no error"
            # Only print every 16th to avoid spam
            if cmd_id % 0x10 == 0:
                print('[hv_probe] cmd %#04x: ret=0 status=0 (probing...)' % cmd_id)

    # Summary
    interesting = {k: v for k, v in results.items()
                   if v['status'] != 0 or v['ret'] != 0}
    print('\n[hv_probe] === PROBE SUMMARY ===')
    print('[hv_probe] %d commands tested, %d returned non-zero' % (
        len(results), len(interesting)))

    if interesting:
        print('[hv_probe] interesting commands:')
        for cmd_id, v in sorted(interesting.items()):
            print('  cmd %#04x: ret=%#x status=%#x resp[1]=%#x' % (
                cmd_id, v['ret'], v['status'], v['response'][1]))

    return results


def probe_known_commands(gdb, r0gdb, symbols, kdata_base, handle):
    """
    Probe commands known from Byepervisor research on earlier firmware.

    Known PS5 HV mailbox commands (from PS5 wiki / Byepervisor):
    These were the command IDs used on FW ≤2.50. They may have changed
    on FW 4.03, but testing them is safe.
    """
    mailbox_fn = kdata_base + symbols['sceSblServiceMailbox']
    msg_buf = gdb.ieval('r0gdb_kmalloc(256)')
    assert msg_buf

    # Known SBL mailbox command IDs from public research
    # These are the ones used by sceSblAuthMgr / sceSblSrtc etc.
    known_cmds = {
        0x01: 'SM_VERIFY_HEADER',
        0x02: 'SM_LOAD_SELF_SEGMENT',
        0x03: 'SM_DECRYPT_SELF_BLOCK',
        0x04: 'SM_IS_LOADABLE',
        0x05: 'SM_FINALIZE',
        0x06: 'SM_DECRYPT_MULTIPLE_BLOCKS',
        0x0A: 'SBL_CRYPT_ASYNC',
    }

    print('[hv_probe] probing known SBL commands:')
    results = {}

    for cmd_id, name in sorted(known_cmds.items()):
        # Zero buffer, set command
        gdb.ieval('{uint64_t[16]}%d = {}' % msg_buf)
        gdb.ieval('{uint32_t}%d = %d' % (msg_buf, cmd_id))

        ret = gdb.ieval('r0gdb_kfncall(%s, %s, %s, %s)' % (
            ostr(mailbox_fn), ostr(handle), ostr(msg_buf), ostr(msg_buf)))

        status = gdb.ieval('{uint32_t}%d' % (msg_buf + 4))

        results[cmd_id] = {'name': name, 'ret': ret, 'status': status}
        print('  [%#04x] %-30s  ret=%#x status=%#x' % (
            cmd_id, name, ret, status))

    return results


def dump_trace_region(trace, start_idx, count=50):
    """Dump a region of the trace for manual analysis."""
    for i in range(start_idx, min(start_idx + count, len(trace))):
        f = trace[i]
        # Detect instruction type from RIP difference
        if i + 1 < len(trace):
            rip_diff = (trace[i+1].rip - f.rip) % 2**64
            if rip_diff >= 16:
                if trace[i+1].rsp == f.rsp - 8:
                    itype = 'CALL'
                elif trace[i+1].rsp == f.rsp + 8:
                    itype = 'RET '
                else:
                    itype = 'GAP!'
            else:
                itype = '    '
        else:
            itype = '    '

        print('[%6d] %s %#018x  rax=%016x rdx=%016x rdi=%016x rsp=%016x' % (
            i, itype, f.rip, f.rax, f.rdx, f.rdi, f.rsp))


# === Internal helpers ===

def _find_loops(internals, max_loop_len=8):
    """Find short repeating RIP sequences (polling loops)."""
    loops = []
    i = 0
    while i < len(internals) - 2:
        for loop_len in range(2, max_loop_len + 1):
            if i + loop_len * 2 > len(internals):
                break
            pattern = [internals[i+j][1].rip for j in range(loop_len)]
            repeats = 1
            j = i + loop_len
            while j + loop_len <= len(internals):
                chunk = [internals[j+k][1].rip for k in range(loop_len)]
                if chunk != pattern:
                    break
                repeats += 1
                j += loop_len
            if repeats >= 3:
                loops.append({
                    'start': i,
                    'rips': pattern,
                    'iterations': repeats,
                })
                i = j
                break
        else:
            i += 1
    return loops


def _dump_regs(frame):
    """Print register state from a trace frame."""
    print('    RIP=%#x RSP=%#x' % (frame.rip, frame.rsp))
    print('    RAX=%#x RCX=%#x RDX=%#x' % (frame.rax, frame.rcx, frame.rdx))
    print('    RDI=%#x RSI=%#x RBP=%#x' % (frame.rdi, frame.rsi, frame.rbp))
    print('    R8=%#x R9=%#x R10=%#x R11=%#x' % (frame.r8, frame.r9, frame.r10, frame.r11))


def ostr(x):
    return str(x % 2**64)
