"""
PS5 KCFI (Kernel Control Flow Integrity) Bypass Module

The PS5 kernel is compiled with LLVM's -fsanitize=kcfi. This means:
  - Each indirect-callable function has a 4-byte type hash at [addr - 4]
  - At each indirect call site, the caller:
      1. Loads the hash from [target_reg - 4]
      2. Compares it with the expected hash for that call site
      3. Traps (#UD) on mismatch
      4. Executes the indirect CALL on match
  - Function entries may have a small KCFI trampoline (1 instruction)
    that the porting_tool already compensates for (main.py:615-618)

This module automates CFI analysis and bypass:

  Phase 1: Call-site discovery
    Trace a code path, identify all indirect CALL instructions,
    record the register state around each one.

  Phase 2: CFI boundary detection
    For each indirect call, walk backwards in the trace to find
    the CFI check pattern (hash load + compare + conditional branch).
    The "CFI boundary" is the compare instruction — after it executes,
    the check has passed but the call hasn't happened yet.

  Phase 3: Interposition
    Use hardware debug registers (DR0-DR3) to set a breakpoint at
    the CFI boundary. When it fires, the kstuff #DB handler swaps
    the target register, redirecting the call after CFI validation.

All operations use proven-safe primitives: single-step tracing (same
as main.py offset discovery) and debug register breakpoints (same as
main.py loadSelfSegment_watchpoint).

Requires: a working porting_tool setup with offsets discovered.
Usage: called from run_cfi_bypass.py or interactively.
"""

import collections
import traces


def ostr(x):
    return str(x % 2**64)


# =============================================================================
# Data structures
# =============================================================================

class CallSite:
    """An indirect call found in a trace."""
    __slots__ = (
        'trace_idx',      # index in the trace where the CALL executes
        'caller_rip',     # RIP of the instruction that performs the call
        'callee_rip',     # RIP of the target function
        'caller_rsp',     # RSP before the call
        'regs_before',    # full Frame at the call instruction
        'regs_after',     # full Frame at the first instruction of the callee
        'target_reg',     # which register held the call target (or None)
        'cfi_boundary',   # CFIBoundary if detected, else None
    )

    def __init__(self, trace_idx, caller_rip, callee_rip, caller_rsp,
                 regs_before, regs_after):
        self.trace_idx = trace_idx
        self.caller_rip = caller_rip
        self.callee_rip = callee_rip
        self.caller_rsp = caller_rsp
        self.regs_before = regs_before
        self.regs_after = regs_after
        self.target_reg = None
        self.cfi_boundary = None

    def __repr__(self):
        return 'CallSite(idx=%d, %#x -> %#x, target_reg=%s, cfi=%s)' % (
            self.trace_idx, self.caller_rip, self.callee_rip,
            self.target_reg, 'yes' if self.cfi_boundary else 'no')


class CFIBoundary:
    """The CFI check boundary for an indirect call."""
    __slots__ = (
        'check_start_idx',  # trace index where the CFI check begins
        'check_end_idx',    # trace index of the last CFI check instruction
        'check_rip',        # RIP of the compare instruction
        'hash_reg',         # register used for the hash value
        'hash_value',       # the expected hash value (from the compare)
        'call_idx',         # trace index of the actual CALL
        'pattern',          # string describing the detected pattern
    )

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))

    def __repr__(self):
        return 'CFIBoundary(check=%#x, hash=%s, pattern=%s)' % (
            self.check_rip or 0,
            '%#x' % self.hash_value if self.hash_value is not None else '?',
            self.pattern or '?')


class InterpositionPlan:
    """Plan for redirecting an indirect call past CFI."""
    __slots__ = (
        'breakpoint_addr',  # address to set HW breakpoint on
        'target_reg',       # register to overwrite (e.g. 'rax')
        'dr_index',         # which DR to use (0-3)
        'call_site',        # the CallSite being targeted
    )

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))


# =============================================================================
# Phase 1: Call-site discovery
# =============================================================================

def discover_call_sites(trace, start_idx=0, end_idx=None):
    """
    Scan a trace for all indirect CALL instructions.

    An indirect CALL is detected as: is_jump(i) AND trace[i+1].rsp == trace[i].rsp - 8
    (i.e., a non-sequential jump that pushes a return address).

    Direct calls to nearby addresses (rip_diff < 16) are filtered out by
    the Trace.is_jump() method which requires rip_diff >= 16.

    Returns list of CallSite objects.
    """
    if end_idx is None:
        end_idx = len(trace) - 1

    sites = []
    for i in range(max(1, start_idx), min(end_idx, len(trace) - 1)):
        if not trace.is_jump(i):
            continue
        # Check for CALL pattern: RSP decreases by 8 (return address pushed)
        if trace[i + 1].rsp != trace[i].rsp - 8:
            continue

        caller = trace[i]
        callee = trace[i + 1]

        cs = CallSite(
            trace_idx=i,
            caller_rip=caller.rip,
            callee_rip=callee.rip,
            caller_rsp=caller.rsp,
            regs_before=caller,
            regs_after=callee,
        )

        # Determine which register held the call target
        cs.target_reg = _identify_target_register(caller, callee.rip)
        sites.append(cs)

    return sites


def discover_call_sites_for_function(trace, func_addr):
    """
    Find all indirect calls made BY a specific function.

    Traces from the function's entry to its return, collecting only
    calls at the same stack depth (direct calls by this function,
    not by its callees).
    """
    # Find entry point in trace
    entry = trace.find_next_rip(0, func_addr)
    if entry is None:
        return []

    entry_rsp = trace[entry].rsp
    sites = []

    i = entry
    while i < len(trace):
        if trace.is_jump(i) and trace[i + 1].rsp == trace[i].rsp - 8:
            # This is a CALL. Is it from our function's stack depth?
            if trace[i].rsp == entry_rsp:
                caller = trace[i]
                callee = trace[i + 1]
                cs = CallSite(
                    trace_idx=i,
                    caller_rip=caller.rip,
                    callee_rip=callee.rip,
                    caller_rsp=caller.rsp,
                    regs_before=caller,
                    regs_after=callee,
                )
                cs.target_reg = _identify_target_register(caller, callee.rip)
                sites.append(cs)
        # Detect function return
        if i > entry and trace.is_jump(i):
            if i + 1 < len(trace) and trace[i + 1].rsp == entry_rsp + 8:
                break
        i += 1

    return sites


def trace_function_single_step(gdb, kdata_base, func_addr, args=None):
    """
    Single-step through a function, recording register state at each step.

    This is the same technique used by main.py for offset discovery
    (justreturn, eventhandler_register, etc). XOM allows execute,
    so each instruction runs and we observe the result.

    Arguments:
        func_addr: virtual address of the function to trace
        args: dict of register name -> value to set before tracing

    Returns list of (rip, register_dict) tuples.
    """
    steps = []

    gdb.ieval('$pc = ' + ostr(func_addr))
    gdb.ieval('$rsp = ((unsigned long long)$rsp & -16) | 8')

    if args:
        for reg, val in args.items():
            gdb.ieval('$%s = %s' % (reg, ostr(val)))

    prev_rsp = gdb.ieval('$rsp') % 2**64
    entry_rsp = prev_rsp

    while True:
        pc = gdb.ieval('$pc') % 2**64
        rsp = gdb.ieval('$rsp') % 2**64
        rax = gdb.ieval('$rax') % 2**64
        rcx = gdb.ieval('$rcx') % 2**64
        rdx = gdb.ieval('$rdx') % 2**64
        rbx = gdb.ieval('$rbx') % 2**64
        rdi = gdb.ieval('$rdi') % 2**64
        rsi = gdb.ieval('$rsi') % 2**64

        steps.append((pc, {
            'rip': pc, 'rsp': rsp,
            'rax': rax, 'rcx': rcx, 'rdx': rdx, 'rbx': rbx,
            'rdi': rdi, 'rsi': rsi,
        }))

        # Detect return: RSP above entry point
        if len(steps) > 1 and rsp > entry_rsp:
            break

        gdb.ieval('$eflags = 0x102')  # TF | reserved
        gdb.execute('stepi')
        prev_rsp = rsp

    return steps


# =============================================================================
# Phase 2: CFI boundary detection
# =============================================================================

# KCFI check patterns on x86-64 (LLVM -fsanitize=kcfi):
#
# Pattern A (standard LLVM KCFI):
#   movl -4(%r11), %ecx        ; load hash from [target - 4]
#   cmpl $<hash>, %ecx          ; compare with expected
#   je .Lok                      ; skip trap if match
#   ud2                          ; trap on mismatch
#   .Lok:
#   call *%r11                   ; actual call
#
# Observable in trace:
#   Frame N-2: RCX changes to a small 32-bit value (the hash)
#   Frame N-1: conditional branch taken (to the call), RIP advances
#   Frame N:   CALL (RSP -= 8, jump to target)
#
# Pattern B (Sony variant — callee trampoline):
#   At function entry, a 1-instruction trampoline is present.
#   The porting_tool skips it with a single stepi (main.py:615-618).
#   Observable: first instruction of function jumps to nearby address.
#
# Pattern C (hash in EAX):
#   movl -4(%rax), %ecx         ; load hash from [target - 4]
#   cmpl $<hash>, %ecx
#   je .Lok
#   ud2
#   .Lok:
#   call *%rax

def detect_cfi_boundaries(trace, call_sites):
    """
    For each call site, look backwards in the trace to find the
    CFI check pattern.

    Returns the same call_sites list with .cfi_boundary populated
    where a CFI pattern is detected.
    """
    for cs in call_sites:
        boundary = _detect_single_cfi_boundary(trace, cs)
        if boundary:
            cs.cfi_boundary = boundary

    return call_sites


def _detect_single_cfi_boundary(trace, cs):
    """
    Analyze the instructions before an indirect call to find the
    CFI check.

    KCFI on x86-64 has a characteristic pattern: one of the registers
    (typically ECX or EAX) is loaded with a 32-bit hash value from
    [target_reg - 4] in the 2-4 instructions before the call.

    We detect this by looking for:
    1. A register that changes to a value fitting in 32 bits
    2. That value appearing as a constant in the compare
    3. A conditional branch between the compare and the call
    """
    idx = cs.trace_idx
    if idx < 3:
        return None

    # Look at up to 6 instructions before the call
    window_start = max(0, idx - 6)
    window = [(i, trace[i]) for i in range(window_start, idx + 1)]

    # Strategy 1: Find a register that takes on a 32-bit hash-like value
    # The hash is a 4-byte value, so when loaded into a 64-bit register,
    # the upper 32 bits are zero (movl zero-extends on x86-64).
    call_frame = trace[idx]
    hash_candidates = []

    for wi in range(len(window) - 1):
        i, fa = window[wi]
        _, fb = window[wi + 1]

        # Check all registers for a change to a 32-bit value
        for reg in ('rax', 'rcx', 'rdx', 'rbx', 'r8', 'r9', 'r10', 'r11'):
            va = getattr(fa, reg) % 2**64
            vb = getattr(fb, reg) % 2**64
            # The hash is a 32-bit value (upper 32 bits zero after movl)
            if va != vb and vb < 2**32 and vb > 0:
                hash_candidates.append((i, reg, vb, wi))

    if not hash_candidates:
        # No obvious hash load found — might not be KCFI-protected
        return None

    # Strategy 2: Look for conditional branch behavior
    # After the compare, there should be a conditional branch. In the
    # "match" case (which we're tracing), the branch is taken to the call.
    # This shows up as a non-sequential RIP change that isn't a CALL or RET.
    branch_candidates = []
    for wi in range(len(window) - 1):
        i, fa = window[wi]
        _, fb = window[wi + 1]
        rip_diff = (fb.rip - fa.rip) % 2**64
        rsp_same = fb.rsp == fa.rsp
        # Conditional branch: non-sequential jump, RSP unchanged
        if rsp_same and 2 <= rip_diff < 16:
            # This is a normal sequential instruction (2-15 bytes), skip
            pass
        elif rsp_same and rip_diff >= 16:
            # Non-sequential with same RSP: likely a conditional branch taken
            branch_candidates.append((i, wi))

    # Correlate: hash load should come before a branch, branch before the call
    best = None
    for hi, hreg, hval, hwi in hash_candidates:
        for bi, bwi in branch_candidates:
            if hwi < bwi < len(window) - 1:
                # hash load at hwi, branch at bwi, call at end of window
                best = CFIBoundary(
                    check_start_idx=hi,
                    check_end_idx=bi,
                    check_rip=trace[bi].rip,
                    hash_reg=hreg,
                    hash_value=hval,
                    call_idx=idx,
                    pattern='hash_in_%s_branch_at_%#x' % (hreg, trace[bi].rip),
                )
                break
        if best:
            break

    # Strategy 3: If no branch found, look for the simpler pattern where
    # the hash check and call are back-to-back (je over ud2, then call).
    # In this case, the branch skips 2 bytes (ud2) and we may see:
    # rip_diff of the instruction after compare is exactly 2 more than expected.
    if not best and hash_candidates:
        hi, hreg, hval, hwi = hash_candidates[-1]  # last hash candidate
        # Check if the instruction after the hash load has a small skip
        if hwi + 2 < len(window):
            _, f_after_hash = window[hwi + 1]
            _, f_after_that = window[hwi + 2]
            skip = (f_after_that.rip - f_after_hash.rip) % 2**64
            if skip in (4, 5, 6, 7, 8) and f_after_that.rsp == f_after_hash.rsp:
                # Likely: cmp + je skipping ud2
                best = CFIBoundary(
                    check_start_idx=hi,
                    check_end_idx=window[hwi + 1][0],
                    check_rip=f_after_hash.rip,
                    hash_reg=hreg,
                    hash_value=hval,
                    call_idx=idx,
                    pattern='hash_in_%s_skip_%d' % (hreg, skip),
                )

    return best


def find_kcfi_trampolines(trace, func_addrs=None):
    """
    Find KCFI trampolines at function entries.

    On PS5, some function entries have a 1-instruction trampoline that
    the porting_tool compensates for (main.py:615-618). This function
    identifies such trampolines in a trace by looking for:
    - Function entry (CALL target)
    - Immediate jump to nearby address (within 16 bytes)
    - No RSP change (not another CALL)

    Arguments:
        func_addrs: if provided, only check these addresses

    Returns list of dicts with trampoline info.
    """
    trampolines = []
    seen = set()

    for i in range(1, len(trace) - 1):
        if not trace.is_jump(i - 1):
            continue
        if trace[i].rsp != trace[i - 1].rsp - 8:
            continue
        # This is a function entry (CALL target)
        entry_rip = trace[i].rip

        if func_addrs and entry_rip not in func_addrs:
            continue
        if entry_rip in seen:
            continue
        seen.add(entry_rip)

        # Check if the first instruction is a short jump
        next_rip = trace[i + 1].rip if i + 1 < len(trace) else None
        if next_rip is None:
            continue

        rip_diff = (next_rip - entry_rip) % 2**64
        rsp_same = trace[i + 1].rsp == trace[i].rsp

        # Trampoline: jumps forward 2-32 bytes, RSP unchanged
        if rsp_same and 2 < rip_diff <= 32:
            trampolines.append({
                'entry_rip': entry_rip,
                'body_rip': next_rip,
                'trampoline_size': rip_diff,
                'trace_idx': i,
            })

    return trampolines


def skip_kcfi_trampoline(gdb, kdata_base, func_addr):
    """
    Step past a KCFI trampoline at function entry and return the
    real function body address.

    This is exactly what main.py:615-618 does:
        gdb.ieval('$pc = '+ostr(resumectx))
        gdb.execute('stepi')
        resumectx = gdb.ieval('$pc') % 2**64

    Returns the address of the first real instruction (after trampoline).
    """
    gdb.ieval('$pc = ' + ostr(func_addr))
    gdb.execute('stepi')
    return gdb.ieval('$pc') % 2**64


# =============================================================================
# Phase 3: Interposition
# =============================================================================

def plan_interposition(call_site, dr_index=0):
    """
    Create an interposition plan for a CFI-protected indirect call.

    The plan specifies:
    - Where to set the hardware breakpoint (at the CFI boundary)
    - Which register to overwrite (the target register)
    - Which debug register to use

    Arguments:
        call_site: CallSite with cfi_boundary populated
        dr_index: which DR to use (0-3)

    Returns InterpositionPlan or None if no CFI boundary detected.
    """
    if not call_site.cfi_boundary:
        # No CFI check detected — the call may be direct or unprotected.
        # We can still interpose at the call instruction itself.
        if call_site.target_reg:
            return InterpositionPlan(
                breakpoint_addr=call_site.caller_rip,
                target_reg=call_site.target_reg,
                dr_index=dr_index,
                call_site=call_site,
            )
        return None

    boundary = call_site.cfi_boundary

    # Set breakpoint AFTER the CFI check completes (at the compare RIP).
    # When the #DB fires, the check has already passed. We then overwrite
    # the target register with our desired address.
    return InterpositionPlan(
        breakpoint_addr=boundary.check_rip,
        target_reg=call_site.target_reg or 'rax',
        dr_index=dr_index,
        call_site=call_site,
    )


def arm_interposition(gdb, plan):
    """
    Set up hardware breakpoint for the interposition.

    Uses r0gdb_write_dbreg (same as main.py:1437) to set an execution
    breakpoint at the CFI boundary address.

    Arguments:
        gdb: GDB RPC connection
        plan: InterpositionPlan from plan_interposition()
    """
    addr = plan.breakpoint_addr
    dr = plan.dr_index

    # DR7 encoding for execution breakpoint:
    #   bit 2*dr: local enable for DRn
    #   bits 16+4*dr: condition (00 = execution)
    #   bits 18+4*dr: length (00 = 1 byte)
    dr7_bit = 1 << (2 * dr)
    # Read current DR7 and OR in our breakpoint
    gdb.eval('r0gdb_write_dbreg(%d, %s)' % (dr, ostr(addr)))
    gdb.eval('r0gdb_write_dbreg(7, r0gdb_read_dbreg(7) | %d)' % dr7_bit)

    print('[cfi] armed DR%d at %#x (target_reg=%s)' % (
        dr, addr, plan.target_reg))


def disarm_interposition(gdb, plan):
    """Remove the hardware breakpoint."""
    dr = plan.dr_index
    dr7_bit = 1 << (2 * dr)
    gdb.eval('r0gdb_write_dbreg(7, r0gdb_read_dbreg(7) & ~%d)' % dr7_bit)
    gdb.eval('r0gdb_write_dbreg(%d, 0)' % dr)
    print('[cfi] disarmed DR%d' % dr)


def execute_redirected_call(gdb, kdata_base, plan, new_target, args=None):
    """
    Execute an indirect call with the target redirected past CFI.

    This is the full bypass sequence:
    1. Set up the HW breakpoint at the CFI boundary
    2. Set the original call's arguments
    3. Start execution — the CFI check runs with the ORIGINAL valid target
    4. The breakpoint fires after the check passes
    5. We overwrite the target register with new_target
    6. Resume execution — the call goes to new_target

    Arguments:
        gdb: GDB RPC connection
        plan: InterpositionPlan
        new_target: address to redirect the call to
        args: optional dict of register values to set

    Returns the register state after the redirected call returns.
    """
    cs = plan.call_site

    # Step 1: Arm the breakpoint
    arm_interposition(gdb, plan)

    # Step 2: Set up registers for the call
    # We need to be at a point where the CFI check will execute.
    # Set PC to a few instructions before the call site.
    if cs.cfi_boundary:
        gdb.ieval('$pc = ' + ostr(cs.cfi_boundary.check_rip))
    else:
        gdb.ieval('$pc = ' + ostr(cs.caller_rip))

    if args:
        for reg, val in args.items():
            gdb.ieval('$%s = %s' % (reg, ostr(val)))

    # The target register must hold a VALID target (one that passes CFI)
    # so the check succeeds. The caller is responsible for setting this.

    # Step 3: Enable single-step and continue
    gdb.ieval('$eflags = 0x102')
    gdb.execute('stepi')

    # Step 4: We should now be stopped at the breakpoint (after CFI check)
    pc = gdb.ieval('$pc') % 2**64

    # Step 5: Overwrite target register
    gdb.ieval('$%s = %s' % (plan.target_reg, ostr(new_target)))
    print('[cfi] redirected %s: %#x -> %#x' % (
        plan.target_reg, cs.callee_rip, new_target))

    # Step 6: Disarm and continue to the call
    disarm_interposition(gdb, plan)
    gdb.ieval('$eflags = 0x102')
    gdb.execute('stepi')

    # Read result registers
    result = {}
    for reg in ('rip', 'rsp', 'rax', 'rcx', 'rdx', 'rbx', 'rdi', 'rsi',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
        result[reg] = gdb.ieval('$%s' % reg) % 2**64

    return result


# =============================================================================
# Analysis helpers
# =============================================================================

def analyze_trace_cfi(trace, kdata_base=0):
    """
    Full CFI analysis of a trace: discover calls, detect boundaries,
    find trampolines.

    Returns dict with all findings.
    """
    print('[cfi] analyzing trace (%d frames)...' % len(trace))

    # Phase 1: Find all indirect calls
    call_sites = discover_call_sites(trace)
    print('[cfi] found %d indirect call sites' % len(call_sites))

    # Phase 2: Detect CFI boundaries
    detect_cfi_boundaries(trace, call_sites)
    cfi_protected = [cs for cs in call_sites if cs.cfi_boundary]
    print('[cfi] %d/%d calls have detected CFI checks' % (
        len(cfi_protected), len(call_sites)))

    # Find KCFI trampolines at function entries
    trampolines = find_kcfi_trampolines(trace)
    print('[cfi] %d KCFI trampolines at function entries' % len(trampolines))

    # Group calls by target
    by_target = collections.defaultdict(list)
    for cs in call_sites:
        by_target[cs.callee_rip].append(cs)

    # Summary
    print('\n[cfi] === CALL SITE SUMMARY ===')
    for target, sites in sorted(by_target.items()):
        offset = target - kdata_base if kdata_base else target
        has_cfi = any(cs.cfi_boundary for cs in sites)
        regs = set(cs.target_reg for cs in sites if cs.target_reg)
        print('  %#x (offset %#x): %d calls, CFI=%s, target_regs=%s' % (
            target, offset, len(sites),
            'YES' if has_cfi else 'no',
            ','.join(regs) if regs else '?'))

    if cfi_protected:
        print('\n[cfi] === CFI-PROTECTED CALLS ===')
        for cs in cfi_protected:
            b = cs.cfi_boundary
            print('  call at %#x -> %#x' % (cs.caller_rip, cs.callee_rip))
            print('    check at %#x, hash_reg=%s, hash=%#x' % (
                b.check_rip, b.hash_reg,
                b.hash_value if b.hash_value is not None else 0))
            print('    pattern: %s' % b.pattern)
            print('    target_reg: %s' % cs.target_reg)

    if trampolines:
        print('\n[cfi] === KCFI TRAMPOLINES ===')
        for t in trampolines:
            offset = t['entry_rip'] - kdata_base if kdata_base else t['entry_rip']
            print('  %#x (offset %#x): trampoline %d bytes -> body at %#x' % (
                t['entry_rip'], offset, t['trampoline_size'], t['body_rip']))

    return {
        'call_sites': call_sites,
        'cfi_protected': cfi_protected,
        'trampolines': trampolines,
        'by_target': dict(by_target),
    }


def diff_traces_for_cfi(trace1, trace2, kdata_base=0):
    """
    Compare two traces of the same code path to identify CFI checks.

    By tracing the same function with two different (valid) indirect call
    targets, CFI checks become visible as the ONLY instructions that
    differ between traces (the hash comparison fails/succeeds differently,
    and the call target is different).

    Arguments:
        trace1, trace2: two Trace objects of the same code path
                        with different valid indirect call targets

    Returns list of divergence points (likely CFI check sites).
    """
    divergences = []
    min_len = min(len(trace1), len(trace2))

    i = 0
    while i < min_len:
        if trace1[i].rip != trace2[i].rip:
            # Divergence found
            div = {
                'idx': i,
                'rip1': trace1[i].rip,
                'rip2': trace2[i].rip,
            }
            # Walk forward to find where they reconverge
            j = i + 1
            while j < min_len and trace1[j].rip != trace2[j].rip:
                j += 1
            div['diverge_len'] = j - i
            if j < min_len:
                div['reconverge_rip'] = trace1[j].rip

            # Check if one path has a hash-like value in a register
            for reg in ('rax', 'rcx', 'rdx'):
                v1 = getattr(trace1[i], reg) % 2**64
                v2 = getattr(trace2[i], reg) % 2**64
                if v1 != v2 and v1 < 2**32 and v2 < 2**32:
                    div['hash_reg'] = reg
                    div['hash_values'] = (v1, v2)

            divergences.append(div)
            i = j
        else:
            i += 1

    print('[cfi] %d divergence points between traces' % len(divergences))
    for d in divergences:
        offset = d['rip1'] - kdata_base if kdata_base else d['rip1']
        msg = '  idx %d: RIP %#x vs %#x (offset %#x), span %d' % (
            d['idx'], d['rip1'], d['rip2'], offset, d['diverge_len'])
        if 'hash_reg' in d:
            msg += ', hash in %s (%#x vs %#x)' % (
                d['hash_reg'], d['hash_values'][0], d['hash_values'][1])
        print(msg)

    return divergences


def extract_cfi_hashes_from_trace(trace, kdata_base=0):
    """
    Extract all KCFI hash values observed in a trace.

    Scans for the characteristic pattern of a 32-bit value appearing
    in a register (typically RCX or EAX) right before an indirect call,
    where that register wasn't used for the call target.

    Returns dict mapping call_site_rip -> hash_value.
    """
    hashes = {}

    for i in range(2, len(trace) - 1):
        if not trace.is_jump(i):
            continue
        if i + 1 >= len(trace):
            continue
        if trace[i + 1].rsp != trace[i].rsp - 8:
            continue
        # This is an indirect call. Check preceding instructions for hash.
        for j in range(max(0, i - 4), i):
            for reg in ('rcx', 'rax', 'rdx'):
                v_before = getattr(trace[j], reg) % 2**64
                v_after = getattr(trace[j + 1], reg) % 2**64 if j + 1 <= i else 0
                if v_before != v_after and 0 < v_after < 2**32:
                    target_reg = _identify_target_register(trace[i], trace[i + 1].rip)
                    if target_reg != reg:
                        hashes[trace[i].rip] = {
                            'hash': v_after,
                            'hash_reg': reg,
                            'target': trace[i + 1].rip,
                            'target_reg': target_reg,
                            'offset': trace[i].rip - kdata_base if kdata_base else 0,
                        }
                        break
            else:
                continue
            break

    if hashes:
        print('[cfi] extracted %d KCFI hashes:' % len(hashes))
        for rip, info in sorted(hashes.items()):
            print('  call at %#x -> %#x: hash=%#010x in %s' % (
                rip, info['target'], info['hash'], info['hash_reg']))

    return hashes


# =============================================================================
# Internal helpers
# =============================================================================

# Register names matching Trace.Frame field names
_REG_NAMES = ['rax', 'rcx', 'rdx', 'rbx', 'rbp', 'rsi', 'rdi',
              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def _identify_target_register(frame, callee_rip):
    """
    Determine which register held the indirect call target.

    Checks each general-purpose register against the callee RIP.
    Returns register name or None.
    """
    callee = callee_rip % 2**64
    for reg in _REG_NAMES:
        val = getattr(frame, reg, None)
        if val is not None and val % 2**64 == callee:
            return reg
    return None
