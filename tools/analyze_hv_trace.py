#!/usr/bin/env python3
"""
analyze_hv_trace.py - PS5 Hypervisor Timing Trace Analyzer

Parses binary output from the trace-based hv_research.c payload.
Identifies VMMCALL/hypercall instructions by their VMEXIT timing spike,
and extracts the full register state (ABI) at each site.

Usage:
    python3 analyze_hv_trace.py hv_trace_results.bin
    python3 analyze_hv_trace.py hv_trace_results.bin --threshold 3000
    python3 analyze_hv_trace.py hv_trace_results.bin --json
"""

import struct
import sys
import os
import argparse
from collections import defaultdict

ENTRY_SIZE = 8 * 18 + 4 + 4  # 18 uint64 + 2 uint32 = 152 bytes

# Trace entry flags (in the 'flags' field, formerly '_pad')
FLAG_NORMAL = 0         # Normal entry
FLAG_SCHED_SKIP = 1     # Scheduler was skipped before this instruction
                        # (TSC delta from previous entry is unreliable)

REG_NAMES = [
    "rip", "tsc", "rax", "rcx", "rdx", "rbx",
    "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "eflags"
]


def parse_trace_file(path):
    with open(path, "rb") as f:
        data = f.read()

    # Parse file header
    if len(data) < 32:
        print("ERROR: File too small")
        sys.exit(1)

    magic = data[0:8]
    if magic != b"HV_TIME\x00":
        print(f"ERROR: Bad magic: {magic!r}")
        sys.exit(1)

    version, fw_version, kdata_base, n_probes, threshold = struct.unpack_from(
        "<II Q II", data, 8)

    fw_major = (fw_version >> 24) & 0xFF
    fw_minor = (fw_version >> 16) & 0xFF

    header = {
        "version": version,
        "fw_version": fw_version,
        "fw_str": f"{fw_major:x}.{fw_minor:02x}",
        "kdata_base": kdata_base,
        "n_probes": n_probes,
        "threshold": threshold,
    }

    offset = 32  # after file header
    probes = []

    for p in range(n_probes):
        if offset + 40 > len(data):
            print(f"WARNING: Truncated at probe {p}")
            break

        name_bytes = data[offset:offset + 32]
        name = name_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
        n_entries, n_spikes = struct.unpack_from("<II", data, offset + 32)
        offset += 40

        entries = []
        for i in range(n_entries):
            if offset + ENTRY_SIZE > len(data):
                print(f"WARNING: Truncated at probe {p} entry {i}")
                break

            vals = struct.unpack_from("<18Q I I", data, offset)
            offset += ENTRY_SIZE

            entry = {
                "rip": vals[0],
                "tsc": vals[1],
                "rax": vals[2], "rcx": vals[3], "rdx": vals[4], "rbx": vals[5],
                "rsp": vals[6], "rbp": vals[7], "rsi": vals[8], "rdi": vals[9],
                "r8": vals[10], "r9": vals[11], "r10": vals[12], "r11": vals[13],
                "r12": vals[14], "r13": vals[15], "r14": vals[16], "r15": vals[17],
                "eflags": vals[18],
                "flags": vals[19],  # 0=normal, 1=post-scheduler-skip
            }
            entries.append(entry)

        probes.append({
            "name": name,
            "n_entries": len(entries),
            "n_spikes_reported": n_spikes,
            "entries": entries,
        })

    return header, probes


def find_spikes(entries, threshold):
    """Find timing spikes that indicate potential VMEXITs.

    Skips entries with FLAG_SCHED_SKIP set, as their TSC delta includes
    scheduler time and would cause false positives.
    """
    spikes = []
    for i in range(1, len(entries)):
        # Skip entries after scheduler skip - their TSC delta is unreliable
        if entries[i].get("flags", 0) == FLAG_SCHED_SKIP:
            continue

        delta = entries[i]["tsc"] - entries[i - 1]["tsc"]
        if delta > threshold:
            # The slow instruction was at entries[i-1]["rip"]
            # (it just finished executing, causing the spike)
            # entries[i] has the state AFTER that instruction
            spikes.append({
                "index": i - 1,
                "rip_before": entries[i - 1]["rip"],  # instruction that executed
                "rip_after": entries[i]["rip"],        # next instruction
                "delta_cycles": delta,
                "instr_size": entries[i]["rip"] - entries[i - 1]["rip"],
                "regs_before": entries[i - 1],
                "regs_after": entries[i],
            })
    return spikes


def compute_baseline(entries):
    """Compute baseline single-step overhead from the median timing.

    Excludes scheduler-skip entries which have inflated TSC deltas.
    """
    if len(entries) < 3:
        return 0
    deltas = []
    for i in range(1, len(entries)):
        # Skip scheduler-skip entries
        if entries[i].get("flags", 0) == FLAG_SCHED_SKIP:
            continue
        d = entries[i]["tsc"] - entries[i - 1]["tsc"]
        if d > 0:
            deltas.append(d)
    if not deltas:
        return 0
    deltas.sort()
    return deltas[len(deltas) // 2]  # median


def print_analysis(header, probes, threshold_override=None):
    threshold = threshold_override or header["threshold"]

    print("=" * 72)
    print("  PS5 Hypervisor Timing Trace Analysis")
    print("=" * 72)
    print(f"  Firmware:      {header['fw_str']}")
    print(f"  kdata_base:    0x{header['kdata_base']:016x}")
    print(f"  Probes:        {header['n_probes']}")
    print(f"  Threshold:     {threshold} cycles")
    print("=" * 72)

    all_spikes = []
    unique_rips = set()

    for probe in probes:
        entries = probe["entries"]
        if not entries:
            continue

        baseline = compute_baseline(entries)
        spikes = find_spikes(entries, threshold)
        sched_skips = sum(1 for e in entries if e.get("flags", 0) == FLAG_SCHED_SKIP)

        print(f"\n--- Probe: {probe['name']} ---")
        print(f"  Instructions traced: {len(entries)}")
        print(f"  Baseline overhead:   ~{baseline} cycles/step")
        print(f"  Scheduler skips:     {sched_skips}")
        print(f"  Timing spikes:       {len(spikes)}")

        for s in spikes:
            rip = s["rip_before"]
            kdata_base = header["kdata_base"]
            offset = rip - kdata_base
            sign = "-" if offset < 0 else "+"
            abs_off = abs(offset)

            # Check if this looks like a 3-byte instruction (VMMCALL/VMCALL)
            is_3byte = (s["instr_size"] == 3)
            tag = " [LIKELY VMMCALL - 3 bytes!]" if is_3byte else ""

            print(f"\n  SPIKE at kdata_base{sign}0x{abs_off:x}  "
                  f"(0x{rip:x})  delta={s['delta_cycles']} cycles  "
                  f"size={s['instr_size']}b{tag}")

            # Show register state BEFORE the instruction (= what was passed to HV)
            rb = s["regs_before"]
            print(f"    Registers BEFORE (passed to hypervisor):")
            print(f"      rax=0x{rb['rax']:016x}  rcx=0x{rb['rcx']:016x}  "
                  f"rdx=0x{rb['rdx']:016x}")
            print(f"      rdi=0x{rb['rdi']:016x}  rsi=0x{rb['rsi']:016x}  "
                  f"rbx=0x{rb['rbx']:016x}")
            print(f"      r8 =0x{rb['r8']:016x}  r9 =0x{rb['r9']:016x}  "
                  f"r10=0x{rb['r10']:016x}")

            # Show register changes (= what the hypervisor returned)
            ra = s["regs_after"]
            changes = []
            for reg in ["rax", "rcx", "rdx", "rbx", "rsi", "rdi",
                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
                if rb[reg] != ra[reg]:
                    changes.append(f"{reg}: 0x{rb[reg]:x} -> 0x{ra[reg]:x}")

            if changes:
                print(f"    Register CHANGES (hypervisor response):")
                for ch in changes:
                    print(f"      {ch}")
            else:
                print(f"    No register changes (HV returned same state)")

            all_spikes.append(s)
            unique_rips.add(rip)

    # Summary
    print(f"\n{'=' * 72}")
    print(f"  SUMMARY")
    print(f"{'=' * 72}")
    print(f"  Total timing spikes: {len(all_spikes)}")
    print(f"  Unique RIP addresses: {len(unique_rips)}")

    if unique_rips:
        print(f"\n  Unique hypercall candidate addresses:")
        kdata_base = header["kdata_base"]
        for rip in sorted(unique_rips):
            offset = rip - kdata_base
            sign = "-" if offset < 0 else "+"
            # Count how many times this RIP appeared
            count = sum(1 for s in all_spikes if s["rip_before"] == rip)
            avg_delta = sum(s["delta_cycles"] for s in all_spikes
                          if s["rip_before"] == rip) // count
            print(f"    kdata_base{sign}0x{abs(offset):x}  "
                  f"(seen {count}x, avg {avg_delta} cycles)")

    if not all_spikes:
        print("\n  No timing spikes detected. Possible reasons:")
        print("  - The traced code paths don't contain VMMCALL instructions")
        print("  - The threshold is too high (try --threshold with a lower value)")
        print("  - RDTSC is virtualized and hides VMEXIT latency")
        print("  - The hypervisor uses a different communication mechanism")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze PS5 hypervisor timing trace results")
    parser.add_argument("trace_file",
                        help="Binary trace file from hv_research.c")
    parser.add_argument("--threshold", type=int, default=None,
                        help="Override timing threshold (cycles)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--raw-deltas", action="store_true",
                        help="Print all timing deltas (for calibration)")
    args = parser.parse_args()

    if not os.path.exists(args.trace_file):
        print(f"ERROR: File not found: {args.trace_file}")
        sys.exit(1)

    header, probes = parse_trace_file(args.trace_file)

    if args.json:
        import json
        threshold = args.threshold or header["threshold"]
        output = {
            "header": {
                "fw_str": header["fw_str"],
                "kdata_base": f"0x{header['kdata_base']:x}",
                "threshold": threshold,
            },
            "probes": []
        }
        for probe in probes:
            spikes = find_spikes(probe["entries"], threshold)
            p = {
                "name": probe["name"],
                "n_instructions": len(probe["entries"]),
                "baseline_cycles": compute_baseline(probe["entries"]),
                "spikes": [{
                    "rip": f"0x{s['rip_before']:x}",
                    "offset": s["rip_before"] - header["kdata_base"],
                    "delta_cycles": s["delta_cycles"],
                    "instr_size": s["instr_size"],
                    "rax_before": f"0x{s['regs_before']['rax']:x}",
                    "rax_after": f"0x{s['regs_after']['rax']:x}",
                } for s in spikes]
            }
            output["probes"].append(p)
        print(json.dumps(output, indent=2))
        return

    if args.raw_deltas:
        print("Raw timing deltas per probe (for calibration):")
        print("(Scheduler-skip entries excluded)")
        for probe in probes:
            entries = probe["entries"]
            print(f"\n--- {probe['name']} ({len(entries)} entries) ---")
            deltas = []
            sched_skips = 0
            for i in range(1, len(entries)):
                if entries[i].get("flags", 0) == FLAG_SCHED_SKIP:
                    sched_skips += 1
                    continue
                d = entries[i]["tsc"] - entries[i - 1]["tsc"]
                deltas.append(d)
            if sched_skips:
                print(f"  Scheduler skips: {sched_skips} (excluded)")
            if deltas:
                deltas.sort()
                print(f"  Min:    {deltas[0]}")
                print(f"  Median: {deltas[len(deltas)//2]}")
                print(f"  P95:    {deltas[int(len(deltas)*0.95)]}")
                print(f"  P99:    {deltas[int(len(deltas)*0.99)]}")
                print(f"  Max:    {deltas[-1]}")
                # Histogram
                buckets = defaultdict(int)
                for d in deltas:
                    if d < 500:
                        buckets["<500"] += 1
                    elif d < 1000:
                        buckets["500-1k"] += 1
                    elif d < 2000:
                        buckets["1k-2k"] += 1
                    elif d < 5000:
                        buckets["2k-5k"] += 1
                    elif d < 10000:
                        buckets["5k-10k"] += 1
                    else:
                        buckets[">10k"] += 1
                print(f"  Distribution:")
                for bucket in ["<500", "500-1k", "1k-2k", "2k-5k", "5k-10k", ">10k"]:
                    count = buckets.get(bucket, 0)
                    pct = 100 * count / len(deltas) if deltas else 0
                    bar = "#" * int(pct / 2)
                    print(f"    {bucket:>8s}: {count:6d} ({pct:5.1f}%) {bar}")
        return

    print_analysis(header, probes, args.threshold)


if __name__ == "__main__":
    main()
