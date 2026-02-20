#!/usr/bin/env python3
"""
analyze_hv_scan.py - PS5 Hypervisor Scan Analyzer

Parses the binary output from hv_research.c and provides:
  1. List of all VMMCALL/VMCALL sites with kernel offsets
  2. Disassembly around each site (requires capstone)
  3. Register setup analysis (ABI identification)
  4. Optional raw kernel dump extraction

Usage:
    # Basic analysis (no dependencies needed):
    python3 analyze_hv_scan.py hv_scan_results.bin

    # Full disassembly analysis (requires: pip3 install capstone):
    python3 analyze_hv_scan.py hv_scan_results.bin --disasm

    # Extract raw kernel dump:
    python3 analyze_hv_scan.py hv_scan_results.bin --extract-dump kernel.bin

    # All options:
    python3 analyze_hv_scan.py hv_scan_results.bin --disasm --extract-dump kernel.bin
"""

import struct
import sys
import os
import argparse

# Instruction types
TYPE_VMMCALL = 1
TYPE_VMCALL = 2
TYPE_NAMES = {1: "VMMCALL", 2: "VMCALL"}

# AMD64 register names for ABI analysis
REG_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def parse_scan_file(path):
    """Parse the binary scan output from hv_research.c"""
    with open(path, "rb") as f:
        data = f.read()

    # Parse header
    if len(data) < 48:
        print("ERROR: File too small for header")
        sys.exit(1)

    magic = data[0:8]
    if magic != b"HV_SCAN\x00":
        print(f"ERROR: Bad magic: {magic!r} (expected HV_SCAN)")
        sys.exit(1)

    hdr = struct.unpack_from("<II QQQ III I", data, 8)
    version = hdr[0]
    fw_version = hdr[1]
    kdata_base = hdr[2]
    scan_start = hdr[3]
    scan_end = hdr[4]
    n_results = hdr[5]
    ctx_before = hdr[6]
    ctx_after = hdr[7]
    flags = hdr[8]

    # Decode firmware version
    fw_major = (fw_version >> 24) & 0xFF
    fw_minor = (fw_version >> 16) & 0xFF
    fw_str = f"{fw_major:x}.{fw_minor:02x}"

    header_info = {
        "version": version,
        "fw_version": fw_version,
        "fw_str": fw_str,
        "kdata_base": kdata_base,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "n_results": n_results,
        "ctx_before": ctx_before,
        "ctx_after": ctx_after,
        "has_dump": bool(flags & 1),
    }

    # Parse results
    results = []
    offset = 48  # after header

    for i in range(n_results):
        if offset + 12 > len(data):
            print(f"WARNING: Truncated at result {i}/{n_results}")
            break

        rtype, instr_len, padding, roffset = struct.unpack_from("<BBh q", data, offset)
        offset += 12

        ctx_size = ctx_before + instr_len + ctx_after
        if offset + ctx_size > len(data):
            print(f"WARNING: Truncated context at result {i}")
            break

        context = data[offset:offset + ctx_size]
        offset += ctx_size

        results.append({
            "type": rtype,
            "type_name": TYPE_NAMES.get(rtype, f"UNKNOWN({rtype})"),
            "instr_len": instr_len,
            "offset": roffset,
            "abs_addr": kdata_base + roffset,
            "context": context,
            "ctx_before": ctx_before,
            "ctx_after": ctx_after,
        })

    # Parse dump if present
    dump_data = None
    dump_start = None
    if header_info["has_dump"] and offset + 24 <= len(data):
        dump_magic = data[offset:offset + 8]
        if dump_magic[:5] == b"KDUMP":
            dump_start, dump_size = struct.unpack_from("<QQ", data, offset + 8)
            offset += 24
            if offset + dump_size <= len(data):
                dump_data = data[offset:offset + dump_size]
            else:
                print(f"WARNING: Dump truncated (have {len(data) - offset}, expected {dump_size})")
                dump_data = data[offset:]

    return header_info, results, dump_data, dump_start


def hex_dump_line(data, offset, width=16):
    """Format one line of hex dump"""
    hex_part = " ".join(f"{b:02x}" for b in data[:width])
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:width])
    return f"  {offset:04x}: {hex_part:<{width*3}}  {ascii_part}"


def print_basic_analysis(header, results):
    """Print basic scan results without disassembly"""
    print("=" * 70)
    print("  PS5 Hypervisor Instruction Scan Results")
    print("=" * 70)
    print(f"  Firmware:    {header['fw_str']}")
    print(f"  kdata_base:  0x{header['kdata_base']:016x}")
    print(f"  Scan range:  0x{header['scan_start']:016x} - 0x{header['scan_end']:016x}")
    print(f"  Results:     {header['n_results']}")
    print(f"  Raw dump:    {'yes' if header['has_dump'] else 'no'}")
    print("=" * 70)

    # Count by type
    vmmcall_count = sum(1 for r in results if r["type"] == TYPE_VMMCALL)
    vmcall_count = sum(1 for r in results if r["type"] == TYPE_VMCALL)
    print(f"\n  VMMCALL (AMD): {vmmcall_count}")
    print(f"  VMCALL (Intel): {vmcall_count}")
    print()

    # List each result
    for i, r in enumerate(results):
        sign = "-" if r["offset"] < 0 else "+"
        abs_off = abs(r["offset"])
        print(f"[{i:3d}] {r['type_name']:8s} at kdata_base{sign}0x{abs_off:x}"
              f"  (0x{r['abs_addr']:016x})")

        # Show hex context with the instruction highlighted
        ctx = r["context"]
        before = r["ctx_before"]
        ilen = r["instr_len"]

        # Show a few lines before and the instruction line
        show_before = 32  # bytes before to show
        show_after = 32   # bytes after to show
        start = max(0, before - show_before)
        end = min(len(ctx), before + ilen + show_after)
        region = ctx[start:end]

        # Mark the instruction bytes
        instr_offset = before - start
        hex_parts = []
        for j, b in enumerate(region):
            if instr_offset <= j < instr_offset + ilen:
                hex_parts.append(f"[{b:02x}]")
            else:
                hex_parts.append(f" {b:02x} ")
        print("    " + "".join(hex_parts))
        print()


def disassemble_context(results, header):
    """Disassemble around each hypercall site using Capstone"""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        print("\nERROR: capstone not installed. Install with: pip3 install capstone")
        print("Skipping disassembly analysis.\n")
        return

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print("\n" + "=" * 70)
    print("  Disassembly Analysis")
    print("=" * 70)

    for i, r in enumerate(results):
        ctx = r["context"]
        before = r["ctx_before"]
        ilen = r["instr_len"]

        # Disassemble starting from a reasonable point before the instruction
        # Start 64 bytes before, which should be enough to sync
        dis_start = max(0, before - 64)
        dis_data = ctx[dis_start:]
        dis_addr = r["abs_addr"] - (before - dis_start)

        sign = "-" if r["offset"] < 0 else "+"
        abs_off = abs(r["offset"])
        print(f"\n--- [{i}] {r['type_name']} at kdata_base{sign}0x{abs_off:x} ---")

        target_addr = r["abs_addr"]
        found_target = False

        # Collect instructions for ABI analysis
        pre_instructions = []

        for insn in md.disasm(dis_data, dis_addr):
            if insn.address > target_addr + 32:
                break

            # Mark the hypercall instruction
            marker = ">>>" if insn.address == target_addr else "   "
            hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
            print(f"  {marker} 0x{insn.address:x}:  {hex_bytes:<24s}  "
                  f"{insn.mnemonic} {insn.op_str}")

            if insn.address == target_addr:
                found_target = True
            elif insn.address < target_addr:
                pre_instructions.append(insn)

        if not found_target:
            print("  (instruction not aligned in disassembly stream)")

        # ABI analysis: look at register setup before the hypercall
        if pre_instructions:
            print(f"\n  Register setup (last 8 instructions before {r['type_name']}):")
            reg_state = {}
            for insn in pre_instructions[-8:]:
                mnem = insn.mnemonic
                ops = insn.op_str
                # Track MOV reg, imm patterns
                if mnem == "mov" and "," in ops:
                    parts = [p.strip() for p in ops.split(",", 1)]
                    dst = parts[0]
                    src = parts[1]
                    if dst in REG_NAMES or dst in [r[:3] for r in REG_NAMES]:
                        # Map 32-bit names to 64-bit
                        full_reg = dst
                        for rn in REG_NAMES:
                            if dst == rn or dst == "e" + rn[1:]:
                                full_reg = rn
                                break
                        reg_state[full_reg] = src
                elif mnem == "xor" and "," in ops:
                    parts = [p.strip() for p in ops.split(",", 1)]
                    if parts[0] == parts[1]:
                        reg_state[parts[0]] = "0"
                elif mnem == "lea" and "," in ops:
                    parts = [p.strip() for p in ops.split(",", 1)]
                    reg_state[parts[0]] = f"&({parts[1]})"

            if reg_state:
                for reg, val in sorted(reg_state.items()):
                    print(f"    {reg:5s} = {val}")
            else:
                print("    (no simple register setup detected)")

    print()


def extract_dump(dump_data, dump_start, output_path):
    """Extract the raw kernel dump to a file"""
    if dump_data is None:
        print("ERROR: No kernel dump in scan file")
        return

    with open(output_path, "wb") as f:
        f.write(dump_data)
    print(f"Kernel dump written to: {output_path}")
    print(f"  Start address: 0x{dump_start:016x}")
    print(f"  Size: {len(dump_data)} bytes ({len(dump_data) / 1024 / 1024:.1f} MB)")
    print(f"\nTo analyze with objdump:")
    print(f"  x86_64-linux-gnu-objdump -D -b binary -m i386:x86-64 {output_path}")
    print(f"\nTo search for patterns:")
    print(f"  python3 -c \"")
    print(f"    data = open('{output_path}', 'rb').read()")
    print(f"    # Find all VMMCALL (0f 01 d9)")
    print(f"    i = 0")
    print(f"    while True:")
    print(f"      i = data.find(b'\\x0f\\x01\\xd9', i)")
    print(f"      if i == -1: break")
    print(f"      print(f'VMMCALL at dump+0x{{i:x}} = kernel 0x{{0x{dump_start:x}+i:x}}')")
    print(f"      i += 1")
    print(f"  \"")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze PS5 hypervisor scan results from hv_research.c")
    parser.add_argument("scan_file", help="Path to the binary scan results file")
    parser.add_argument("--disasm", action="store_true",
                        help="Disassemble around each hypercall (requires capstone)")
    parser.add_argument("--extract-dump", metavar="OUTPUT",
                        help="Extract raw kernel dump to file")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON for further processing")
    args = parser.parse_args()

    if not os.path.exists(args.scan_file):
        print(f"ERROR: File not found: {args.scan_file}")
        sys.exit(1)

    header, results, dump_data, dump_start = parse_scan_file(args.scan_file)

    if args.json:
        import json
        output = {
            "header": {k: v for k, v in header.items()},
            "results": [{
                "type": r["type_name"],
                "offset": r["offset"],
                "abs_addr": f"0x{r['abs_addr']:x}",
                "context_hex": r["context"].hex(),
            } for r in results],
        }
        # Make header values JSON-serializable
        output["header"]["kdata_base"] = f"0x{header['kdata_base']:x}"
        output["header"]["scan_start"] = f"0x{header['scan_start']:x}"
        output["header"]["scan_end"] = f"0x{header['scan_end']:x}"
        print(json.dumps(output, indent=2))
        return

    # Always print basic analysis
    print_basic_analysis(header, results)

    # Disassembly if requested
    if args.disasm:
        disassemble_context(results, header)

    # Extract dump if requested
    if args.extract_dump:
        extract_dump(dump_data, dump_start, args.extract_dump)

    # Summary advice
    if results and not args.disasm:
        print("\nTip: Run with --disasm for instruction-level analysis")
        print("     (requires: pip3 install capstone)")
    if header["has_dump"] and not args.extract_dump:
        print("\nTip: Run with --extract-dump kernel.bin to save the raw kernel dump")


if __name__ == "__main__":
    main()
