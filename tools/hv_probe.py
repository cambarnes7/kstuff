#!/usr/bin/env python3
"""
PS5 Hypervisor Probe Controller (PC-side)

Connects to the PS5-side probe server over TCP and drives MSR/CR
probing with automatic checkpointing and panic recovery.

Usage:
    python3 hv_probe.py <ps5_ip> [--port 9020] [--resume checkpoint.json]

The PS5 must be running the probe server (loaded via kstuff-ldr or
a separate ELF that calls the kekcall interface).

Protocol (binary, little-endian):
    Request:  [cmd:u8] [arg1:u64] [arg2:u64]
    Response: [status:u8] [value:u64]

    Commands:
        0x01 = MSR read   (arg1=msr)
        0x02 = MSR write  (arg1=msr, arg2=value)
        0x03 = MSR write+readback (arg1=msr, arg2=value)
        0x04 = CR read    (arg1=cr_num)
        0x05 = CR write+readback (arg1=cr_num, arg2=value)
        0xFF = Ping

    Status:
        0x00 = success (value field valid)
        0x01 = #GP / blocked
        0x02 = error
"""

import argparse
import json
import os
import socket
import struct
import sys
import time

CMD_MSR_READ       = 0x01
CMD_MSR_WRITE      = 0x02
CMD_MSR_WRITE_RB   = 0x03
CMD_CR_READ        = 0x04
CMD_CR_WRITE_RB    = 0x05
CMD_PING           = 0xFF

STATUS_OK      = 0x00
STATUS_GP      = 0x01
STATUS_ERROR   = 0x02

REQ_FMT  = "<BQQ"   # cmd(1) + arg1(8) + arg2(8) = 17 bytes
RESP_FMT = "<BQ"     # status(1) + value(8) = 9 bytes

# AMD MSR ranges of interest
MSR_RANGES = [
    # (name, start, end_exclusive)
    ("Architectural",        0x00000000, 0x00000400),
    ("MTRR/PAT",             0x00000200, 0x00000280),
    ("x2APIC",               0x00000800, 0x00000840),
    ("AMD Extended",         0xC0000000, 0xC0000200),
    ("AMD SVM",              0xC0010000, 0xC0010200),
]

# High-priority MSRs to probe first (safe reads)
PRIORITY_MSRS = [
    (0xC0000101, "GS_BASE (kernel uses this — baseline)"),
    (0xC0000080, "EFER (SVM enable bit 12)"),
    (0x0000001B, "APIC_BASE"),
    (0x00000277, "PAT"),
    (0xC0000082, "LSTAR (syscall entry)"),
    (0xC0000081, "STAR"),
    (0xC0000084, "SYSCALL_MASK"),
    (0xC0010114, "VM_CR (SVM lock — may cause HV termination)"),
    (0xC0010117, "VM_HSAVE_PA (HV save area phys addr — HIGH VALUE TARGET)"),
    (0xC0010058, "MMIO_CFG_BASE (PCI config space)"),
    (0xC0010010, "SYSCFG"),
    (0xC001001A, "TOP_MEM"),
    (0xC001001D, "TOP_MEM2"),
]


class Checkpoint:
    def __init__(self, path):
        self.path = path
        self.data = {"msr_reads": {}, "msr_writes": {}, "cr_reads": {},
                     "cr_writes": {}, "panicked_on": [], "metadata": {}}
        if path and os.path.exists(path):
            with open(path) as f:
                self.data = json.load(f)
            print(f"[*] Resumed from checkpoint: {len(self.data['msr_reads'])} MSR reads, "
                  f"{len(self.data['panicked_on'])} panics recorded")

    def save(self):
        if self.path:
            with open(self.path, "w") as f:
                json.dump(self.data, f, indent=2)

    def has_msr_read(self, msr):
        return hex(msr) in self.data["msr_reads"]

    def add_msr_read(self, msr, status, value):
        self.data["msr_reads"][hex(msr)] = {"status": status, "value": hex(value)}
        self.save()

    def add_msr_write(self, msr, written, readback, status):
        self.data["msr_writes"][hex(msr)] = {
            "written": hex(written), "readback": hex(readback), "status": status}
        self.save()

    def add_cr_read(self, cr, value):
        self.data["cr_reads"][str(cr)] = hex(value)
        self.save()

    def add_cr_write(self, cr, written, readback):
        self.data["cr_writes"][str(cr)] = {
            "written": hex(written), "readback": hex(readback)}
        self.save()

    def add_panic(self, operation, detail):
        self.data["panicked_on"].append({"op": operation, "detail": detail,
                                         "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.save()

    def is_blacklisted(self, operation, detail):
        for p in self.data["panicked_on"]:
            if p["op"] == operation and p["detail"] == detail:
                return True
        return False


class ProbeConnection:
    def __init__(self, host, port, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send_recv(self, cmd, arg1=0, arg2=0):
        req = struct.pack(REQ_FMT, cmd, arg1, arg2)
        self.sock.sendall(req)
        resp = b""
        while len(resp) < struct.calcsize(RESP_FMT):
            chunk = self.sock.recv(struct.calcsize(RESP_FMT) - len(resp))
            if not chunk:
                raise ConnectionError("Connection lost")
            resp += chunk
        status, value = struct.unpack(RESP_FMT, resp)
        return status, value

    def ping(self):
        status, _ = self._send_recv(CMD_PING)
        return status == STATUS_OK

    def msr_read(self, msr):
        return self._send_recv(CMD_MSR_READ, msr)

    def msr_write(self, msr, value):
        return self._send_recv(CMD_MSR_WRITE, msr, value)

    def msr_write_readback(self, msr, value):
        return self._send_recv(CMD_MSR_WRITE_RB, msr, value)

    def cr_read(self, cr_num):
        return self._send_recv(CMD_CR_READ, cr_num)

    def cr_write_readback(self, cr_num, value):
        return self._send_recv(CMD_CR_WRITE_RB, cr_num, value)


def wait_for_connection(host, port, checkpoint):
    """Wait for PS5 to come back online after a panic/reboot."""
    print("[*] Waiting for PS5 to come back online...")
    while True:
        try:
            conn = ProbeConnection(host, port, timeout=3.0)
            conn.connect()
            if conn.ping():
                print("[+] PS5 is back online")
                return conn
            conn.close()
        except (ConnectionRefusedError, ConnectionError, socket.timeout, OSError):
            pass
        time.sleep(2)


def phase1_priority_msrs(conn, checkpoint):
    """Phase 1: Read high-priority MSRs to establish baseline."""
    print("\n" + "="*60)
    print("PHASE 1: Priority MSR Reads (Behavioral Classification)")
    print("="*60)

    results = []
    for msr, desc in PRIORITY_MSRS:
        if checkpoint.has_msr_read(msr):
            print(f"  [skip] 0x{msr:08X} {desc} (already probed)")
            continue
        if checkpoint.is_blacklisted("msr_read", hex(msr)):
            print(f"  [SKIP] 0x{msr:08X} {desc} (previously caused panic)")
            continue

        try:
            status, value = conn.msr_read(msr)
            if status == STATUS_OK:
                print(f"  [OK]   0x{msr:08X} = 0x{value:016X}  {desc}")
                checkpoint.add_msr_read(msr, "ok", value)
            elif status == STATUS_GP:
                print(f"  [#GP]  0x{msr:08X}  BLOCKED            {desc}")
                checkpoint.add_msr_read(msr, "gp", 0)
            else:
                print(f"  [ERR]  0x{msr:08X}  status={status}    {desc}")
                checkpoint.add_msr_read(msr, "error", 0)
            results.append((msr, desc, status, value if status == STATUS_OK else 0))
        except (ConnectionError, socket.timeout):
            print(f"  [PANIC] 0x{msr:08X} {desc} — connection lost!")
            checkpoint.add_panic("msr_read", hex(msr))
            return None  # signal panic

    return results


def phase2_msr_sweep(conn, checkpoint, msr_start, msr_end):
    """Phase 2: Sweep an MSR range."""
    print(f"\n  Scanning MSR range 0x{msr_start:08X} - 0x{msr_end:08X}...")
    accessible = 0
    blocked = 0

    for msr in range(msr_start, msr_end):
        if checkpoint.has_msr_read(msr):
            continue
        if checkpoint.is_blacklisted("msr_read", hex(msr)):
            continue

        try:
            status, value = conn.msr_read(msr)
            if status == STATUS_OK:
                print(f"    [OK]  0x{msr:08X} = 0x{value:016X}")
                checkpoint.add_msr_read(msr, "ok", value)
                accessible += 1
            elif status == STATUS_GP:
                checkpoint.add_msr_read(msr, "gp", 0)
                blocked += 1
            else:
                checkpoint.add_msr_read(msr, "error", 0)
        except (ConnectionError, socket.timeout):
            print(f"    [PANIC] 0x{msr:08X} — connection lost!")
            checkpoint.add_panic("msr_read", hex(msr))
            return None  # signal panic

    print(f"  Range complete: {accessible} accessible, {blocked} blocked")
    return accessible


def phase3_cr_analysis(conn, checkpoint):
    """Phase 3: Read and probe control registers."""
    print("\n" + "="*60)
    print("PHASE 3: Control Register Analysis")
    print("="*60)

    # Read CR0
    try:
        status, value = conn.cr_read(0)
        if status == STATUS_OK:
            print(f"  CR0 = 0x{value:016X}")
            checkpoint.add_cr_read(0, value)
            print(f"    PE={value&1} MP={(value>>1)&1} EM={(value>>2)&1} "
                  f"TS={(value>>3)&1} ET={(value>>4)&1}")
            print(f"    NE={(value>>5)&1} WP={(value>>16)&1} AM={(value>>18)&1} "
                  f"NW={(value>>29)&1} CD={(value>>30)&1} PG={(value>>31)&1}")

            # Try toggling WP bit (Write Protect) — safest bit to test
            cr0_no_wp = value & ~(1 << 16)
            if cr0_no_wp != value:
                print(f"\n  Testing CR0 WP bit toggle (0x{value:X} -> 0x{cr0_no_wp:X})...")
                status2, readback = conn.cr_write_readback(0, cr0_no_wp)
                if status2 == STATUS_OK:
                    if readback == cr0_no_wp:
                        print(f"    WP clear SUCCEEDED — readback 0x{readback:016X}")
                    else:
                        print(f"    WP clear FILTERED by HV — wrote 0x{cr0_no_wp:X}, "
                              f"got back 0x{readback:016X}")
                    checkpoint.add_cr_write(0, cr0_no_wp, readback)
                    # Restore original value
                    conn.cr_write_readback(0, value)
                else:
                    print(f"    WP clear BLOCKED (status={status2})")
    except (ConnectionError, socket.timeout):
        print("  [PANIC] CR0 probe — connection lost!")
        checkpoint.add_panic("cr_read", "cr0")
        return None

    return True


def print_summary(checkpoint):
    """Print a summary of all findings."""
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    reads = checkpoint.data["msr_reads"]
    ok_msrs = {k: v for k, v in reads.items() if v["status"] == "ok"}
    gp_msrs = {k: v for k, v in reads.items() if v["status"] == "gp"}

    print(f"\nMSR reads: {len(ok_msrs)} accessible, {len(gp_msrs)} blocked")
    print(f"Panics: {len(checkpoint.data['panicked_on'])}")

    if ok_msrs:
        print("\nAccessible MSRs:")
        for msr_hex, info in sorted(ok_msrs.items(), key=lambda x: int(x[0], 16)):
            desc = ""
            for m, d in PRIORITY_MSRS:
                if hex(m) == msr_hex:
                    desc = f"  ({d})"
                    break
            print(f"  {msr_hex} = {info['value']}{desc}")

    if checkpoint.data["panicked_on"]:
        print("\nOperations that caused panics:")
        for p in checkpoint.data["panicked_on"]:
            print(f"  {p['op']} {p['detail']} at {p['time']}")

    cr_reads = checkpoint.data["cr_reads"]
    if cr_reads:
        print("\nControl Registers:")
        for cr, val in cr_reads.items():
            print(f"  CR{cr} = {val}")


def main():
    parser = argparse.ArgumentParser(description="PS5 Hypervisor Probe Controller")
    parser.add_argument("ps5_ip", help="IP address of the PS5")
    parser.add_argument("--port", type=int, default=9020, help="Probe server port (default: 9020)")
    parser.add_argument("--resume", default="hv_probe_checkpoint.json",
                        help="Checkpoint file (default: hv_probe_checkpoint.json)")
    parser.add_argument("--phase", type=int, default=0,
                        help="Run specific phase only (1-3, 0=all)")
    args = parser.parse_args()

    checkpoint = Checkpoint(args.resume)

    print(f"[*] Connecting to PS5 at {args.ps5_ip}:{args.port}...")
    conn = wait_for_connection(args.ps5_ip, args.port, checkpoint)

    run_all = args.phase == 0

    # Phase 1: Priority MSR reads
    if run_all or args.phase == 1:
        result = phase1_priority_msrs(conn, checkpoint)
        if result is None:
            conn = wait_for_connection(args.ps5_ip, args.port, checkpoint)
            # Retry once after reconnect
            phase1_priority_msrs(conn, checkpoint)

    # Phase 2: MSR range sweep
    if run_all or args.phase == 2:
        print("\n" + "="*60)
        print("PHASE 2: MSR Range Sweep")
        print("="*60)
        for name, start, end in MSR_RANGES:
            print(f"\n  [{name}]")
            result = phase2_msr_sweep(conn, checkpoint, start, end)
            if result is None:
                conn = wait_for_connection(args.ps5_ip, args.port, checkpoint)

    # Phase 3: CR analysis
    if run_all or args.phase == 3:
        result = phase3_cr_analysis(conn, checkpoint)
        if result is None:
            conn = wait_for_connection(args.ps5_ip, args.port, checkpoint)
            phase3_cr_analysis(conn, checkpoint)

    print_summary(checkpoint)
    conn.close()


if __name__ == "__main__":
    main()
