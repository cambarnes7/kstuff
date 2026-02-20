/*
 * hv_research.c - PS5 Hypervisor Research Payload
 *
 * Steps 1 & 3: Scan kernel text for VMMCALL/VMCALL instructions,
 * dump surrounding context bytes for ABI analysis.
 *
 * This payload replaces ps5-kstuff's main.c for research purposes.
 * It initializes r0gdb for kernel R/W, then scans the kernel text
 * section for hypervisor call instructions and sends results to a
 * TCP listener on your Mac.
 *
 * Usage:
 *   1. Set LISTENER_IP to your Mac's IP address
 *   2. Build with: make payload-hv.bin
 *   3. Copy payload-hv.bin to payload.bin
 *   4. Build kstuff-ldr: cd ../ps5-kstuff-ldr && make clean && make
 *   5. On Mac: nc -l 9999 > hv_scan_results.bin
 *   6. Load kstuff.elf on PS5
 *   7. Analyze with: python3 tools/analyze_hv_scan.py hv_scan_results.bin
 */

#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"

/* ================================================================
 * CONFIGURATION - Edit these before building
 * ================================================================ */

/* Your Mac's IP address on the local network */
#define LISTENER_IP   "192.168.1.100"

/* TCP port your Mac is listening on (nc -l 9999) */
#define LISTENER_PORT 9999

/* How far back from kdata_base to scan (bytes).
 * 12MB covers all kernel text for FW 3.00-10.01.
 * Increase if your firmware has larger kernel text. */
#define SCAN_RANGE    (12 * 1024 * 1024)

/* Bytes of context to capture around each found instruction */
#define CONTEXT_BEFORE 96
#define CONTEXT_AFTER  96

/* Set to 1 to also dump raw kernel text after scanning.
 * This enables deeper offline analysis with Capstone.
 * Warning: dumps ~10MB over the network. */
#define DUMP_RAW_KERNEL 1

/* ================================================================ */

extern uint64_t kdata_base;

/* ---- PS5 notification (shows on screen) ---- */
static void notify(const char* s)
{
    struct {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while((*d++ = *s++));
    int fd = open("/dev/notification0", 1);
    if(fd >= 0)
    {
        write(fd, &notification, 0xc30);
        close(fd);
    }
}

/* ---- Minimal formatting helpers (no libc) ---- */

static const char hextab[] = "0123456789abcdef";

static void fmt_hex8(char* buf, uint8_t v)
{
    buf[0] = hextab[v >> 4];
    buf[1] = hextab[v & 0xf];
}

static void fmt_hex64(char* buf, uint64_t v)
{
    for(int i = 15; i >= 0; i--)
    {
        buf[i] = hextab[v & 0xf];
        v >>= 4;
    }
}

static int fmt_int(char* buf, int v)
{
    if(v == 0)
    {
        buf[0] = '0';
        return 1;
    }
    char tmp[12];
    int n = 0;
    int neg = 0;
    if(v < 0) { neg = 1; v = -v; }
    while(v > 0)
    {
        tmp[n++] = '0' + (v % 10);
        v /= 10;
    }
    int pos = 0;
    if(neg) buf[pos++] = '-';
    for(int i = n - 1; i >= 0; i--)
        buf[pos++] = tmp[i];
    return pos;
}

static int my_strlen(const char* s)
{
    int n = 0;
    while(s[n]) n++;
    return n;
}

static void my_memset(void* dst, int c, size_t n)
{
    char* d = dst;
    while(n--) *d++ = (char)c;
}

/* ---- Protocol: binary output format ---- */

/*
 * Output format (binary, sent over TCP):
 *
 * Header (fixed):
 *   magic:      "HV_SCAN\x00"          (8 bytes)
 *   version:    uint32_t = 1            (4 bytes)
 *   fw_version: uint32_t               (4 bytes)
 *   kdata_base: uint64_t               (8 bytes)
 *   scan_start: uint64_t               (8 bytes)
 *   scan_end:   uint64_t               (8 bytes)
 *   n_results:  uint32_t               (4 bytes)
 *   ctx_before: uint32_t               (4 bytes)
 *   ctx_after:  uint32_t               (4 bytes)
 *   flags:      uint32_t               (4 bytes) bit0=has_raw_dump
 *
 * For each result:
 *   type:       uint8_t                (1 byte: 1=VMMCALL, 2=VMCALL)
 *   instr_len:  uint8_t                (1 byte: length of the instruction)
 *   padding:    uint16_t               (2 bytes)
 *   offset:     int64_t                (8 bytes: offset from kdata_base)
 *   context:    uint8_t[ctx_before + instr_len + ctx_after]
 *
 * If DUMP_RAW_KERNEL:
 *   dump_magic: "KDUMP\x00\x00\x00"   (8 bytes)
 *   dump_start: uint64_t               (8 bytes: kernel address of dump start)
 *   dump_size:  uint64_t               (8 bytes: total dump size)
 *   data:       uint8_t[dump_size]     (raw kernel text)
 */

#pragma pack(push, 1)
struct scan_header {
    char magic[8];
    uint32_t version;
    uint32_t fw_version;
    uint64_t kdata_base;
    uint64_t scan_start;
    uint64_t scan_end;
    uint32_t n_results;
    uint32_t ctx_before;
    uint32_t ctx_after;
    uint32_t flags;
};

struct scan_result {
    uint8_t type;       /* 1=VMMCALL, 2=VMCALL */
    uint8_t instr_len;  /* 3 for VMMCALL/VMCALL */
    uint16_t padding;
    int64_t offset;     /* offset from kdata_base (negative = text) */
};

struct dump_header {
    char magic[8];
    uint64_t dump_start;
    uint64_t dump_size;
};
#pragma pack(pop)

/* ---- Scan buffer ---- */
#define CHUNK_SIZE 4096
#define MAX_RESULTS 4096

static struct scan_result results[MAX_RESULTS];
static int n_results = 0;

/* context storage: each result gets CONTEXT_BEFORE + 3 + CONTEXT_AFTER bytes */
#define CTX_SIZE (CONTEXT_BEFORE + 3 + CONTEXT_AFTER)
/* We store context in a flat buffer indexed by result number */
static uint8_t ctx_storage[MAX_RESULTS * CTX_SIZE];

static void record_result(uint8_t type, uint64_t addr, uint64_t kbase)
{
    if(n_results >= MAX_RESULTS)
        return;

    struct scan_result* r = &results[n_results];
    r->type = type;
    r->instr_len = 3;
    r->padding = 0;
    r->offset = (int64_t)(addr - kbase);

    /* Read context bytes around the instruction */
    uint8_t* ctx = &ctx_storage[n_results * CTX_SIZE];
    my_memset(ctx, 0xcc, CTX_SIZE); /* fill with INT3 as sentinel */

    uint64_t ctx_start = addr - CONTEXT_BEFORE;
    copyout(ctx, ctx_start, CTX_SIZE);

    n_results++;
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    /* Initialize kernel R/W */
    if(r0gdb_init(ds, a, b, c, d))
    {
        notify("HV Research: FW not supported");
        return 1;
    }

    notify("HV Research: Connecting...");

    /* Get firmware version */
    uint32_t fw_version = r0gdb_get_fw_version();

    /* Open TCP connection to listener */
    int sock = r0gdb_open_socket(LISTENER_IP, LISTENER_PORT);
    if(sock < 0)
    {
        notify("HV Research: Connect failed!");
        return 1;
    }

    notify("HV Research: Scanning kernel...");

    /* Scan kernel text for VMMCALL/VMCALL */
    uint64_t scan_start = kdata_base - SCAN_RANGE;
    uint64_t scan_end = kdata_base;

    uint8_t* buf = mmap(0, CHUNK_SIZE, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANON, -1, 0);
    if(buf == MAP_FAILED)
    {
        notify("HV Research: mmap failed!");
        close(sock);
        return 1;
    }

    int chunks_ok = 0;
    int chunks_fail = 0;

    for(uint64_t addr = scan_start; addr < scan_end; addr += CHUNK_SIZE)
    {
        ssize_t n = copyout(buf, addr, CHUNK_SIZE);
        if(n != CHUNK_SIZE)
        {
            chunks_fail++;
            continue;
        }
        chunks_ok++;

        /* Scan this chunk for target instructions */
        for(int i = 0; i < CHUNK_SIZE - 2; i++)
        {
            /* VMMCALL: 0f 01 d9 (AMD hypercall) */
            if(buf[i] == 0x0f && buf[i+1] == 0x01 && buf[i+2] == 0xd9)
            {
                record_result(1, addr + i, kdata_base);
            }
            /* VMCALL: 0f 01 c1 (Intel hypercall) */
            else if(buf[i] == 0x0f && buf[i+1] == 0x01 && buf[i+2] == 0xc1)
            {
                record_result(2, addr + i, kdata_base);
            }
        }
    }

    /* Send header */
    struct scan_header hdr;
    hdr.magic[0] = 'H'; hdr.magic[1] = 'V'; hdr.magic[2] = '_';
    hdr.magic[3] = 'S'; hdr.magic[4] = 'C'; hdr.magic[5] = 'A';
    hdr.magic[6] = 'N'; hdr.magic[7] = 0;
    hdr.version = 1;
    hdr.fw_version = fw_version;
    hdr.kdata_base = kdata_base;
    hdr.scan_start = scan_start;
    hdr.scan_end = scan_end;
    hdr.n_results = n_results;
    hdr.ctx_before = CONTEXT_BEFORE;
    hdr.ctx_after = CONTEXT_AFTER;
    hdr.flags = DUMP_RAW_KERNEL ? 1 : 0;

    r0gdb_sendall(sock, &hdr, sizeof(hdr));

    /* Send each result + its context */
    for(int i = 0; i < n_results; i++)
    {
        r0gdb_sendall(sock, &results[i], sizeof(struct scan_result));
        r0gdb_sendall(sock, &ctx_storage[i * CTX_SIZE], CTX_SIZE);
    }

#if DUMP_RAW_KERNEL
    /* Dump raw kernel text */
    notify("HV Research: Dumping kernel...");

    struct dump_header dhdr;
    dhdr.magic[0] = 'K'; dhdr.magic[1] = 'D'; dhdr.magic[2] = 'U';
    dhdr.magic[3] = 'M'; dhdr.magic[4] = 'P'; dhdr.magic[5] = 0;
    dhdr.magic[6] = 0;   dhdr.magic[7] = 0;
    dhdr.dump_start = scan_start;
    dhdr.dump_size = scan_end - scan_start;

    r0gdb_sendall(sock, &dhdr, sizeof(dhdr));

    /* Send in chunks, zero-fill unmapped pages */
    uint8_t zeros[CHUNK_SIZE];
    my_memset(zeros, 0, CHUNK_SIZE);

    for(uint64_t addr = scan_start; addr < scan_end; addr += CHUNK_SIZE)
    {
        ssize_t n = copyout(buf, addr, CHUNK_SIZE);
        if(n != CHUNK_SIZE)
            r0gdb_sendall(sock, zeros, CHUNK_SIZE);
        else
            r0gdb_sendall(sock, buf, CHUNK_SIZE);
    }
#endif

    close(sock);
    munmap(buf, CHUNK_SIZE);

    /* Show summary notification */
    {
        char msg[128];
        char* p = msg;
        const char* s = "HV Scan: ";
        while(*s) *p++ = *s++;
        p += fmt_int(p, n_results);
        s = " hypercalls found";
        while(*s) *p++ = *s++;
        *p = 0;
        notify(msg);
    }

    return 1; /* return non-zero to skip kstuff app.db patching */
}
