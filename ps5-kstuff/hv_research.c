/*
 * hv_research.c - PS5 Hypervisor Research Payload (Trace-Based)
 *
 * Detects VMMCALL/VMCALL instructions by timing kernel execution
 * via r0gdb's single-step trace infrastructure. Each kernel instruction
 * is executed one at a time; VMMCALL causes a VMEXIT (~1000+ cycles)
 * which shows up as a timing spike vs normal instructions (~1-10 cycles).
 *
 * This approach does NOT read kernel text (which would panic due to
 * hypervisor execute-only enforcement on kernel text pages).
 * Instead it executes code paths and observes the timing + register state.
 *
 * Combined Steps 1-3:
 *   Step 1: Finds hypercall sites by their VMEXIT timing signature
 *   Step 2: Measures exact cycle cost of each hypercall
 *   Step 3: Captures full register state = the ABI
 *
 * Usage:
 *   1. Set LISTENER_IP to your Mac's IP address
 *   2. Build: cd ps5-kstuff && make payload-hv.bin
 *   3. Swap:  cp payload-hv.bin payload.bin
 *   4. Build: cd ../ps5-kstuff-ldr && make clean && make
 *   5. Mac:   nc -l 9999 > hv_trace_results.bin
 *   6. Load kstuff.elf on PS5
 *   7. Mac:   python3 tools/analyze_hv_trace.py hv_trace_results.bin
 */

#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"

/* ================================================================
 * CONFIGURATION - Edit before building
 * ================================================================ */

#define LISTENER_IP   "192.168.0.99"
#define LISTENER_PORT 9999

/* Timing threshold: instructions taking more than this many cycles
 * above baseline are flagged as potential hypercalls.
 * VMEXIT typically costs 1000-5000 cycles. Single-step overhead is
 * ~300-1000 cycles. Set threshold to catch VMEXITs but not noise. */
#define TIMING_THRESHOLD 2000

/* Max instructions to trace per syscall/function call */
#define MAX_TRACE_INSTRS (512 * 1024)

/* ================================================================ */

extern uint64_t kdata_base;
extern uint64_t iret;
extern uint64_t kstack;
extern void kmemcpy(void* dst, const void* src, size_t sz);

/* ---- PS5 notification ---- */
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

/* ---- Formatting helpers ---- */
static int fmt_int(char* buf, int v)
{
    if(v == 0) { buf[0] = '0'; return 1; }
    char tmp[12];
    int n = 0, neg = 0;
    if(v < 0) { neg = 1; v = -v; }
    while(v > 0) { tmp[n++] = '0' + (v % 10); v /= 10; }
    int pos = 0;
    if(neg) buf[pos++] = '-';
    for(int i = n - 1; i >= 0; i--) buf[pos++] = tmp[i];
    return pos;
}

/* ---- Timing trace data structures ---- */

/*
 * Each traced instruction produces one entry.
 * We capture RIP, RDTSC, and all registers for ABI analysis.
 *
 * The _pad field doubles as flags:
 *   0 = normal entry
 *   1 = scheduler was skipped before this instruction (TSC delta unreliable)
 */
#pragma pack(push, 1)
struct trace_entry {
    uint64_t rip;
    uint64_t tsc;
    uint64_t rax, rcx, rdx, rbx;
    uint64_t rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint32_t eflags;
    uint32_t flags;     /* 0=normal, 1=post-scheduler-skip */
};

/* File header */
struct trace_file_header {
    char     magic[8];       /* "HV_TIME\0" */
    uint32_t version;        /* 1 */
    uint32_t fw_version;
    uint64_t kdata_base;
    uint32_t n_probes;       /* number of probe sections */
    uint32_t threshold;      /* timing threshold used */
};

/* Per-probe header (one per triggered syscall/function) */
struct probe_header {
    char     name[32];       /* description of what was traced */
    uint32_t n_entries;      /* number of trace entries */
    uint32_t n_spikes;       /* number of timing spikes detected */
};
#pragma pack(pop)

/* ---- Global trace state ---- */
static struct trace_entry* g_trace_buf;
static volatile int g_trace_count;
static volatile int g_trace_max;
static volatile int g_in_kernel;
static volatile int g_scheduler_skip;

/* Saved uretframe contents for set_trace reimplementation */
static uint64_t saved_uretframe[5];

/* ---- Scheduler skip (reimplements static untrace_fn from r0gdb.c) ---- */
/*
 * When we hit cpu_switch (scheduler context switch), we skip over it
 * by clearing TF temporarily. The iret frame on the kernel stack
 * re-enables TF via the saved eflags after the scheduler returns.
 * This avoids tracing scheduler internals while keeping the trace
 * going for our target syscall.
 */
static void my_untrace(uint64_t* regs)
{
    g_scheduler_skip = 1;
    uint64_t rsp = regs[3];
    uint64_t ret_gadget = offsets.nop_ret;
    /* Build iret frame: {iret_addr, nop_ret, CS=0x20, eflags(with TF), rsp, SS=0}
     * After scheduler returns and hits this frame, TF is restored */
    uint64_t frame[6] = {iret, ret_gadget, 0x20, regs[2], rsp, 0};
    rsp -= 0x30;
    kmemcpy((void*)rsp, frame, 48);
    regs[3] = rsp;
    regs[2] &= -257; /* clear TF so scheduler runs untraced */
}

/*
 * Custom trace_prog: called on every single-stepped instruction.
 * Captures RIP + RDTSC + all registers for kernel instructions only.
 *
 * Key design:
 * - Only records kernel-mode instructions (CS == 0x20)
 * - Clears TF when kernel returns to userland, stopping the trace
 * - Marks entries after scheduler skips (unreliable TSC deltas)
 *
 * regs layout (from r0run.asm / trap_state.h):
 *   [0]=rip [1]=cs [2]=eflags [3]=rsp [4]=ss
 *   [5]=rax [6]=rcx [7]=rdx [8]=rbx [9]=---
 *   [10]=rbp [11]=rsi [12]=rdi [13]=r8 [14]=r9
 *   [15]=r10 [16]=r11 [17]=r12 [18]=r13 [19]=r14 [20]=r15
 */
static void timing_trace_prog(uint64_t* regs)
{
    /* Skip scheduler to avoid tracing context switch internals */
    if(regs[0] == offsets.cpu_switch)
    {
        my_untrace(regs);
        return;
    }

    int is_kernel = (regs[1] == 0x20);

    if(!is_kernel)
    {
        if(g_in_kernel)
        {
            /* Transition from kernel to userland = syscall returned.
             * Clear TF to stop tracing. */
            regs[2] &= ~((uint64_t)256);
            return;
        }
        /* Still in userland before syscall - keep TF set but don't record */
        return;
    }

    /* We're in kernel mode - mark that we've entered the kernel */
    g_in_kernel = 1;

    if(g_trace_count >= g_trace_max)
        return;

    /* Read timestamp counter */
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));

    struct trace_entry* e = &g_trace_buf[g_trace_count];
    e->rip    = regs[0];
    e->tsc    = ((uint64_t)hi << 32) | lo;
    e->rax    = regs[5];
    e->rcx    = regs[6];
    e->rdx    = regs[7];
    e->rbx    = regs[8];
    e->rsp    = regs[3];
    e->rbp    = regs[10];
    e->rsi    = regs[11];
    e->rdi    = regs[12];
    e->r8     = regs[13];
    e->r9     = regs[14];
    e->r10    = regs[15];
    e->r11    = regs[16];
    e->r12    = regs[17];
    e->r13    = regs[18];
    e->r14    = regs[19];
    e->r15    = regs[20];
    e->eflags = (uint32_t)regs[2];

    /* Mark scheduler skip entries so the analyzer ignores their TSC delta */
    if(g_scheduler_skip)
    {
        e->flags = 1;
        g_scheduler_skip = 0;
    }
    else
    {
        e->flags = 0;
    }

    g_trace_count++;
}

/* ---- Probe execution helpers ---- */

/*
 * Reimplements set_trace() from r0gdb.c (which is static).
 * 1. Resets uretframe to point back to ret2trace
 * 2. Enables TF (Trap Flag) in EFLAGS
 *
 * After this returns, every instruction triggers #DB -> ret2trace ->
 * trace_prog -> int 9 -> resume. This is how single-step tracing works.
 */
static void my_set_trace(void)
{
    /* Restore uretframe to the saved ret2trace state.
     * This is needed because other operations might modify uretframe. */
    kmemcpy((void*)uretframe, saved_uretframe, 40);

    /* Set TF in EFLAGS (identical to r0gdb.c's set_trace) */
    uint64_t q;
    asm volatile("pop %0\npushfq\norb $1, 1(%%rsp)\npopfq\npush %0":"=r"(q));
}

/*
 * Trace a syscall by calling a function under single-step.
 * The function should perform a syscall (e.g., getpid()) which enters
 * the kernel. Kernel instructions are traced via TF until the syscall
 * returns to userland.
 *
 * Flow:
 *   1. Set trace_prog and enable TF via my_set_trace()
 *   2. Call fn() - userland instructions run traced but unrecorded
 *   3. syscall enters kernel - CS=0x20, trace_prog starts recording
 *   4. Kernel runs, each instruction's timing + regs captured
 *   5. sysret/iret returns to userland - CS=0x43, trace_prog clears TF
 *   6. fn() returns normally, trace_prog set to NULL
 *
 * Returns the number of kernel instructions traced.
 */
static int trace_syscall(void(*fn)(void))
{
    g_trace_count = 0;
    g_in_kernel = 0;
    g_scheduler_skip = 0;

    trace_prog = timing_trace_prog;
    my_set_trace();

    /* Call the function - its syscall enters the kernel under trace */
    fn();

    trace_prog = 0;
    return g_trace_count;
}

/* Count timing spikes in the trace buffer (skipping scheduler-skip entries) */
static int count_spikes(int n_entries, uint64_t threshold)
{
    int spikes = 0;
    for(int i = 1; i < n_entries; i++)
    {
        /* Skip entries right after a scheduler skip - their TSC delta is
         * unreliable (includes scheduler time, not instruction time) */
        if(g_trace_buf[i].flags == 1)
            continue;

        uint64_t delta = g_trace_buf[i].tsc - g_trace_buf[i-1].tsc;
        if(delta > threshold)
            spikes++;
    }
    return spikes;
}

/* ---- Syscall wrappers for probing ---- */

static void probe_getpid(void)
{
    getpid();
}

static void probe_getuid(void)
{
    getuid();
}

static void probe_open_devnull(void)
{
    int fd = open("/dev/null", O_RDONLY);
    if(fd >= 0) close(fd);
}

static void probe_stat(void)
{
    struct stat st;
    stat("/", &st);
}

static void probe_mmap_anon(void)
{
    void* p = mmap(0, 4096, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANON, -1, 0);
    if(p != MAP_FAILED)
        munmap(p, 4096);
}

static void probe_pipe(void)
{
    int fds[2];
    if(pipe(fds) == 0)
    {
        close(fds[0]);
        close(fds[1]);
    }
}

static void probe_sysctl_kern(void)
{
    /* Query kernel version via sysctl */
    int mib[2] = {1, 46}; /* CTL_KERN, KERN_VERSION-ish */
    unsigned long sz = 4;
    unsigned int val = 0;
    sysctl(mib, 2, &val, &sz, 0, 0);
}

/* ---- Probe table ---- */
struct probe_def {
    const char* name;
    void (*fn)(void);
};

static struct probe_def probes[] = {
    {"getpid",       probe_getpid},
    {"getuid",       probe_getuid},
    {"open_devnull", probe_open_devnull},
    {"stat_root",    probe_stat},
    {"mmap_anon",    probe_mmap_anon},
    {"pipe",         probe_pipe},
    {"sysctl",       probe_sysctl_kern},
    {0, 0}
};

/* ---- Main ---- */

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    notify("HV: payload started");

    uint32_t fw_version = r0gdb_get_fw_version();

    if(r0gdb_init(ds, a, b, c, d))
    {
        notify("HV: r0gdb_init failed (FW not supported?)");
        return 1;
    }

    notify("HV: r0gdb init OK");

    int sock = r0gdb_open_socket(LISTENER_IP, LISTENER_PORT);
    if(sock < 0)
    {
        notify("HV: connect failed - check IP/port");
        return 1;
    }

    /* Allocate trace buffer */
    size_t buf_size = sizeof(struct trace_entry) * MAX_TRACE_INSTRS;
    g_trace_buf = mmap(0, buf_size, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANON, -1, 0);
    if(g_trace_buf == MAP_FAILED)
    {
        notify("HV: alloc failed!");
        close(sock);
        return 1;
    }
    g_trace_max = MAX_TRACE_INSTRS;

    /* Set up r0gdb instrumentation (single-step infrastructure) */
    r0gdb_instrument(0);
    copyout(saved_uretframe, uretframe, sizeof(saved_uretframe));

    notify("HV: starting traces...");

    /* Send file header */
    struct trace_file_header fhdr;
    fhdr.magic[0] = 'H'; fhdr.magic[1] = 'V'; fhdr.magic[2] = '_';
    fhdr.magic[3] = 'T'; fhdr.magic[4] = 'I'; fhdr.magic[5] = 'M';
    fhdr.magic[6] = 'E'; fhdr.magic[7] = 0;
    fhdr.version = 1;
    fhdr.fw_version = fw_version;
    fhdr.kdata_base = kdata_base;
    /* count probes */
    fhdr.n_probes = 0;
    for(int i = 0; probes[i].name; i++)
        fhdr.n_probes++;
    fhdr.threshold = TIMING_THRESHOLD;
    r0gdb_sendall(sock, &fhdr, sizeof(fhdr));

    int total_spikes = 0;

    /* Run each probe */
    for(int i = 0; probes[i].name; i++)
    {
        /* Notify which probe is running */
        {
            char msg[64] = "HV Trace: ";
            char* p = msg + 10;
            const char* s = probes[i].name;
            while(*s) *p++ = *s++;
            *p = 0;
            notify(msg);
        }

        /* Execute the probe under trace */
        int n = trace_syscall(probes[i].fn);

        /* Count spikes */
        int spikes = count_spikes(n, TIMING_THRESHOLD);
        total_spikes += spikes;

        /* Send probe header */
        struct probe_header phdr;
        /* Copy name */
        for(int j = 0; j < 32; j++) phdr.name[j] = 0;
        {
            const char* s = probes[i].name;
            char* d = phdr.name;
            while(*s && d < phdr.name + 31) *d++ = *s++;
        }
        phdr.n_entries = n;
        phdr.n_spikes = spikes;
        r0gdb_sendall(sock, &phdr, sizeof(phdr));

        /* Send all trace entries for this probe */
        if(n > 0)
            r0gdb_sendall(sock, g_trace_buf,
                          n * sizeof(struct trace_entry));
    }

    close(sock);
    munmap(g_trace_buf, buf_size);

    /* Summary notification */
    {
        char msg[96];
        char* p = msg;
        const char* s = "HV Research: ";
        while(*s) *p++ = *s++;
        p += fmt_int(p, total_spikes);
        s = " timing spikes found";
        while(*s) *p++ = *s++;
        *p = 0;
        notify(msg);
    }

    return 1; /* skip kstuff app.db patching */
}
