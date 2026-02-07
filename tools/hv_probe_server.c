/*
 * PS5 HV Probe Server
 *
 * Standalone userspace program that listens on TCP port 9020 and
 * dispatches hypervisor probe commands via the kstuff kekcall interface.
 *
 * Requires kstuff to be loaded (kernel payload active).
 *
 * Build (with PS5 Payload SDK):
 *   $CC -o hv_probe_server.elf hv_probe_server.c
 *
 * Or compile manually:
 *   clang --target=x86_64-sie-ps5 -o hv_probe_server.elf hv_probe_server.c
 *
 * Kekcall convention:
 *   RAX = (kekcall_nr << 32) | SYS_getppid
 *   RDI = arg1
 *   RSI = arg2
 *   Returns: td_retval on success, error code on failure
 *
 * Protocol (binary, little-endian):
 *   Request:  [cmd:u8] [arg1:u64] [arg2:u64]  = 17 bytes
 *   Response: [status:u8] [value:u64]           = 9 bytes
 */

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#define PROBE_PORT 9020

/* Protocol commands — must match hv_probe.py */
#define CMD_MSR_READ       0x01
#define CMD_MSR_WRITE      0x02
#define CMD_MSR_WRITE_RB   0x03
#define CMD_CR_READ        0x04
#define CMD_CR_WRITE_RB    0x05
#define CMD_PING           0xFF

/* Status codes */
#define STATUS_OK    0x00
#define STATUS_GP    0x01
#define STATUS_ERROR 0x02

/* Kekcall numbers — must match kekcall.c */
#define KEKCALL_RDMSR           3
#define KEKCALL_WRMSR           4
#define KEKCALL_CR_READ        30
#define KEKCALL_CR_WRITE_RB    31
#define KEKCALL_MSR_WRITE_RB   32
#define KEKCALL_PING     0xFFFFFFFF

/*
 * Invoke a kstuff kekcall.
 *
 * Sets RAX = (nr << 32) | SYS_getppid, then executes syscall.
 * On success, returns the td_retval value (>= 0).
 * On failure, returns -errno.
 */
static int64_t kekcall(uint32_t nr, uint64_t arg1, uint64_t arg2)
{
    int64_t ret;
    register uint64_t rax __asm__("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi __asm__("rdi") = arg1;
    register uint64_t rsi __asm__("rsi") = arg2;

    __asm__ volatile(
        "syscall"
        : "+r"(rax), "+r"(rdi), "+r"(rsi)
        :
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );

    /*
     * After syscall:
     *   rax = 0 on success (carry clear), errno on failure (carry set)
     *   On success, the actual return value is in the thread's td_retval,
     *   which libc getppid() would return. Since we bypassed libc, we
     *   read it from rdi (FreeBSD convention: td_retval copied to rdi).
     *
     * In practice, the kekcall handler sets:
     *   regs[RAX] = error code (0 = success)
     *   td_retval = args[RAX] (the result value)
     *
     * The syscall return path copies td_retval to RAX on success.
     */
    if ((int64_t)rax < 0)
        return -(int64_t)rax; /* error */

    /* For getppid, the return value IS in rax (td_retval[0]) */
    return (int64_t)rax;
}

static int sendall(int fd, const void* buf, int len)
{
    const char* p = buf;
    while(len > 0)
    {
        int n = write(fd, p, len);
        if(n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int recvall(int fd, void* buf, int len)
{
    char* p = buf;
    while(len > 0)
    {
        int n = read(fd, p, len);
        if(n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static void handle_client(int client_fd)
{
    uint8_t req[17]; /* cmd(1) + arg1(8) + arg2(8) */
    uint8_t resp[9]; /* status(1) + value(8) */

    for(;;)
    {
        if(recvall(client_fd, req, 17) < 0)
            break;

        uint8_t cmd = req[0];
        uint64_t arg1 = *(uint64_t*)(req + 1);
        uint64_t arg2 = *(uint64_t*)(req + 9);
        uint8_t status = STATUS_ERROR;
        uint64_t value = 0;

        switch(cmd)
        {
        case CMD_PING:
            status = STATUS_OK;
            value = 0xCAFE;
            break;

        case CMD_MSR_READ:
        {
            int64_t ret = kekcall(KEKCALL_RDMSR, arg1, 0);
            if(ret >= 0)
            {
                status = STATUS_OK;
                value = (uint64_t)ret;
            }
            else
                status = STATUS_GP;
            break;
        }

        case CMD_MSR_WRITE:
        {
            int64_t ret = kekcall(KEKCALL_WRMSR, arg1, arg2);
            status = (ret >= 0) ? STATUS_OK : STATUS_GP;
            break;
        }

        case CMD_MSR_WRITE_RB:
        {
            int64_t ret = kekcall(KEKCALL_MSR_WRITE_RB, arg1, arg2);
            if(ret >= 0)
            {
                status = STATUS_OK;
                value = (uint64_t)ret;
            }
            else
                status = STATUS_GP;
            break;
        }

        case CMD_CR_READ:
        {
            int64_t ret = kekcall(KEKCALL_CR_READ, arg1, 0);
            if(ret >= 0)
            {
                status = STATUS_OK;
                value = (uint64_t)ret;
            }
            else
                status = STATUS_ERROR;
            break;
        }

        case CMD_CR_WRITE_RB:
        {
            int64_t ret = kekcall(KEKCALL_CR_WRITE_RB, arg1, arg2);
            if(ret >= 0)
            {
                status = STATUS_OK;
                value = (uint64_t)ret;
            }
            else
                status = STATUS_ERROR;
            break;
        }

        default:
            status = STATUS_ERROR;
            break;
        }

        resp[0] = status;
        *(uint64_t*)(resp + 1) = value;
        if(sendall(client_fd, resp, 9) < 0)
            break;
    }
}

int main(void)
{
    /* Verify kstuff is loaded by doing a ping kekcall */
    int64_t ping = kekcall(KEKCALL_PING, 0, 0);
    /* ping returns 0 on success (kekcall 0xffffffff sets args[RAX]=0) */

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        return 1;

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = 0 },
        .sin_port = (PROBE_PORT >> 8) | (PROBE_PORT << 8), /* htons */
    };

    if(bind(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0)
        return 2;

    if(listen(sock, 1) < 0)
        return 3;

    /* Accept connections in a loop (one at a time) */
    for(;;)
    {
        int client = accept(sock, 0, 0);
        if(client < 0)
            continue;
        handle_client(client);
        close(client);
    }

    return 0;
}
