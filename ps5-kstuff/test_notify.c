/*
 * test_notify.c - Minimal PS5 payload that just shows a notification.
 * Used to verify the build/load chain works.
 *
 * Build:
 *   cd ps5-kstuff && make payload-test.bin CROSS_COMPILE=x86_64-elf-
 *   cp payload-test.bin payload.bin
 *   cd ../ps5-kstuff-ldr
 *   xxd -i ../ps5-kstuff/payload.bin > payload_bin.c
 *   $(CC) -o kstuff.elf main.c stub_sqlite.c
 */

#define sysctl __sysctl
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

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

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    notify("TEST: payload is alive!");
    return 1;
}
