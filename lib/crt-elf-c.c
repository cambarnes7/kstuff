#include <sys/types.h>

struct specter_args
{
    void* dlsym;
    int* pipe;
    int* rwpair;
    uint64_t kpipe_addr;
    uint64_t kdata_base;
    int* retval;
};

uint64_t _start(void* dlsym, int master, int victim, uint64_t pktopts, uint64_t kdata_base);

void elf_main(struct specter_args* args)
{
    // Don't pass rwpair/kdata_base - elfldr uses pipe-based kernel RW
    // which is incompatible with prosper0gdb's pktopts technique.
    // The GDB stub starts without kernel RW; it can be set up via GDB.
    uint64_t ret = _start(args->dlsym, -1, -1, 0, 0);
    if(args->retval)
        *args->retval = ret;
}
