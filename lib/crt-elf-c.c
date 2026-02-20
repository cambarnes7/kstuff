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
    int rw0 = args->rwpair ? args->rwpair[0] : -1;
    int rw1 = args->rwpair ? args->rwpair[1] : -1;
    uint64_t ret = _start(args->dlsym, rw0, rw1, 0, args->kdata_base);
    if(args->retval)
        *args->retval = ret;
}
