#include <errno.h>
#include "hv_probe.h"
#include "utils.h"

int hv_probe_msr_read(uint32_t msr, uint64_t* value)
{
    *value = 0;
    return rdmsr(msr, value) ? 0 : EFAULT;
}

int hv_probe_msr_write(uint32_t msr, uint64_t value)
{
    return wrmsr(msr, value) ? 0 : EFAULT;
}

int hv_probe_msr_write_readback(uint32_t msr, uint64_t value, uint64_t* readback)
{
    *readback = 0;
    if(!wrmsr(msr, value))
        return EFAULT;
    if(!rdmsr(msr, readback))
        return EFAULT;
    return 0;
}

uint64_t hv_probe_cr_read(uint32_t cr_num)
{
    if(cr_num == HV_CR0)
        return read_cr0();
    /* CR4 not yet available — needs gadget discovery via single-stepping */
    return 0;
}

int hv_probe_cr_write_readback(uint32_t cr_num, uint64_t value, uint64_t* readback)
{
    *readback = 0;
    if(cr_num == HV_CR0)
    {
        write_cr0(value);
        *readback = read_cr0();
        return 0;
    }
    /* CR4 not yet available */
    return EINVAL;
}
