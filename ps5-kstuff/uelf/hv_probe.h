#pragma once
#include <sys/types.h>

/* MSR probe status codes */
#define HV_MSR_OK      0  /* read/write succeeded */
#define HV_MSR_GP      1  /* #GP — blocked or nonexistent */

/* CR numbers */
#define HV_CR0  0
#define HV_CR4  4

/*
 * Probe a single MSR read. Returns 0 on success, EFAULT on #GP.
 * On success, *value holds the MSR value.
 */
int hv_probe_msr_read(uint32_t msr, uint64_t* value);

/*
 * Probe a single MSR write. Returns 0 on success, EFAULT on #GP.
 */
int hv_probe_msr_write(uint32_t msr, uint64_t value);

/*
 * Write an MSR and immediately read it back.
 * Returns 0 on success, EFAULT if either write or readback fails.
 * On success, *readback holds the value read back after the write.
 */
int hv_probe_msr_write_readback(uint32_t msr, uint64_t value, uint64_t* readback);

/*
 * Read a control register. Currently supports CR0 only.
 * CR4 requires a gadget that must be found via single-stepping.
 * Returns the register value, or 0 on error.
 */
uint64_t hv_probe_cr_read(uint32_t cr_num);

/*
 * Write a control register and read it back.
 * Returns 0 on success, EINVAL for unsupported CR.
 * On success, *readback holds the value read back after the write.
 */
int hv_probe_cr_write_readback(uint32_t cr_num, uint64_t value, uint64_t* readback);
