#ifndef __UK_ARM_CCA_GUEST_H__
#define __UK_ARM_CCA_GUEST_H__

#include <uk/arch/types.h>
#include <uk/asm/rsi.h>
#include <uk/rsi.h>

/**
 * Set RIPAS RAM on all private memory regions in the IPA space based on
 * bootinfo memory regions.
 *
 * @return 0 on success, a non-zero error code otherwise
 */
int arm_cca_init_memory(void);

#endif /* __UK_ARM_CCA_GUEST_H__ */
