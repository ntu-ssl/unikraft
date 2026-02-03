#ifndef __UK_ARM_CCA_GUEST_H__
#define __UK_ARM_CCA_GUEST_H__

#include <uk/arch/types.h>
#include <uk/asm/rsi.h>
#include <uk/rsi.h>

/**
 * Update early boot identity-mapped PTEs to map to the unprotected IPA space by
 * setting the unprotected bit. Does not set any other attributes, or change the
 * RIPAS of the region.
 *
 * For use only during early boot with identity page tables but before paging
 * has been fully initialised, otherwise see arm_cca_map_unprotected_rw.
 *
 *  @return 0 on success, a non-zero error code otherwise
 */
int arm_cca_early_map_unprotected(__u64 base, __sz size);

/**
 * Set RIPAS RAM on all private memory regions in the IPA space based on
 * bootinfo memory regions.
 *
 * @return 0 on success, a non-zero error code otherwise
 */
int arm_cca_init_memory(void);

/**
 * Map a memory region as RW to unprotected IPA space with by setting the
 * unprotected bit on the PTE. Does not change the RIPAS of the region. Intended
 * for e.g. a device region.
 *
 * Use only after paging has been fully initialised, otherwise see
 * arm_cca_early_map_unprotected.
 *
 *  @return 0 on success, a non-zero error code otherwise
 */
int arm_cca_map_unprotected_rw(__vaddr_t vaddr, __sz size);

#endif /* __UK_ARM_CCA_GUEST_H__ */
