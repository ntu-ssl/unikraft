/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Benjamin Higgins
 *          Xingjian Zhang
 *
 * Copyright (c) 2026, National Taiwan University, Secure Systems Lab.
 * Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
