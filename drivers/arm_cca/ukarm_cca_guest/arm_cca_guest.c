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

#include <uk/arm_cca_guest.h>
#include <uk/plat/common/bootinfo.h>

int arm_cca_early_map_unprotected(__u64 base, __sz size)
{
	__u64 end;
	int rc;
	unsigned long ttbr0;
	int lvl;
	__u64 idx;
	unsigned long tbl_base;
	unsigned long pg_addr;
	__pte_t pte;

	/* Base address is both virt and phys, as this should only be called
	 * during early boot with identity page tables. */

	UK_ASSERT(UK_PAGING_PAGE_ALIGNED(base));
	UK_ASSERT(UK_PAGING_PAGE_ALIGNED(size));

	end = base + size;

	ttbr0 = (unsigned long)uk_paging_pt_read_base();

	pg_addr = base;

	while (pg_addr < end) {
		tbl_base = ttbr0;
		lvl = UK_PAGING_PT_LEVELS - 1;

		/* Walk the page table */
		while (1) {
			idx = UK_PAGING_PT_Lx_IDX(pg_addr, lvl);
			rc = uk_paging_pte_read(tbl_base, lvl, idx, &pte);
			if (unlikely(rc))
				return rc;

			/* Exit if this is a leaf */
			if (UK_PAGING_PAGE_Lx_IS(pte, lvl))
				break;

			/* Get address of next level */
			tbl_base = UK_PAGING_PT_Lx_PTE_PADDR(pte, lvl);

			lvl--;
		}

		// Function should only be used on identity mappings
		UK_ASSERT(UK_PAGING_PT_Lx_PTE_PADDR(pte, lvl) == pg_addr);

		rc = uk_paging_pte_write(tbl_base, lvl, idx,
					 pte | PTE_RME_UNPROTECTED_BIT);

		if (unlikely(rc))
			return rc;

		pg_addr += UK_PAGING_PAGE_Lx_SIZE(lvl);
	}

	return 0;
}

int __check_result arm_cca_init_memory(void)
{
	struct ukplat_bootinfo *bi;
	const struct ukplat_memregion_desc *mrd;
	__paddr_t pstart, pend, len;
	rsi_return_t ret;
	__u32 i;

	bi = ukplat_bootinfo_get();

	for (i = 0; i < bi->mrds.count; i++) {
		mrd = &bi->mrds.mrds[i];

		/* Don't know what's in a reserved region, so don't know whether
		 * it should be protected or not. Protection would need to be
		 * handled by whatever subsystem reserved the memory. */
		if (mrd->type == UKPLAT_MEMRT_RESERVED)
			continue;

		/* Devices are separately mapped to unprotected IPA space */
		if (mrd->type == UKPLAT_MEMRT_DEVICE)
			continue;

		pstart = ALIGN_DOWN(mrd->pbase, __PAGE_SIZE);
		len = ALIGN_UP(mrd->len, __PAGE_SIZE);
		pend = pstart + len;

		uk_pr_info("Setting up memory: 0x%lx - 0x%lx\n", pstart, pend);
		ret =
		    uk_rsi_ipa_state_set_range(pstart, pend, RSI_RIPAS_RAM, 0);
		if (ret != RSI_SUCCESS)
			return -ENOTSUP;
	}

	return 0;
}

int arm_cca_map_unprotected_rw(__vaddr_t vaddr, __sz size)
{
	unsigned long pages, prot;

	UK_ASSERT(UK_PAGING_PAGE_ALIGNED(vaddr));
	UK_ASSERT(UK_PAGING_PAGE_ALIGNED(size));

	pages = size / __PAGE_SIZE;
	prot = UK_PAGING_PAGE_ATTR_PROT_RW |
	       UK_PLAT_NATIVE_PAGE_ATTR_RME_UNPROTECTED;

	return uk_paging_page_set_attr(uk_paging_pt_get_active(), vaddr, pages,
				       prot, 0);
}
