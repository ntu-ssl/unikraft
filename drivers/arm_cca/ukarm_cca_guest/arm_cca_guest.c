#include <uk/arm_cca_guest.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/plat/io.h>
#include <uk/plat/paging.h>

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
