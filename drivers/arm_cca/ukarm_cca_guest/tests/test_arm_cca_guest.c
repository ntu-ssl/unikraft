#include <uk/alloc.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/memory.h>
#include <uk/plat/paging.h>
#include <uk/arm_cca_guest.h>
#include <uk/plat/io.h>
#include <uk/rsi.h>
#include <uk/test.h>

/* Helper functions to check attributes of a page table entry, based on
 * plat/common/include/arm/arm64/paging.h: pgarch_attr_from_pte() */
static inline int pte_is_rw(__pte_t pte)
{
	return (pte &
		PTE_ATTR_AP(PTE_ATTR_AP_RW) == PTE_ATTR_AP(PTE_ATTR_AP_RW));
}

static inline int pte_is_rme_unprotected(__pte_t pte)
{
	return (pte & PTE_RME_UNPROTECTED_BIT) == PTE_RME_UNPROTECTED_BIT;
}

/**
 * Tests if the arm_cca_init_memory function correctly sets IPA states based on
 * the memory region types defined in bootinfo
 */
UK_TESTCASE(ukarm_cca_guest_testsuite, ukarm_cca_guest_test_init_memory)
{
	int rc;
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};

	/* Fake bootinfo with custom memory region descriptor */
	struct bootinfo_wrapper {
		struct ukplat_bootinfo bi;
		struct ukplat_memregion_desc mrds[1];
	} __packed __align(__SIZEOF_LONG__);

	struct bootinfo_wrapper test_bi = {0};
	test_bi.bi.magic = UKPLAT_BOOTINFO_MAGIC;
	test_bi.bi.version = UKPLAT_BOOTINFO_VERSION;

	struct ukplat_memregion_list *test_mrd_list = &test_bi.bi.mrds;
	ukplat_memregion_list_init(test_mrd_list, 1);

	struct ukplat_memregion_desc mrd = {
	    .pbase = ukplat_virt_to_phys(buffer),
	    .vbase = ukplat_virt_to_phys(buffer),
	    .pg_off = 0,
	    .len = GRANULE_SIZE,
	    .pg_count = 1,
	    .type = UKPLAT_MEMRT_DEVICE,
	    .flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE,
	};
	ukplat_memregion_list_insert(test_mrd_list, &mrd);

	struct ukplat_bootinfo *real_bi = ukplat_bootinfo_get();
	ukplat_bootinfo_set((struct ukplat_bootinfo *)&test_bi);

	/* Check if its IPA state is RAM at first */
	unsigned long out_top;
	unsigned char ripas;
	rc = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				  ukplat_virt_to_phys(buffer) + PAGE_SIZE,
				  &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(rc, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(out_top,
			       ukplat_virt_to_phys(buffer) + PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);

	/* Pretend we are a device */
	rc = uk_rsi_ipa_state_set_range(ukplat_virt_to_phys(buffer),
					ukplat_virt_to_phys(buffer) + PAGE_SIZE,
					RSI_RIPAS_EMPTY,
					RSI_RIPAS_CHANGE_DESTROYED);
	UK_TEST_EXPECT_SNUM_EQ(rc, RSI_SUCCESS);

	/* Test with a UKPLAT_MEMRT_DEVICE memory region */
	rc = arm_cca_init_memory();
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);

	rc = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				  ukplat_virt_to_phys(buffer) + PAGE_SIZE,
				  &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(rc, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_NQ(ripas, RSI_RIPAS_RAM);

	/* Test with a UKPLAT_MEMRT_RESERVED memory region */
	test_bi.mrds[0].type = UKPLAT_MEMRT_RESERVED;
	rc = arm_cca_init_memory();
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);

	rc = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				  ukplat_virt_to_phys(buffer) + PAGE_SIZE,
				  &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(rc, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_NQ(ripas, RSI_RIPAS_RAM);

	/* Test with a non UKPLAT_MEMRT_DEVICE or
	 * UKPLAT_MEMRT_RESERVED memory region */
	test_bi.mrds[0].type = UKPLAT_MEMRT_KERNEL;
	rc = arm_cca_init_memory();
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);

	rc = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				  ukplat_virt_to_phys(buffer) + PAGE_SIZE,
				  &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(rc, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);

	ukplat_bootinfo_set(real_bi);
}

/**
 * Tests if the arm_cca_map_unprotected_rw function correctly updates
 * the page table entries attribute to PAGE_ATTR_RME_UNPROTECTED and
 * PAGE_ATTR_PROT_RW
 */
UK_TESTCASE(ukarm_cca_guest_testsuite, ukarm_cca_guest_test_pt_unprotected_rw)
{
	struct uk_alloc *a = uk_alloc_get_default();
	char *buffer = uk_memalign(a, PAGE_SIZE, PAGE_SIZE);
	int rc;

	if (unlikely(!buffer)) {
		uk_pr_err("Could not allocate memory for testing\n");
		return;
	}

	rc = arm_cca_map_unprotected_rw((__vaddr_t)buffer, PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);

	__vaddr_t pt_vaddr;
	__pte_t pte;
	/* Check pte */
	rc = ukplat_pt_walk(ukplat_pt_get_active(), (__vaddr_t)buffer,
			    PAGE_LEVEL, &pt_vaddr, &pte);
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);
	UK_TEST_EXPECT_NOT_ZERO(pt_vaddr);
	UK_TEST_EXPECT_NOT_ZERO(pte);
	UK_TEST_EXPECT_SNUM_EQ(pte_is_rw(pte), 1);
	UK_TEST_EXPECT_SNUM_EQ(pte_is_rme_unprotected(pte), 1);

	/* Restore pagetable entry */
	rc = ukplat_page_set_attr(ukplat_pt_get_active(), (__vaddr_t)buffer, 1,
				  PAGE_ATTR_PROT_RW, 0);
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);

	uk_free(a, buffer);
}

uk_testsuite_register(ukarm_cca_guest_testsuite, NULL);
