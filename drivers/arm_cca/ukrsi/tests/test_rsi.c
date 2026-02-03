/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Ching-Yun Lin
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

#include <arm/smccc.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/arch/paging.h>
#include <uk/plat/io.h>
#include <uk/rsi.h>
#include <uk/test.h>

#define FID_INVALID 0xc5000041

/* Helper function to print a hex dump of a buffer  */
void print_hex_dump(const void *buffer, size_t size)
{
	const uint8_t *data = (const uint8_t *)buffer;

	for (size_t i = 0; i < size; i++) {
		// Print the byte in 0x00 format
		printf("0x%02x ", data[i]);

		// Every 8 bytes, print a newline
		if ((i % 8) == 7)
			printf("\n");
	}

	// Add a trailing newline if the last line wasn't finished
	if (size > 0 && (size % 8) != 0)
		printf("\n");
}

/**
 * Tests the failure condition of uk_rsi_attestation_token_init
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_attestation_token_continue_fail)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long challenge[8];
	unsigned long ret;
	unsigned long size, max_size, len;

	memset(challenge, 0xAB, sizeof(challenge));

	/* Test with not ATTEST_IN_PROGRESS */
	size = GRANULE_SIZE;
	ret = uk_rsi_attestation_token_continue(ukplat_virt_to_phys(buffer), 0,
						size, &len);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_STATE);

	size = GRANULE_SIZE - 10;
	/* Test with a different attest address */
	ret = uk_rsi_attestation_token_init(challenge, &max_size);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	ret = uk_rsi_attestation_token_continue(
	    ukplat_virt_to_phys(buffer) + 10, 10, size, &len);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	size = GRANULE_SIZE;
	/* Test with a non-page aligned address */
	ret = uk_rsi_attestation_token_continue(
	    ukplat_virt_to_phys(buffer) + 10, 0, size, &len);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an out-of-bound address */
	ret = uk_rsi_attestation_token_continue(ARM64_INVALID_ADDR, 0, size,
						&len);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with offset >= RMM_GRANULE_SIZE */
	ret = uk_rsi_attestation_token_continue(ukplat_virt_to_phys(buffer),
						GRANULE_SIZE + 10, size, &len);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the RSI attestion
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_attestation)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long challenge[8];
	unsigned long ret;
	unsigned long size;

	memset(challenge, 0xAB, sizeof(challenge));

	/* Get attestation in normal case */
	ret = uk_rsi_generate_attestation_token(ukplat_virt_to_phys(buffer),
						challenge, &size);

	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_NOT_ZERO(size);

	printf("attestation token:\n");
	print_hex_dump(buffer, size);
}

/**
 * Tests the host call
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_hostcall_fail)
{
	struct rsi_host_call_data __align(256) host_call_data = {0};
	unsigned long ret;

	/* Test with a not-aligned address */
	ret = uk_rsi_host_call(ukplat_virt_to_phys(&host_call_data) + 10);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an out-of-bound address */
	ret = uk_rsi_host_call(ARM64_INVALID_ADDR);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the host call
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_hostcall)
{
	struct rsi_host_call_data __align(256) host_call_data = {0};
	unsigned long ret;

	/* Test with normal host call */
	host_call_data.gprs[0] = SMCCC_FID_SMCCC_VERSION;

	ret = uk_rsi_host_call(ukplat_virt_to_phys(&host_call_data));

	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(host_call_data.gprs[0], SMCCC_VERSION_1_1);

	/* Test with unsupported host call */
	host_call_data.gprs[0] = FID_INVALID;

	ret = uk_rsi_host_call(ukplat_virt_to_phys(&host_call_data));

	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(host_call_data.gprs[0], SMCCC_NOT_SUPPORTED);
}

/**
 * Tests the failure cases for RSI_IPA_STATE_GET seen in RMM Specification
 * section B5.3.5.2.
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_ripas_get_fail)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long out_top;
	unsigned long ret;
	unsigned char ripas;

	/* Test with a not-aligned base address */
	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(&buffer) + 10,
				   ukplat_virt_to_phys(&buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with a not-aligned top address */
	ret = uk_rsi_ipa_state_get(
	    ukplat_virt_to_phys(&buffer),
	    ukplat_virt_to_phys(&buffer) + GRANULE_SIZE + 10, &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid size */
	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(&buffer),
				   ukplat_virt_to_phys(&buffer) - GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an out-of-bound address */
	ret = uk_rsi_ipa_state_get(ARM64_INVALID_ADDR,
				   ARM64_INVALID_ADDR + GRANULE_SIZE, &out_top,
				   &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the failure conditions for RSI_IPA_STATE_SET seen in RMM Specification
 * section B5.3.6.2.
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_ripas_set_fail)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	__paddr_t new_base, ret;
	__u8 resp;

	/* Test with a not-aligned base address */
	ret = uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer) + 10,
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   RSI_RIPAS_RAM, 0, &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with a not-aligned top address */
	ret = uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE +
				       10,
				   RSI_RIPAS_RAM, 0, &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid size */
	ret = uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) - GRANULE_SIZE,
				   RSI_RIPAS_RAM, 0, &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid address */
	ret = uk_rsi_ipa_state_set(ARM64_INVALID_ADDR,
				   ARM64_INVALID_ADDR + GRANULE_SIZE,
				   RSI_RIPAS_RAM, 0, &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid RIPAS */
	ret =
	    uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer),
				 ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				 RSI_RIPAS_DESTROYED + 1, 0, &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests state set failure conditions as above, but applied to a range
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_ripas_set_range_fail)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long ret;

	/* Test with a not-aligned base address */
	ret = uk_rsi_ipa_state_set_range(
	    ukplat_virt_to_phys(buffer) + 10,
	    ukplat_virt_to_phys(buffer) + GRANULE_SIZE, RSI_RIPAS_RAM, 0);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with a not-aligned top address */
	ret = uk_rsi_ipa_state_set_range(
	    ukplat_virt_to_phys(buffer),
	    ukplat_virt_to_phys(buffer) + GRANULE_SIZE + 10, RSI_RIPAS_RAM, 0);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid size */
	ret = uk_rsi_ipa_state_set_range(
	    ukplat_virt_to_phys(buffer),
	    ukplat_virt_to_phys(buffer) - GRANULE_SIZE, RSI_RIPAS_RAM, 0);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid address */
	ret = uk_rsi_ipa_state_set_range(ARM64_INVALID_ADDR,
					 ARM64_INVALID_ADDR + GRANULE_SIZE,
					 RSI_RIPAS_RAM, 0);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an invalid RIPAS */
	ret = uk_rsi_ipa_state_set_range(ukplat_virt_to_phys(buffer),
					 ukplat_virt_to_phys(buffer) +
					     GRANULE_SIZE,
					 RSI_RIPAS_DESTROYED + 1, 0);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests that setting and getting RIPAS values returns the value expected
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_ripas_set_get)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long out_top;
	unsigned char ripas;
	__paddr_t new_base, ret;
	__u8 resp;

	/* test ripas of the buffer */
	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);

	/* set ripas and then get */
	ret = uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   RSI_RIPAS_EMPTY, RSI_RIPAS_CHANGE_DESTROYED,
				   &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);

	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_EMPTY);

	ret = uk_rsi_ipa_state_set(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   RSI_RIPAS_RAM, RSI_RIPAS_CHANGE_DESTROYED,
				   &new_base, &resp);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);

	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);
}

/**
 * Tests setting and getting RIPAS values as above, but applied to a whole range
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_ripas_set_range_get)
{
	char buffer[GRANULE_SIZE] __align(GRANULE_SIZE) = {0};
	unsigned long ret;
	unsigned long out_top;
	unsigned char ripas;

	/* test ripas of the buffer */
	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);

	/* set ripas and then get */
	ret = uk_rsi_ipa_state_set_range(
	    ukplat_virt_to_phys(buffer),
	    ukplat_virt_to_phys(buffer) + GRANULE_SIZE, RSI_RIPAS_EMPTY,
	    RSI_RIPAS_CHANGE_DESTROYED);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);

	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_EMPTY);

	ret = uk_rsi_ipa_state_set_range(
	    ukplat_virt_to_phys(buffer),
	    ukplat_virt_to_phys(buffer) + GRANULE_SIZE, RSI_RIPAS_RAM,
	    RSI_RIPAS_CHANGE_DESTROYED);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);

	ret = uk_rsi_ipa_state_get(ukplat_virt_to_phys(buffer),
				   ukplat_virt_to_phys(buffer) + GRANULE_SIZE,
				   &out_top, &ripas);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	UK_TEST_EXPECT_SNUM_EQ(ripas, RSI_RIPAS_RAM);
}

/**
 * Tests the uk_rsi_measurement_extend failure function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_measurement_extend_fail)
{
	unsigned long value[8];
	unsigned long ret;

	memset(value, 0xAB, sizeof(value));

	/* Test with out-of-bound index */
	ret = uk_rsi_measurement_extend(0, sizeof(value), value);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	ret = uk_rsi_measurement_extend(5, sizeof(value), value);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with too large size */
	ret = uk_rsi_measurement_extend(1, 65, value);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the uk_rsi_measurement_extend function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_measurement_extend)
{
	unsigned long value[8];
	unsigned long ret;
	int i;

	memset(value, 0xAB, sizeof(value));

	for (i = 1; i < 5; i++) {
		ret = uk_rsi_measurement_extend(i, sizeof(value), value);
		UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
	}
}

/**
 * Tests the uk_rsi_measurement_extend failure function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_measurement_read_fail)
{
	unsigned long value[8];
	unsigned long ret;

	memset(value, 0xAB, sizeof(value));

	/* Test with out-of-bound index */
	ret = uk_rsi_measurement_read(5, value);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the uk_rsi_measurement_extend function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_measurement_read)
{
	unsigned long value[8];
	unsigned long ret;
	int i, j;

	memset(value, 0xAB, sizeof(value));

	for (i = 0; i < 5; i++) {
		ret = uk_rsi_measurement_read(i, value);
		UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);
		printf("Measurement %d:\n", i);
		for (j = 0; j < 8; j++)
			printf("0x%016lx ", value[j]);
		printf("\n");
	}
}

/**
 * Tests the uk_rsi_realm_config failure function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_realm_config_fail)
{
	struct rsi_realm_config config __align(GRANULE_SIZE) = {0};
	unsigned long ret;

	/* Test with a non-page aligned address */
	ret = uk_rsi_realm_config((void *)&config + 1);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);

	/* Test with an out-of-bound address */
	ret =
	    uk_rsi_realm_config((struct rsi_realm_config *)ARM64_INVALID_ADDR);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_ERROR_INPUT);
}

/**
 * Tests the uk_rsi_realm_config function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_realm_config)
{
	struct rsi_realm_config config __align(GRANULE_SIZE) = {0};
	unsigned long ret;

	ret = uk_rsi_realm_config(&config);
	UK_TEST_EXPECT_SNUM_EQ(ret, RSI_SUCCESS);

	// Minimum possible IPA width
	UK_TEST_EXPECT_SNUM_GE(config.ipa_width, 32);

	// Arm FEAT_LPA2 allows IPA space of up to 52 bits
	UK_TEST_EXPECT_SNUM_LE(config.ipa_width, 52);

	// Hash algorithm values
	UK_TEST_EXPECT_SNUM_GE(config.hash_algo, 0);
	UK_TEST_EXPECT_SNUM_LE(config.hash_algo, 1);

	printf("realm personalization value:\n");
	print_hex_dump(config.rpv, sizeof(rsi_rpv_t));
}

/**
 * Tests the uk_rsi_version function
 */
UK_TESTCASE(ukrsi_testsuite, ukrsi_test_rsi_version)
{
	rsi_version_t req = RSI_VERSION_1_0;
	rsi_version_t lower, higher;

	uk_rsi_version(req, &lower, &higher);

	/* Check if the version is valid, 0xC0000 is a legacy version */
	UK_TEST_EXPECT_SNUM_EQ(req, RSI_VERSION_1_0);
	UK_TEST_EXPECT_NOT_ZERO(req);
}

uk_testsuite_register(ukrsi_testsuite, NULL);
