/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <arm/smccc.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/rsi.h>

rsi_return_t uk_rsi_unprotected_mask;
rsi_return_t uk_rsi_attestation_token_continue(__paddr_t paddr, __u64 offset,
					       __u64 size, __u64 *len)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_ATTESTATION_TOKEN_CONTINUE;
	args.a1 = paddr;
	args.a2 = offset;
	args.a3 = size;

	smccc_invoke(&args);
	*len = args.a1;

	return args.a0;
}

rsi_return_t uk_rsi_attestation_token_init(__u64 challenge[8], __u64 *size)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_ATTESTATION_TOKEN_INIT;
	args.a1 = challenge[0];
	args.a2 = challenge[1];
	args.a3 = challenge[2];
	args.a4 = challenge[3];
	args.a5 = challenge[4];
	args.a6 = challenge[5];
	args.a7 = challenge[6];
	args.a8 = challenge[7];

	smccc_invoke(&args);
	*size = args.a1;

	return args.a0;
}

rsi_return_t uk_rsi_host_call(__paddr_t paddr)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_HOST_CALL;
	args.a1 = paddr;

	smccc_invoke(&args);

	return args.a0;
}

rsi_return_t uk_rsi_ipa_state_get(__paddr_t base, __paddr_t top,
				  __paddr_t *out_top, rsi_ripas_t *ripas)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_IPA_STATE_GET;
	args.a1 = base;
	args.a2 = top;

	smccc_invoke(&args);
	*out_top = args.a1;
	*ripas = (rsi_ripas_t)args.a2;

	return args.a0;
}

rsi_return_t uk_rsi_ipa_state_set(__paddr_t base, __paddr_t top,
				  rsi_ripas_t ripas,
				  rsi_ripas_change_flags_t flags,
				  __paddr_t *new_base, rsi_response_t *response)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_IPA_STATE_SET;
	args.a1 = base;
	args.a2 = top;
	args.a3 = ripas;
	args.a4 = flags;

	smccc_invoke(&args);

	if (args.a0 == RSI_SUCCESS) {
		if (new_base)
			*new_base = args.a1;
		if (response)
			*response = (__u8)args.a2;
	}

	return args.a0;
}

rsi_return_t uk_rsi_measurement_extend(__u64 index, __u64 size, __u64 value[8])
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_MEASUREMENT_EXTEND;
	args.a1 = index;
	args.a2 = size;
	args.a3 = value[0];
	args.a4 = value[1];
	args.a5 = value[2];
	args.a6 = value[3];
	args.a7 = value[4];
	args.a8 = value[5];
	args.a9 = value[6];
	args.a10 = value[7];

	smccc_invoke(&args);

	return args.a0;
}

rsi_return_t uk_rsi_measurement_read(__u64 index, __u64 value[8])
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_MEASUREMENT_READ;
	args.a1 = index;

	smccc_invoke(&args);

	value[0] = args.a1;
	value[1] = args.a2;
	value[2] = args.a3;
	value[3] = args.a4;
	value[4] = args.a5;
	value[5] = args.a6;
	value[6] = args.a7;
	value[7] = args.a8;

	return args.a0;
}

rsi_return_t uk_rsi_realm_config(struct rsi_realm_config *out)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_REALM_CONFIG;
	args.a1 = (__u64)out;

	smccc_invoke(&args);

	return args.a0;
}

rsi_return_t uk_rsi_version(rsi_version_t req, rsi_version_t *lower,
			    rsi_version_t *higher)
{
	struct smccc_args args = {0};

	args.a0 = RSI_CMD_VERSION;
	args.a1 = req;

	smccc_invoke(&args);
	*lower = args.a1;
	*higher = args.a2;

	return args.a0;
}

void uk_rsi_init(void)
{
	struct rsi_realm_config config __align(PAGE_SIZE);
	rsi_return_t ret = uk_rsi_realm_config(&config);

	if (ret != RSI_SUCCESS)
		UK_CRASH("Could not initialize RSI\n");

	/* Set the mask of the unprotected bit */
	uk_rsi_unprotected_mask = (1UL) << (config.ipa_width - 1);
}

rsi_return_t uk_rsi_generate_attestation_token(__paddr_t paddr,
					       __u64 challenge[8], __u64 *len)
{

	rsi_return_t ret;
	__u64 size, max_size;
	__u64 granule;

	ret = uk_rsi_attestation_token_init(challenge, &max_size);
	if (ret != RSI_SUCCESS)
		return ret;

	granule = paddr;

	do {
		__u64 offset = 0;

		do {
			size = GRANULE_SIZE - offset;
			ret = uk_rsi_attestation_token_continue(granule, offset,
								size, len);
			offset += (*len);
		} while (ret == RSI_INCOMPLETE && offset < GRANULE_SIZE);

		if (ret == RSI_INCOMPLETE)
			granule += GRANULE_SIZE;
	} while ((ret == RSI_INCOMPLETE) && (granule < paddr + max_size));

	return ret;
}

rsi_return_t uk_rsi_ipa_state_set_range(__paddr_t base, __paddr_t end,
					rsi_ripas_t ripas,
					rsi_ripas_change_flags_t flags)
{
	__paddr_t new_base, ret;
	__u8 resp;

	/* Iterate over the memory space to set RIPAS */
	while (base != end) {
		ret = uk_rsi_ipa_state_set(base, end, ripas, flags, &new_base,
					   &resp);
		if (ret != RSI_SUCCESS)
			break;
		if (resp == RSI_REJECT) {
			ret = RSI_ERROR_INPUT;
			break;
		}
		base = new_base;
	}
	return ret;
}
