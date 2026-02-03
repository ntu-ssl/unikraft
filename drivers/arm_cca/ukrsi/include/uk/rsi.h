/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_RSI_H__
#define __UK_RSI_H__

#include <stddef.h>
#include <uk/asm/rsi.h>
#include "uk/arch/types.h"
#include "uk/essentials.h"

typedef __u64 rsi_return_t;
typedef __u64 rsi_version_t;
typedef __u8 rsi_response_t;
typedef __u8 rsi_ripas_t;
typedef __u64 rsi_ripas_change_flags_t;
typedef __u8 rsi_rpv_t[64];

extern __u64 uk_rsi_unprotected_mask;
#define PTE_RME_UNPROTECTED_BIT ((uk_rsi_unprotected_mask))

#define GRANULE_SIZE 4096 /* 4KB Granule size */

#define RSI_VERSION_1_0 0x00010000

enum rsi_hash_alg : __u8 {
	RSI_HASH_SHA_256 = 0,
	RSI_HASH_SHA_512 = 1,
};

/* RsiRealmConfig type */
#define RSI_RPV_OFFSET 0x200
struct rsi_realm_config {
	__u64 ipa_width;	     /* IPA width in bits */
	enum rsi_hash_alg hash_algo; /* Hash algorithm */

	__u8 __padding[RSI_RPV_OFFSET - sizeof(__u64) - sizeof(__u8)];

	rsi_rpv_t rpv; /* Realm Personalization Value, Bits512 */
} __packed __align(GRANULE_SIZE);

UK_CTASSERT(offsetof(struct rsi_realm_config, ipa_width) == 0x0);
UK_CTASSERT(offsetof(struct rsi_realm_config, hash_algo) == 0x8);
UK_CTASSERT(offsetof(struct rsi_realm_config, rpv) == 0x200);

struct rsi_host_call_data {
	__u16 imm;	/* Immediate value */
	__u64 gprs[31]; /* Registers */
};

/**
 * Continue the operation to retrieve an attestation token.
 *
 * @param paddr IPA of the Granule to which the token will be written
 * @param offset Offset within Granule to start of buffer in bytes
 * @param size Size of buffer in bytes
 * @param[out] len Number of bytes written to buffer
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_attestation_token_continue(__paddr_t paddr, __u64 offset,
					       __u64 size, __u64 *len);

/**
 * Initialize the operation to retrieve an attestation token.
 *
 * @param challenge Challenge value
 * @param[out] size Upper bound on attestation token size in bytes
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_attestation_token_init(__u64 challenge[8], __u64 *size);

/**
 * Make a Host call.
 *
 * @param paddr IPA of the Host call data structure
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_host_call(__u64 paddr);

/**
 * Get RIPAS of a target IPA range.
 *
 * @param base Base of target IPA region
 * @param top End of target IPA region
 * @param[out] out_top Top of IPA region which has the reported RIPAS value
 * @param[out] ripas RIPAS value
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_ipa_state_get(__paddr_t base, __paddr_t top,
				  __paddr_t *out_top, rsi_ripas_t *ripas);

/**
 * Request RIPAS of a target IPA range to be changed to a specified value.
 *
 * @param base Base of target IPA region
 * @param top Top of target IPA region
 * @param ripas RIPAS value
 * @param flags Flags
 * @param[out] new_base Base of IPA region which was not modified by the command
 * @param[out] response Whether the Host accepted or rejected the request
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_ipa_state_set(__paddr_t base, __paddr_t top,
				  rsi_ripas_t ripas,
				  rsi_ripas_change_flags_t flags,
				  __paddr_t *new_base,
				  rsi_response_t *response);

/**
 * Extend Realm Extensible Measurement (REM) value.
 *
 * @param index Measurement index
 * @param size Measurement size in bytes
 * @param value The measurement value
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_measurement_extend(__u64 index, __u64 size, __u64 value[8]);

/**
 * Read measurement for the current Realm.
 *
 * @param index Measurement index
 * @param[out] value The Realm measurement identified by “index”
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_measurement_read(__u64 index, __u64 value[8]);

/**
 * Read configuration for the current Realm.
 *
 * @param addr IPA of the Granule to which the configuration will be written
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_realm_config(struct rsi_realm_config *out);

/**
 * Returns RSI version.
 *
 * @param req Requested interface version
 * @param[out] lower Lower implemented interface version
 * @param[out] higher Higher implemented interface version
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_version(rsi_version_t req, rsi_version_t *lower,
			    rsi_version_t *higher);

/**
 * Initialize the RSI interface.
 */
void uk_rsi_init(void);

/**
 * Generate an attestation token. This function wraps up calls to
 * uk_rsi_attestation_token_init and uk_rsi_attestation_token_continue.
 *
 * @param addr IPA of the Granule to which the token will be written
 * @param challenge Challenge value
 * @param[out] size Attestation token size in bytes
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_generate_attestation_token(__u64 addr, __u64 challenge[8],
					       __u64 *size);

/**
 * Set the RIPAS on a range of memory. This function wraps up calls to
 * uk_rsi_ipa_state_set.
 *
 * @param base The base address of the memory range
 * @param end The end address of the memory range
 * @param ripas The RIPAS value
 *
 * @return Command return status
 */
rsi_return_t uk_rsi_ipa_state_set_range(__paddr_t base, __paddr_t end,
					rsi_ripas_t ripas,
					rsi_ripas_change_flags_t flags);

#endif /* __UK_RSI_H__ */
