/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Benjamin Higgins, Tzu-Hao Lin
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

#ifndef __UKARCH_RSI_H__
#define __UKARCH_RSI_H__

#define RSI_CMD_ATTESTATION_TOKEN_CONTINUE	0xC4000195
#define RSI_CMD_ATTESTATION_TOKEN_INIT		0xC4000194
#define RSI_CMD_FEATURES					0xC4000191
#define RSI_CMD_HOST_CALL					0xC4000199
#define RSI_CMD_IPA_STATE_GET				0xC4000198
#define RSI_CMD_IPA_STATE_SET				0xC4000197
#define RSI_CMD_MEASUREMENT_EXTEND			0xC4000193
#define RSI_CMD_MEASUREMENT_READ			0xC4000192
#define RSI_CMD_REALM_CONFIG				0xC4000196
#define RSI_CMD_VERSION						0xC4000190

/**
 * RsiCommandReturnCode type
 */
#define RSI_SUCCESS			0x0
#define RSI_ERROR_INPUT		0x1
#define RSI_ERROR_STATE		0x2
#define RSI_INCOMPLETE		0x3
#define RSI_ERROR_UNKNOWN	0x4

/* RsiRipas type */
#define RSI_RIPAS_EMPTY		0x0
#define RSI_RIPAS_RAM		0x1
#define RSI_RIPAS_DESTROYED	0x2
#define RSI_RIPAS_DEV		0x3

/* Version shift */
#define RSI_VERSION_MAJOR_SHIFT	16
#define RSI_VERSION_MAJOR_MASK	0x7fff
#define RSI_VERSION_MINOR_SHIFT	0
#define RSI_VERSION_MINOR_MASK	0xffff

/* RsiResponse type */
#define RSI_ACCEPT 0
#define RSI_REJECT 1

/* RsiRipasChangeFlags */
#define RSI_RIPAS_CHANGE_DESTROYED 1

#endif /* __UKARCH_RSI_H__ */
