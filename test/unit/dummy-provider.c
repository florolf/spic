/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "spic.h"

int spic_ed25519_verify(const uint8_t *public_key,
                        const uint8_t *signature,
                        const uint8_t *message,
                        size_t message_len)
{
	return -1;
}

void spic_sha256_reset(void)
{
}

void spic_sha256_update(const uint8_t *in, size_t inlen)
{
}

void spic_sha256_finish(uint8_t *out)
{
}

void spic_sha256(uint8_t *out, const uint8_t *in, size_t inlen)
{
}
