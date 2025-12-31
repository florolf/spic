/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#ifndef SPIC_H
#define SPIC_H

#include <stdint.h>
#include <stddef.h>

/*
 * Functions that need to be supplied externally
 */

int spic_ed25519_verify(const uint8_t *public_key,
                        const uint8_t *signature,
                        const uint8_t *message,
                        size_t message_len);

void spic_sha256_reset(void);
void spic_sha256_update(const uint8_t *in, size_t inlen);
void spic_sha256_finish(uint8_t *out);

void spic_sha256(uint8_t *out, const uint8_t *in, size_t inlen);

/*
 * BARE decoder
 */

#if defined(SPIC_EXPOSE_BARE) || defined(SPIC_INTERNAL)
struct bare_buf {
	const uint8_t *p, *end;
};

static inline void bare_buf_init(struct bare_buf *buf, const uint8_t *data, size_t len)
{
	buf->p = data;
	buf->end = buf->p + len;
}
#endif

#if defined(SPIC_EXPOSE_BARE)
int bare_read_uint(struct bare_buf *buf, uint64_t *out);
int bare_read_uint32(struct bare_buf *buf, uint32_t *out);
const uint8_t *bare_fetch_exact(struct bare_buf *buf, size_t len);
int bare_read_exact(struct bare_buf *buf, void *out, size_t len);
#endif

/*
 * Verifier API
 */

enum spic_result {
	SPIC_OK = 0,

	SPIC_ENCODING_ERROR = -1,
	SPIC_INVALID_KEY_ID = -2,
	SPIC_INVALID_LEAF_SIGNATURE = -3,
	SPIC_INVALID_INCLUSION_PROOF = -4,
	SPIC_INVALID_LOG_KEY = -5,
	SPIC_INVALID_ROOT_SIGNATURE = -6,
	SPIC_INVALID_WITNESS = -7,
	SPIC_INVALID_COSIGNATURE = -8,
	SPIC_BYTECODE_EVAL_FAILURE = -9,
	SPIC_QUORUM_UNSATISFIED = -10,
};

#define SPIC_SCRATCH_SIZE_REQUIRED 189

/*
 * hash is the 32 byte "message" value as supplied to the /add-leaf log API
 * endpoint.
 *
 * proof_data/proof_size is the compiled proof that is to be verified.
 *
 * pubkeys contains one or more 32-byte Ed25519 public keys one after another.
 * n_pubkeys is the number of public keys supplied.
 *
 * policy_data/policy_size is the compiled policy used to verify the proof.
 *
 * scratch is a buffer of at least SPIC_SCRATCH_SIZE_REQUIRED bytes. It can be
 * uninitialized and has no alignment requirements.
 *
 * spic_verify returns 0 (SPIC_OK) when the proof is valid and a negative
 * number otherwise. See enum spic_result for possible error cases.
 */

enum spic_result spic_verify(
	const uint8_t *hash,
	const uint8_t *proof_data, size_t proof_size,
	const uint8_t *pubkeys, size_t n_pubkeys,
	const uint8_t *policy_data, size_t policy_size,
	uint8_t *scratch
);

#endif /* SPIC_H */
