/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SPIC_INTERNAL
#include "spic.h"

#define checked(expr, ret) do {\
	if ((expr) < 0) \
		return (ret); \
} while (0)

#define notnull(lvalue, expr, ret) do {\
	(lvalue) = (expr); \
	if ((lvalue) == NULL) \
		return (ret); \
} while (0)

/*
 * BARE decoder
 */

#ifdef SPIC_EXPOSE_BARE
#define SPIC_STATIC
#else
#define SPIC_STATIC static
#endif

SPIC_STATIC int bare_read_uint(struct bare_buf *buf, uint64_t *out)
{
	uint8_t shift = 0;
	uint64_t val = 0;

	while (1) {
		if (buf->p == buf->end)
			return -1;

		uint8_t c = *(buf->p++);
		val |= ((uint64_t)c & 0x7f) << shift;
		if (!(c & 0x80))
			break;

		if (shift == 63)
			return -1;

		shift += 7;
	}

	if (out)
		*out = val;

	return 0;
}

SPIC_STATIC int bare_read_uint32(struct bare_buf *buf, uint32_t *out)
{
	uint64_t val;
	if (bare_read_uint(buf, &val) < 0)
		return -1;

	if (val > UINT32_MAX)
		return -1;

	if (out)
		*out = val;

	return 0;
}

SPIC_STATIC const uint8_t *bare_fetch_exact(struct bare_buf *buf, size_t len)
{
	if ((size_t)(buf->end - buf->p) < len)
		return NULL;

	const uint8_t *out = buf->p;
	buf->p += len;

	return out;
}

SPIC_STATIC int bare_read_exact(struct bare_buf *buf, void *out, size_t len)
{
	const uint8_t *p = bare_fetch_exact(buf, len);
	if (!p)
		return -1;

	if (out)
		memcpy(out, p, len);

	return 0;
}

/*
 * Encoding helpers
 */

#undef SPIC_STATIC
#ifdef SPIC_INTERNAL_TESTEXPOSE
#define SPIC_STATIC
#include "spic-test.h"
#else
#define SPIC_STATIC static
#endif

static inline uint8_t b64c(uint8_t v)
{
	if (v < 26)
		return 'A' + v;
	v -= 26;

	if (v < 26)
		return 'a' + v;
	v -= 26;

	if (v < 10)
		return '0' + v;

	return (v == 10) ? '+' : '/';
}

SPIC_STATIC void b64_32(uint8_t out[static 45], const uint8_t in[static 32])
{
	for (size_t i = 0; i < 11; i++) {
		*out++ = b64c((in[0] >> 2) & 0x3F);
		*out++ = b64c(((in[0] & 0x03) << 4) | ((in[1] >> 4) & 0x0F));

		if (i != 10) {
			*out++ = b64c(((in[1] & 0x0F) << 2) | ((in[2] >> 6) & 0x03));
			*out++ = b64c(in[2] & 0x3F);
		} else {
			*out++ = b64c((in[1] & 0x0F) << 2);
		}

		in += 3;
	}

	*out++ = '=';
	*out++ = 0;
}

static inline uint8_t hex_nibble(uint8_t v)
{
	if (v < 10)
		return '0' + v;
	v -= 10;

	return 'a' + v;
}

static void encode_hex(uint8_t *out, uint8_t *in, size_t len)
{
	while (len--) {
		*out++ = hex_nibble((*in >> 4) & 0x0f);
		*out++ = hex_nibble((*in >> 0) & 0x0f);

		in++;
	}
}

static uint8_t *encode_dec(uint8_t *out_lsd, uint64_t in)
{
	/* Special case: Sigsum only allows integers in the range [0..2**63-1].
	 * To avoid having to handle this corner case everywhere, just clobber
	 * the value here - this will make all the signatures based on this
	 * data invalid.
	 *
	 * Technically, this introduces other ways to encode a "0" value into
	 * the proof format, but there is no practical reason why a proof
	 * representation should have to be unique anyway. */
	if (in & (1ull<<63))
		in = 0;

	do {
		*out_lsd-- = '0' + (in % 10);
		in /= 10;
	} while (in);

	out_lsd++;

	return out_lsd;
}

/*
 * Verifier proper
 */

static enum spic_result walk_inclusion_proof(struct bare_buf *proof, uint8_t *scratch, uint64_t leaf_index, uint64_t tree_size)
{
	/* 1. Compare leaf_index from the inclusion_proof_v2 structure against
	 * tree_size. If leaf_index is greater than or equal to tree_size, then
	 * fail the proof verification.*/
	if (leaf_index >= tree_size)
		return SPIC_INVALID_INCLUSION_PROOF;

	/* 2. Set fn to leaf_index and sn to tree_size - 1. */
	uint64_t fn = leaf_index;
	uint64_t sn = tree_size - 1;

	/* 3. Set r to hash. Already done by the caller. */

	/* 4. For each value p in the inclusion_path array: */
	uint32_t proof_steps;
	checked(bare_read_uint32(proof, &proof_steps), SPIC_ENCODING_ERROR);

	for (uint32_t i = 0; i < proof_steps; i++) {
		/* a. If sn is 0, then stop the iteration and fail the proof
		 * verification. */
		if (sn == 0)
			return SPIC_INVALID_INCLUSION_PROOF;

		checked(bare_read_exact(proof, &scratch[32], 32), SPIC_ENCODING_ERROR);

		uint8_t one[1];
		one[0] = 1;
		spic_sha256_reset();
		spic_sha256_update(one, 1);

		/* b. If LSB(fn) is set, or if fn is equal to sn, then: */
		if ((fn & 1) || (fn == sn)) {
			/* i. Set r to HASH(0x01 || p || r). */
			spic_sha256_update(&scratch[32], 32);
			spic_sha256_update(&scratch[0], 32);

			/* ii. If LSB(fn) is not set, then right-shift both fn
			 * and sn equally until either LSB(fn) is set or fn is
			 * 0. */
			if (!(fn & 1)) {
				do {
					fn >>= 1;
					sn >>= 1;
				} while (!((fn&1) || (fn == 0)));
			}
			/* Otherwise: */
		} else {
			/* i. Set r to HASH(0x01 || r || p). */
			spic_sha256_update(&scratch[0], 32);
			spic_sha256_update(&scratch[32], 32);
		}

		spic_sha256_finish(&scratch[0]);

		/* c. Finally, right-shift both fn and sn one time. */
		fn >>= 1;
		sn >>= 1;
	}

	/* 5. Compare sn to 0. Compare r against the root_hash. If sn is equal
	 * to 0 and r and the root_hash are equal, then the log has proven the
	 * inclusion of hash. Otherwise, fail the proof verification. */

	if (sn != 0)
		return SPIC_INVALID_INCLUSION_PROOF;

	/* Root hash will be checked by caller */

	return SPIC_OK;
}

static enum spic_result policy_fetch_key(const uint8_t **out, struct bare_buf *policy, uint32_t key_idx)
{
	uint32_t log_keys;
	checked(bare_read_uint32(policy, &log_keys), SPIC_ENCODING_ERROR);

	if (key_idx >= log_keys)
		return SPIC_INVALID_LOG_KEY;

	for (size_t i = 0; i < log_keys; i++) {
		const uint8_t *p;

		notnull(p, bare_fetch_exact(policy, 32), SPIC_ENCODING_ERROR);
		if (i == key_idx)
			*out = p;
	}

	return SPIC_OK;
}

enum spic_result spic_verify(
	const uint8_t *hash,
	const uint8_t *proof_data, size_t proof_size,
	const uint8_t *pubkeys, size_t n_pubkeys,
	const uint8_t *policy_data, size_t policy_size,
	uint8_t *scratch
) {
	enum spic_result ret;

	struct bare_buf proof, policy;
	bare_buf_init(&proof, proof_data, proof_size);
	bare_buf_init(&policy, policy_data, policy_size);

	/*
	 * Step 1: Handle the leaf
	 */

	// Step 1.1: Check the leaf signature
	uint32_t key_index;
	checked(bare_read_uint32(&proof, &key_index), SPIC_ENCODING_ERROR);
	if (key_index >= n_pubkeys)
		return SPIC_INVALID_KEY_ID;

	const uint8_t *pubkey = &pubkeys[32 * key_index];

	/*
	 * Scratch layout during this step
	 *
	 *   [0..23]    24 bytes: "sigsum.org/v1/tree-leaf\x00"
	 *   [24..55]   32 bytes: SHA256(hash) (a.k.a. the checksum in the leaf)
	 *   [56..119]  64 bytes: leaf signature
	 *   [120..151] 32 bytes: SHA256(pubkey)
	 *
	 * We use this specific layout to be able to to first verify the leaf
	 * signature (which is computed over bytes 0 to 55) and then compute
	 * the leaf hash in Step 1.2 (which utilizes the last three entries
	 * above).
	 */

	memcpy(&scratch[0], "sigsum.org/v1/tree-leaf", 24);
	spic_sha256(&scratch[24], hash, 32);
	checked(bare_read_exact(&proof, &scratch[24+32], 64), SPIC_ENCODING_ERROR);
	spic_sha256(&scratch[24+32+64], pubkey, 32);

	if (spic_ed25519_verify(pubkey, &scratch[24+32], &scratch[0], 56) < 0)
		return SPIC_INVALID_LEAF_SIGNATURE;

	/*
	 * Step 1.2: Calculate the leaf hash
	 *
	 * We reuse the data staged by Step 1.1 - bytes 24 to 151 exactly
	 * constitute a Sigsum leaf.
	 *
	 * Additionally, since a leaf hash is defined as HASH('\x00' +
	 * leaf_data), we can also reuse the NUL byte from the domain separator
	 * in byte 23 here.
	 *
	 * Note that this step outputs data (namely the leaf hash) into bytes 0
	 * to 31 which overrides the data we are consuming for the hash, so
	 * whatever implementation we use spic_sha256 needs to handle this case
	 * correctly. However, given how SHA256 implementations usually work
	 * (absorbing input data into some internal state first), this should
	 * not be a problem.
	 */

	spic_sha256(&scratch[0], &scratch[23], 1 + 32 + 64 + 32);

	/*
	 * Step 2: Calculate and verify the log checkpoint
	 */

	/*
	 * Step 2.1: Walk inclusion proof to generate root hash
	 *
	 * Scratch layout during this step:
	 *
	 *   [0..31]  32 bytes: "r" in the inclusion proof verification algorithm
	 *   [32..63] 32 bytes: "p" in the inclusion proof verification algorithm
	 *
	 * Note that we start out with "r" already initialized correctly to the
	 * leaf hash value by the previous step. After this step has finished,
	 * bytes 0 to 31 will instead contain the root hash implied by the
	 * inclusion proof, which we will then use to construct and verify the
	 * checkpoint in the next step.
	 *
	 * XXX possible future improvement: If we place the root hash at
	 * [33..64] we could place the sibling hash before ([1..32] and [0] for
	 * the \x01 byte) or after ([64..95] and [32] for the \0x01 byte) it
	 * while processing the inclusion proof. This would remove the only
	 * place where we actually rely on having a streaming SHA256 API
	 * available, easing the burden on what the crypto provider needs to
	 * support.
	 *
	 * Note that this would then require a memmove() of the resulting hash
	 * to make space for the checkpoint construction in the next step.
	 */

	uint64_t tree_size, leaf_index;
	checked(bare_read_uint(&proof, &tree_size), SPIC_ENCODING_ERROR);
	checked(bare_read_uint(&proof, &leaf_index), SPIC_ENCODING_ERROR);

	ret = walk_inclusion_proof(&proof, scratch, leaf_index, tree_size);
	if (ret != SPIC_OK)
		return ret;

	/*
	 * Step 2.2: Render the checkpoint body
	 *
	 * This part is a bit tricky since it involves formatting decimal
	 * numbers (namely the tree size and later also the cosignature
	 * timestamp) in a variable-width fashion.
	 *
	 * For this, note that Sigsum limits all integers to [0..2**63-1]
	 * rather than the full 64 bits, so the maximum value we will ever see
	 * here is 9223372036854775807 (19 digits). Thus, the worst-case
	 * checkpoint is:
	 *
	 *  sigsum.org/v1/tree/0000000000000000000000000000000000000000000000000000000000000000\n
	 *  9223372036854775807\n
	 *  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n
	 *
	 * -> 149 bytes
	 *
	 * Cosignatures prepend a prefix to this checkpoint:
	 *
	 *   cosignature/v1\n
	 *   time 9223372036854775807\n
	 *
	 * -> 40 bytes
	 *
	 * Thus, we reserve [0..39] for the prefix we'll add later when we are
	 * verifying cosignatures. This also conveniently leaves [0..31]
	 * unclobbered for now so we can leave the root hash sitting there for
	 * now until we format it to base64 later in this step.
	 *
	 * The checkpoint iself is then placed in the area [40..188]:
	 *
	 *   [40..58]    19 bytes: origin prefix "sigsum.org/v1/tree/"
	 *   [59..122]   64 bytes: origin suffix (hex-encoded log keyhash)
	 *   [123]       '\n'
	 *
	 *   [124..x]    19 bytes max: decimal tree size
	 *   [x+1]       '\n'
	 *   [x+2..x+45] 44 bytes: base64 encoded root_hash (32 bytes raw -> 44 bytes
	 *               encoded)
	 *   [x+46]      '\n'
	 *
	 * Since x is 142 (124 + 19 - 1) in the worst case, the final '\n' is
	 * at index 188 in the worst case. This is also the highest scratch
	 * usage we have during this entire function, resulting in a
	 * SPIC_SCRATCH_SIZE_REQUIRED value of 189.
	 *
	 * We format the various bits of the checkpoint out-of-order since we
	 * need 32 bytes of space to hash the log key to (so we can hex-encode
	 * it into the origin line). However, the only space we have [0..39] is
	 * currently occupied by the root hash and we can't reuse it until we
	 * have rendered the base64 root hash line. However, the position of
	 * *that* depends on how long the decimal tree_size ends up being.
	 * Thus, we need to start with that, then format the root hash and only
	 * then can we place the origin line.
	 */

	/* After this, p points to the last digit of tree_size, p2 to the
	 * first. The length of the formatted number is p-p2+1. */
	uint8_t *p = &scratch[142];
	uint8_t *p2 = encode_dec(p, tree_size);
	memmove(&scratch[124], p2, p-p2+1);

	/* Make p point to where the newline after tree_size should go
	 * ([x+46]). */
	p = &scratch[124 + p-p2+1];
	*p++ = '\n';

	/* Format root_hash. After this, p points to the first byte *after* the
	 * complete checkpoint. We use this for various size calculations
	 * below. */
	b64_32(p, &scratch[0]);
	p += 44;
	*p++ = '\n';

	/* Now we can finally format the origin line */
	checked(bare_read_uint32(&proof, &key_index), SPIC_ENCODING_ERROR);

	const uint8_t *log_key;
	ret = policy_fetch_key(&log_key, &policy, key_index);
	if (ret != SPIC_OK)
		return ret;

	/* Root hash is not needed anymore, so we can put the keyhash there */
	spic_sha256(&scratch[0], log_key, 32);

	memcpy(&scratch[40], "sigsum.org/v1/tree/", 19);
	encode_hex(&scratch[59], &scratch[0], 32);
	scratch[123] = '\n';

	// Step 2.3: Verify the checkpoint signature
	const uint8_t *sig;
	notnull(sig, bare_fetch_exact(&proof, 64), SPIC_ENCODING_ERROR);
	if (spic_ed25519_verify(log_key, sig, &scratch[40], p - &scratch[40]) < 0)
		return SPIC_INVALID_ROOT_SIGNATURE;

	/*
	 * Step 3: Verify the witness quorum
	 */

	/*
	 * Step 3.1: Check witness cosignatures
	 *
	 * Here, we reuse the checkpoint we already placed into the scratch
	 * area before and prepend the various cosignature prefixes in the area
	 * [0..39]. Since these depend on the individual witness timestamps,
	 * the can vary in content as well as in size (although it will only
	 * happen in the *very* rare cases where a timestamp rolls over to a
	 * new power of ten).
	 *
	 * Here, we work backwards. [39] will always be the final newline of
	 * the cosignature prefix. [38] is the last digit of the formatted
	 * timestamp and [x] is the first. This is what p2 will point to after
	 * the encode_dec call below.
	 *
	 * Then we prepend the fixed prefix "cosignature/v1\ntime " (20 bytes).
	 * This means writing it to the range [x-20..x-1]. Thus, the final
	 * cosignature payload ranges from p2-20 to the byte before p.
	 */

	uint64_t witness_word = 0;
	uint64_t timestamp = 0;

	uint32_t policy_witness_count;
	const uint8_t *policy_witness_pubkeys;
	checked(bare_read_uint32(&policy, &policy_witness_count), SPIC_ENCODING_ERROR);
	notnull(policy_witness_pubkeys, bare_fetch_exact(&policy, 32*policy_witness_count), SPIC_ENCODING_ERROR);

	scratch[39] = '\n';

	uint32_t cosignature_count;
	checked(bare_read_uint32(&proof, &cosignature_count), SPIC_ENCODING_ERROR);
	for (uint32_t i = 0; i < cosignature_count; i++) {
		uint64_t timestamp_delta;
		checked(bare_read_uint(&proof, &timestamp_delta), SPIC_ENCODING_ERROR);
		timestamp += timestamp_delta;

		p2 = encode_dec(&scratch[38], timestamp);
		memcpy(p2-20, "cosignature/v1\ntime ", 20);

		checked(bare_read_uint32(&proof, &key_index), SPIC_ENCODING_ERROR);
		if (key_index >= policy_witness_count)
			return SPIC_INVALID_WITNESS;

		notnull(sig, bare_fetch_exact(&proof, 64), SPIC_ENCODING_ERROR);
		if (spic_ed25519_verify(&policy_witness_pubkeys[32*key_index], sig, p2-20, p - (p2-20)) < 0)
			return SPIC_INVALID_COSIGNATURE;

		witness_word |= (uint64_t)1 << key_index;
	}

	uint32_t bytecode_len;
	checked(bare_read_uint32(&policy, &bytecode_len), SPIC_ENCODING_ERROR);

	const uint8_t *bytecode;
	notnull(bytecode, bare_fetch_exact(&policy, bytecode_len), SPIC_ENCODING_ERROR);

	bare_buf_init(&policy, bytecode, bytecode_len);

	/*
	 * Step 3.2: Bytecode quorum evaluation
	 *
	 * At this point, neither the checkpoint text nor the cosignature
	 * prefix is needed anymore. Thus, we can reuse the entire scratch
	 * space as the stack for our quorum bytecode evaluator.
	 *
	 * Here, p always points to the next free stack slot. So pushing to the
	 * stack means doing
	 *
	 *   *p-- = ...;
	 *
	 * And popping means
	 *
	 *   ... = *++p;
	 */

	p = &scratch[188];

	while (policy.p < policy.end) {
		uint32_t sum = 0;

		uint32_t flags_and_threshold;
		checked(bare_read_uint32(&policy, &flags_and_threshold), SPIC_ENCODING_ERROR);

		uint32_t tmp;
		// pop a group result from the stack
		if (flags_and_threshold & 1) {
			checked(bare_read_uint32(&policy, &tmp), SPIC_ENCODING_ERROR);
			while (tmp--) {
				if (p == &scratch[188])
					return SPIC_BYTECODE_EVAL_FAILURE;

				p++;
				sum += *p;
			}
		}

		// check a range of cosignatures
		if (flags_and_threshold & 2) {
			checked(bare_read_uint32(&policy, &tmp), SPIC_ENCODING_ERROR);
			while (tmp--) {
				if (witness_word & 1)
					sum++;

				witness_word >>= 1;
			}
		}

		if (p == &scratch[0])
			return SPIC_BYTECODE_EVAL_FAILURE;

		if (sum >= (flags_and_threshold >> 2))
			*p-- = 1;
		else
		 	*p-- = 0;
	}

	p++;
	if (p != &scratch[188] || *p != 1)
		return SPIC_QUORUM_UNSATISFIED;

	return SPIC_OK;
}
