/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "../spic.h"

static EVP_MD_CTX *sha256_evp_ctx;

int spic_ed25519_verify(const uint8_t *public_key,
                        const uint8_t *signature,
                        const uint8_t *message,
                        size_t message_len)
{
	int ret = -1;

	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
	if (!pkey) {
		goto out;
	}

	EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!pkey_ctx)
		goto out_pkey;

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	if (!md_ctx)
		goto out_pkey_ctx;

	EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

	if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, NULL, NULL, pkey) <= 0)
		goto out_md_ctx;

        if (EVP_DigestVerify(md_ctx, signature, 64, message, message_len) == 1)
		ret = 0;

out_md_ctx:
	EVP_MD_CTX_free(md_ctx);
out_pkey_ctx:
	EVP_PKEY_CTX_free(pkey_ctx);
out_pkey:
	EVP_PKEY_free(pkey);
out:
	return ret;
}

void spic_sha256(uint8_t *out, const uint8_t *in, size_t inlen)
{
	if (!sha256_evp_ctx)
		sha256_evp_ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(sha256_evp_ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(sha256_evp_ctx, in, inlen);
	EVP_DigestFinal_ex(sha256_evp_ctx, out, NULL);
}
