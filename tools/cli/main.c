/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "spic.h"

static uint8_t *slurp(const char *file, size_t *size_out)
{
	FILE *f = fopen(file, "r");
	if (!f) {
		perror("fopen");
		return NULL;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		perror("fseek");
		goto err_fopen;
	}

	long size = ftell(f);
	if (size < 0) {
		perror("ftell");
		goto err_fopen;
	}

	*size_out = size;

	uint8_t *buf = malloc(size);
	if (!buf) {
		perror("malloc");
		goto err_fopen;
	}

	if (fseek(f, 0, SEEK_SET) < 0) {
		perror("fseek2");
		goto err_malloc;
	}

	size_t bytes_read = fread(buf, 1, *size_out, f);
	if (bytes_read != *size_out) {
		fprintf(stderr, "short read: %zu < %ld\n", bytes_read, *size_out);
		goto err_malloc;
	}

	fclose(f);

	return buf;

err_malloc:
	free(buf);
err_fopen:
	fclose(f);

	return NULL;
}

static int16_t nibble(char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';

	c |= 0x20;

	if ('a' <= c && c <= 'f')
		return c - 'a' + 10;

	return -1;
}

static int parse_hex(uint8_t *out, size_t out_space, const char *in)
{
	for (size_t i = 0; in[i]; i++) {
		int16_t n = nibble(in[i]);
		if (n < 0) {
			fprintf(stderr, "invalid hex nibble '%c'\n", in[i]);
			return -1;
		}

		if (i/2 >= out_space) {
			fprintf(stderr, "hex input '%s' overflows %zu byte buffer", in, out_space);
			return -1;
		}

		if (i % 2 == 0)
			out[i/2] = (uint8_t)n << 4;
		else
			out[i/2] |= (uint8_t)n;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	bool verbose = false;
	bool raw_hash = false;

	uint8_t *policy = NULL;
	uint8_t *proof = NULL;
	uint8_t *pubkeys = NULL;
	size_t policy_size, proof_size, n_pubkeys;

	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, 0, 'v'},
			{"raw-hash", no_argument, 0, 'r'},
			{0, 0, 0, 0}
		};

		int option_index;
		int c = getopt_long(argc, argv, "vr", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'v':
				verbose = true;
				break;
			case 'r':
				raw_hash = true;
				break;
		}
	}

	if (argc - optind < 3) {
		fprintf(stderr, "usage: %s [--verbose|-v] [--raw-hash|-r] policy-path proof-path leaf-pubkey [leaf-pubkey...]\n", argv[0]);
		goto out;
	}

	policy = slurp(argv[optind++], &policy_size);
	if (!policy) {
		fprintf(stderr, "failed to load policy\n");
		goto out;
	}

	proof = slurp(argv[optind++], &proof_size);
	if (!proof) {
		fprintf(stderr, "failed to load proof\n");
		goto out;
	}

	n_pubkeys = argc - optind;
	pubkeys = calloc(n_pubkeys, 32);
	for (size_t i = 0; i < n_pubkeys; i++) {
		if (parse_hex(&pubkeys[32 * i], 32, argv[optind++]) < 0) {
			fprintf(stderr, "parsing pubkey %zu failed\n", i);
			goto out;
		}
	}

	uint8_t hash[32];
	if (!raw_hash) {
		static EVP_MD_CTX *sha256_evp_ctx;
		sha256_evp_ctx = EVP_MD_CTX_new();

		EVP_DigestInit_ex(sha256_evp_ctx, EVP_sha256(), NULL);

		uint8_t buf[BUFSIZ];
		ssize_t bytes_read;
		while (1) {
			bytes_read = read(STDIN_FILENO, buf, sizeof(buf));
			if (bytes_read < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;

				perror("read");
				EVP_MD_CTX_free(sha256_evp_ctx);
				goto out;
			} else if (bytes_read == 0) {
				EVP_DigestFinal_ex(sha256_evp_ctx, hash, NULL);
				EVP_MD_CTX_free(sha256_evp_ctx);
				break;
			}

			EVP_DigestUpdate(sha256_evp_ctx, buf, bytes_read);
		}
	} else {
		uint8_t buf[BUFSIZ];
		size_t fill = 0;

		while (1) {
			ssize_t bytes_read;
			bytes_read = read(STDIN_FILENO, &buf[fill], sizeof(buf)-fill);
			if (bytes_read < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;

				perror("read");
				goto out;
			} else if (bytes_read == 0) {
				break;
			}

			fill += (size_t)bytes_read;
		}

		if (fill == 32) {
			memcpy(hash, buf, 32);
		} else if (fill == 64 || (fill == 65 && buf[64] == '\n')) {
			buf[64] = 0;
			if (parse_hex(hash, 32, (char*)buf) < 0) {
				fprintf(stderr, "failed to parse hex input to --raw-hash\n");
				goto out;
			}
		} else {
			fprintf(stderr, "unexpected input for --raw-hash (must be either: 64 hex characters with optional newline or 32 raw bytes)\n");
			goto out;
		}
	}

	uint8_t scratch[SPIC_SCRATCH_SIZE_REQUIRED];
	enum spic_result result;
	result = spic_verify(hash,
	                     proof, proof_size,
	                     pubkeys, n_pubkeys,
	                     policy, policy_size,
	                     scratch);

	const char * const results[] = {
		"SPIC_OK",
		"SPIC_ENCODING_ERROR",
		"SPIC_INVALID_KEY_ID",
		"SPIC_INVALID_LEAF_SIGNATURE",
		"SPIC_INVALID_INCLUSION_PROOF",
		"SPIC_INVALID_LOG_KEY",
		"SPIC_INVALID_ROOT_SIGNATURE",
		"SPIC_INVALID_WITNESS",
		"SPIC_INVALID_COSIGNATURE",
		"SPIC_BYTECODE_EVAL_FAILURE",
		"SPIC_QUORUM_UNSATISFIED",
	};

	if (verbose || result != SPIC_OK)
		fprintf(stderr, "%s\n", results[-result]);

	if (result == SPIC_OK)
		ret = EXIT_SUCCESS;

out:
	free(pubkeys);
	free(policy);
	free(proof);

	return ret;
}
