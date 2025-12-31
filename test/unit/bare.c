/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "spic.h"

static void test_valid_int(void **state)
{
	(void) state;

	const struct {
		uint8_t in[16];
		uint64_t out;
	} vectors[] = {
		{{0x00}, 0},
		{{0x01}, 1},
		{{0x7e}, 126},
		{{0x7f}, 127},
		{{0x80, 0x01}, 128},
		{{0x81, 0x01}, 129},
		{{0xff, 0x01}, 255},
		{{0x80, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 0xffffffffffffff00ull},
		{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, 0x7fffffffffffffffull},
		{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 0xffffffffffffffffull},
	};

	uint64_t out;
	int _;
	for (size_t i = 0; i < sizeof(vectors)/sizeof(*vectors); i++) {
		struct bare_buf b;
		bare_buf_init(&b, vectors[i].in, 16);

		_ = bare_read_uint(&b, &out);
		assert_int_equal(_, 0);
		assert_int_equal(out, vectors[i].out);
	}
}

static void test_invalid_int(void **state)
{
	const struct {
		size_t size;
		uint8_t in[16];
	} vectors[] = {
		// too long
		{11, {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}},

		// out of bounds
		{2, {0x80, 0x80}},
	};

	uint64_t out;
	int _;
	for (size_t i = 0; i < sizeof(vectors)/sizeof(*vectors); i++) {
		struct bare_buf b;
		bare_buf_init(&b, vectors[i].in, vectors[i].size);

		_ = bare_read_uint(&b, &out);
		assert_int_equal(_, -1);
	}
}

static void test_int_seq(void **state)
{
	const uint8_t data[] = {0x01, 0x80, 0x01, 0x02};

	struct bare_buf b;
	bare_buf_init(&b, data, sizeof(data));

	uint64_t out;

	assert_int_equal(bare_read_uint(&b, &out), 0);
	assert_int_equal(out, 1);
	assert_int_equal(bare_read_uint(&b, &out), 0);
	assert_int_equal(out, 128);
	assert_int_equal(bare_read_uint(&b, &out), 0);
	assert_int_equal(out, 2);
}

static void test_exact_read(void **state)
{
	(void) state;

	const uint8_t data[] = "sixteen letters.";
	uint8_t out[8];

	struct bare_buf b;
	bare_buf_init(&b, data, sizeof(data)-1);

	assert_int_equal(bare_read_exact(&b, out, 4), 0);
	assert_memory_equal(out, "sixt", 4);

	assert_int_equal(bare_read_exact(&b, out, 0), 0);

	assert_int_equal(bare_read_exact(&b, out, 5), 0);
	assert_memory_equal(out, "een l", 5);

	assert_int_equal(bare_read_exact(&b, NULL, 1), 0);

	assert_int_equal(bare_read_exact(&b, out, 6), 0);
	assert_memory_equal(out, "tters.", 6);

	assert_int_equal(bare_read_exact(&b, out, 1), -1);
	assert_int_equal(bare_read_exact(&b, NULL, 1), -1);

	bare_buf_init(&b, data, sizeof(data)-1);
	assert_int_equal(bare_read_exact(&b, NULL, 16), 0);

	bare_buf_init(&b, data, sizeof(data)-1);
	assert_int_equal(bare_read_exact(&b, NULL, 17), -1);

	bare_buf_init(&b, data, sizeof(data)-1);
	assert_int_equal(bare_read_exact(&b, NULL, SIZE_MAX), -1);

	bare_buf_init(&b, data, sizeof(data)-1);
	assert_int_equal(bare_read_exact(&b, NULL, SIZE_MAX-1), -1);
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_valid_int),
		cmocka_unit_test(test_invalid_int),
		cmocka_unit_test(test_int_seq),
		cmocka_unit_test(test_exact_read),
	};

	return cmocka_run_group_tests_name("bare", tests, NULL, NULL);
}
