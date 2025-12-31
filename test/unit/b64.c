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
#include "spic-test.h"

static void test_encode(void **state)
{
	(void) state;

	struct {
		uint8_t in[32];
		const char *out;
	} vectors[] = {
		{
			{
				0x00, 0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00,
				0x40, 0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x02,
				0x00, 0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00,
				0x65, 0xac, 0xf4, 0xf7, 0xef, 0xc0, 0xff, 0xff
			},
			"AAABAAAgAABAAAgAABAAAgAABAAAgAAAZaz09+/A//8=",
		},
		{
			{
				0x0a, 0xa2, 0xc9, 0x41, 0x12, 0x18, 0x96, 0xbb,
				0xd3, 0x38, 0x7a, 0x09, 0xeb, 0x85, 0xf1, 0x98,
				0xee, 0xe1, 0xb9, 0x4e, 0x36, 0xf3, 0x17, 0xc9,
				0x49, 0xc3, 0x2b, 0xf5, 0x0f, 0x4c, 0x1c, 0x40
			},
			"CqLJQRIYlrvTOHoJ64XxmO7huU428xfJScMr9Q9MHEA="
		},
	};

	uint8_t buf[45];
	for (size_t i = 0; i < sizeof(vectors)/sizeof(*vectors); i++) {
		b64_32(buf, vectors[i].in);
		assert_string_equal((char*)buf, vectors[i].out);
	}
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_encode),
	};

	return cmocka_run_group_tests_name("base64", tests, NULL, NULL);
}
