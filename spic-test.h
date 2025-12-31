/*
 * SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
 */

#pragma once

#include <stdint.h>

void b64_32(uint8_t out[static 45], const uint8_t in[static 32]);
