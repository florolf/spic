# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import hashlib

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
