# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import hashlib
import base64
import nacl.signing

from typing import Optional

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def derive(string: str) -> tuple[bytes, bytes]:
    priv_bytes = sha256(string.encode())
    priv = nacl.signing.SigningKey(priv_bytes)
    return priv_bytes, bytes(priv.verify_key)


class PRNG:
    def __init__(self, seed: bytes):
        self.seed = seed

    def get_named(self, name: str) -> bytes:
        return sha256(self.seed + name.encode())

    def get_named_int(self, name: str, limit: Optional[int] = None) -> int:
        b = self.get_named(name)
        i = int.from_bytes(b[:8])

        if limit is not None:
            i = i % limit

        return i
