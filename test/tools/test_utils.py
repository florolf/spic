# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import hashlib
import base64

from nacl.signing import SigningKey, VerifyKey
from pathlib import Path

from typing import Optional

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def derive_key(string: str) -> SigningKey:
    priv_bytes = sha256(string.encode())
    return SigningKey(priv_bytes)


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


def read_policy(file: Path) -> tuple[list[str], list[str]]:
    logs = []
    witnesses = []

    policy = file.read_text()
    for line in policy.splitlines():
        if line.startswith('log '):
            _, _, url = line.split()
            logs.append(url)
        elif line.startswith('witness '):
            _, name, _= line.split(maxsplit=2)
            witnesses.append(name)

    return logs, witnesses


def make_leaf(key: SigningKey, message_hash: bytes) -> bytes:
    if len(message_hash) != 32:
        raise ValueError('invalid message hash')

    checksum = sha256(message_hash)
    sig = key.sign(b'sigsum.org/v1/tree-leaf\x00' + checksum).signature

    return checksum + sig + sha256(bytes(key.verify_key))


def format_checkpoint(key: VerifyKey, tree_size: int, root_hash) -> str:
    checkpoint = f'sigsum.org/v1/tree/{sha256(bytes(key)).hex()}\n'
    checkpoint += '%d\n' % tree_size
    checkpoint += b64enc(root_hash) + '\n'

    return checkpoint


def cosign_root(key: SigningKey, timestamp: int, checkpoint: str) -> bytes:
    data = f'cosignature/v1\ntime {timestamp}\n{checkpoint}'
    return key.sign(data.encode()).signature


def make_inclusion_proof(leaf: bytes, leaf_index: int, tree_size: int) -> tuple[list[bytes], bytes]:
    leaf_hash = sha256(b'\x00' + leaf)

    fn = leaf_index
    sn = tree_size - 1

    r = leaf_hash

    proof = []

    step = 1
    while sn:
        p = step.to_bytes(8, byteorder='little') + b'\x5a'*24
        proof.append(p)

        if (fn&1 != 0) or (fn == sn):
            r = sha256(b'\x01' + p + r)

            if fn&1 == 0:
                while True:
                    fn >>= 1
                    sn >>= 1

                    if (fn&1 != 0) or (fn == 0):
                        break
        else:
            r = sha256(b'\x01' + r + p)

        fn >>= 1
        sn >>= 1
        step += 1

    return proof, r


def generate_proof(
    message_hash: bytes,
    leaf_key: SigningKey, log_key: SigningKey,
    leaf_index: int, tree_size: int,
    witnesses: list[str], cosignature_timestamp: int,
) -> str:
    lines = []

    lines.append('version=2')
    lines.append(f'log={sha256(bytes(log_key.verify_key)).hex()}')

    leaf = make_leaf(leaf_key, message_hash)
    inclusion_proof, root_hash = make_inclusion_proof(leaf, leaf_index, tree_size)

    lines.append(f'leaf={leaf[96:].hex()} {leaf[32:96].hex()}')
    lines.append('')
    lines.append(f'size={tree_size}')
    lines.append(f'root_hash={root_hash.hex()}')
    checkpoint = format_checkpoint(log_key.verify_key, tree_size, root_hash)
    root_signature = log_key.sign(checkpoint.encode()).signature
    lines.append(f'signature={root_signature.hex()}')
    for witness_name in witnesses:
        witness_key = derive_key(witness_name)
        cosignature = cosign_root(witness_key, cosignature_timestamp, checkpoint)
        lines.append(f'cosignature={sha256(bytes(witness_key.verify_key)).hex()} {cosignature_timestamp} {cosignature.hex()}')

    if tree_size > 1:
        lines.append('')
        lines.append(f'leaf_index={leaf_index}')
        for h in inclusion_proof:
            lines.append(f'node_hash={h.hex()}')

    return '\n'.join(lines)


def rekey_policy(input: str) -> str:
    def format_entity(name: str, type_: str) -> list[str]:
        lines = []

        key = derive_key(name)
        privkey = bytes(key)
        pubkey = bytes(key.verify_key)

        lines.append(f'# private key: {privkey.hex()}')
        if type_ == 'log':
            lines.append(f'log {pubkey.hex()} {name}')
        elif type_ == 'witness':
            lines.append(f'witness {name} {pubkey.hex()}')
        else:
            raise ValueError()

        return lines

    lines = []
    for line in input.splitlines():
        if line.startswith('log '):
            _, _, url = line.split()
            lines.extend(format_entity(url, 'log'))
        elif line.startswith('witness '):
            _, name, *_ = line.split()
            lines.extend(format_entity(name, 'witness'))
        else:
            lines.append(line)

    return '\n'.join(lines)
