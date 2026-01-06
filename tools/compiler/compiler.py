# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import itertools
import hashlib
import typing

from collections import defaultdict
from dataclasses import dataclass

from typing import Self, Optional, Iterable

import bare

__all__ = ['SigsumProof', 'SpicProof', 'SigsumPolicy', 'SpicPolicy']


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _parse_ascii(doc: str) -> dict[str, list[list[str]]]:
    out = defaultdict(list)

    for line in doc.splitlines():
        if not line:
            continue

        key, value = line.split('=', 1)
        out[key].append(value.split())

    return out


@dataclass(frozen=True)
class SigsumProof:
    leaf_sig: tuple[bytes, bytes]

    root_hash: bytes
    tree_size: int
    root_sig: tuple[bytes, bytes]

    cosignatures: list[tuple[int, bytes, bytes]]

    leaf_index: int
    inclusion_proof: list[bytes]

    @classmethod
    def from_ascii(cls, text: str) -> Self:
        proof = _parse_ascii(text)

        cosignatures = []
        for keyhash, timestamp, signature in proof['cosignature']:
            cosignatures.append((
                int(timestamp),
                bytes.fromhex(keyhash),
                bytes.fromhex(signature)
            ))

        tree_size = int(proof['size'][0][0])
        if tree_size == 1:
            leaf_index = 0
        else:
            leaf_index = int(proof['leaf_index'][0][0])

        inclusion_proof = []
        for node in proof.get('node_hash', []):
            inclusion_proof.append(bytes.fromhex(node[0]))

        return cls(
            leaf_sig = (
                bytes.fromhex(proof['leaf'][0][0]),
                bytes.fromhex(proof['leaf'][0][1]),
            ),

            root_hash = bytes.fromhex(proof['root_hash'][0][0]),
            tree_size = tree_size,
            root_sig = (
                bytes.fromhex(proof['log'][0][0]),
                bytes.fromhex(proof['signature'][0][0]),
            ),

            cosignatures = cosignatures,

            leaf_index = leaf_index,
            inclusion_proof = inclusion_proof
        )


@dataclass(frozen=True)
class SpicProof:
    leaf_signature: tuple[int, bytes]

    tree_size: int
    leaf_index: int
    inclusion_proof: list[bytes]

    root_signature: tuple[int, bytes]

    cosignatures: list[tuple[int, int, bytes]]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        proof = bytearray(data)

        leaf_signature = (
            bare.unpack_uint(proof),
            bare.unpack_fixed(proof, 64)
        )

        tree_size = bare.unpack_uint(proof)
        leaf_index = bare.unpack_uint(proof)

        inclusion_proof = []
        for _ in range(0, bare.unpack_uint(proof)):
            inclusion_proof.append(bare.unpack_fixed(proof, 32))

        root_signature = (
            bare.unpack_uint(proof),
            bare.unpack_fixed(proof, 64)
        )

        cosignatures = []
        for _ in range(0, bare.unpack_uint(proof)):
            cosignatures.append((
                bare.unpack_uint(proof),
                bare.unpack_uint(proof),
                bare.unpack_fixed(proof, 64)
            ))

        return cls(
            leaf_signature = leaf_signature,

            tree_size = tree_size,
            leaf_index = leaf_index,
            inclusion_proof = inclusion_proof,

            root_signature = root_signature,

            cosignatures = cosignatures
        )

    def to_bytes(self) -> bytes:
        out = bytearray()

        out.extend(bare.pack_uint(self.leaf_signature[0]))
        out.extend(self.leaf_signature[1])

        out.extend(bare.pack_uint(self.tree_size))
        out.extend(bare.pack_uint(self.leaf_index))

        out.extend(bare.pack_uint(len(self.inclusion_proof)))
        for node in self.inclusion_proof:
            out.extend(node)

        out.extend(bare.pack_uint(self.root_signature[0]))
        out.extend(self.root_signature[1])

        out.extend(bare.pack_uint(len(self.cosignatures)))
        for ts_delta, key_idx, signature in self.cosignatures:
            out.extend(bare.pack_uint(ts_delta))
            out.extend(bare.pack_uint(key_idx))
            out.extend(signature)

        return bytes(out)

    def dump(self, with_sigs: bool = False) -> str:
        lines = []

        lines.append(f'Leaf signature key index: {self.leaf_signature[0]}')
        if with_sigs:
            lines.append(f'Leaf signature: {self.leaf_signature[1].hex()}')

        lines.append('')

        lines.append(f'Tree size: {self.tree_size}')
        lines.append(f'Leaf index: {self.leaf_index}')

        lines.append(f'Inclusion proof ({len(self.inclusion_proof)} steps):')
        for node in self.inclusion_proof:
            lines.append(f' - {node.hex()}')

        lines.append('')
        lines.append(f'Log signature key index: {self.root_signature[0]}')
        if with_sigs:
            lines.append(f'Checkpoint signature: {self.root_signature[1].hex()}')

        lines.append('')
        lines.append(f'Cosignatures ({len(self.cosignatures)}):')

        timestamp = 0
        for ts_delta, key_idx, signature in self.cosignatures:
            timestamp += ts_delta
            if with_sigs:
                lines.append(f' - key {key_idx}, timestamp {timestamp}, signature {signature.hex()}')
            else:
                lines.append(f' - key {key_idx}, timestamp {timestamp}')

        return '\n'.join(lines)

@dataclass(frozen=True)
class SigsumPolicy:
    logs: list[bytes]
    entities: dict[str, bytes|tuple[int, list[str]]]
    quorum_entry: Optional[str]

    @classmethod
    def from_ascii(cls, text: str) -> Self:
        logs = []

        entry_point = None
        quorum_seen = False

        entities = {}

        for line in text.splitlines():
            if line.startswith('#'):
                continue

            match line.split():
                case ['log', pubkey, *_]:
                    logs.append(bytes.fromhex(pubkey))

                case ['quorum', name]:
                    if quorum_seen:
                        raise ValueError('multiple quorum definitions in policy')

                    quorum_seen = True

                    if name != 'none':
                        if name not in entities:
                            raise ValueError(f'quorum entry point "{name}" is unknown')

                        entry_point = name

                case ['witness', name, pubkey, *_]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    entities[name] = bytes.fromhex(pubkey)

                case ['group', name, threshold, *members]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    if len(members) == 0:
                        raise ValueError(f'group "{name}" has no members')

                    if threshold == 'all':
                        threshold = len(members)
                    elif threshold == 'any':
                        threshold = 1
                    else:
                        threshold = int(threshold)
                        if not (1 <= threshold <= len(members)):
                            raise ValueError(f'group "{name}" has invalid threshold')

                    for member in members:
                        if member not in entities:
                            raise ValueError(f'group "{name}" refers to unknown entity "{member}"')

                    entities[name] = (threshold, members)

        if not logs:
            raise ValueError('no logs specified')

        if not quorum_seen:
            raise ValueError('quorum not specified')

        return cls(
            logs = logs,
            entities = entities,
            quorum_entry = entry_point
        )

    def compile(self) -> 'SpicPolicy':
        def compile_group(entities, name) -> tuple[list, list]:
            threshold, members = entities[name]

            if threshold == 1 and len(members) == 1 and type(entities[members[0]]) is not bytes:
                return compile_group(entities, members[0])

            my_witnesses = []
            child_operations = []
            child_witnesses = []
            n_children = 0

            for member_name in members:
                member = entities[member_name]
                if type(member) is bytes:
                    my_witnesses.append(member_name)
                else:
                    sub_ops, sub_wit = compile_group(entities, member_name)
                    child_operations.extend(sub_ops)
                    child_witnesses.extend(sub_wit)

                    n_children += 1

            my_operation = (
                threshold,
                n_children,
                len(my_witnesses),
            )

            return [*child_operations, my_operation], [*child_witnesses, *my_witnesses]

        if self.quorum_entry is None:
            entities = {'empty': (0, [])}
            entry_point = 'empty'
        elif type(self.entities[self.quorum_entry]) is bytes:
            entities = self.entities.copy()
            entities[''] = (1, [self.quorum_entry])
            entry_point = ''
        else:
            entities = self.entities
            entry_point = self.quorum_entry

        # sort by keyhash for determinism
        logs = list(sorted(self.logs))

        # TODO: this is nondeterministic / depends on the syntax but not the
        # underlying structure of the input policy
        quorum, witnesses = compile_group(entities, entry_point)
        witness_keys = typing.cast(list[bytes], [self.entities[name] for name in witnesses])

        return SpicPolicy(
            logs = logs,
            witnesses = witness_keys,
            quorum = quorum
        )


@dataclass(frozen=True)
class SpicPolicy:
    logs: list[bytes]
    witnesses: list[bytes]
    quorum: list[tuple[int, int, int]]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        buf = bytearray(data)

        logs = []
        for _ in range(0, bare.unpack_uint(buf)):
            logs.append(bare.unpack_fixed(buf, 32))

        witnesses = []
        for _ in range(0, bare.unpack_uint(buf)):
            witnesses.append(bare.unpack_fixed(buf, 32))

        bc = bytearray(bare.unpack_data(buf))

        quorum = []
        while bc:
            start = bare.unpack_uint(bc)
            n_children = 0
            if start & 1:
                n_children = bare.unpack_uint(bc)

            n_witnesses = 0
            if start & 2:
                n_witnesses  = bare.unpack_uint(bc)

            quorum.append((start >> 2, n_children, n_witnesses))

        if buf:
            raise ValueError(f'extraneous bytes in policy: {buf.hex()})')

        return cls(
            logs = logs,
            witnesses = witnesses,
            quorum = quorum
        )

    def to_bytes(self) -> bytes:
        out = bytearray()

        out.extend(bare.pack_uint(len(self.logs)))
        for log in self.logs:
            out.extend(log)

        out.extend(bare.pack_uint(len(self.witnesses)))
        for witness in self.witnesses:
            out.extend(witness)

        bc = bytearray()
        for threshold, n_children, n_witnesses in self.quorum:

            start_byte = threshold << 2
            if n_children:
                start_byte = start_byte | 1
            if n_witnesses:
                start_byte = start_byte | 2

            gbc = bytearray()
            gbc.extend(bare.pack_uint(start_byte))

            if n_children:
                gbc.extend(bare.pack_uint(n_children))

            if n_witnesses:
                gbc.extend(bare.pack_uint(n_witnesses))

            bc.extend(gbc)

        out.extend(bare.pack_uint(len(bc)))
        out.extend(bc)

        return bytes(out)

    def dump(self) -> str:
        lines = []

        lines.append('Logs:')
        for idx, key in enumerate(self.logs):
            lines.append(f'  {idx}: {key.hex()}')

        lines.append('')
        lines.append('Witnesses:')
        for idx, key in enumerate(self.witnesses):
            lines.append(f'  {idx}: {key.hex()}')

        lines.append('')
        lines.append('Quorum bytecode:')
        wit_idx = 0
        stack_size = 0
        for threshold, children, wits in self.quorum:
            line = '  '

            if wits:
                line += f'consume {wits} witnesses ({wit_idx} to {wit_idx + wits - 1}), '
                wit_idx += wits

            if children:
                line += f'consume {children} children, '
                if stack_size < children:
                    line += '(UNDERFLOWS) '

                stack_size -= children

            stack_size += 1
            line += f'check threshold >= {threshold} (stack depth: {stack_size})'
            lines.append(line)

        if stack_size != 1:
            lines.append('invalid stack size at end of program: {stack_size} != 1')

        return '\n'.join(lines)

    def _check_quorum(self, witnesses: Iterable[int]) -> bool:
        stack = []

        ww = 0
        for i in witnesses:
            ww |= 1 << i

        for threshold, n_children, n_witnesses in self.quorum:
            level = 0

            for _ in range(0, n_children):
                level += stack.pop()

            for _ in range(0, n_witnesses):
                if ww & 1:
                    level += 1

                ww >>= 1

            if level >= threshold:
                stack.append(1)
            else:
                stack.append(0)

        if len(stack) != 1:
            raise RuntimeError(f'invalid stack size {len(stack)}')

        return stack[0] == 1

    @staticmethod
    def _sig_to_idx(list_: list[bytes], sig: tuple[bytes, bytes]) -> tuple[int, bytes]:
        hash_, payload = sig
        for idx, key in enumerate(list_):
            if _sha256(key) == hash_:
                return (idx, payload)

        raise KeyError(f'could not find key for hash {hash_.hex()} in policy')

    def _optimize_cosignatures(self, cosignatures: list[tuple[int, int, bytes]]) -> list[tuple[int, int, bytes]]:
        for i in range(0, len(cosignatures)+1):
            for combination in itertools.combinations(cosignatures, i):
                indexes = [idx for (_, idx, _) in combination]
                if self._check_quorum(indexes):
                    return list(combination)

        raise RuntimeError('could not find satisfying cosignature set')

    def _compile_proof(self, proof: SigsumProof, leaf_keys: list[bytes], optimize: bool = True, check_quorum: bool = True) -> SpicProof:
        cosignatures = []
        ts_last = 0

        # sort first by timestamp for delta compression and then by keyhash to define a deterministic order
        for ts, keyhash, signature in sorted(proof.cosignatures, key=lambda cs: (cs[0], cs[1])):
            try:
                sig = self._sig_to_idx(self.witnesses, (keyhash, signature))
            except KeyError:
                continue

            cosignatures.append((ts - ts_last, *sig))
            ts_last = ts

        if optimize:
            cosignatures = self._optimize_cosignatures(cosignatures)
        elif check_quorum:
            if not self._check_quorum(set([cs[1] for cs in cosignatures])):
                raise RuntimeError("cosignatures don't satisfy quorum")

        return SpicProof(
            leaf_signature = self._sig_to_idx(leaf_keys, proof.leaf_sig),

            tree_size = proof.tree_size,
            leaf_index = proof.leaf_index,
            root_signature = self._sig_to_idx(self.logs, proof.root_sig),

            inclusion_proof = proof.inclusion_proof,

            cosignatures = cosignatures
        )

    def compile_proof(self, proof: SigsumProof, leaf_keys: list[bytes], optimize: bool = True) -> SpicProof:
        return self._compile_proof(proof, leaf_keys, optimize)

