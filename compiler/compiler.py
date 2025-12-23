#!/usr/bin/env python3

import argparse
import sys
import typing
import itertools

from pathlib import Path

from collections import OrderedDict, defaultdict
from typing import Optional, Self

import bare
from utils import sha256

def parse_ascii(doc: str) -> dict[str, list[list[str]]]:
    out = defaultdict(list)

    for line in doc.splitlines():
        if not line:
            continue

        key, value = line.split('=', 1)
        out[key].append(value.split())

    return out


class QuorumPolicy:
    def __init__(self, entities: OrderedDict[str, bytes|tuple[int, list[str]]], entry_point: Optional[str]):
        if entry_point is None:
            self.entities = {'empty': (0, [])}
            self.entry_point = 'empty'
            return

        self.entities = entities
        self.entry_point = entry_point

        if type(self.entities[self.entry_point]) is bytes:
            self.entities['single_witness'] = (1, [self.entry_point])
            self.entry_point = 'single_witness'

    @classmethod
    def from_policy(cls, policy: str) -> Self:
        quorum = None
        entities = {}

        for line in policy.splitlines():
            if line.startswith('#'):
                continue

            match line.split():
                case ['quorum', entry_point]:
                    if quorum is not None:
                        raise ValueError('multiple quorum definitions in policy')

                    if entry_point == 'none':
                        quorum = cls(entities, None)
                    else:
                        if entry_point not in entities:
                            raise ValueError(f'quorum entry point "{entry_point}" is unknown')

                        quorum = cls(entities, entry_point)

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

        if quorum is None:
            raise ValueError('quorum not specified')

        return quorum

def compile_entity(entities, name, indent=0) -> tuple[list, list]:
    print(' ' * indent + f"compiling group {name}")
    threshold, members = entities[name]

    if threshold == 1 and len(members) == 1:
        return compile_entity(entities, members[0])

    operations = []
    witnesses = []
    child_witnesses = []
    children = 0

    for member_name in members:
        member = entities[member_name]
        if type(member) is bytes:
            witnesses.append(member_name)
        else:
            sub_ops, sub_wit = compile_entity(entities, member_name, indent+4)
            operations.extend(sub_ops)
            child_witnesses.extend(sub_wit)

            children += 1

    operations.append((
        threshold,
        children,
        len(witnesses),
    ))

    result = operations, [*child_witnesses, *witnesses]
    print(' ' * indent + f'-> result({name}): t={threshold} c={children} w({len(witnesses)})={witnesses}')
    return result

def load_cpol(raw: bytes):
    buf = bytearray(raw)

    pol = {
        'logs': [],
        'witnesses': [],
    }

    for _ in range(0, bare.unpack_uint(buf)):
        pol['logs'].append(bare.unpack_fixed(buf, 32))

    for _ in range(0, bare.unpack_uint(buf)):
        pol['witnesses'].append(bare.unpack_fixed(buf, 32))

    bc = bytearray(bare.unpack_data(buf))
    quorum = []

    while bc:
        start = bare.unpack_uint(bc)
        children = 0
        if start & 1:
            children = bare.unpack_uint(bc)

        witnesses = 0
        if start & 2:
            witnesses  = bare.unpack_uint(bc)

        quorum.append((start >> 2, children, witnesses))

    pol['quorum'] = quorum

    if buf:
        raise ValueError(f'extraneous bytes in policy: {buf.hex()})')

    return pol

def eval_quorum(operations: list[tuple[int, int, int]], witnesses: set[int]) -> bool:
    stack = []

    ww = 0
    for i in witnesses:
        ww |= 1 << i

    for threshold, n_children, n_witnesses in operations:
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

def do_policy(args):
    policy = args.input.read_text()

    logs = []
    for line in policy.splitlines():
        if line.startswith('#'):
            continue

        match line.split():
            case ['log', key, _]:
                logs.append(bytes.fromhex(key))

    logs.sort()

    quorum = QuorumPolicy.from_policy(policy)
    groups, wits = compile_entity(quorum.entities, quorum.entry_point)

    out = bytearray()

    out.extend(bare.pack_uint(len(logs)))
    for log in logs:
        out.extend(log)

    out.extend(bare.pack_uint(len(wits)))
    for wit in wits:
        out.extend(typing.cast(bytes, quorum.entities[wit]))

    bc = bytearray()
    for threshold, children, wits in groups:

        start_byte = threshold << 2
        if children:
            start_byte = start_byte | 1
        if wits:
            start_byte = start_byte | 2

        gbc = bytearray()
        gbc.extend(bare.pack_uint(start_byte))

        if children:
            gbc.extend(bare.pack_uint(children))
        if wits:
            gbc.extend(bare.pack_uint(wits))

        bc.extend(gbc)

    print(bc.hex(), len(bc))
    out.extend(bare.pack_uint(len(bc)))
    out.extend(bc)

    with args.output.open('wb') as f:
        f.write(out)

def do_dump_policy(args):
    cpol = args.input.read_bytes()
    pol = load_cpol(cpol)

    print('Logs:')
    for idx, key in enumerate(pol['logs']):
        print(f'  {idx}: {key.hex()}')

    print()
    print('Witnesses:')
    for idx, key in enumerate(pol['witnesses']):
        print(f'  {idx}: {key.hex()}')

    print()
    print('Quorum bytecode:')
    wit_idx = 0
    stack_size = 0
    for threshold, children, wits in pol['quorum']:
        print('  ', end='')

        if wits:
            print(f'consume {wits} witnesses ({wit_idx} to {wit_idx + wits - 1}), ', end='')
            wit_idx += wits

        if children:
            print(f'consume {children} children, ', end='')
            if stack_size < children:
                print("UNDERFLOW")
                sys.exit(1)

            stack_size -= children

        stack_size += 1
        print(f'check threshold >= {threshold} (stack depth: {stack_size})')

    if stack_size != 1:
        print('invalid stack size at end of program: {stack_size} != 1')

def find_key_index(key_list: list[bytes], keyhash: bytes) -> Optional[int]:
    for idx, key in enumerate(key_list):
        cur_kh = sha256(key)
        if cur_kh == keyhash:
            return idx

    return None

def do_proof(args):
    policy = load_cpol(args.policy.read_bytes())
    proof = parse_ascii(args.proof.read_text())

    out = bytearray()

    # leaf_signature
    leaf_key_index = 0
    if args.leaf_key is not None:
        leaf_key_index = args.leaf_key

    out.extend(bare.pack_uint(leaf_key_index))
    out.extend(bytes.fromhex(proof['leaf'][0][1]))

    # tree_size
    out.extend(bare.pack_uint(int(proof['size'][0][0])))

    # leaf_index
    out.extend(bare.pack_uint(int(proof['leaf_index'][0][0])))

    # inclusion_proof
    out.extend(bare.pack_uint(len(proof['node_hash'])))
    for h in proof['node_hash']:
        out.extend(bytes.fromhex(h[0]))

    # root_signature
    root_key_index = find_key_index(policy['logs'], bytes.fromhex(proof['log'][0][0]))
    if root_key_index is None:
        raise ValueError('log key not found in policy')

    out.extend(bare.pack_uint(root_key_index))
    out.extend(bytes.fromhex(proof['signature'][0][0]))

    # cosignatures
    cosignatures = {}
    for keyhash, timestamp, signature in proof['cosignature']:
        idx = find_key_index(policy['witnesses'], bytes.fromhex(keyhash))
        if idx is None:
            continue

        cosignatures[idx] = {
            'ts': int(timestamp),
            'signature': bytes.fromhex(signature)
        }

    all_cosignatures = set(cosignatures.keys())
    needed_cosignatures = None
    for i in range(1, len(cosignatures)+1):
        for combination in itertools.combinations(all_cosignatures, i):
            if eval_quorum(policy['quorum'], set(combination)):
                needed_cosignatures = set(combination)
                break
        else:
            continue

        break

    if needed_cosignatures is None:
        raise RuntimeError('could not find satisfying cosignature set')

    print(f'Minimum cosignature set: {needed_cosignatures}')

    last_ts = 0
    for idx in sorted(cosignatures, key=lambda idx: cosignatures[idx]['ts']):
        if idx not in needed_cosignatures:
            continue

        cosig = cosignatures[idx]

        out.extend(bare.pack_uint(cosig['ts'] - last_ts))
        last_ts = cosig['ts']

        out.extend(bare.pack_uint(idx))
        out.extend(cosig['signature'])


    with args.output.open('wb') as f:
        f.write(out)


def build_parser():
    parser = argparse.ArgumentParser(prog="sigsum-nano")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparser = subparsers.add_parser("policy", help="Compile a policy")
    subparser.add_argument("input", type=Path)
    subparser.add_argument("output", type=Path)

    subparser = subparsers.add_parser("dump-policy", help="Dump a policy")
    subparser.add_argument("input", type=Path)

    subparser = subparsers.add_parser("proof", help="Compile a proof")
    subparser.add_argument("policy", type=Path)
    subparser.add_argument("--leaf_key", type=int)
    subparser.add_argument("proof", type=Path)
    subparser.add_argument("output", type=Path)

    return parser

def main():
    args = build_parser().parse_args()

    match args.command:
        case 'policy':
            do_policy(args)
        case 'dump-policy':
            do_dump_policy(args)
        case 'proof':
            do_proof(args)

if __name__ == "__main__":
    main()
