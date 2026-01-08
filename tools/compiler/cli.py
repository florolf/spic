#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import argparse
import sys

import compiler

from pathlib import Path
from typing import Optional

def write_blob(target: Optional[str], blob: bytes):
    if target is None or target == '-':
        if sys.stdout.isatty():
            print('refusing to write binary data to terminal', file=sys.stderr)
            sys.exit(1)

        sys.stdout.buffer.write(blob)
    else:
        Path(target).write_bytes(blob)


def read_blob(source: Optional[str]) -> bytes:
    if source is None or source == '-':
        return sys.stdin.buffer.read()
    else:
        return Path(source).read_bytes()


def do_policy(args):
    policy_txt = read_blob(args.input).decode()
    policy = compiler.SigsumPolicy.from_ascii(policy_txt)
    cpol = policy.compile()

    write_blob(args.output, cpol.to_bytes())


def do_dump_policy(args):
    policy_raw = read_blob(args.input)
    policy = compiler.SpicPolicy.from_bytes(policy_raw)
    print(policy.dump())


def do_proof(args):
    policy = compiler.SpicPolicy.from_bytes(args.policy.read_bytes())

    proof_txt = read_blob(args.proof).decode()
    proof = compiler.SigsumProof.from_ascii(proof_txt)

    leaf_keys = []
    for key in args.leaf_key:
        leaf_keys.append(bytes.fromhex(key))

    cprf = policy.compile_proof(proof, leaf_keys)

    write_blob(args.output, cprf.to_bytes())


def do_dump_proof(args):
    proof_raw = read_blob(args.input)
    proof = compiler.SpicProof.from_bytes(proof_raw)
    with_sigs = False
    if args.with_sigs:
        with_sigs = True

    print(proof.dump(with_sigs=with_sigs))


def build_parser():
    parser = argparse.ArgumentParser(prog="spic-compiler")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparser = subparsers.add_parser("policy", help="Compile a policy")
    subparser.add_argument("input", type=str, nargs='?')
    subparser.add_argument("output", type=str, nargs='?')

    subparser = subparsers.add_parser("dump-policy", help="Dump a policy")
    subparser.add_argument("input", type=str, nargs='?')

    subparser = subparsers.add_parser("proof", help="Compile a proof")
    subparser.add_argument("policy", type=Path)
    subparser.add_argument("proof", type=str)
    subparser.add_argument("output", type=str)
    subparser.add_argument("leaf_key", type=str, nargs='+')

    subparser = subparsers.add_parser("dump-proof", help="Dump a proof")
    subparser.add_argument("--with-sigs", action='store_true')
    subparser.add_argument("input", type=str, nargs='?')

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
        case 'dump-proof':
            do_dump_proof(args)

if __name__ == "__main__":
    main()
