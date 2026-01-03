#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import argparse

import compiler

from pathlib import Path

def do_policy(args):
    policy = compiler.SigsumPolicy.from_ascii(args.input.read_text())
    cpol = policy.compile()

    with args.output.open('wb') as f:
        f.write(cpol.to_bytes())


def do_dump_policy(args):
    policy = compiler.SpicPolicy.from_bytes(args.input.read_bytes())
    print(policy.dump())


def do_proof(args):
    policy = compiler.SpicPolicy.from_bytes(args.policy.read_bytes())
    proof = compiler.SigsumProof.from_ascii(args.proof.read_text())

    leaf_keys = []
    for key in args.leaf_key:
        leaf_keys.append(bytes.fromhex(key))

    cprf = policy.compile_proof(proof, leaf_keys)

    with args.output.open('wb') as f:
        f.write(cprf.to_bytes())


def do_dump_proof(args):
    proof = compiler.SpicProof.from_bytes(args.input.read_bytes())
    with_sigs = False
    if args.with_sigs:
        with_sigs = True

    print(proof.dump(with_sigs=with_sigs))


def build_parser():
    parser = argparse.ArgumentParser(prog="spic-compiler")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparser = subparsers.add_parser("policy", help="Compile a policy")
    subparser.add_argument("input", type=Path)
    subparser.add_argument("output", type=Path)

    subparser = subparsers.add_parser("dump-policy", help="Dump a policy")
    subparser.add_argument("input", type=Path)

    subparser = subparsers.add_parser("proof", help="Compile a proof")
    subparser.add_argument("policy", type=Path)
    subparser.add_argument("proof", type=Path)
    subparser.add_argument("output", type=Path)
    subparser.add_argument("leaf_key", type=str, nargs='+')

    subparser = subparsers.add_parser("dump-proof", help="Dump a proof")
    subparser.add_argument("input", type=Path)
    subparser.add_argument("--with-sigs", action='store_true')

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
