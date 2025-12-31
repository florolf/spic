#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

"""
Regenerate a policy with known private keys

Reads a Sigsum policy from stdin and outputs a policy with the same structure
but with deterministically derived private keys for logs and witensses.
"""

import sys

from utils import derive

def write_entity(name: str, type_: str) -> None:
    privkey, pubkey = derive(name)
    print(f'# private key: {privkey.hex()}')
    if type_ == 'log':
        print(f'log {pubkey.hex()} {name}')
    elif type_ == 'witness':
        print(f'witness {name} {pubkey.hex()}')
    else:
        raise ValueError()

def main():
    for line in sys.stdin:
        line = line.strip()

        if line.startswith('log '):
            _, _, url = line.split()
            write_entity(url, 'log')
        elif line.startswith('witness '):
            _, name, *_ = line.split()
            write_entity(name, 'witness')
        else:
            print(line)


if __name__ == "__main__":
    main()
