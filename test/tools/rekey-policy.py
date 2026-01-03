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

from test_utils import rekey_policy

def main():
    policy = sys.stdin.read()
    print(rekey_policy(policy))


if __name__ == "__main__":
    main()
