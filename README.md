<!--
SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>

SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
-->

# spic

**spic is a work in progress**

spic (/ˈspaɪ.si/) is a freestanding C implementation of a verifier for transparent ("spicy") signatures of the [Sigsum](https://sigsum.org) flavor.

It's meant to be used in very constrained environments (microcontrollers/bootloaders) and thus doesn't use the normal ASCII-based Sigsum proof and policy formats, but [translates](compiler/compiler.py) them to [binary representations](doc/formats.md) that are equivalent, but much more compact.

spic does not require a heap but rather uses a small (189 byte) user-provided scratch area and some intentionally modest amount of stack space to store intermediate values. Optionally, users can plug in their own SHA256 and Ed25519 implementations to reduce the amount of code duplication and to potentially take advantage of hardware implementations.

spic is delivered as a single-file library, see [spic.c](spic.c) and [spic.h](spic.h). An example provider for the required cryptographic functions using OpenSSL can be found in [providers/openssl.c](providers/openssl.c).

## License

spic is licensed under CC0-1.0 or the 2-Clause BSD License with a patent grant (BSD-2-Clause-Patent) at your choice to maximize the ability to embed it in other code without hassle.

This project follows the [REUSE](https://reuse.software/) specification.

## Related work

The [sigsum-c](https://git.glasklar.is/sigsum/core/sigsum-c) from the Sigsum authors is a more full-featured implementation that can (among other things) also process the regular Sigsum ASCII format.
