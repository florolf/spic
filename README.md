<!--
SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>

SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0
-->

# spic

**spic is a work in progress and not fully complete yet**

spic (/ˈspaɪ.si/) is a freestanding C implementation of a verifier for transparent ("spicy") signatures of the [Sigsum](https://sigsum.org) flavor.

It's meant to be used in very constrained environments (microcontrollers/bootloaders) and thus doesn't use the normal ASCII-based Sigsum proof and policy formats, but [translates](tools/compiler/compiler.py) them to [binary representations](doc/formats.md) that are equivalent, but much more compact (328 bytes vs. 1438 bytes for a typical policy and 534 bytes vs 2775 bytes for a typical proof).

spic does not require a heap but rather uses a small (189 byte) user-provided scratch area and some intentionally modest amount of stack space to store intermediate values. Optionally, users can plug in their own SHA256 and Ed25519 implementations to reduce the amount of code duplication and to potentially take advantage of hardware implementations.

spic is delivered as a single-file library, see [spic.c](spic.c) and [spic.h](spic.h).

As an example, a provider for the required cryptographic functions based on OpenSSL can be found in [providers/openssl.c](providers/openssl.c) and a Linux CLI tool for verifying proofs can be found in [tools/cli](tools/cli).

## Limitations

spic tries to use the absolute minimum of resources required to implement verification of Sigsum proofs. To achieve this, some trade-offs had to be made. Chiefly, unlike regular Sigsum proofs, the spic compiled proof representation can only be evaluated in the context of the exact policy it was compiled against. This means verification is less flexible when your policy evolves (for example when rolling over logs or witnesses) and using it requires knowing more about the entities that are going to verify a given proof. Also, policies are limited to 64 witnesses and around 180 groups (though this is an implementation limitation rather than a file format limitation).

Thus, spic is mostly useful when size limitations (either for the implementation or the policies/proofs) mean that the regular Sigsum tooling is too heavy-weight for you, you operate in a freestanding environment like a bootloader or on a microcontroller or you need a single-file library to embed the verifier in your application. In all other cases, you are probably better off using [sigsum-go](https://git.glasklar.is/sigsum/core/sigsum-go) (the reference implementation that also implements more than just proof verification) or [sigsum-c](https://git.glasklar.is/sigsum/core/sigsum-c).

## License

spic is licensed under CC0-1.0 or the 2-Clause BSD License with a patent grant (BSD-2-Clause-Patent) at your choice to maximize the ability to embed it in other code without hassle.

This project follows the [REUSE](https://reuse.software/) specification.
