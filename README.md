# spic

**spic is a work in progress**

spic (/ˈspaɪ.si/) is a freestanding C implementation of a verifier for transparent ("spicy") signatures of the [Sigsum](https://sigsum.org) flavor.

It's mean to be used in very constrained environments (microcontrollers/bootloaders) and thus doesn't use the normal ASCII-based Sigsum proof and policy formats, but [translates](compiler/compiler.py) them to [binary representations](doc/formats.md) that are equivalent, but much more compact.

spic does not require a heap but rather uses an user-provided scratch area (and some intentionally modest amount of stack space) to store intermediate values. Optionally, users can plug in their own SHA256 and Ed25519 implementations to reduce the amount of code duplication and to potentially take advantage of hardware implementations.

## Related work

The [sigsum-c](https://git.glasklar.is/sigsum/core/sigsum-c) from the Sigsum authors is a more full-featured implementation that can (among other things) also process the regular Sigsum ASCII format.
