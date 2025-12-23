# Introduction

This document describes size-optimized compiled versions of the Sigsum policy and proof formats meant for consumption in a very resource-constrained environment. (see [example.md](example.md) for example output)

There are a few core ideas here that work differently than the regular Sigsum serializations or the proposed "compiled policy" format:

 - We assume that a proof is compiled *with respect to* a specific compiled policy. This allows us to store the pubkeys in the policy and refer to them by index rather than by keyhash, which is much smaller (this makes debugging harder in the case of a mismatched policy since the only thing you'll see for a mismatched key is a signature verification error, but this is considered acceptable here)
 - This also allows us to trim down the set of cosignatures in the proof to the minimum set required to satisfy the policy
 - The new strict policy rules imply that the quorum rules form a tree and each witness is referenced exactly oce. We can number the witnesses in the order they are used when verifying the quorum so each group only needs to say how many of the next in-order witnesses to consume rather than having to refer to them individually.
 - Since we can refer to witnesses via their index now (rather than having to search via keyhash), we are free to sort them non-lexicographically. So we can sort them according to their timestamp (which generally doesn't differ much, if at all) and delta-compress the timestamps

# General notes

Where appropriate, we use the language of [BARE](https://baremessages.org/) here. In particular, we use the BARE encoding for variable-sized integers.

# Proof format

```
type Signature struct {
    key_id: uint
    signature: data[64]
}

type Hash data[32]

type Cosignature struct {
    # delta to previous timestamp value (or to 0, for the first element in the list)
    timestamp_delta: uint

    signature: Signature # id indexes "witnesses" in policy
}

type ProofV1 struct {
    leaf_signature: Signature # id indexes "leaf_keys" argument

    tree_size: uint
    leaf_index: uint
    inclusion_proof: list<Hash>

    root_signature: Signature # id indexes "logs" in policy

    # Sorted ascending by timestamp
    cosignatures: list<Cosignature>
}

```

Some notes:

 - Storing the root hash is redundant: We can recalculate it from the inclusion proof and check its validity through the root signature rather than comparing with a stored root hash for equality.
 - The format version is explicitly not stored in the proof struct: There will be out of band framing anyway.
 - Same for "which policy does this proof refer to"

TODO:

 - Describe a canonical encoding such that semantically identical policies result in the same compiled policy irrespective of ordering/naming in the ASCII format

# Policy format

```
type Pubkey data[32]

type PolicyV1 struct {
    logs: list<Pubkey>
    witnesses: list<Pubkey>
    quorum: data
}
```

For each cosignature in the proof that validates, set the bit at `key_id` in the witness word to 1.

Quorum elements start with a `flags_and_threshold` uint encoded as follows:
 - bit 0: groups field present
 - bit 1: witnesses field present
 - bit 2-n: `threshold`

Followed by a `groups` and `witnesses` uint respectively if the corresponding bits are set. Process each quorum element as follows:

 - Initialize `count` to 0
 - Pop `groups` elements off the stack and add each to `count`
 - Add the number of set bits in the lower `witnesses` bits of the witness words to `count`, then shift the witness word right by `witnesses` bits
 - If `count >= threshold` push 1 to the stack, else push 0 to the stack

If after evaluating all quorum elements there is exactly one element on the stack and it is `1`, the quorum is satisfied, otherwise it isn't.
