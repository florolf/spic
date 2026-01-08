# SPDX-FileCopyrightText: 2026 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

import sys
import textwrap
import subprocess
import tempfile
import itertools
import dataclasses

from nacl.signing import VerifyKey

from typing import Any, Optional
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'test' / 'tools'))

from spic_compiler import compiler
import test_utils

def mkpolicy(policy: str) -> compiler.SigsumPolicy:
    policy = textwrap.dedent(policy)
    policy = test_utils.rekey_policy(policy)
    return compiler.SigsumPolicy.from_ascii(policy)

def run_spic(
    policy: Any, proof: Any, leaf_keys: list[VerifyKey],
    checksum: Optional[bytes] = None, payload: Optional[bytes] = None,
    should_fail: bool = False, failure_code: Optional[str] = None) -> None:
    tempdir = tempfile.TemporaryDirectory()
    base = Path(tempdir.name)


    if isinstance(policy, str):
        policy = compiler.SigsumPolicy.from_ascii(policy)

    if isinstance(policy, compiler.SigsumPolicy):
        policy = policy.compile()

    assert isinstance(policy, compiler.SpicPolicy)
    (base / 'policy.bin').write_bytes(policy.to_bytes())


    if isinstance(proof, str):
        proof = compiler.SigsumProof.from_ascii(proof)

    if isinstance(proof, compiler.SigsumProof):
        proof = policy.compile_proof(proof, leaf_keys=[bytes(k) for k in leaf_keys])

    assert isinstance(proof, compiler.SpicProof)
    (base / 'proof.bin').write_bytes(proof.to_bytes())

    # TODO: don't hardcode
    cli = ROOT / 'tools' / 'cli' / 'build' / 'spic-check'
    cmd = [str(cli)]

    if checksum is not None:
        cmd.append('--raw-hash')
        input_ = checksum.hex().encode()
    else:
        input_ = payload

    cmd.extend([
        str(base / 'policy.bin'),
        str(base / 'proof.bin'),
    ])

    for key in leaf_keys:
        cmd.append(bytes(key).hex())

    #print(input_)
    #print(' '.join(cmd))
    #import time
    #time.sleep(60)
    result = subprocess.run(cmd, input=input_, stderr=subprocess.PIPE)
    if should_fail:
        assert result.returncode != 0
        if failure_code is not None:
            assert failure_code in result.stderr.decode()
    else:
        assert result.returncode == 0

MSGHASH = test_utils.sha256(b'hello world')
LEAF_KEY1 = test_utils.derive_key('leaf1')
LEAF_KEY2 = test_utils.derive_key('leaf2')
LOG_KEY1 = test_utils.derive_key('log1')
LOG_KEY2 = test_utils.derive_key('log2')

TRIVIAL_POLICY = mkpolicy("""
log 0 log1
quorum none
""")

def test_quorum_basic_single_entry_log():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 1,
        [], 123
    )

    run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_basic_first_entry():
    for size in [5, 10, 16, 2**63 - 1]:
        proof = test_utils.generate_proof(
            MSGHASH, LEAF_KEY1, LOG_KEY1,
            0, size,
            [], 123
        )

        run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_basic_last_entry():
    for size in [5, 10, 16, 2**63 - 1]:
        proof = test_utils.generate_proof(
            MSGHASH, LEAF_KEY1, LOG_KEY1,
            size-1, size,
            [], 123
        )

        run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_basic():
    for size in [5, 10, 16, 2**63 - 1]:
        proof = test_utils.generate_proof(
            MSGHASH, LEAF_KEY1, LOG_KEY1,
            size // 3, size,
            [], 123
        )

        run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_invalid_tree_size():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 2**63,
        [], 123
    )

    run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True)

def test_payload():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )

    run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], payload=b'wrong payload', should_fail=True, failure_code='INVALID_LEAF_SIGNATURE')
    run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], payload=b'hello world')

def test_quorum_one_witness():
    policy = mkpolicy("""
    log 0 log1
    witness w1 0
    quorum w1
    """)

    proof = test_utils.generate_proof(
        MSGHASH,
        LEAF_KEY1, LOG_KEY1,
        0, 10, ['w1'], 123
    )

    run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_quorum_group():
    policy = mkpolicy("""
    log 0 log1
    witness w1 0
    witness w2 0
    witness w3 0
    group g1 2 w1 w2 w3
    quorum g1
    """)

    policy = policy.compile()

    def check(witnesses: list[str], good: bool):
        proof = test_utils.generate_proof(MSGHASH, LEAF_KEY1, LOG_KEY1,
            0, 10, witnesses, 123
        )

        proof = compiler.SigsumProof.from_ascii(proof)
        proof = policy._compile_proof(proof, leaf_keys=[bytes(LEAF_KEY1.verify_key)], check_quorum=False, optimize=False)

        if good:
            run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)
        else:
            run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='QUORUM_UNSATISFIED')

    witnesses = ['w1', 'w2', 'w3']
    for size in range(0, len(witnesses)+1):
        for subset in itertools.combinations(witnesses, size):
            check(list(subset), size >= 2)

def test_quorum_hierarchy():
    policy = mkpolicy("""
    log 0 log1
    witness w1 0
    witness w2 0
    witness w3 0
    witness w4 0
    group g2 1 w3 w4
    group g1 2 w1 w2 g2
    quorum g1
    """)

    policy = policy.compile()

    def check(witnesses: list[str], good: bool):
        proof = test_utils.generate_proof(MSGHASH, LEAF_KEY1, LOG_KEY1,
            0, 10, witnesses, 123
        )

        proof = compiler.SigsumProof.from_ascii(proof)
        proof = policy._compile_proof(proof, leaf_keys=[bytes(LEAF_KEY1.verify_key)], check_quorum=False, optimize=False)

        if good:
            run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)
        else:
            run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='QUORUM_UNSATISFIED')

    check(['w1', 'w2'], True)
    check(['w1', 'w3'], True)
    check(['w3'], False)
    check(['w3', 'w4'], False)

def test_quorum_wrong_cosignature():
    policy = mkpolicy("""
    log 0 log1
    witness w1 0
    witness w2 0
    witness w3 0
    group g1 2 w1 w2 w3
    quorum g1
    """)
    policy = policy.compile()

    proof = test_utils.generate_proof(MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10, ['w1', 'w2'], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)
    proof = policy.compile_proof(proof, leaf_keys=[bytes(LEAF_KEY1.verify_key)])

    run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)
    good_cosignature = list(proof.cosignatures[0])

    bad_key = good_cosignature.copy()
    bad_key[1] = 10
    proof.cosignatures[0] = tuple(bad_key)
    run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_WITNESS')

    bad_timestamp = good_cosignature.copy()
    bad_timestamp[0] = 1
    proof.cosignatures[0] = tuple(bad_timestamp)
    run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_COSIGNATURE')

    bad_signature = good_cosignature.copy()
    bad_signature[2] = bytes(64)
    proof.cosignatures[0] = tuple(bad_signature)
    run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_COSIGNATURE')

def test_leaf_wrong_hash():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )

    wrong_hash=test_utils.sha256(b'wrong')

    run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key], checksum=wrong_hash, should_fail=True, failure_code='INVALID_LEAF_SIGNATURE')

def test_leaf_multi_key():
    for key in [LEAF_KEY1, LEAF_KEY2]:
        proof = test_utils.generate_proof(
            MSGHASH, key, LOG_KEY1,
            0, 10,
            [], 123
        )

        run_spic(TRIVIAL_POLICY, proof, [LEAF_KEY1.verify_key, LEAF_KEY2.verify_key], checksum=MSGHASH)

def test_leaf_wrong_key():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)

    cpol = TRIVIAL_POLICY.compile()
    cprf = cpol.compile_proof(proof, [bytes(LEAF_KEY1.verify_key)])

    run_spic(cpol, cprf, [LEAF_KEY2.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_LEAF_SIGNATURE')

def test_leaf_key_unknown():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)

    cpol = TRIVIAL_POLICY.compile()
    cprf = cpol.compile_proof(proof, [bytes(LEAF_KEY1.verify_key)])

    cprf = dataclasses.replace(cprf, leaf_signature=(10, cprf.leaf_signature[1]))
    run_spic(TRIVIAL_POLICY, cprf, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_KEY_ID')

def test_log_multi_key():
    policy = mkpolicy("""
    log 0 log1
    log 0 log2
    quorum none
    """)

    for key in [LOG_KEY1, LOG_KEY2]:
        proof = test_utils.generate_proof(
            MSGHASH, LEAF_KEY1, key,
            0, 10,
            [], 123
        )

        run_spic(policy, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

def test_wrong_log_key():
    policy = mkpolicy("""
    log 0 log1
    log 0 log2
    quorum none
    """)
    cpol = policy.compile()

    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)

    cprf = cpol.compile_proof(proof, [bytes(LEAF_KEY1.verify_key)])

    oob_log_key = dataclasses.replace(cprf, root_signature=(10, cprf.root_signature[1]))
    run_spic(policy, oob_log_key, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_LOG_KEY')

    broken_sig = dataclasses.replace(cprf, root_signature=(cprf.root_signature[0], bytes(64)))
    run_spic(policy, broken_sig, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_ROOT_SIGNATURE')

def test_bad_inclusion_proof():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)

    cpol = TRIVIAL_POLICY.compile()
    cprf = cpol.compile_proof(proof, [bytes(LEAF_KEY1.verify_key)])
    run_spic(TRIVIAL_POLICY, cprf, [LEAF_KEY1.verify_key], checksum=MSGHASH)

    wrong_leaf_index = dataclasses.replace(cprf, leaf_index=11)
    run_spic(TRIVIAL_POLICY, wrong_leaf_index, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_INCLUSION_PROOF')

    too_short = dataclasses.replace(cprf, inclusion_proof=cprf.inclusion_proof[1:])
    run_spic(TRIVIAL_POLICY, too_short, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_INCLUSION_PROOF')

    too_long = dataclasses.replace(cprf, inclusion_proof=[*cprf.inclusion_proof, bytes(32)])
    run_spic(TRIVIAL_POLICY, too_long, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='INVALID_INCLUSION_PROOF')

def test_bytecode():
    proof = test_utils.generate_proof(
        MSGHASH, LEAF_KEY1, LOG_KEY1,
        0, 10,
        [], 123
    )
    proof = compiler.SigsumProof.from_ascii(proof)

    cpol = TRIVIAL_POLICY.compile()
    run_spic(cpol, proof, [LEAF_KEY1.verify_key], checksum=MSGHASH)

    underflow = dataclasses.replace(cpol, quorum=[(1, 1, 0)])
    cprf = underflow._compile_proof(proof, leaf_keys=[bytes(LEAF_KEY1.verify_key)], check_quorum=False, optimize=False)
    run_spic(underflow, cprf, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='BYTECODE_EVAL_FAILURE')

    overflow_quorum = []
    for _ in range(0, 200):
        overflow_quorum.append((1, 0, 1))

    overflow = dataclasses.replace(cpol, quorum=overflow_quorum)
    cprf = overflow._compile_proof(proof, leaf_keys=[bytes(LEAF_KEY1.verify_key)], check_quorum=False, optimize=False)
    run_spic(overflow, cprf, [LEAF_KEY1.verify_key], checksum=MSGHASH, should_fail=True, failure_code='BYTECODE_EVAL_FAILURE')
