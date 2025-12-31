#!/bin/bash

# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

set -ueo pipefail

TOPDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )

WORKDIR="$(mktemp -d -t "spic-test.XXXXXXXX")"
cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

cd "$WORKDIR"

test_one() {
	local expected="$1"
	local desc="$2"
	local make_proof_args="${3:-}"
	local compiler_args="${4:-}"
	local check_keys="${5:-}"

	local leaf_privkey="e0cb7ad66ddab2d2d1e4593864e6c623fc4e14b179deb772c3e5c227f0429503"
	local leaf_pubkey="567d730ae3904342ee7e6b61b54c476c3f53f7f7d94952bf6f746fbbb7b86504"
	local message_hash="6de9e4d88aeea9136ea5e484eaa0da55bf1c88217c56fcecf4a6867a52795f0f"

	rm -f proof proof.bin

	rc=0
	(
		set -xueo pipefail
		"$TOPDIR/test/generator/make-proof.py" \
			--seed=00 \
			--message-hash="$message_hash" \
			--leaf-key="$leaf_privkey" \
			$make_proof_args \
			policy >proof
		"$TOPDIR/tools/compiler/compiler.py" proof $compiler_args policy.bin proof proof.bin
	) &> log || rc=$?

	if [[ "$rc" -ne 0 ]]
	then
		echo "[!] preparing test '$desc' failed"
		echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
		cat log
		echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"

		return 1
	fi

	rc=0
	(
		set -xueo pipefail
		echo "$message_hash" | "$TOPDIR/tools/cli/build/spic-check" --verbose --raw-hash policy.bin proof.bin $leaf_pubkey $check_keys
	) &>> log || rc=$?

	if [[ ("$expected" = "success" && "$rc" -ne 0) || ("$expected" = "failure" && "$rc" -eq 0) ]]
	then
		trap - EXIT

		echo "[!] test '$desc' failed"
		echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
		cat log
		echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"

		echo
		echo "full state in $WORKDIR"

		return 1
	fi

	echo "[.] test '$desc' succeeded"
}

echo
echo 'Generating policy'
echo '-----------------'
echo
sigsum-policy show sigsum-test-2025-3 | python "$TOPDIR/test/generator/rekey-policy.py" > policy
"$TOPDIR/tools/compiler/compiler.py" policy policy policy.bin

echo
echo 'Executing tests'
echo '---------------'
echo
test_one success 'single-element log' --tree-size=1
test_one success 'two-element log' --tree-size=2
test_one success 'leaf in the beginning' "--tree-size=10 --leaf-index=0"
test_one success 'leaf in the beginning 2' "--tree-size=16 --leaf-index=0"
test_one success 'leaf in the end' "--tree-size=10 --leaf-index=9"
test_one success 'leaf in the end 2' "--tree-size=16 --leaf-index=15"
test_one success 'zigzag' "--tree-size=8 --leaf-index=2"

test_one failure 'unknown leaf key' "" "--leaf-key=1"
test_one success 'two leaf keys, use first' "" "--leaf-key=0" "51f51312a97ecb528c4b27973f0d07764ce96d9de9d675b8745043ffcf19184f"
test_one success 'two leaf keys, use second' "--leaf-key=8950b44bb958a9737ab466bcda0725ff48d39bb43184b5d92d87f63ff04f4c86" "--leaf-key=1" "51f51312a97ecb528c4b27973f0d07764ce96d9de9d675b8745043ffcf19184f"
test_one failure 'two leaf keys, use wrong one' "--leaf-key=8950b44bb958a9737ab466bcda0725ff48d39bb43184b5d92d87f63ff04f4c86" "--leaf-key=0" "51f51312a97ecb528c4b27973f0d07764ce96d9de9d675b8745043ffcf19184f"

test_one failure 'oversized tree' --tree-size=9223372036854775808
test_one failure 'oversized cosignature timestamp' --cosignature-timestamp=9223372036854775808

for i in $(seq 1 10)
do
	test_one success "randomized $i" --seed=$(printf "%02x" $i)
done
