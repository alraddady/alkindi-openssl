import json
from pathlib import Path

import pytest

from alkindi import KEM
from alkindi.kem import STANDARDIZED_KEM_ALGORITHMS

KEYGEN_VECTOR_PATH = Path(__file__).parents[1] / "NIST_ACVP/ML-KEM-keyGen-FIPS203/internalProjection.json"
DECAP_VECTOR_PATH = Path(__file__).parents[1] / "NIST_ACVP/ML-kem-encapDecap-FIPS203/internalProjection.json"


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def select_keygen_groups(vectors: dict, algorithm_name: str):
    for group in vectors.get("testGroups", []):
        if group.get("parameterSet") == algorithm_name:
            yield group


def select_encapdecap_groups(vectors: dict, algorithm_name: str, function_type: str):
    for group in vectors.get("testGroups", []):
        if (group.get("function", "") == function_type
                and group.get("parameterSet") == algorithm_name):
            yield group


@pytest.mark.parametrize("algorithm_name", sorted(STANDARDIZED_KEM_ALGORITHMS))
def test_acvp_mlkem_keygen_vectors(algorithm_name):
    vectors = load_json(KEYGEN_VECTOR_PATH)
    found = False

    for group in select_keygen_groups(vectors, algorithm_name):
        found = True
        kem = KEM(algorithm_name)

        for test_case in group["tests"]:
            tc_id = test_case["tcId"]
            keygen_seed = bytes.fromhex(test_case["d"])
            aux_seed = bytes.fromhex(test_case["z"])
            seed = keygen_seed + aux_seed

            ref_ek = bytes.fromhex(test_case["ek"])
            ref_dk = bytes.fromhex(test_case["dk"])
            comp_ek, comp_dk = kem._generate_keypair_derand(seed)

            print(f"\n--- KeyGen Debug: {algorithm_name} tcId={tc_id} ---")
            print(f"seed d: {test_case['d']}")
            print(f"seed z: {test_case['z']}")

            assert comp_ek == ref_ek, (
                f"Public key mismatch for {algorithm_name} tcId={tc_id}\n"
                f"ref: {ref_ek.hex()}\n comp: {comp_ek.hex()}"
            )
            assert comp_dk == ref_dk, (
                f"Secret key mismatch for {algorithm_name} tcId={tc_id}\n"
                f"ref: {ref_dk.hex()}\n comp: {comp_dk.hex()}"
            )

    assert found, f"No keygen test vectors found for {algorithm_name}"


@pytest.mark.parametrize("algorithm_name", STANDARDIZED_KEM_ALGORITHMS)
def test_acvp_mlkem_decapsulation_vectors(algorithm_name):
    vectors = load_json(DECAP_VECTOR_PATH)
    found = False

    for group in select_encapdecap_groups(vectors, algorithm_name, "decapsulation"):
        found = True
        group_dk = bytes.fromhex(group["dk"])
        kem = KEM(algorithm_name)

        for test_case in group["tests"]:
            tc_id = test_case["tcId"]
            ciphertext = bytes.fromhex(test_case["c"])
            expected_ss = bytes.fromhex(test_case["k"])
            result_ss = bytes(kem.decaps(memoryview(ciphertext), memoryview(group_dk)))

            print(f"\n--- Decap Debug: {algorithm_name} tcId={tc_id} ---")
            print(f"ciphertext: {test_case['c'][:64]}...")

            assert result_ss == expected_ss, (
                f"Decapsulation failed for {algorithm_name} tcId={tc_id}\n"
                f"exp: {expected_ss.hex()}\n act: {result_ss.hex()}"
            )

    assert found, f"No decapsulation test vectors found for {algorithm_name}"
