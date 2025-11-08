import pytest

from alkindi.core import ffi
from alkindi.kem import KEM, STANDARDIZED_KEM_ALGORITHMS

"""
Tests for KEM initialization and structure tests.

This module verifies:
- Attributes are correctly loaded from the C struct.
- Types and values are valid and consistent.
- Python-accessible fields match the underlying C values.
- Invalid scheme names raise a ValueError.
"""


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_kem_cstruct_matches_python_attributes(scheme):
    kem = KEM(scheme)
    c_struct = kem._kem

    # Check method name (C side only)
    method_name = ffi.string(c_struct.method_name).decode()
    assert isinstance(method_name, str)
    assert method_name == scheme

    # Check algorithm version (C side only)
    alg_version = ffi.string(c_struct.alg_version).decode()
    assert isinstance(alg_version, str)
    assert len(alg_version.strip()) > 0

    # NIST level (C side only)
    assert isinstance(c_struct.claimed_nist_level, int)
    assert 1 <= c_struct.claimed_nist_level <= 5

    # IND-CCA flag (C side only)
    assert isinstance(c_struct.ind_cca, int)
    assert c_struct.ind_cca in (0, 1)

    # Keys & ciphertext lengths (C and Python sides)
    assert isinstance(c_struct.length_public_key, int)
    assert isinstance(kem.length_public_key, int)
    assert c_struct.length_public_key == kem.length_public_key
    assert kem.length_public_key > 0

    assert isinstance(c_struct.length_secret_key, int)
    assert isinstance(kem.length_secret_key, int)
    assert c_struct.length_secret_key == kem.length_secret_key
    assert kem.length_secret_key > 0

    assert isinstance(c_struct.length_ciphertext, int)
    assert isinstance(kem.length_ciphertext, int)
    assert c_struct.length_ciphertext == kem.length_ciphertext
    assert kem.length_ciphertext > 0

    assert isinstance(c_struct.length_shared_secret, int)
    assert isinstance(kem.length_shared_secret, int)
    assert c_struct.length_shared_secret == kem.length_shared_secret
    assert kem.length_shared_secret > 0


def test_invalid_kem_scheme():
    with pytest.raises(ValueError, match="INVALID"):
        KEM("INVALID")
