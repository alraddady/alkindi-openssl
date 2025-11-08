import pytest

from alkindi.core import ffi
from alkindi.signatures import Signature, STANDARDIZED_SIGNATURES_ALGORITHMS

"""
Tests for Signature initialization and attribute consistency.

This module verifies:
- Attributes are correctly loaded from the C struct.
- Types and values are valid and consistent.
- Python-accessible fields match the underlying C values.
- Invalid scheme names raise a ValueError.
"""

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_signature_attributes_consistency(scheme):
    sig = Signature(scheme)
    c_struct = sig._sig

    # --- Python-side attribute checks ---
    assert isinstance(sig.length_public_key, int)
    assert sig.length_public_key > 0

    assert isinstance(sig.length_secret_key, int)
    assert sig.length_secret_key > 0

    assert isinstance(sig.length_signature, int)
    assert sig.length_signature > 0

    # --- C-side struct consistency and checks ---
    method_name = ffi.string(c_struct.method_name).decode()
    assert isinstance(method_name, str)
    assert method_name == scheme

    alg_version = ffi.string(c_struct.alg_version).decode()
    assert isinstance(alg_version, str)
    assert len(alg_version.strip()) > 0

    assert isinstance(c_struct.claimed_nist_level, int)
    assert 1 <= c_struct.claimed_nist_level <= 5

    assert isinstance(c_struct.euf_cma, int)
    assert c_struct.euf_cma in (0, 1)

    assert isinstance(c_struct.suf_cma, int)
    assert c_struct.suf_cma in (0, 1)

    assert isinstance(c_struct.sig_with_ctx_support, int)
    assert c_struct.sig_with_ctx_support in (0, 1)

    assert c_struct.length_public_key == sig.length_public_key
    assert c_struct.length_secret_key == sig.length_secret_key
    assert c_struct.length_signature == sig.length_signature


def test_invalid_signature_scheme():
    with pytest.raises(ValueError, match="must be one of"):
        Signature("INVALID")
