import pytest

from alkindi import KEM
from alkindi.kem import STANDARDIZED_KEM_ALGORITHMS

"""
Unit tests for Alkindi KEM.

Tests cover:
1. Correct functionality
    - Round trip
    - Cross key decapsulation
2. Invalid input handling
   - Public key (encaps input)
   - Ciphertext (decaps input)
   - Secret key (decaps input)

Invalid input cases:
- One byte truncated
- One byte extended
- One bit flipped
"""


# ------------------------------------------------------------------------------
# 1. Correct functionality
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_roundtrip_encaps_decaps(scheme):
    """
    A valid encapsulation followed by decapsulation must recover
    the exact same shared secret for each KEM scheme.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()

    ciphertext, shared_secret_initial = kem.encaps(public_key)
    shared_secret_recovered = kem.decaps(ciphertext, secret_key)

    assert len(public_key) == kem.length_public_key
    assert len(secret_key) == kem.length_secret_key
    assert len(ciphertext) == kem.length_ciphertext
    assert len(shared_secret_initial) == kem.length_shared_secret
    assert len(shared_secret_recovered) == kem.length_shared_secret
    assert list(shared_secret_initial) == list(shared_secret_recovered)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_cross_key_decaps(scheme):
    """
    Ensure a ciphertext from an old keypair does not recover the same secret
    after regenerating the secret key on the same KEM instance.
    """
    kem = KEM(scheme)

    public_key1, secret_key1 = kem.generate_keypair()
    ciphertext1, shared_secret1 = kem.encaps(public_key1)

    public_key2, secret_key2 = kem.generate_keypair()
    shared_secret2 = kem.decaps(ciphertext1, secret_key2)

    assert shared_secret2 != shared_secret1


# ------------------------------------------------------------------------------
# 2. Invalid input handling
# ------------------------------------------------------------------------------

# 2.1 Public key mutations (encaps)

@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_encaps_truncated_public_key(scheme):
    """
    encaps() must raise ValueError when the public key
    is one byte shorter than expected.
    """
    kem = KEM(scheme)
    public_key, _ = kem.generate_keypair()
    truncated_public_key = public_key[:-1]

    with pytest.raises(ValueError):
        kem.encaps(truncated_public_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_encaps_extended_public_key(scheme):
    """
    encaps() must raise ValueError when the public key
    is one byte longer than expected.
    """
    kem = KEM(scheme)
    public_key, _ = kem.generate_keypair()
    extended_public_key = bytearray(public_key)
    extended_public_key.append(0)

    with pytest.raises(ValueError):
        kem.encaps(extended_public_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_encaps_bitflip_public_key(scheme):
    """
    When a single bit in the public key is flipped (length correct),
    encapsulation must produce valid-length outputs that differ
    from a clean run.
    """
    kem = KEM(scheme)
    public_key, _ = kem.generate_keypair()

    original_ciphertext, original_shared_secret = kem.encaps(public_key)

    corrupted_public_key = bytearray(public_key)
    corrupted_public_key[0] ^= 0x01

    corrupted_ciphertext, corrupted_shared_secret = kem.encaps(corrupted_public_key)

    assert len(corrupted_ciphertext) == kem.length_ciphertext
    assert len(corrupted_shared_secret) == kem.length_shared_secret
    assert list(corrupted_ciphertext) != list(original_ciphertext)
    assert list(corrupted_shared_secret) != list(original_shared_secret)


# 2.2 Ciphertext mutations (decaps)
@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_truncated_ciphertext(scheme):
    """
    decaps() must raise ValueError when the ciphertext
    is one byte shorter than expected.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encaps(public_key)
    truncated_ciphertext = ciphertext[:-1]

    with pytest.raises(ValueError):
        kem.decaps(truncated_ciphertext, secret_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_extended_ciphertext(scheme):
    """
    decaps() must raise ValueError when the ciphertext
    is one byte longer than expected.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encaps(public_key)
    extended_ciphertext = bytearray(ciphertext)
    extended_ciphertext.append(0)

    with pytest.raises(ValueError):
        kem.decaps(extended_ciphertext, secret_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_bitflip_ciphertext(scheme):
    """
    When a single bit in the ciphertext is flipped (length correct),
    decapsulation must return a shared secret of the correct length
    that does not match a clean run.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()

    _, original_shared_secret = kem.encaps(public_key)

    ciphertext, _ = kem.encaps(public_key)
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0x01

    new_shared_secret = kem.decaps(corrupted_ciphertext, secret_key)

    assert len(new_shared_secret) == kem.length_shared_secret
    assert list(new_shared_secret) != list(original_shared_secret)


# 2.3 Secret key mutations (decaps)
@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_truncated_secret_key(scheme):
    """
    decaps() must raise ValueError when the secret key
    is one byte shorter than expected.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encaps(public_key)
    truncated_secret_key = secret_key[:-1]

    with pytest.raises(ValueError):
        kem.decaps(ciphertext, truncated_secret_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_extended_secret_key(scheme):
    """
    decaps() must raise ValueError when the secret key
    is one byte longer than expected.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encaps(public_key)
    extended_secret_key = bytearray(secret_key)
    extended_secret_key.append(0)

    with pytest.raises(ValueError):
        kem.decaps(ciphertext, extended_secret_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decaps_bitflip_secret_key(scheme):
    """
    When a single bit in the secret key is flipped (length correct),
    decapsulation must return a shared secret of the correct length
    that does not match a clean run.
    """
    kem = KEM(scheme)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, original_shared_secret = kem.encaps(public_key)
    corrupted_secret_key = bytearray(secret_key)
    corrupted_secret_key[len(corrupted_secret_key) // 2] ^= 0x01

    try:
        new_shared_secret = kem.decaps(ciphertext, corrupted_secret_key)
        assert bytes(new_shared_secret) != bytes(original_shared_secret), (
            "Decapsulation with corrupted secret key should not yield the original shared secret"
        )
    except RuntimeError:
        pass
