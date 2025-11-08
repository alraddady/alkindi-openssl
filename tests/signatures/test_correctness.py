import pytest

from alkindi.signatures import Signature, STANDARDIZED_SIGNATURES_ALGORITHMS

"""
Unit tests for Alkindi Signature.

Tests cover:
1. Correct functionality
    - Round trip
    - Zero-length messages
2. Invalid input handling
   - Signature (verify input)
   - Public key (verify input)
   - Secret key (sign input)

Invalid input cases:
- One byte truncated
- One byte extended
- One bit flipped
"""

# ------------------------------------------------------------------------------
# 1. Correct functionality
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_roundtrip_sign_verify(scheme):
    """
    A valid signature must verify against the signed message for each scheme.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        assert sig.verify(message, signature, public_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_zero_length_message_signature(scheme):
    """
    Signature schemes must correctly handle empty messages.
    """
    with Signature(scheme) as sig:
        public_key, secret_key = sig.generate_keypair()
        message = b""
        signature = sig.sign(message, secret_key)

        assert sig.verify(message, signature, public_key)


# ------------------------------------------------------------------------------
# 2. Invalid input handling
# ------------------------------------------------------------------------------

# 2.1 Signature mutations (verify)

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_truncated_signature(scheme):
    """
    verify() must raise ValueError when the signature is one byte shorter.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        truncated = signature[:-1]

        with pytest.raises(ValueError):
            sig.verify(message, truncated, public_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_extended_signature(scheme):
    """
    verify() must raise ValueError when the signature is one byte longer.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        extended = bytearray(signature)
        extended.append(0)

        with pytest.raises(ValueError):
            sig.verify(message, extended, public_key)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_bitflip_signature(scheme):
    """
    A flipped bit in the signature (with valid length) must fail verification.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        corrupted = bytearray(signature)
        corrupted[0] ^= 0x01

        assert not sig.verify(message, corrupted, public_key)


# 2.2 Public key mutations (verify)

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_truncated_public_key(scheme):
    """
    verify() must raise ValueError when the public key is one byte shorter.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        truncated = public_key[:-1]

        with pytest.raises(ValueError):
            sig.verify(message, signature, truncated)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_extended_public_key(scheme):
    """
    verify() must raise ValueError when the public key is one byte longer.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        extended = bytearray(public_key)
        extended.append(0)

        with pytest.raises(ValueError):
            sig.verify(message, signature, extended)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_verify_bitflip_public_key(scheme):
    """
    A flipped bit in the public key (with valid length) must fail verification.
    """
    with Signature(scheme) as sig:
        message = b"Hello, World!"
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)

        corrupted = bytearray(public_key)
        corrupted[0] ^= 0x01

        assert not sig.verify(message, signature, corrupted)


# 2.3 Secret key mutations (sign)

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_sign_truncated_secret_key(scheme):
    """
    sign() must raise ValueError when the secret key is one byte shorter.
    """
    with Signature(scheme) as sig:
        _, secret_key = sig.generate_keypair()
        message = b"Hello, World!"

        truncated = secret_key[:-1]

        with pytest.raises(ValueError):
            sig.sign(message, truncated)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_sign_extended_secret_key(scheme):
    """
    sign() must raise ValueError when the secret key is one byte longer.
    """
    with Signature(scheme) as sig:
        _, secret_key = sig.generate_keypair()
        message = b"alkindi-test-message"

        extended = bytearray(secret_key)
        extended.append(0)

        with pytest.raises(ValueError):
            sig.sign(message, extended)


@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
def test_sign_bitflip_secret_key(scheme):
    """
    A flipped bit in the secret key must result in a different signature
    than the original. The signature may still verify (depending on scheme),
    but must differ in content.
    """
    with Signature(scheme) as sig:
        public_key, secret_key = sig.generate_keypair()
        message = b"alkindi-test-message"

        original_signature = sig.sign(message, secret_key)

        corrupted = bytearray(secret_key)
        corrupted[len(corrupted) // 2] ^= 0x01
        corrupted_signature = sig.sign(message, corrupted)

        assert bytes(original_signature) != bytes(corrupted_signature)
