import pytest
from alkindi.kem import KEM, STANDARDIZED_KEM_ALGORITHMS

@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_keypair_uniqueness(scheme):
    """
    Two successive calls to generate_keypair() on the same KEM instance
    must yield completely independent keypairs.
    """
    kem = KEM(scheme)
    pk1, sk1 = kem.generate_keypair()
    pk2, sk2 = kem.generate_keypair()

    assert pk1 != pk2
    assert sk1 != sk2


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_keypair_collision_free_batch(scheme):
    """
    Over a batch of generate_keypair() calls, no two public keys collide.
    """
    kem = KEM(scheme)
    seen = set()
    N = 100

    for _ in range(N):
        pk, _ = kem.generate_keypair()
        bpk = bytes(pk)
        assert bpk not in seen
        seen.add(bpk)

    assert len(seen) == N


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_encapsulation_non_determinism(scheme):
    """
    Two back-to-back encaps() calls with the same public key must
    yield different ciphertexts and different shared secrets.
    """
    kem = KEM(scheme)
    pk, _ = kem.generate_keypair()

    c1, ss1 = kem.encaps(pk)
    c2, ss2 = kem.encaps(pk)

    assert c1 != c2
    assert ss1 != ss2


@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_shared_secret_collision_free_batch(scheme):
    """
    Over a batch of encaps() calls under the same public key,
    every shared secret must be unique.
    """
    kem = KEM(scheme)
    pk, _ = kem.generate_keypair()
    seen = set()
    M = 100

    for _ in range(M):
        _, ss = kem.encaps(pk)
        bss = bytes(ss)
        assert bss not in seen
        seen.add(bss)

    assert len(seen) == M

@pytest.mark.parametrize("scheme", STANDARDIZED_KEM_ALGORITHMS)
def test_decapsulation_idempotence(scheme):
    """
    Calling decaps() multiple times on the same (ciphertext, secret_key)
    must always return the exact same shared secret.
    """
    kem = KEM(scheme)
    pk, sk = kem.generate_keypair()
    ciphertext, orig_ss = kem.encaps(pk)

    ss1 = kem.decaps(ciphertext, sk)
    ss2 = kem.decaps(ciphertext, sk)
    ss3 = kem.decaps(ciphertext, sk)

    assert ss1 == ss2 == ss3 == orig_ss
