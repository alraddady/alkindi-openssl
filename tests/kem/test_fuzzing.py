import pytest
from hypothesis import strategies as st
from hypothesis import given, settings, HealthCheck

from alkindi import KEM
from alkindi.kem import STANDARDIZED_KEM_ALGORITHMS

any_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(),
    st.binary(),
    st.lists(st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary()
    )),
    st.dictionaries(st.text(), st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary()
    )),
    st.sets(st.text()),
)


@given(any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_kem_constructor_fuzz(input_alg):
    try:
        kem = KEM(input_alg)
        assert input_alg in STANDARDIZED_KEM_ALGORITHMS
    except Exception:
        pass


@pytest.mark.parametrize("kem_alg", STANDARDIZED_KEM_ALGORITHMS)
@given(any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_kem_encaps_fuzz(kem_alg, pubkey):
    with KEM(kem_alg) as kem:
        try:
            kem.encaps(pubkey)
        except Exception:
            pass


@pytest.mark.parametrize("kem_alg", STANDARDIZED_KEM_ALGORITHMS)
@given(any_value, any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_kem_decaps_fuzz(kem_alg, ciphertext, secretkey):
    with KEM(kem_alg) as kem:
        try:
            kem.decaps(ciphertext, secretkey)
        except Exception:
            pass
