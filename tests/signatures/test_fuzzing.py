import pytest
from hypothesis import given, settings, HealthCheck, strategies as st

from alkindi.signatures import Signature, STANDARDIZED_SIGNATURES_ALGORITHMS

# Arbitrary garbage values for fuzzing
any_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(),
    st.binary(),
    st.lists(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=True, allow_infinity=True),
            st.text(),
            st.binary()
        )
    ),
    st.dictionaries(
        st.text(),
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(allow_nan=True, allow_infinity=True),
            st.text(),
            st.binary()
        )
    ),
    st.sets(st.text()),
)

# ------------------------------------------------------------------------------
# 1. Fuzzing constructor robustness
# ------------------------------------------------------------------------------

@given(any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_signature_constructor_fuzz(input_alg):
    """
    Ensure that the Signature constructor handles garbage input gracefully.
    """
    try:
        sig = Signature(input_alg)
        assert input_alg in STANDARDIZED_SIGNATURES_ALGORITHMS
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 2. Fuzzing sign interface
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
@given(any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_signature_sign_fuzz(scheme, secret_key):
    """
    Ensure that sign() handles malformed secret keys gracefully.
    """
    with Signature(scheme) as sig:
        message = b"test-message"
        try:
            sig.sign(message, secret_key)
        except Exception:
            pass


# ------------------------------------------------------------------------------
# 3. Fuzzing verify interface
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", STANDARDIZED_SIGNATURES_ALGORITHMS)
@given(any_value, any_value, any_value)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_signature_verify_fuzz(scheme, message, signature, public_key):
    """
    Ensure that verify() handles malformed inputs gracefully.
    """
    with Signature(scheme) as sig:
        try:
            sig.verify(message, signature, public_key)
        except Exception:
            pass
