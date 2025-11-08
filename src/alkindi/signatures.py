import weakref
from typing import Literal, Final, Tuple

from alkindi.core import ffi, liboqs, OQS_SUCCESS

SIG_Algorithm = Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

STANDARDIZED_SIGNATURES_ALGORITHMS: Final[frozenset[str]] = frozenset({
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
})


class Signature:
    __slots__ = (
        "_sig",
        "length_public_key",
        "length_secret_key",
        "length_signature",
        "_finalizer",
        "__weakref__",
    )

    def __init__(self, alg_name: SIG_Algorithm) -> None:
        if alg_name not in STANDARDIZED_SIGNATURES_ALGORITHMS:
            raise ValueError(
                f"Algorithm must be one of {STANDARDIZED_SIGNATURES_ALGORITHMS}, got {alg_name}"
            )

        sig = liboqs.OQS_SIG_new(alg_name.encode("utf-8"))
        if sig == ffi.NULL:
            raise RuntimeError(
                f"Could not initialize Signature algorithm '{alg_name}'. It may be unsupported or due to an internal error.")

        self._sig = sig
        self.length_public_key = self._sig.length_public_key
        self.length_secret_key = self._sig.length_secret_key
        self.length_signature = self._sig.length_signature
        self._finalizer = weakref.finalize(self, liboqs.OQS_SIG_free, self._sig)

    def __enter__(self) -> "Signature":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        if self._finalizer.alive:
            self._finalizer()

    def generate_keypair(self) -> Tuple[memoryview, memoryview]:
        public_key_buffer = ffi.new("uint8_t[]", self.length_public_key)
        secret_key_buffer = ffi.new("uint8_t[]", self.length_secret_key)

        result = liboqs.OQS_SIG_keypair(self._sig, public_key_buffer, secret_key_buffer)
        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to generate the keypair")

        public_key = ffi.buffer(public_key_buffer, self.length_public_key)
        secret_key = ffi.buffer(secret_key_buffer, self.length_secret_key)

        weakref.finalize(secret_key_buffer, liboqs.OQS_MEM_cleanse, secret_key_buffer, self.length_secret_key)

        return public_key, secret_key

    def sign(self, message: memoryview, secret_key: memoryview) -> memoryview:
        if len(secret_key) != self.length_secret_key:
            raise ValueError(
                f"Secret key length {len(secret_key)} does not match expected {self.length_secret_key}"
            )

        signature_buffer = ffi.new("uint8_t[]", self.length_signature)
        signature_len = ffi.new("size_t *")

        result = liboqs.OQS_SIG_sign(
            self._sig,
            signature_buffer,
            signature_len,
            message,
            len(message),
            ffi.from_buffer(secret_key),
        )

        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to sign the message")

        signature = ffi.buffer(signature_buffer, signature_len[0])

        return signature

    def _sign_with_ctx_str(self, message: memoryview, context: memoryview, secret_key: memoryview) -> memoryview:
        if len(secret_key) != self.length_secret_key:
            raise ValueError(
                f"Secret key length {len(secret_key)} does not match expected {self.length_secret_key}"
            )

        signature_buffer = ffi.new("uint8_t[]", self.length_signature)
        signature_len = ffi.new("size_t *")

        result = liboqs.OQS_SIG_sign_with_ctx_str(
            self._sig,
            signature_buffer,
            signature_len,
            message,
            len(message),
            context,
            len(context),
            ffi.from_buffer(secret_key),
        )

        if result != OQS_SUCCESS:
            raise RuntimeError("Failed to sign the message with context string")

        return ffi.buffer(signature_buffer, signature_len[0])

    def verify(self, message: memoryview, signature: memoryview, public_key: memoryview) -> bool:
        if len(signature) != self.length_signature:
            raise ValueError(
                f"Signature length {len(signature)} does not match expected {self.length_signature}"
            )

        if len(public_key) != self.length_public_key:
            raise ValueError(
                f"Public key length {len(public_key)} does not match expected {self.length_public_key}"
            )

        result = liboqs.OQS_SIG_verify(
            self._sig,
            message,
            len(message),
            ffi.from_buffer(signature),
            len(signature),
            ffi.from_buffer(public_key),
        )

        return result == OQS_SUCCESS

    def _verify_with_ctx_str(
            self,
            message: memoryview,
            signature: memoryview,
            context: memoryview,
            public_key: memoryview
    ) -> bool:
        if len(signature) > self.length_signature:
            raise ValueError(
                f"Signature length {len(signature)} exceeds expected maximum {self.length_signature}"
            )

        if len(public_key) != self.length_public_key:
            raise ValueError(
                f"Public key length {len(public_key)} does not match expected {self.length_public_key}"
            )

        result = liboqs.OQS_SIG_verify_with_ctx_str(
            self._sig,
            message,
            len(message),
            ffi.from_buffer(signature),
            len(signature),
            context,
            len(context),
            ffi.from_buffer(public_key),
        )

        return result == OQS_SUCCESS


__all__ = ["Signature"]
