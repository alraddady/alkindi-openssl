import sys

from cffi import FFI

ffi = FFI()

ffi.cdef("""
/* ============================================================== */
/*                Overview of liboqs C Definitions                */
/* ============================================================== */


/* ============================================================== */
/*                       Type Definitions                         */
/* ============================================================== */


/*
 * - OQS_STATUS: Return type for OQS function status (int)
 * - uint8_t: 8-bit unsigned integer type (unsigned char)
 * - size_t: Type for memory size specifications (unsigned long)
 * - bool: Boolean type mapped to int for CFFI
 * - All type definitions are required to be declared at the start of the FFI configuration
 */


typedef int OQS_STATUS;
typedef unsigned char uint8_t;
typedef unsigned long size_t;
typedef int bool;


/* ============================================================== */
/*                       Function Definitions                     */
/* ============================================================== */


/*
 * - OQS_version: Returns the library version string
 * - OQS_MEM_cleanse: Securely zeroes out memory
 */


const char *OQS_version(void);
void OQS_MEM_cleanse(void *ptr, size_t len);


/* ============================================================== */
/*                       Signature Definitions                    */
/* ============================================================== */


/*
 * - OQS_SIG: Structure for signature schemes with fields:
 *   - method_name: Signature scheme identifier
 *   - alg_version: Algorithm version string
 *   - claimed_nist_level: NIST security level (1-5)
 *   - euf_cma: TRUE if the scheme provides EUF-CMA security; FALSE otherwise.
 *   - suf_cma: TRUE if the scheme provides SUF-CMA security; FALSE otherwise.
 *   - sig_with_ctx_support: TRUE if the scheme supports signing with a context string; FALSE otherwise.
 *   - length_public_key: Public key size in bytes
 *   - length_secret_key: Secret key size in bytes
 *   - length_signature: Signature size in bytes
 *
 * - OQS_SIG_alg_identifier: Get SIG algorithm by index
 * - OQS_SIG_alg_count: Total SIG mechanisms
 * - OQS_SIG_alg_is_enabled: Check if SIG is enabled
 * - OQS_SIG_new: Create SIG instance
 * - OQS_SIG_free: Free SIG instance
 * - OQS_SIG_keypair: Generate SIG keypair
 * - OQS_SIG_sign: Create a digital signature
 * - OQS_SIG_sign_with_ctx_str: Create a digital signature with a context string.
 * - OQS_SIG_verify: Verify a digital signature
 * - OQS_SIG_verify_with_ctx_str: Verify a digital signature with a context string.
*/


typedef struct {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
    ...;
} OQS_SIG;


const char *OQS_SIG_alg_identifier(size_t i);
int OQS_SIG_alg_count(void);
int OQS_SIG_alg_is_enabled(const char *method_name);


OQS_SIG *OQS_SIG_new(const char *method_name);
void OQS_SIG_free(OQS_SIG *sig);


OQS_STATUS OQS_SIG_keypair(
    const OQS_SIG *sig,
    uint8_t *public_key,
    uint8_t *secret_key
);


OQS_STATUS OQS_SIG_sign(
    const OQS_SIG *sig,
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key
);

OQS_STATUS OQS_SIG_sign_with_ctx_str(
    const OQS_SIG *sig, 
    uint8_t *signature, 
    size_t *signature_len, 
    const uint8_t *message, 
    size_t message_len, 
    const uint8_t *ctx_str, 
    size_t ctx_str_len, 
    const uint8_t *secret_key
);

OQS_STATUS OQS_SIG_verify(
    const OQS_SIG *sig,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *public_key
);

OQS_STATUS OQS_SIG_verify_with_ctx_str(
    const OQS_SIG *sig,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *ctx_str,
    size_t ctx_str_len,
    const uint8_t *public_key
);

/* ============================================================== */
/*                  Key Encapsulation Definitions                 */
/* ============================================================== */


/*
 * - OQS_KEM: Structure for KEM schemes with fields:
 *   - method_name: KEM scheme identifier
 *   - alg_version: Algorithm version string
 *   - claimed_nist_level: NIST security level (1-5)
 *   - ind_cca: TRUE for IND-CCA, FALSE for IND-CPA
 *   - length_public_key: Public key size in bytes
 *   - length_secret_key: Secret key size in bytes
 *   - length_ciphertext: Ciphertext size in bytes
 *   - length_shared_secret: Shared secret size in bytes
 *   - length_keypair_seed: Seed size for derandomized keypair
 *   - keypair: Function pointer for standard keypair generation
 *   - keypair_derand: Function pointer for derandomized keypair generation
 *   - encaps: Function pointer for encapsulation
 *   - decaps: Function pointer for decapsulation
 *
 * - OQS_KEM_alg_identifier: Get KEM algorithm by index
 * - OQS_KEM_alg_count: Total KEM mechanisms
 * - OQS_KEM_alg_is_enabled: Check if KEM is enabled
 * - OQS_KEM_new: Create KEM instance
 * - OQS_KEM_free: Free KEM instance
 * - OQS_KEM_keypair: Generate standard KEM keypair
 * - OQS_KEM_keypair_derand: Generate derandomized KEM keypair
 * - OQS_KEM_encaps: Encapsulate a shared secret
 * - OQS_KEM_decaps: Decapsulate a shared secret
 */


/*
 * The field `ind_cca` is now explicitly declared using `unsigned char` to match the actual C layout.
 *
 * Originally defined in the C header as:
 *     bool ind_cca;
 *
 * The C `bool` type can vary in size across platforms and compilers (commonly 1 byte or 4 bytes),
 * which causes CFFI to reject mismatched struct layouts. In this build, `bool` resolves to 1 byte,
 * so we declare `ind_cca` as `unsigned char` in CFFI, which is ABI-compatible and avoids size issues.
 */


typedef struct OQS_KEM {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    unsigned char ind_cca;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
    
    OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    
    OQS_STATUS (*keypair_derand)(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed);
    
    OQS_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
    
    OQS_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
    
    ...;
} OQS_KEM;


const char *OQS_KEM_alg_identifier(size_t i);
int OQS_KEM_alg_count(void);
int OQS_KEM_alg_is_enabled(const char *method_name);
OQS_KEM *OQS_KEM_new(const char *method_name);
void OQS_KEM_free(OQS_KEM *kem);


OQS_STATUS OQS_KEM_keypair(
    const OQS_KEM *kem,
    uint8_t *public_key,
    uint8_t *secret_key
);


/* Top-level derandomized keypair helper */
OQS_STATUS OQS_KEM_keypair_derand(
    const OQS_KEM *kem,
    uint8_t *public_key,
    uint8_t *secret_key,
    const uint8_t *seed
);


OQS_STATUS OQS_KEM_encaps(
    const OQS_KEM *kem,
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key
);


OQS_STATUS OQS_KEM_decaps(
    const OQS_KEM *kem,
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key
);
""")


# Determine the platform-specific static library name
# - On Windows, CMake produces 'oqs.lib'
# - On Linux/macOS, it produces 'liboqs.a'
if sys.platform == "win32":
    oqs_static_lib = "oqs.lib"
else:
    oqs_static_lib = "liboqs.a"

# Construct keyword arguments for ffi.set_source:
# - Always include the liboqs headers and link the static library
# - On Windows, additionally link against Advapi32 to resolve CryptoAPI dependencies
extra_args = {
    "include_dirs": ["oqs-install/include"],
    "extra_objects": [f"oqs-install/lib/{oqs_static_lib}"],
}

if sys.platform == "win32":
    extra_args["libraries"] = ["Advapi32"]

ffi.set_source(
    "alkindi._liboqs",
    "#include <oqs/oqs.h>",
    **extra_args,
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
