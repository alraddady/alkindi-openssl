# Alkindi

**Alkindi** is named in honor of the 9th-century Arab Muslim
scholar [Al-Kindi](https://www.britannica.com/biography/al-Kindi), a pioneer in cryptography, mathematics, and
philosophy. He is often credited as one of the earliest figures in the history of cryptanalysis, and his contributions
represent significant milestones in the evolution of secure communication and information security.

---

## Overview

As quantum computing continues to evolve, the cryptographic algorithms securing today's digital world are increasingly
vulnerable. **Alkindi** is a Python library that delivers **NIST-standardized, quantum-safe cryptographic solutions**,
including secure key generation, encryption, and digital signatures.

Alkindi is a high-level Python binding to the [liboqs](https://github.com/open-quantum-safe/liboqs) C library, part of
the [Open Quantum Safe](https://openquantumsafe.org/) project. It provides access to vetted post-quantum algorithms
through a clean interface.

Designed with developer productivity in mind, Alkindi abstracts away complex low-level operations, enabling the use of
advanced post-quantum cryptography through a clean and intuitive Python API—**no C code, compilation, or build
configuration required.**

---

## Supported Algorithms

Alkindi supports two post-quantum cryptographic algorithms standardized by NIST:

- **ML-KEM** (Kyber): Security levels **512**, **768**, and **1024**. A lattice-based key encapsulation mechanism used
  for secure **key exchange** and **public-key encryption**.  
  See [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf) for full specifications and implementation
  details.

- **ML-DSA** (Dilithium): Variants **44**, **65**, and **87**. A lattice-based digital signature algorithm used for
  **authenticating messages**, **documents**, and **software**.  
  See [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) for full specifications and implementation
  details.

---

## Features

- **Quantum‑Safe Cryptography:** Defends against quantum attacks using **NIST-standardized** key encapsulation and
  digital signature algorithms. Built on trusted libraries—see [liboqs](https://openquantumsafe.org/liboqs/) for
  contributors and implementation details.
- **Zero-Hassle Integration:** Easily integrates into Python projects with **no native compilation** or low-level build
  steps required.
- **Secure by Design:** Implements strict memory handling practices for sensitive materials (e.g., key erasure, context
  management).

---

## Applications

Quantum computing is advancing rapidly—putting today’s encryption at risk. Transitioning to quantum-safe security is
**not optional, but inevitable**. Alkindi helps you prepare before vulnerabilities become liabilities.

Use Alkindi to protect:

- **Communications** – Email, messaging, VoIP
- **Finance** – Banking, blockchain, digital contracts
- **Healthcare** – Patient records, regulatory compliance
- **Government & Defense** – Confidential data, secure transmissions
- **Cloud Services** – Encrypted storage, secure APIs

> **Don't wait until the last minute—future-proof your systems today.**

---

## Installation

```bash
pip install alkindi
```

---

## Usage

Alkindi exposes high-level classes for working with **Key Encapsulation Mechanisms (KEM)** and **Digital Signatures**.
These classes wrap native cryptographic operations and manage sensitive resources such as memory and keys.

> **Important:** Always use `with` when working with `KEM` or `Signature` instances. This ensures proper cleanup of
> native resources and secure erasure of sensitive data.

### Key Encapsulation (KEM)

```python
from alkindi import KEM

with KEM("ML-KEM-1024") as kem:
    public_key, secret_key = kem.generate_keypair()
    ciphertext, shared_secret_sender = kem.encaps(public_key)
    shared_secret_recipient = kem.decaps(ciphertext, secret_key)

    print("Shared Secret Match:", shared_secret_sender == shared_secret_recipient)
```

### Digital Signatures

```python
from alkindi import Signature

with Signature("ML-DSA-87") as sig:
    public_key, secret_key = sig.generate_keypair()

    message = b"Hello, World!"
    signature = sig.sign(message, secret_key)

    is_valid = sig.verify(message, signature, public_key)

    print("Signature valid:", is_valid)
```

---

## Contributing

Whether it’s a bug fix, documentation improvement, or a new feature, your contributions are welcome. To get involved,
please open an issue or submit a pull request.

---

## License

**Alkindi is licensed under the [LGPLv3 license](https://www.gnu.org/licenses/lgpl-3.0.en.html).**  
All rights are reserved to their respective authors and contributors. This applies to all source code, documentation,
bindings, tests, cryptographic implementations, and other content included in the Alkindi project.

---

## Acknowledgments

Alkindi stands on the shoulders of giants—built on the groundbreaking work of countless teams and individual
contributors, notably the [Open Quantum Safe](https://openquantumsafe.org/) project and its associated libraries and
researchers. We extend our sincere gratitude to all those whose dedication and innovation have laid the foundation for
today’s post-quantum security tools.

---

## Contact

For inquiries, contributions, or collaboration opportunities, feel free to connect via [LinkedIn](https://linkedin.com/in/alraddady).
