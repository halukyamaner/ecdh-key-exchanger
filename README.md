# ECDH Key Exchanger

## Overview
ECDH Key Exchanger is a Python library that implements the Elliptic Curve Diffie-Hellman (ECDH) cryptographic protocol for secure key exchange, combined with ChaCha20Poly1305 for message encryption and decryption. It ensures secure communication by generating a shared secret between two parties without transmitting the secret over the network.

## Features
- **Secure Key Exchange**: Utilizes the SECP521R1 elliptic curve for robust ECDH key exchanges.
- **Encryption and Decryption**: Employs ChaCha20Poly1305 AEAD for encrypting and decrypting messages, ensuring data integrity and confidentiality.
- **Performance Logging**: Measures and logs the duration of cryptographic operations, which helps in performance tuning and debugging.
- **Detailed Debugging Output**: Logs all cryptographic operations in detail, both to console and to a dedicated log file (`ecdhtest.log`), aiding in troubleshooting and educational purposes.
- **Error Handling**: Gracefully handles errors, including improper decryption attempts, with comprehensive logging for each scenario.

## Requirements
- Python 3.x
- Cryptography library version 2.8 or higher

## Usage
To use the ECDH Key Exchanger library, you need to initialize an instance of the `SecureECDH` class and call the `ecdh_process` method to perform the key exchange and message encryption/decryption. Here is a quick example:

```python
from ecdh_key_exchanger import SecureECDH

# Initialize the SecureECDH object
ecdh = SecureECDH()

# Perform the ECDH process
ecdh.ecdh_process()

# Results and logs can be viewed in the console and in ecdhtest.log
