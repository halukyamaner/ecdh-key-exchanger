"""
Library: ECDH Key Exchanger
Author: Haluk YAMANER
Email: haluk@halukyamaner.com
Web: https://www.halukyamaner.com
Version: 1.0

Description:
    ECDH Key Exchanger is a Python library designed to facilitate secure cryptographic key exchanges using
    the Elliptic Curve Diffie-Hellman (ECDH) method, coupled with the ChaCha20Poly1305 cipher for message
    encryption and decryption. This library provides robust logging mechanisms and secure implementation
    practices, ensuring the integrity and confidentiality of the exchanged data. It is particularly suited
    for applications requiring secure communication channels, such as messaging apps, financial transaction
    platforms, and any system where data security is paramount.

Usage:
    To use ECDH Key Exchanger, instantiate the `SecureECDH` class and call its `ecdh_process` method to
    automatically handle the ECDH key exchange, followed by message encryption and decryption. The library
    manages detailed logging of each step, making it ideal for debugging and educational purposes. Logs are
    stored in both console and file outputs, ensuring comprehensive traceability of operations.

Requirements:
    Python 3.x
    cryptography>=2.8

Features:
    - Implements secure key exchange using the well-established SECP521R1 elliptic curve.
    - Encrypts and decrypts messages using the ChaCha20Poly1305 AEAD cipher, providing strong security against various attack vectors.
    - Features function decorators to log the duration of cryptographic operations, aiding in performance analysis.
    - Detailed logging of key generation, key exchange, and encryption processes to facilitate debugging and validation of cryptographic procedures.
    - Robust error handling, including specific logs for normal operations and decryption failures when an incorrect key is used.

Potential Use Cases:
    - Secure communication platforms where privacy and data integrity are critical.
    - Cryptographic modules for educational purposes, demonstrating secure key exchange and encryption methodologies.
    - Backend systems that require secure data exchange capabilities, particularly in environments with stringent data protection requirements.

Example:
    Below is a simple example of how to use the ECDH Key Exchanger library:

    ```python
    from ecdh_key_exchanger import SecureECDH

    # Instantiate the SecureECDH class
    ecdh = SecureECDH()

    # Run the ECDH key exchange and encryption/decryption process
    ecdh.ecdh_process()

    # Console
    python ecdh-key-exchanger.py

    # Check logs in console and ecdhtest.log file for detailed output of cryptographic steps performed
    ```
"""
import logging
import time
import os
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class SecureECDH:
    def __init__(self):
        self.logger = self.setup_logger()
        self.curve = ec.SECP521R1()
        self.alice_private_key = None
        self.bob_private_key = None
        self.alice_public_key = None
        self.bob_public_key = None
        self.alice_shared_key = None
        self.bob_shared_key = None

    def setup_logger(self):
        logger = logging.getLogger('ECDHTest')
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler
        fh = logging.FileHandler('ecdhtest.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        return logger

    @staticmethod
    def log_duration(func):
        def wrapper(self, *args, **kwargs):
            start_time = time.time()
            result = func(self, *args, **kwargs)
            end_time = time.time()
            duration = end_time - start_time
            self.logger.debug(f"{func.__name__} completed in {duration:.4f} seconds")
            return result
        return wrapper

    def generate_random_message(self, word_count=25):
        """Generate a random string of specified word count with only lowercase letters."""
        words = []
        for _ in range(word_count):
            word_length = random.randint(3, 10)  # Random word length between 3 and 10
            word = ''.join(random.choice(string.ascii_lowercase) for _ in range(word_length))
            words.append(word)
        return ' '.join(words).encode()

    @log_duration
    def generate_keys(self):
        self.logger.debug("Generating private keys...")
        self.alice_private_key = ec.generate_private_key(self.curve)
        self.bob_private_key = ec.generate_private_key(self.curve)
        
        self.logger.debug(f"Alice's private key: {self.alice_private_key.private_numbers().private_value}")
        self.logger.debug(f"Bob's private key: {self.bob_private_key.private_numbers().private_value}")
        
        self.logger.debug("Deriving public keys...")
        self.alice_public_key = self.alice_private_key.public_key()
        self.bob_public_key = self.bob_private_key.public_key()
        
        self.logger.debug(f"Alice's public key: {self.alice_public_key.public_numbers().x}, {self.alice_public_key.public_numbers().y}")
        self.logger.debug(f"Bob's public key: {self.bob_public_key.public_numbers().x}, {self.bob_public_key.public_numbers().y}")

    @log_duration
    def perform_key_exchange(self):
        self.logger.debug("Performing key exchange...")
        self.alice_shared_key = self.alice_private_key.exchange(ec.ECDH(), self.bob_public_key)
        self.bob_shared_key = self.bob_private_key.exchange(ec.ECDH(), self.alice_public_key)
        
        self.logger.debug(f"Alice's shared key: {self.alice_shared_key.hex()}")
        self.logger.debug(f"Bob's shared key: {self.bob_shared_key.hex()}")

    @log_duration
    def encrypt_message(self, shared_secret, message, sender="Alice", receiver="Bob"):
        self.logger.debug(f"{sender} is encrypting a message to {receiver}...")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()  # Ensure default_backend is imported
        ).derive(shared_secret)
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # 12-byte nonce
        encrypted_msg = chacha.encrypt(nonce, message, None)  # No associated data
        self.logger.debug(f"Encrypted message from {sender} to {receiver}: {encrypted_msg.hex()}")
        return (nonce, encrypted_msg)

    @log_duration
    def decrypt_message(self, shared_secret, nonce, encrypted_message, sender="Alice", receiver="Bob"):
        self.logger.debug(f"{receiver} is decrypting the message from {sender}...")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()  # Ensure default_backend is imported
        ).derive(shared_secret)
        chacha = ChaCha20Poly1305(key)
        decrypted_message = chacha.decrypt(nonce, encrypted_message, None)
        self.logger.debug(f"Decrypted message by {receiver} from {sender}: {decrypted_message.decode()}")
        return decrypted_message

    def ecdh_process(self):
        self.generate_keys()
        self.perform_key_exchange()
        
        # Generate a random message with only lowercase letters
        message = self.generate_random_message()
        self.logger.debug(f"Original message: {message.decode()}")
        nonce, encrypted_message = self.encrypt_message(self.alice_shared_key, message, sender="Alice", receiver="Bob")
        
        # Decrypt the message using Bob's shared key
        decrypted_message = self.decrypt_message(self.bob_shared_key, nonce, encrypted_message, sender="Alice", receiver="Bob")
        assert message == decrypted_message, "Decryption failed, integrity check failed!"
        
        self.logger.info("ECDH key exchange and message encryption/decryption successful!")
        
        # Attempt to decrypt with the wrong key
        try:
            wrong_shared_key = os.urandom(32)  # Generate a random wrong key
            self.decrypt_message(wrong_shared_key, nonce, encrypted_message, sender="Alice", receiver="Bob")
        except InvalidTag:
            self.logger.info("Decryption with wrong key failed as expected, integrity check passed!")

if __name__ == "__main__":
    ecdh = SecureECDH()
    start_time = time.time()
    ecdh.ecdh_process()
    end_time = time.time()
    total_duration = end_time - start_time
    ecdh.logger.info(f"Total execution time: {total_duration:.4f} seconds")
