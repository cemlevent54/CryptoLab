import hashlib
import random

class QuantumEncryptionAlgorithms:
    """Class containing encryption algorithms for Lattice, Hash, and Code-Based Cryptography."""

    @staticmethod
    def lattice_encrypt(message, public_key):
        """Encrypts a message using a lattice-based cryptography technique."""
        encrypted_message = ''.join(chr((ord(char) + public_key) % 256) for char in message)
        return encrypted_message

    @staticmethod
    def hash_encrypt(message):
        """Encrypts a message using a hash-based cryptography technique."""
        return hashlib.sha256(message.encode()).hexdigest()

    @staticmethod
    def code_based_encrypt(message, key):
        """Encrypts a message using a simple code-based cryptography technique."""
        encoded = ''.join(chr(ord(char) ^ key) for char in message)
        return encoded

# Example Keys
PUBLIC_KEY = random.randint(1, 255)  # Example public key
SECRET_KEY = random.randint(1, 255)  # Example secret key
