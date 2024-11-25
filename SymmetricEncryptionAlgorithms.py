import os
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4, ChaCha20
from Crypto.Util.Padding import pad


class SymmetricEncryptionAlgorithms:
    def aes_encrypt(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return cipher.iv + ciphertext

    def des_encrypt(self, plaintext, key):
        cipher = DES.new(key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
        return cipher.iv + ciphertext

    def des3_encrypt(self, plaintext, key):
        cipher = DES3.new(key, DES3.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
        return cipher.iv + ciphertext

    def blowfish_encrypt(self, plaintext, key):
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), Blowfish.block_size))
        return cipher.iv + ciphertext

    def rc4_encrypt(self, plaintext, key):
        cipher = ARC4.new(key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    def chacha20_encrypt(self, plaintext, key):
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.nonce + cipher.encrypt(plaintext.encode())
        return ciphertext


# Key size information for reference
KEY_SIZES = {
    'aes': 16,      # 16 bytes = 128 bits
    'des': 8,       # 8 bytes = 64 bits
    'des3': 24,     # 24 bytes = 192 bits
    'blowfish': 16, # Up to 448 bits
    'rc4': 16,      # Variable, 16 bytes used here
    'chacha20': 32, # 32 bytes = 256 bits
}
