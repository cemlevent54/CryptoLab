from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4, ChaCha20
from Crypto.Util.Padding import unpad
from twofish import Twofish

class SymmetricDecryptionAlgorithms:
    def aes_decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        return plaintext.decode()

    def des_decrypt(self, ciphertext, key):
        iv = ciphertext[:DES.block_size]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)
        return plaintext.decode()

    def des3_decrypt(self, ciphertext, key):
        iv = ciphertext[:DES3.block_size]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[DES3.block_size:]), DES3.block_size)
        return plaintext.decode()

    def blowfish_decrypt(self, ciphertext, key):
        iv = ciphertext[:Blowfish.block_size]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[Blowfish.block_size:]), Blowfish.block_size)
        return plaintext.decode()

    def rc4_decrypt(self, ciphertext, key):
        cipher = ARC4.new(key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

    def chacha20_decrypt(self, ciphertext, key):
        nonce = ciphertext[:8]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext[8:])
        return plaintext.decode()
    
    # twofish decrypt algorithm will be added.
    def twofish_decrypt(self, ciphertext, key):
        """
        Twofish şifre çözme fonksiyonu
        """
        cipher = Twofish(key)

        # Şifre çözme ve padding kaldırma
        decrypted = b''.join([cipher.decrypt(ciphertext[i:i + 16]) for i in range(0, len(ciphertext), 16)])
        return unpad(decrypted, 16).decode()  # Padding kaldırılır ve orijinal metin döndürülür