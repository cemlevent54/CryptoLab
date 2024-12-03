from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64


class AESGCMDecryption:
    """
    AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
    """
    @staticmethod
    def aes_gcm_decrypt(encrypted_data: dict, key: bytes):
        """
        AES-GCM ile şifre çözme yapar.
        """
        cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(encrypted_data["nonce"]))
        plaintext = cipher.decrypt_and_verify(
            base64.b64decode(encrypted_data["ciphertext"]),
            base64.b64decode(encrypted_data["tag"]),
        )
        return plaintext.decode()


class RSAPSSVerification:
    """
    RSA-PSS (Probabilistic Signature Scheme)
    """
    @staticmethod
    def rsa_pss_verify(message: str, signature: str, public_key: bytes):
        """
        RSA-PSS ile imza doğrulama yapar.
        """
        public_key_obj = RSA.import_key(public_key)
        h = SHA256.new(message.encode())
        try:
            pss.new(public_key_obj).verify(h, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False
