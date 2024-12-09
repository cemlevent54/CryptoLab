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
    def rsa_pss_verify(message: str, signature: str, public_key: bytes) -> bool:
        """
        RSA-PSS ile imza doğrulama yapar.
        :param message: İmzalanmış mesaj
        :param signature: Base64 ile kodlanmış imza
        :param public_key: Public key (PEM formatında byte)
        :return: Doğrulama başarılıysa True, aksi halde False
        """
        try:
            # Public key'i yükle
            public_key_obj = RSA.import_key(public_key)
            # Mesajı SHA256 ile hashle
            h = SHA256.new(message.encode())
            # Base64 ile çözülmüş imzayı doğrula
            verifier = pss.new(public_key_obj)
            verifier.verify(h, base64.b64decode(signature))
            print("İmza doğrulandı: Geçerli")
            return True
        except (ValueError, TypeError) as e:
            print(f"İmza doğrulama başarısız: {e}")
            return False
