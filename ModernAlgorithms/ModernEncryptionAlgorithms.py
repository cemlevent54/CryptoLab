from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import os
import base64


class AESGCMEncryption:
    """
    AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
    """
    @staticmethod
    def generate_aes_key():
        """
        AES için rastgele 256 bit anahtar oluşturur.
        """
        return os.urandom(32)  # 256-bit AES anahtarı

    @staticmethod
    def aes_gcm_encrypt(plaintext: str, key: bytes):
        """
        AES-GCM ile şifreleme yapar.
        """
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        }


class RSAPSS:
    """
    RSA-PSS (Probabilistic Signature Scheme)
    """
    @staticmethod
    def generate_rsa_key_pair():
        """
        RSA anahtar çifti oluşturur ve bellekte tutar.
        """
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        print("RSA-PSS özel ve genel anahtarları oluşturuldu ve bellekte tutuluyor.")
        return private_key, public_key

    @staticmethod
    def rsa_pss_sign(message: str, private_key: bytes):
        """
        RSA-PSS ile imzalama yapar.
        """
        private_key_obj = RSA.import_key(private_key)
        h = SHA256.new(message.encode())
        signature = pss.new(private_key_obj).sign(h)
        return base64.b64encode(signature).decode()

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
