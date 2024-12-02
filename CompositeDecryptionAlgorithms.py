from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
import base64


class CompositeDecryptionAlgorithms:
    def __init__(self):
        pass

    # RSA + AES
    def rsa_aes_decrypt(self, encrypted_data: dict, private_key: str):
        """
        RSA + AES şifrelenmiş veriyi çözmek için kullanılır.
        :param encrypted_data: Şifrelenmiş veri (AES anahtarı, ciphertext, nonce, tag)
        :param private_key: RSA Private Key
        :return: Çözülmüş plaintext
        """
        # RSA Private Key ile AES anahtarını çöz
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(base64.b64decode(encrypted_data["encrypted_aes_key"]))

        # AES ile veriyi çöz
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=base64.b64decode(encrypted_data["nonce"]))
        plaintext = aes_cipher.decrypt_and_verify(
            base64.b64decode(encrypted_data["ciphertext"]),
            base64.b64decode(encrypted_data["tag"]),
        )
        return plaintext.decode()

    # ECC + AES
    def ecc_aes_decrypt(self, encrypted_data: dict, private_key, public_key):
        # ECC Private Key ile Shared Key üret
        shared_key = private_key.exchange(ec.ECDH(), public_key)

        # Shared Key'den AES anahtarı türet
        aes_key = HKDF(
            algorithm=SHA256(),
            length=16,
            salt=None,
            info=b"ecc+aes-key",
        ).derive(shared_key)

        # AES ile veriyi çöz
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=base64.b64decode(encrypted_data["nonce"]))
        plaintext = aes_cipher.decrypt_and_verify(
            base64.b64decode(encrypted_data["ciphertext"]),
            base64.b64decode(encrypted_data["tag"]),
        )

        return plaintext.decode()

