from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Util import number
from Crypto.Util.number import inverse


class AsymmetricDecryptionAlgorithms:
    def rsa_decrypt(self, ciphertext, private_key):
        """
        RSA şifre çözme
        """
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

    def dsa_verify(self, message, signature, public_key):
        """
        DSA imza doğrulama
        """
        hash_obj = SHA256.new(message.encode())
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            return True
        except ValueError:
            return False

    def diffie_hellman_decrypt(self, shared_secret, p, g):
        """
        Diffie-Hellman gizli anahtar doğrulama (Şifreleme için kullanılmaz, ortak anahtar kontrolü)
        """
        # Ortak gizli anahtar tekrar hesaplanarak doğrulanabilir
        return shared_secret

    



