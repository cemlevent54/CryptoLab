from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Util import number
from Crypto.Util.number import inverse
from Crypto.Cipher import AES


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
    
    def Diffie_H_decryption(self, encrypted_message, nonce, tag, shared_secret):
        """
        AES-GCM ile Diffie-Hellman mesajını çözme.
        """
        try:
            # Ortak gizli anahtardan AES anahtarı türet
            print("Nonce:")
            print(nonce)

            shared_secret_bytes = str(shared_secret).encode('utf-8')  # Ortak gizli anahtarı string'e dönüştürüp byte formatına al
            print("Shared Secret Bytes:")
            print(shared_secret_bytes)

            aes_key = SHA256.new(shared_secret_bytes).digest()  # AES anahtarını SHA-256 ile türet
            print("AES Key:")
            print(aes_key.hex())

            # AES-GCM modunda şifre çözme
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            print("Cipher:")
            print(cipher)

            # Şifrelenmiş mesajı çöz ve doğrula
            decrypted_message = cipher.decrypt_and_verify(encrypted_message, tag)
            print("Decrypted Message:")
            print(decrypted_message)

            return decrypted_message.decode('utf-8')  # Byte'ı string'e dönüştür ve geri döndür
        
        except ValueError as e:
            raise ValueError(f"Decryption failed: {e}")

    def rsa_decryption(self, ciphertext, private_key):
        """
        RSA ile şifrelenmiş mesajı çözme.
        Parametreler:
            ciphertext (bytes): Şifrelenmiş veri.
            private_key (RSA key): RSA özel anahtarı.
        Dönüş:
            plaintext (str): Çözülen metin.
        """
        try:
            cipher = PKCS1_OAEP.new(private_key)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')  # Byte'ı string'e dönüştür
        except Exception as e:
            raise ValueError(f"RSA Decryption failed: {e}")
        



