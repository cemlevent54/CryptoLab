from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util import number
from binascii import hexlify, unhexlify
from Crypto.Util.number import inverse
import sympy
import random

from Crypto.Cipher import AES


class AsymmetricEncryptionAlgorithms:
    def rsa_encrypt(self, plaintext):
        # RSA Şifreleme
        key = RSA.generate(2048)
        public_key = key.publickey()
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext, key

    def dsa_encrypt(self, message):
        # DSA ile Dijital İmza
        key = DSA.generate(2048)
        hash_obj = SHA256.new(message.encode())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return signature, key

    def diffie_hellman_key_exchange(self):
        # Diffie-Hellman Anahtar Paylaşımı
        p = number.getPrime(256)  # Büyük bir asal sayı
        g = 2  # Üreteç
        a = number.getRandomRange(1, p)  # Özel anahtar A
        b = number.getRandomRange(1, p)  # Özel anahtar B

        A = pow(g, a, p)  # A'nın genel anahtarı
        B = pow(g, b, p)  # B'nin genel anahtarı

        shared_secret_a = pow(B, a, p)  # A tarafından hesaplanan ortak gizli anahtar
        shared_secret_b = pow(A, b, p)  # B tarafından hesaplanan ortak gizli anahtar

        if shared_secret_a == shared_secret_b:
            return {"shared_secret": shared_secret_a, "p": p, "g": g}
        else:
            raise ValueError("Anahtar değişimi başarısız oldu!")
    
    def diffie_hellman_text_key_exchange(self, message):
        # Diffie-Hellman Anahtar Paylaşımı
        p = number.getPrime(256)  # Büyük bir asal sayı
        g = 2  # Üreteç
        a = number.getRandomRange(1, p)  # Özel anahtar A
        b = number.getRandomRange(1, p)  # Özel anahtar B

        A = pow(g, a, p)  # A'nın genel anahtarı
        B = pow(g, b, p)  # B'nin genel anahtarı

        shared_secret_a = pow(B, a, p)  # A tarafından hesaplanan ortak gizli anahtar
        shared_secret_b = pow(A, b, p)  # B tarafından hesaplanan ortak gizli anahtar

        if shared_secret_a == shared_secret_b:
            shared_secret = shared_secret_a
        else:
            raise ValueError("Anahtar değişimi başarısız oldu!")

        # Ortak anahtarı AES anahtarına dönüştürmek için SHA-256 kullanılır
        shared_secret_bytes = str(shared_secret).encode('utf-8')  # String formatına dönüştür
        aes_key = SHA256.new(shared_secret_bytes).digest()  # AES anahtarı türet

        # AES-GCM ile mesajı şifrele
        cipher = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher.nonce  # Nonce değeri
        encrypted_message, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

        # Sonuçları döndür
        return {
            "shared_secret": shared_secret,
            "p": p,
            "g": g,
            "nonce": nonce,
            "encrypted_message": encrypted_message,
            "tag": tag
        }
    
    
    
    
