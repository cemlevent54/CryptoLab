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
    
    
