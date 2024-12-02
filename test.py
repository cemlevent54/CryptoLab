from CompositeEncryptionAlgorithms import CompositeEncryptionAlgorithms
from CompositeDecryptionAlgorithms import CompositeDecryptionAlgorithms
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import time

def run_tests():
    print("==== Hybrid Encryption Test Başlıyor ====")
    startingtime = time.time()

    # Sınıf örneklerini oluştur
    encryptor = CompositeEncryptionAlgorithms()
    decryptor = CompositeDecryptionAlgorithms()

    # Test Verisi
    plaintext = "Merhaba Dünya! Bu, bir test mesajıdır."

    # ==== RSA + AES Test ====
    print("\n-- RSA + AES Test --")

    # RSA Anahtar Çifti Oluştur
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key.export_key()
    rsa_public_key = rsa_key.publickey().export_key()

    # Şifreleme
    rsa_encrypted = encryptor.rsa_aes_encrypt(plaintext, rsa_public_key)
    print("RSA + AES Şifrelenmiş Veri:", rsa_encrypted)

    # Çözme
    rsa_decrypted = decryptor.rsa_aes_decrypt(rsa_encrypted, rsa_private_key)
    print("RSA + AES Çözülmüş Veri:", rsa_decrypted)
    
    
    # Doğrulama
    assert plaintext == rsa_decrypted, "RSA + AES Testi Başarısız!"
    endingtime = time.time()
    print("required time: ",endingtime-startingtime)
    print("-- RSA + AES Test Başarılı --")

    # ==== ECC + AES Test ====
    print("\n-- ECC + AES Test --")
    startingtime = time.time()
    # ECC Anahtar Çifti Oluştur
    encryptor.generate_ecc_keys()
    ecc_private_key = encryptor.private_key
    ecc_public_key = encryptor.public_key

    # Şifreleme
    ecc_encrypted = encryptor.ecc_aes_encrypt(plaintext, ecc_public_key)
    print("ECC + AES Şifrelenmiş Veri:", ecc_encrypted)

    # Çözme
    ecc_decrypted = decryptor.ecc_aes_decrypt(ecc_encrypted, ecc_private_key, ecc_public_key)
    print("ECC + AES Çözülmüş Veri:", ecc_decrypted)

    # Doğrulama
    assert plaintext == ecc_decrypted, "ECC + AES Testi Başarısız!"
    print("-- ECC + AES Test Başarılı --")
    endingtime = time.time()
    print("\n==== Hybrid Encryption Test Başarılı ====")
    print("required time: ",endingtime-startingtime)


if __name__ == "__main__":
    run_tests()
