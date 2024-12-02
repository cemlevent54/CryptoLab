import os
from SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms, KEY_SIZES
from SymmetricDecryptionAlgorithms import SymmetricDecryptionAlgorithms
from AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from AsymmetricDecryptionAlgorithms import AsymmetricDecryptionAlgorithms
from OldEncryptionAlgorithms import OldEncryptionAlgorithms, DecryptionAlgorithms
from Cryptodome.PublicKey import RSA, DSA
from CompositeEncryptionAlgorithms import CompositeEncryptionAlgorithms
from CompositeDecryptionAlgorithms import CompositeDecryptionAlgorithms
from Crypto.PublicKey import RSA

def save_public_key_to_file(public_key, filename="public_key.pem"):
    """
    Genel anahtarı PEM formatında bir dosyaya kaydeder.
    """
    try:
        with open(filename, "w") as file:
            file.write(public_key.export_key(format='PEM').decode())
        print(f"Genel anahtar '{filename}' dosyasına başarıyla kaydedildi.")
    except Exception as e:
        print(f"Genel anahtar dosyası kaydedilemedi: {e}")

def load_public_key_from_file(filename="public_key.pem"):
    """
    Dosyadan PEM formatındaki genel anahtarı okur ve DSA genel anahtar nesnesine dönüştürür.
    """
    try:
        with open(filename, "r") as file:
            return DSA.import_key(file.read())
    except Exception as e:
        raise ValueError(f"Dosya okunamadı veya geçerli bir PEM formatında değil: {e}")

def private_key_to_pem(private_key):
    """
    Özel anahtarı PEM formatına dönüştürür.
    """
    return private_key.export_key().decode()

def pem_to_private_key(pem_key):
    """
    PEM formatındaki özel anahtarı tekrar PrivateKey nesnesine dönüştürür.
    """
    return RSA.import_key(pem_key)

def save_private_key_to_file(private_key, filename="private_key.pem"):
    """
    Özel anahtarı PEM formatında bir dosyaya kaydeder.
    """
    with open(filename, "w") as file:
        file.write(private_key.export_key().decode())
    print(f"Özel anahtar {filename} dosyasına kaydedildi.")

def load_private_key_from_file(filename="private_key.pem"):
    """
    Dosyadan PEM formatındaki özel anahtarı okur ve RSA özel anahtar nesnesine dönüştürür.
    """
    try:
        with open(filename, "r") as file:
            return RSA.import_key(file.read())
    except Exception as e:
        raise ValueError(f"Dosya okunamadı veya geçerli bir PEM formatında değil: {e}")

def main():
    encryption = OldEncryptionAlgorithms()
    decryption = DecryptionAlgorithms()
    symmetric_encrypt = SymmetricEncryptionAlgorithms()
    symmetric_decrypt = SymmetricDecryptionAlgorithms()
    asymmetric_encrypt = AsymmetricEncryptionAlgorithms()
    asymmetric_decrypt = AsymmetricDecryptionAlgorithms()
    composite_encrypt = CompositeEncryptionAlgorithms()
    composite_decrypt = CompositeDecryptionAlgorithms()
    generated_keys = {}  # Rastgele oluşturulan anahtarları saklamak için bir sözlük

    while True:
        print("\nŞifreleme Algoritmaları:")
        print("Old Algorithms:")
        print("1. Caesar Cipher\t2. Vigenere Cipher\t3. Substitution Cipher\t4. Transposition Cipher\t5. Playfair Cipher\t6. Enigma Machine")
        print("\nSymmetric Algorithms:")
        print("7. AES\t8. DES\t9. 3DES\t10. Blowfish\t11. RC4\t12. ChaCha20\t13. Twofish")
        print("\nAsymmetric Algorithms:")
        print("14. RSA\t15. DSA\t16. Diffie-Hellman Key Exchange")
        print("\nComposite Algorithms:")
        print("17. RSA + AES\t18. ECC + AES")
        print("\nModern Algorithms:")
        print("19.AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)")
        print("20.RSA-PSS (Probabilistic Signature Scheme)")
        print("\nQuantum Algorithms:")
        print("21. Lattice Based Cryptography")
        print("22. Hash-Based Cryptography")
        print("23. Code-Based Cryptography")
        
        print("x. Çıkış")

        choice = input("Bir seçenek girin (1-19): ")
        if choice == 'x':
            print("Çıkış yapılıyor...")
            break

        text = input("Metni girin: ")

        # Simetrik şifreleme algoritmaları için işlemler
        if choice in ['7', '8', '9', '10', '11', '12', '13']:
            algo = ['aes', 'des', 'des3', 'blowfish', 'rc4', 'chacha20', 'twofish'][int(choice) - 7]
            key_size = KEY_SIZES[algo]

            key = os.urandom(key_size)
            print(f"Rastgele oluşturulan anahtar (hex): {key.hex()}")

            encrypted = symmetric_encrypt.__getattribute__(f"{algo}_encrypt")(text, key)
            generated_keys[algo] = key
            print("\nŞifrelenmiş Metin (hex):", encrypted.hex())

            print("\nŞifre çözme işlemi başlıyor. Lütfen doğru anahtarı tahmin edin.")
            while True:
                key_hex = input(f"{algo} algoritması için tahmini anahtarı (hex) girin: ")
                try:
                    guessed_key = bytes.fromhex(key_hex)
                    decrypted = symmetric_decrypt.__getattribute__(f"{algo}_decrypt")(encrypted, guessed_key)
                    
                    # Eğer doğru anahtar bulunursa:
                    if guessed_key == key:
                        print("\nTebrikler! Doğru anahtarı buldunuz.")
                        x = decrypted
                        print("Şifresi Çözülmüş Metin:", x)
                        break
                    else:
                        print("Hatalı anahtar. Lütfen tekrar deneyin.")
                except Exception as e:
                    print("Hatalı anahtar. Lütfen tekrar deneyin.")

        # Asimetrik şifreleme algoritmaları için işlemler
        elif choice in ['14', '15', '16']:
            if choice == '14':  # RSA
                encrypted, private_key = asymmetric_encrypt.rsa_encrypt(text)
                save_private_key_to_file(private_key, "private_key.pem")
                print("\nRSA Şifrelenmiş Metin (hex):", encrypted.hex())

                while True:
                    try:
                        guessed_filename = input("Özel anahtarın olduğu dosya adını girin: ")
                        guessed_private_key = load_private_key_from_file(guessed_filename)
                        decrypted = asymmetric_decrypt.rsa_decrypt(encrypted, guessed_private_key)
                        print("\nTebrikler! Doğru anahtarı buldunuz.")
                        print("RSA Şifresi Çözülmüş Metin:", decrypted)
                        break
                    except Exception as e:
                        print(f"Hatalı dosya veya anahtar: {e}")
                        print("Lütfen tekrar deneyin.")

            elif choice == '15':  # DSA
                signature, private_key = asymmetric_encrypt.dsa_encrypt(text)
                public_key = private_key.publickey()

                public_key_file = "public_key.pem"
                save_public_key_to_file(public_key, public_key_file)

                print("\nDSA İmzalanmış Metin (hex):", signature.hex())
                print(f"Genel anahtar '{public_key_file}' dosyasına başarıyla kaydedildi.")
                print("Lütfen doğrulama için genel anahtar dosyasını girin.")

                while True:
                    try:
                        guessed_filename = input("Genel anahtarın olduğu dosya adını girin: ")
                        guessed_public_key = load_public_key_from_file(guessed_filename)

                        from Cryptodome.Hash import SHA256
                        message_hash = SHA256.new(text.encode('utf-8'))

                        from Cryptodome.Signature import DSS
                        verifier = DSS.new(guessed_public_key, 'fips-186-3')
                        verifier.verify(message_hash, signature)

                        print("\nTebrikler! Doğru genel anahtarı buldunuz.")
                        print("DSA Doğrulama Başarılı.")
                        break
                    except ValueError as e:
                        print(f"Hatalı anahtar veya doğrulama başarısız: {e}")
                        print("Lütfen tekrar deneyin.")
                    except Exception as e:
                        print(f"Hatalı dosya veya anahtar: {e}")
                        print("Lütfen tekrar deneyin.")

            elif choice == '16':  # Diffie-Hellman
                dh_result = asymmetric_encrypt.diffie_hellman_key_exchange()
                shared_secret = dh_result["shared_secret"]

                shared_secret_hex = hex(shared_secret)[2:]
                print("Diffie-Hellman anahtar değişimi tamamlandı.")
                print("Ortak Anahtar (hex):", shared_secret_hex)

                print("Ortak anahtarı doğru tahmin etmeye çalışın.")
                while True:
                    guessed_secret = input("Tahmini ortak anahtarı girin (hex formatında): ")
                    try:
                        guessed_secret_int = int(guessed_secret, 16)

                        if guessed_secret_int == shared_secret:
                            print("\nTebrikler! Doğru ortak anahtarı buldunuz.")
                            break
                        else:
                            print("Hatalı anahtar. Lütfen tekrar deneyin.")
                    except ValueError:
                        print("Geçersiz format. Lütfen ortak anahtarı hex formatında girin.")

        # Eski algoritmalar (Old Algorithms) için işlemler
        elif choice in ['1', '2', '3', '4', '5', '6']:
            if choice == '1':
                key = input("Caesar Cipher için bir kaydırma anahtarı girin (sayı): ")
                try:
                    shift = int(key)
                    encrypted = encryption.caesar_cipher(text, shift)
                    print("\nŞifrelenmiş Metin:", encrypted)
                except ValueError:
                    print("Hatalı giriş! Kaydırma anahtarı bir sayı olmalıdır.")
            elif choice == '2':
                key = input("Vigenere Cipher için bir anahtar girin (yalnızca harf): ")
                if not key.isalpha():
                    print("Anahtar yalnızca harflerden oluşmalıdır. Lütfen geçerli bir anahtar girin.")
                else:
                    encrypted = encryption.vigenere_cipher(text, key)
                    print("\nŞifrelenmiş Metin:", encrypted)
            elif choice == '3':
                key = input("26 harfli bir anahtar girin: ")
                encrypted = encryption.substitution_cipher(text, key)
                print("\nŞifrelenmiş Metin:", encrypted)
            elif choice == '4':
                key = int(input("Bir sayı anahtarı girin: "))
                encrypted = encryption.transposition_cipher(text, key)
                print("\nŞifrelenmiş Metin:", encrypted)
            elif choice == '5':
                key = input("Bir anahtar girin: ")
                encrypted = encryption.playfair_cipher(text, key)
                print("\nŞifrelenmiş Metin:", encrypted)
            elif choice == '6':
                key = input("Bir anahtar girin: ")
                encrypted = encryption.enigma_machine(text, key)
                print("\nŞifrelenmiş Metin:", encrypted)

            print("\nŞifre çözme işlemi başlıyor. Lütfen doğru anahtarı tahmin edin.")
            while True:
                guessed_key = input("Tahmini anahtarı girin: ")
                try:
                    if choice == '1':
                        decrypted = decryption.caesar_cipher(encrypted, int(guessed_key))
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                    elif choice == '2':
                        decrypted = decryption.vigenere_cipher(encrypted, guessed_key)
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                    elif choice == '3':
                        decrypted = decryption.substitution_cipher(encrypted, guessed_key)
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                    elif choice == '4':
                        decrypted = decryption.transposition_cipher(encrypted, int(guessed_key))
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                    elif choice == '5':
                        decrypted = decryption.playfair_cipher(encrypted, guessed_key)
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                    elif choice == '6':
                        decrypted = decryption.enigma_machine(encrypted, guessed_key)
                        print("\nŞifresi Çözülmüş Metin:", decrypted)
                        break
                except Exception:
                    print("Hatalı anahtar. Lütfen tekrar deneyin.")
        
        # Composite şifreleme algoritmaları için işlemler
        elif choice in ['17', '18']:
            if choice == '17':  # RSA + AES
                from Crypto.PublicKey import RSA
                from Crypto.Cipher import PKCS1_OAEP

                # RSA anahtar çifti oluşturuluyor
                key_pair = RSA.generate(2048)
                private_key = key_pair.export_key()
                public_key = key_pair.publickey().export_key()

                # Anahtarları dosyalara kaydet
                private_key_file = "rsa_aes_private_key.pem"
                public_key_file = "rsa_aes_public_key.pem"

                with open(private_key_file, "wb") as priv_file:
                    priv_file.write(private_key)

                with open(public_key_file, "wb") as pub_file:
                    pub_file.write(public_key)

                print(f"\nRSA özel anahtar '{private_key_file}' dosyasına kaydedildi.")
                print(f"RSA genel anahtar '{public_key_file}' dosyasına kaydedildi.")

                # Kullanıcıdan metni al
                text = input("Metni girin: ")

                # Şifreleme işlemi
                encrypted_data = composite_encrypt.rsa_aes_encrypt(text, public_key.decode())
                print("\nRSA + AES Şifrelenmiş Veri:", encrypted_data)

                print("\nŞifre çözme işlemi başlıyor. Lütfen doğru özel anahtar dosya ismini tahmin edin.")

                while True:
                    try:
                        # Kullanıcıdan özel anahtar dosya ismini al
                        guessed_private_key_input = input("Özel anahtar dosyasının ismini girin (örnek: rsa_private_key.pem): ")

                        # Özel anahtarı tahmin edilen dosyadan yükle
                        with open(guessed_private_key_input, "rb") as key_file:
                            guessed_private_key = RSA.import_key(key_file.read())

                        # Şifre çözme işlemi
                        decrypted_text = composite_decrypt.rsa_aes_decrypt(encrypted_data, guessed_private_key.export_key())
                        print("\nTebrikler! Doğru anahtarı buldunuz.")
                        print("RSA + AES Şifresi Çözülmüş Metin:", decrypted_text)
                        break
                    except FileNotFoundError:
                        print("Hata: Dosya bulunamadı. Lütfen doğru bir dosya ismi girin.")
                    except ValueError:
                        print("Hata: Geçersiz anahtar formatı. Lütfen tekrar deneyin.")
                    except Exception as e:
                        print(f"Hata: {e}")
                        print("Lütfen tekrar deneyin.")

            elif choice == '18':  # ECC + AES
                # ECC anahtarları oluştur
                composite_encrypt.generate_ecc_keys()
                
                # Kullanıcıdan dosya isimleri alınır
                private_key_file = "ecc_aes_private_key.pem"
                public_key_file = "ecc_aes_public_key.pem"
                
                # Anahtarlar dosyalara kaydedilir
                composite_encrypt.save_private_key_to_file(private_key_file)
                composite_encrypt.save_public_key_to_file(public_key_file)
                
                print(f"\nÖzel anahtar '{private_key_file}' dosyasına kaydedildi.")
                print(f"Genel anahtar '{public_key_file}' dosyasına kaydedildi.")
                
                # Şifreleme işlemi
                public_key = composite_encrypt.public_key
                encrypted_data = composite_encrypt.ecc_aes_encrypt(text, public_key)
                print("\nECC + AES Şifrelenmiş Veri:", encrypted_data)

                print("\nŞifre çözme işlemi başlıyor. Lütfen doğru genel anahtar dosya ismini tahmin edin.")
                while True:
                    try:
                        # Kullanıcıdan genel anahtar dosya ismini al
                        guessed_public_key_file = input("Genel anahtar dosya ismini girin (örnek: ecc_public_key.pem): ")
                        
                        # Dosyadan tahmin edilen genel anahtarı yükle
                        composite_encrypt.load_public_key_from_file(guessed_public_key_file)
                        guessed_public_key = composite_encrypt.public_key

                        # Tahmin edilen anahtar ile şifre çözme işlemi
                        decrypted_text = composite_decrypt.ecc_aes_decrypt(encrypted_data, composite_encrypt.private_key, guessed_public_key)
                        print("\nTebrikler! Doğru anahtarı buldunuz.")
                        print("ECC + AES Şifresi Çözülmüş Metin:", decrypted_text)
                        break
                    except Exception as e:
                        print(f"Hatalı anahtar dosyası veya içerik: {e}")
                        print("Lütfen tekrar deneyin.")

if __name__ == "__main__":
    main()
