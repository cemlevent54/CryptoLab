import os
from SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms, KEY_SIZES
from SymmetricDecryptionAlgorithms import SymmetricDecryptionAlgorithms
from AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from AsymmetricDecryptionAlgorithms import AsymmetricDecryptionAlgorithms
from OldEncryptionAlgorithms import OldEncryptionAlgorithms, DecryptionAlgorithms
from Cryptodome.PublicKey import RSA

from Cryptodome.PublicKey import DSA

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

def load_private_key_from_file(filename):
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

    generated_keys = {}  # Rastgele oluşturulan anahtarları saklamak için bir sözlük

    while True:
        print("\nŞifreleme Algoritmaları:")
        print("Old Algorithms:")
        print("1. Caesar Cipher\t2. Vigenere Cipher\t3. Substitution Cipher\t4. Transposition Cipher\t5. Playfair Cipher\t6. Enigma Machine")
        print("\nSymmetric Algorithms:")
        print("7. AES\t8. DES\t9. 3DES\t10. Blowfish\t11. RC4\t12. ChaCha20")
        print("\nAsymmetric Algorithms:")
        print("13. RSA\t14. DSA\t15. Diffie-Hellman Key Exchange")
        print("17. Çıkış")

        choice = input("Bir seçenek girin (1-17): ")
        if choice == '17':
            print("Çıkış yapılıyor...")
            break

        text = input("Metni girin: ")

        # Simetrik şifreleme algoritmaları için işlemler
        if choice in ['7', '8', '9', '10', '11', '12']:
            algo = ['aes', 'des', 'des3', 'blowfish', 'rc4', 'chacha20'][int(choice) - 7]
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
                    print("\nTebrikler! Doğru anahtarı buldunuz.")
                    print("Şifresi Çözülmüş Metin:", decrypted)
                    break
                except Exception:
                    print("Hatalı anahtar. Lütfen tekrar deneyin.")

        # Asimetrik şifreleme algoritmaları için işlemler
        elif choice in ['13', '14', '15', '16']:
            if choice == '13':  # RSA
                encrypted, private_key = asymmetric_encrypt.rsa_encrypt(text)
                
                # Özel anahtarı PEM formatında bir dosyaya kaydediyoruz
                pem_file_name = "private_key.pem"
                with open(pem_file_name, "w") as pem_file:
                    pem_file.write(private_key.export_key().decode())
                print(f"\nÖzel anahtar '{pem_file_name}' dosyasına kaydedildi.")

                print("\nRSA Şifrelenmiş Metin (hex):", encrypted.hex())
                print("\nLütfen özel anahtarı çözmek için dosya adını girin.")

                while True:
                    try:
                        # Kullanıcıdan dosya adı alıyoruz
                        guessed_filename = input("Özel anahtarın olduğu dosya adını girin: ")
                        guessed_private_key = load_private_key_from_file(guessed_filename)  # Dosyayı okuyoruz
                        decrypted = asymmetric_decrypt.rsa_decrypt(encrypted, guessed_private_key)
                        print("\nTebrikler! Doğru anahtarı buldunuz.")
                        print("RSA Şifresi Çözülmüş Metin:", decrypted)
                        break
                    except Exception as e:
                        print(f"Hatalı dosya veya anahtar: {e}")
                        print("Lütfen tekrar deneyin.")


            elif choice == '14':  # DSA
                # Mesajı imzala ve özel anahtarı oluştur
                signature, private_key = asymmetric_encrypt.dsa_encrypt(text)
                public_key = private_key.publickey()  # Genel anahtarı elde et

                # Genel anahtarı dosyaya kaydet
                public_key_file = "public_key.pem"
                save_public_key_to_file(public_key, public_key_file)

                print("\nDSA İmzalanmış Metin (hex):", signature.hex())
                print(f"Genel anahtar '{public_key_file}' dosyasına başarıyla kaydedildi.")
                print("Lütfen doğrulama için genel anahtar dosyasını girin.")

                while True:
                    try:
                        # Genel anahtarı okumak için dosya adı al
                        guessed_filename = input("Genel anahtarın olduğu dosya adını girin: ")

                        # Dosyadan genel anahtarı yükle
                        guessed_public_key = load_public_key_from_file(guessed_filename)

                        # Doğrulama için mesaj hash'ini oluştur
                        from Cryptodome.Hash import SHA256
                        message_hash = SHA256.new(text.encode('utf-8'))

                        # DSS ile doğrulama yap
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



            elif choice == '15':  # Diffie-Hellman
                # Diffie-Hellman (DH) algoritması doğrudan bir metni şifrelemek (encrypt) veya çözmek (decrypt) için kullanılmaz. 
                # Bunun yerine, DH algoritması, iki tarafın (örneğin Alice ve Bob) bir ortak gizli anahtar oluşturmasını sağlar. 
                # Bu ortak anahtar daha sonra simetrik bir şifreleme algoritması (ör. AES, DES) kullanılarak 
                # veri şifrelemek ve çözmek için kullanılabilir.
                dh_result = asymmetric_encrypt.diffie_hellman_key_exchange()
                shared_secret = dh_result["shared_secret"]  # Ortak anahtarı alın

                # Ortak anahtarın hex formatını oluştur
                shared_secret_hex = hex(shared_secret)[2:]  # int değeri hex string'e dönüştür
                print("Diffie-Hellman anahtar değişimi tamamlandı.")
                print("Ortak Anahtar (hex):", shared_secret_hex)

                # Kullanıcıdan ortak anahtarı tahmin etmesini isteyin
                print("Ortak anahtarı doğru tahmin etmeye çalışın.")

                while True:
                    guessed_secret = input("Tahmini ortak anahtarı girin (hex formatında): ")
                    try:
                        # Kullanıcıdan alınan hex string'i int formatına dönüştür
                        guessed_secret_int = int(guessed_secret, 16)

                        # Doğruluk kontrolü
                        if guessed_secret_int == shared_secret:
                            # şifresi çözülmüş metni yazdır
                            
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
                    shift = int(key)  # Kaydırma anahtarını tam sayıya dönüştür
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
            elif choice == '3':
                key = input("26 harfli bir anahtar girin: ")
                encrypted = encryption.substitution_cipher(text, key)
            elif choice == '4':
                key = int(input("Bir sayı anahtarı girin: "))
                encrypted = encryption.transposition_cipher(text, key)
            elif choice == '5':
                key = input("Bir anahtar girin: ")
                encrypted = encryption.playfair_cipher(text, key)
            elif choice == '6':
                key = input("Bir anahtar girin: ")
                encrypted = encryption.enigma_machine(text, key)

            print("\nŞifrelenmiş Metin:", encrypted)

            print("\nŞifre çözme işlemi başlıyor. Lütfen doğru anahtarı tahmin edin.")
            while True:
                guessed_key = input("Tahmini anahtarı girin: ")
                try:
                    # Anahtar kontrolü her algoritma için ayrı yapılır
                    if choice == '1':
                        # Caesar Cipher
                        decrypted = decryption.caesar_cipher(encrypted, int(guessed_key))
                        if int(guessed_key) == shift:  # Anahtar doğruluğunu kontrol et
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")  # Yanlış anahtar için hata

                    elif choice == '2':
                        # Vigenere Cipher
                        decrypted = decryption.vigenere_cipher(encrypted, guessed_key)
                        if guessed_key == key:
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")  # Yanlış anahtar için hata

                    elif choice == '3':
                        # Substitution Cipher
                        decrypted = decryption.substitution_cipher(encrypted, guessed_key)
                        if guessed_key == key:
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")

                    elif choice == '4':
                        # Transposition Cipher
                        decrypted = decryption.transposition_cipher(encrypted, int(guessed_key))
                        if int(guessed_key) == key:
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")

                    elif choice == '5':
                        # Playfair Cipher
                        decrypted = decryption.playfair_cipher(encrypted, guessed_key)
                        if guessed_key == key:
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")

                    elif choice == '6':
                        # Enigma Machine
                        decrypted = decryption.enigma_machine(encrypted, guessed_key)
                        if guessed_key == key:
                            print("\nTebrikler! Doğru anahtarı buldunuz.")
                            print("Şifresi Çözülmüş Metin:", decrypted)
                            break
                        else:
                            raise ValueError("Anahtar yanlış!")

                except Exception as e:
                    # Hatalı anahtar mesajı
                    print("Hatalı anahtar. Lütfen tekrar deneyin.")




if __name__ == "__main__":
    main()
