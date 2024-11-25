import os
from SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms, KEY_SIZES
from SymmetricDecryptionAlgorithms import SymmetricDecryptionAlgorithms
from AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from AsymmetricDecryptionAlgorithms import AsymmetricDecryptionAlgorithms
from OldEncryptionAlgorithms import OldEncryptionAlgorithms, DecryptionAlgorithms


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
        print("1. Caesar Cipher")
        print("2. Vigenere Cipher")
        print("3. Substitution Cipher")
        print("4. Transposition Cipher")
        print("5. Playfair Cipher")
        print("6. Enigma Machine")
        print("\nSymmetric Algorithms:")
        print("7. AES")
        print("8. DES")
        print("9. 3DES")
        print("10. Blowfish")
        print("11. RC4")
        print("12. ChaCha20")
        print("\nAsymmetric Algorithms:")
        print("13. RSA")
        print("14. DSA")
        print("15. Diffie-Hellman Key Exchange")
        print("16. ElGamal")
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

            # Anahtar rastgele oluşturulur ve loglanır
            key = os.urandom(key_size)
            print(f"Rastgele oluşturulan anahtar (hex): {key.hex()}")

            # Metin şifrelenir ve anahtar saklanır
            encrypted = symmetric_encrypt.__getattribute__(f"{algo}_encrypt")(text, key)
            generated_keys[algo] = key
            print("\nŞifrelenmiş Metin (hex):", encrypted.hex())

            # Şifre çözme tahmin denemesi
            print("\nŞifre çözme işlemi başlıyor. Lütfen doğru anahtarı tahmin edin.")
            while True:
                key_hex = input(f"{algo} algoritması için tahmini anahtarı (hex) girin: ")
                try:
                    guessed_key = bytes.fromhex(key_hex)
                    decrypted = symmetric_decrypt.__getattribute__(f"{algo}_decrypt")(encrypted, guessed_key)
                    print("\nTebrikler! Doğru anahtarı buldunuz.")
                    print("Şifresi Çözülmüş Metin:", decrypted)
                    break
                except Exception as e:
                    print("Hatalı anahtar. Lütfen tekrar deneyin.")

        # Asimetrik şifreleme algoritmaları için işlemler
        elif choice in ['13', '14', '15', '16']:
            if choice == '13':  # RSA
                encrypted, private_key = asymmetric_encrypt.rsa_encrypt(text)
                print("\nRSA Şifrelenmiş Metin (hex):", encrypted.hex())
                decrypted = asymmetric_decrypt.rsa_decrypt(encrypted, private_key)
                print("RSA Şifresi Çözülmüş Metin:", decrypted)

            elif choice == '14':  # DSA
                signature, private_key = asymmetric_encrypt.dsa_encrypt(text)
                print("\nDSA İmzalanmış Metin (hex):", signature.hex())
                is_valid = asymmetric_decrypt.dsa_verify(text, signature, private_key.publickey())
                print("DSA Doğrulama Sonucu:", "Geçerli" if is_valid else "Geçersiz")

            elif choice == '15':  # Diffie-Hellman
                dh_result = asymmetric_encrypt.diffie_hellman_key_exchange()
                print("Diffie-Hellman Ortak Anahtar:", dh_result["shared_secret"])

            elif choice == '16':  # ElGamal
                elgamal_result = asymmetric_encrypt.elgamal_encrypt(text)
                print("ElGamal Şifrelenmiş Veriler:", elgamal_result)
                decrypted = asymmetric_decrypt.elgamal_decrypt(
                    elgamal_result["c1"], elgamal_result["c2"], elgamal_result["p"], elgamal_result["x"]
                )
                print("ElGamal Şifresi Çözülmüş Metin:", decrypted)

        # Eski algoritmalar (Old Algorithms) için işlemler
        elif choice in ['1', '2', '3', '4', '5', '6']:
            if choice in ['1', '2']:
                if choice == '1':
                    print("Örnek Anahtar: 3")
                elif choice == '2':
                    print("Örnek Anahtar: KEY")
                key = input("Anahtar girin: ")
                if choice == '1':
                    shift = int(key)
                    encrypted = encryption.caesar_cipher(text, shift)
                    decrypted = decryption.caesar_cipher(encrypted, shift)
                elif choice == '2':
                    encrypted = encryption.vigenere_cipher(text, key)
                    decrypted = decryption.vigenere_cipher(encrypted, key)
            elif choice == '3':
                print("Örnek Anahtar: QWERTYUIOPASDFGHJKLZXCVBNM")
                key = input("26 harfli anahtar girin: ")
                encrypted = encryption.substitution_cipher(text, key)
                decrypted = decryption.substitution_cipher(encrypted, key)
            elif choice == '4':
                print("Örnek Anahtar: 5")
                key = int(input("Anahtar olarak bir sayı girin: "))
                encrypted = encryption.transposition_cipher(text, key)
                decrypted = decryption.transposition_cipher(encrypted, key)
            elif choice == '5':
                print("Örnek Anahtar: PLAYFAIR")
                key = input("Anahtar girin: ")
                encrypted = encryption.playfair_cipher(text, key)
                decrypted = decryption.playfair_cipher(encrypted, key)
            elif choice == '6':
                print("Örnek Anahtar: ROTORKEY")
                key = input("Anahtar girin: ")
                encrypted = encryption.enigma_machine(text, key)
                decrypted = decryption.enigma_machine(encrypted, key)

            print("\nŞifrelenmiş Metin:", encrypted)
            print("Şifresi Çözülmüş Metin:", decrypted)

        else:
            print("Geçersiz seçenek, tekrar deneyin.")
            continue


if __name__ == "__main__":
    main()
