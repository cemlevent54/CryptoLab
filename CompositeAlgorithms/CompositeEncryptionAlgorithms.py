from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA

class CompositeEncryptionAlgorithms:
    def __init__(self):
        # ECC Anahtarlarını başlat
        self.private_key = None
        self.public_key = None

    # RSA + AES
    def rsa_aes_encrypt(self, plaintext: str, public_key: str):
        # AES Anahtarı oluştur
        aes_key = os.urandom(16)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext.encode())

        # RSA Public Key ile AES anahtarını şifrele
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP

        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        return {
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(aes_cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        }
    
    def save_rsa_keys_to_files(self, private_key_file: str, public_key_file: str):
        """
        RSA özel ve genel anahtarlarını dosyalara kaydeder.
        """
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(self.private_key)

        with open(public_key_file, "wb") as pub_file:
            pub_file.write(self.public_key)

    def load_rsa_keys_from_files(self, private_key_file: str, public_key_file: str):
        """
        RSA özel ve genel anahtarlarını dosyalardan yükler.
        """
        with open(private_key_file, "rb") as priv_file:
            self.private_key = priv_file.read()

        with open(public_key_file, "rb") as pub_file:
            self.public_key = pub_file.read()
    
    # ECC + AES
    def ecc_aes_encrypt(self, plaintext: str, public_key):
        # Eğer ECC Anahtarları mevcut değilse, otomatik oluştur
        if not self.private_key or not self.public_key:
            self.generate_ecc_keys()

        # ECC Private Key ile Shared Key üret
        shared_key = self.private_key.exchange(ec.ECDH(), public_key)

        # Shared Key'den AES anahtarı türet
        aes_key = HKDF(
            algorithm=SHA256(),
            length=16,
            salt=None,
            info=b"ecc+aes-key",
        ).derive(shared_key)

        # AES ile veriyi şifrele
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext.encode())

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(aes_cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

    # ECC Anahtar Çifti Oluştur ve Dosyaya Kaydet
    def generate_ecc_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def save_private_key_to_file(self, filename: str):
        """
        Özel anahtarı PEM formatında belirtilen dosyaya kaydeder.
        """
        with open(filename, "wb") as file:
            file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    def save_public_key_to_file(self, filename: str):
        """
        Genel anahtarı PEM formatında belirtilen dosyaya kaydeder.
        """
        with open(filename, "wb") as file:
            file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def load_private_key_from_file(self, filename: str):
        """
        Belirtilen dosyadan özel anahtarı yükler.
        """
        with open(filename, "rb") as file:
            self.private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )

    def load_public_key_from_file(self, filename: str):
        """
        Belirtilen dosyadan genel anahtarı yükler.
        """
        with open(filename, "rb") as file:
            self.public_key = serialization.load_pem_public_key(
                file.read(),
                backend=default_backend()
            )

    def ecc_aes_convert_to_public_key(self, public_key_str: str):
        """
        Kullanıcıdan alınan PEM veya Base64 formatındaki genel anahtarı ECC Public Key nesnesine dönüştürür.
        """
        try:
            # Önce PEM formatını dene
            try:
                public_key = serialization.load_pem_public_key(
                    public_key_str.encode('utf-8'),
                    backend=default_backend()
                )
                return public_key
            except ValueError:
                # Eğer PEM değilse, Base64 (DER) formatını dene
                public_key_bytes = base64.b64decode(public_key_str)
                public_key = serialization.load_der_public_key(
                    public_key_bytes,
                    backend=default_backend()
                )
                return public_key
        except Exception as e:
            raise ValueError(f"Geçersiz genel anahtar formatı: {e}")
    
    def ecc_aes_encryption(self,text, composite_encrypt):
        """
        Metni ECC + AES algoritması ile şifreler ve anahtarları dosyalara kaydeder.

        Args:
            text (str): Şifrelenecek metin.
            composite_encrypt: ECC + AES şifreleme sınıfının örneği.

        Returns:
            dict: Şifrelenmiş veri.
        """
        # ECC anahtar çiftini oluştur
        composite_encrypt.generate_ecc_keys()

        # Anahtarları dosyalara kaydet
        private_key_file = "ecc_aes_private_key.pem"
        public_key_file = "ecc_aes_public_key.pem"

        composite_encrypt.save_private_key_to_file(private_key_file)
        composite_encrypt.save_public_key_to_file(public_key_file)

        print(f"Private Key: {composite_encrypt.private_key}")
        print(f"Public Key: {composite_encrypt.public_key}")

        # Public key ile veriyi şifrele
        public_key = composite_encrypt.public_key
        encrypted_data = composite_encrypt.ecc_aes_encrypt(text, public_key)

        print("\nECC + AES Şifrelenmiş veri: ", encrypted_data)
        return encrypted_data
    
    def rsa_aes_encryption(self,text,composite_encrypt):
        """
        Metni RSA + AES algoritması ile şifreler ve anahtarları dosyalara kaydeder.
        
        Args:
            text (str): Şifrelenecek metin.
            composite_encrypt: RSA + AES şifreleme sınıfının örneği.
        
        Returns:
            dict: Şifrelenmiş veri.
        """
        # RSA anahtar çifti oluştur
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

        # Şifreleme işlemi
        encrypted_data = composite_encrypt.rsa_aes_encrypt(text, public_key.decode())

        print(f"Encrypted Data: {encrypted_data}")
        return encrypted_data