import hashlib
import zlib
from argon2 import PasswordHasher


class HashingAlgorithmsEncrypt:
    def __init__(self):
        self.ph = PasswordHasher()  # Argon2 için bir instance

    @staticmethod
    def md5(data: str) -> str:
        """MD5 hash oluşturur."""
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def sha1(data: str) -> str:
        """SHA-1 hash oluşturur."""
        return hashlib.sha1(data.encode()).hexdigest()

    @staticmethod
    def sha256(data: str) -> str:
        """SHA-256 hash oluşturur."""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def sha512(data: str) -> str:
        """SHA-512 hash oluşturur."""
        return hashlib.sha512(data.encode()).hexdigest()

    @staticmethod
    def sha3_256(data: str) -> str:
        """SHA-3 (256-bit) hash oluşturur."""
        return hashlib.sha3_256(data.encode()).hexdigest()

    @staticmethod
    def sha3_512(data: str) -> str:
        """SHA-3 (512-bit) hash oluşturur."""
        return hashlib.sha3_512(data.encode()).hexdigest()

    @staticmethod
    def blake2b(data: str) -> str:
        """Blake2b hash oluşturur."""
        return hashlib.blake2b(data.encode()).hexdigest()

    @staticmethod
    def blake2s(data: str) -> str:
        """Blake2s hash oluşturur."""
        return hashlib.blake2s(data.encode()).hexdigest()

    def argon2(self, password: str) -> str:
        """Argon2 hash oluşturur."""
        return self.ph.hash(password)

    def verify_argon2(self, hashed_password: str, input_password: str) -> bool:
        """Argon2 hash doğrulama yapar."""
        try:
            return self.ph.verify(hashed_password, input_password)
        except:
            return False

    @staticmethod
    def crc32(data: str) -> str:
        """CRC32 checksum oluşturur."""
        return format(zlib.crc32(data.encode()), '08x')

    @staticmethod
    def verify_hash(original_data: str, hashed_data: str, hash_function) -> bool:
        """
        Genel hash doğrulama işlemi.
        :param original_data: Orijinal veri
        :param hashed_data: Karşılaştırılacak hash
        :param hash_function: Kullanılan hash fonksiyonu
        :return: Doğrulama sonucu (True/False)
        """
        return hash_function(original_data) == hashed_data


