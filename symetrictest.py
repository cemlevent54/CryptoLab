from Crypto.Cipher import AES, DES
import time
import os

# Rastgele bir veri oluştur
data = os.urandom(1024)  # 1 KB'lik rastgele veri

# AES için anahtar ve şifreleme nesnesi
aes_key = os.urandom(16)  # 16 byte AES key
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# DES için anahtar ve şifreleme nesnesi
des_key = os.urandom(8)  # 8 byte DES key
des_cipher = DES.new(des_key, DES.MODE_ECB)

# Performans ölçümü için zamanlayıcı
def measure_encryption_time(cipher, data):
    start = time.perf_counter()
    encrypted = cipher.encrypt(data)
    end = time.perf_counter()
    return end - start, encrypted

# Veriyi 16 ve 8 byte'lık bloklara hizala
padded_data_aes = data + b' ' * (16 - len(data) % 16)  # AES için hizalama
padded_data_des = data + b' ' * (8 - len(data) % 8)  # DES için hizalama

# AES Performansı
aes_time, aes_encrypted = measure_encryption_time(aes_cipher, padded_data_aes)

# DES Performansı
des_time, des_encrypted = measure_encryption_time(des_cipher, padded_data_des)

# Sonuçları yazdır
print(f"AES Şifreleme Süresi: {aes_time:.6f} saniye")
print(f"DES Şifreleme Süresi: {des_time:.6f} saniye")

# Şifreleme karşılaştırması
if aes_time < des_time:
    print("AES daha hızlı.")
else:
    print("DES daha hızlı.")
