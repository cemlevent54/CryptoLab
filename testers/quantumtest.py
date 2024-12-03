from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# WhatsApp (Signal Protokolü) Şifreleme
def encrypt_whatsapp(message, key):
    iv = get_random_bytes(16)  # Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    # HMAC-SHA256 ile mesaj doğrulama
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_message)
    mac = hmac.digest()  # Mesaj doğrulama kodu

    return iv + encrypted_message + mac  # IV + Şifreli Mesaj + HMAC

# WhatsApp (Signal Protokolü) Çözme
def decrypt_whatsapp(encrypted_message, key):
    iv = encrypted_message[:16]  # İlk 16 byte IV
    mac = encrypted_message[-32:]  # Son 32 byte HMAC
    encrypted_data = encrypted_message[16:-32]  # Şifreli mesaj kısmı

    # HMAC doğrulama
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)
    hmac.verify(mac)

    # AES-CBC ile çözme
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_message.decode('utf-8')

# AES-IGE Modu Manuel Implementasyonu
def aes_ige_encrypt(data, key, iv):
    """
    AES-IGE (Infinite Garble Extension) modunda şifreleme
    """
    cipher = AES.new(key, AES.MODE_ECB)  # ECB modunu temel alıyoruz
    blocks = [data[i:i + AES.block_size] for i in range(0, len(data), AES.block_size)]
    previous_cipher_block = iv[:AES.block_size]
    previous_plain_block = iv[AES.block_size:]

    encrypted = b""
    for block in blocks:
        xored = bytes([a ^ b for a, b in zip(block, previous_cipher_block)])
        cipher_block = cipher.encrypt(xored)
        encrypted += cipher_block
        previous_cipher_block = cipher_block
        previous_plain_block = block

    return encrypted

def aes_ige_decrypt(data, key, iv):
    """
    AES-IGE (Infinite Garble Extension) modunda çözme
    """
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i + AES.block_size] for i in range(0, len(data), AES.block_size)]
    previous_cipher_block = iv[:AES.block_size]
    previous_plain_block = iv[AES.block_size:]

    decrypted = b""
    for block in blocks:
        xored = bytes([a ^ b for a, b in zip(cipher.decrypt(block), previous_cipher_block)])
        decrypted += xored
        previous_cipher_block = block
        previous_plain_block = xored

    return decrypted

# Telegram (MTProto) Şifreleme
def encrypt_telegram(message, key):
    iv = get_random_bytes(32)  # IGE modunda IV'nin boyutu 32 byte olmalı
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted_message = aes_ige_encrypt(padded_message, key, iv)
    return iv + encrypted_message  # IV + Şifreli Mesaj

# Telegram (MTProto) Çözme
def decrypt_telegram(encrypted_message, key):
    iv = encrypted_message[:32]  # İlk 32 byte IV
    encrypted_data = encrypted_message[32:]  # Şifreli mesaj
    decrypted_message = aes_ige_decrypt(encrypted_data, key, iv)
    return unpad(decrypted_message, AES.block_size).decode('utf-8')

# Test Fonksiyonu
def test_encrypt_decrypt():
    key = get_random_bytes(16)  # AES için 16 byte anahtar
    message = "Bu bir test mesajıdır."
    
    print("\n--- WhatsApp (Signal) Testi ---")
    # WhatsApp Şifreleme ve Çözme
    encrypted_whatsapp = encrypt_whatsapp(message, key)
    print("Şifrelenmiş Mesaj (WhatsApp):", encrypted_whatsapp.hex())
    decrypted_whatsapp = decrypt_whatsapp(encrypted_whatsapp, key)
    print("Çözülmüş Mesaj (WhatsApp):", decrypted_whatsapp)

    print("\n--- Telegram (MTProto) Testi ---")
    # Telegram Şifreleme ve Çözme
    encrypted_telegram = encrypt_telegram(message, key)
    print("Şifrelenmiş Mesaj (Telegram):", encrypted_telegram.hex())
    decrypted_telegram = decrypt_telegram(encrypted_telegram, key)
    print("Çözülmüş Mesaj (Telegram):", decrypted_telegram)

# Testi Çalıştır
if __name__ == "__main__":
    test_encrypt_decrypt()
