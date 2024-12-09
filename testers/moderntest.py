from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64

# RSA Key Pair Oluştur
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Test Mesajı
message = "Bu bir test mesajıdır."

# İmzalama (RSA-PSS)
private_key_obj = RSA.import_key(private_key)
hash_obj = SHA256.new(message.encode())
signature = pss.new(private_key_obj).sign(hash_obj)
encoded_signature = base64.b64encode(signature).decode()

print("İmzalanan Mesaj:", message)
print("Oluşturulan İmza (Base64):", encoded_signature)

# Doğrulama (RSA-PSS)
try:
    decoded_signature = base64.b64decode(encoded_signature)
    public_key_obj = RSA.import_key(public_key)
    hash_obj_verify = SHA256.new(message.encode())
    verifier = pss.new(public_key_obj)
    verifier.verify(hash_obj_verify, decoded_signature)
    print("İmza doğrulandı: Geçerli")
except (ValueError, TypeError):
    print("İmza doğrulama başarısız: Geçersiz!")
