from pkg_resources import ExtractionError
from gmssl.sm4 import SM4Crypt
from binascii import hexlify,unhexlify

key = hexlify(b'3l5butlj26hvv313')
value = b'111'
iv = hexlify(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
crypt_sm4 = SM4Crypt()

print(key)
crypt_sm4.init(key = key, iv= iv, pad_mode = 'zero')
encrypt_value = crypt_sm4.encrypt_ecb(value)
print(encrypt_value)
decrypt_value = crypt_sm4.decrypt_ecb(unhexlify(encrypt_value))
assert value == decrypt_value
print(value)
print(decrypt_value)

# encrypt_value = crypt_sm4.encrypt_cbc(value)
# print(encrypt_value)
# decrypt_value = crypt_sm4.decrypt_cbc(unhexlify(encrypt_value))
# assert value == decrypt_value
# print(value)
# print(repr(decrypt_value))
