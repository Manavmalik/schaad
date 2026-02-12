from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file(data, public_key):
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return enc_aes_key + cipher_aes.nonce + tag + ciphertext

def decrypt_file(data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = data[:256]
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    nonce = data[256:272]
    tag = data[272:288]
    ciphertext = data[288:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)
