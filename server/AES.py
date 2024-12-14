from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class AESCipher:
    def __init__(self):
        self.key = get_random_bytes(16)
        self.iv = bytes([0] * AES.block_size)

    def encrypt(self, data):
        cipher_encrypt = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher_encrypt.encrypt(padded_data)

        return ciphertext

    def decrypt(self, ciphertext):
        cipher_decrypt = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted_padded_data = cipher_decrypt.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        return decrypted_data


class RSACipher:
    def __init__(self, publickey_der):
        try:
            # Import the public key from the DER-encoded binary data
            self.publickey = RSA.import_key(publickey_der)
            print("Public key successfully imported.")
        except ValueError as e:
            print(f"Invalid public key format: {e}")
            raise

    def encryptTRY(self, data):
        # Encrypt the data using the public key
        cipher = PKCS1_OAEP.new(self.publickey)
        ciphertext = cipher.encrypt(data)  # Convert the plaintext data to bytes
        return ciphertext
