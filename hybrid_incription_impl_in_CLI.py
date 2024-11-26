from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# RSA Encryption
def rsa_encrypt(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return base64.b64encode(encrypted_message)

# RSA Decryption
def rsa_decrypt(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode()

# AES Encryption
def aes_encrypt(message, key):
    cipher_aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher_aes.nonce + tag + ciphertext)

# AES Decryption
def aes_decrypt(encrypted_message, key):
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode()

# Hybrid Encryption
def hybrid_encrypt(message, rsa_public_key):
    # Generate AES key
    aes_key = get_random_bytes(32)
    
    # Encrypt message with AES
    encrypted_message = aes_encrypt(message, aes_key)
    
    # Encrypt AES key with RSA
    encrypted_aes_key = rsa_encrypt(aes_key.decode(), rsa_public_key)
    
    return encrypted_message, encrypted_aes_key

# Hybrid Decryption
def hybrid_decrypt(encrypted_message, encrypted_aes_key, rsa_private_key):
    # Decrypt AES key using RSA
    aes_key = rsa_decrypt(encrypted_aes_key, rsa_private_key).encode()
    
    # Decrypt message with AES
    decrypted_message = aes_decrypt(encrypted_message, aes_key)
    
    return decrypted_message

# Main function to test the encryption and decryption
def main():
    # Generate RSA keys (private, public)
    private_key = RSA.generate(2048)
    public_key = private_key.publickey().export_key()
    
    message = "This is a hybrid encrypted message done"
    
def rsa_encrypt(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message)
    return base64.b64encode(encrypted_message)

def hybrid_encrypt(message, rsa_public_key):
    # Generate AES key
    aes_key = get_random_bytes(32)  # AES key is in raw bytes format
    
    # Encrypt message with AES
    encrypted_message = aes_encrypt(message, aes_key)
    
    # Encrypt AES key with RSA (no need to decode aes_key to string)
    encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)  # Pass aes_key as bytes
    
    return encrypted_message, encrypted_aes_key


if __name__ == "__main__":
    main()
