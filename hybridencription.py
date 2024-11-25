from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64

# Step 1: Generate RSA Key Pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Step 2: Encrypt the message with AES (symmetric encryption)
def encrypt_message_aes(message, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    nonce = cipher_aes.nonce
    return ciphertext, tag, nonce

# Step 3: Encrypt AES Key with RSA Public Key
def encrypt_aes_key_with_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

# Step 4: Decrypt AES Key with RSA Private Key
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

# Step 5: Decrypt the message with AES Key
def decrypt_message_aes(encrypted_message, aes_key, nonce, tag):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(encrypted_message, tag)
    return decrypted_message.decode()

# Main Flow
def main():
    # Step 1: Generate RSA Keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Generate AES Key
    aes_key = get_random_bytes(32)  # AES-256 key

    # Step 3: Encrypt the message with AES
    message = "This is a secret message that needs encryption."
    encrypted_message, tag, nonce = encrypt_message_aes(message, aes_key)
    print(f"Encrypted Message (AES): {base64.b64encode(encrypted_message).decode()}")

    # Step 4: Encrypt the AES Key with RSA Public Key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
    print(f"Encrypted AES Key (RSA): {base64.b64encode(encrypted_aes_key).decode()}")

    # Step 5: Decrypt the AES Key with RSA Private Key
    decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

    # Step 6: Decrypt the Message with AES
    decrypted_message = decrypt_message_aes(encrypted_message, decrypted_aes_key, nonce, tag)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()