from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Encrypt the file using AES
def encrypt_file_aes(secret_key, file_path):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Padding the file data to match the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the IV and encrypted data
    with open(f"{file_path}.enc", 'wb') as encrypted_file:
        encrypted_file.write(iv + encrypted_data)
    print(f"File encrypted successfully, saved as '{file_path}.enc'")

# Decrypt the file using AES
def decrypt_file_aes(secret_key, encrypted_file_path):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)  # Extract the IV
        encrypted_data = encrypted_file.read()

    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(f"{encrypted_file_path}_decrypted", 'wb') as decrypted_file:
        decrypted_file.write(original_data)
    print(f"File decrypted successfully, saved as '{encrypted_file_path}_decrypted'")

# Main flow
def main():
    secret_key = os.urandom(32)  # AES-256 key

    # Encrypt a file
    file_path = "example.txt"  # Example file to encrypt
    encrypt_file_aes(secret_key, file_path)

    # Decrypt the file
    encrypted_file_path = "example.txt.enc"
    decrypt_file_aes(secret_key, encrypted_file_path)

if __name__ == "__main__":
    main()
