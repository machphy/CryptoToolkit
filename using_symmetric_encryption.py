import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import shutil

def encrypt_file(file_path, key):
    try:
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)

        # Create a cipher object with AES algorithm
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Open the file to encrypt
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Pad the data to make sure it's a multiple of the block size (16 bytes for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        # Encrypt the data
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Write the IV and encrypted data to a new file
        with open(file_path + '.enc', 'wb') as f_enc:
            f_enc.write(iv + encrypted_data)

        print(f"File '{file_path}' encrypted successfully. Encrypted file saved as '{file_path}.enc'")

    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file(encrypted_file_path, key):
    try:
        with open(encrypted_file_path, 'rb') as f_enc:
            iv = f_enc.read(16)  # Extract the IV (first 16 bytes)
            encrypted_data = f_enc.read()  # Remaining data is the encrypted file content

        # Create cipher object with AES algorithm
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Write the decrypted data back to a file
        decrypted_file_path = encrypted_file_path.replace('.enc', '_decrypted.txt')
        with open(decrypted_file_path, 'wb') as f_dec:
            f_dec.write(original_data)

        print(f"File '{encrypted_file_path}' decrypted successfully. Decrypted file saved as '{decrypted_file_path}'")

    except Exception as e:
        print(f"Error during decryption: {e}")

# Example AES key (32 bytes)
key = os.urandom(32)

# Encrypt the file
encrypt_file("example.txt", key)

# Decrypt the encrypted file (for testing purposes)
decrypt_file("example.txt.enc", key)
