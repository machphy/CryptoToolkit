from cryptography.fernet import Fernet

# Generate and save a key
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Load the key and encrypt data
cipher = Fernet(key)
data = "Confidential Information".encode()
encrypted_data = cipher.encrypt(data)
print("Encrypted:", encrypted_data)

# Decrypt data
decrypted_data = cipher.decrypt(encrypted_data)
print("Decrypted:", decrypted_data.decode())
