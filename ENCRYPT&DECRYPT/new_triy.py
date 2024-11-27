from cryptography.fernet import Fernet

# Generate a new key
key = Fernet.generate_key()

# Save the key to a file named 'kuchbhi.key'
with open('rajeev.key', 'wb') as key_file:
    key_file.write(key)

print("Encryption key generated and saved to 'rajeev.key'.")

from cryptography.fernet import Fernet

# Load the encryption key from the file
with open('kuchbhi.key', 'rb') as key_file:
    key = key_file.read()

# Initialize Fernet with the loaded key
f = Fernet(key)

# Read the contents of the file to encrypt
with open('student.csv', 'rb') as original_file:
    original_data = original_file.read()

# Encrypt the file data
encrypted_data = f.encrypt(original_data)

# Save the encrypted data to a new file
with open('enc_student.csv', 'wb') as encrypted_file:
    encrypted_file.write(encrypted_data)

print("File successfully encrypted and saved as 'enc_student.csv'.")

