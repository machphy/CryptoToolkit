from cryptography.fernet import Fernet

# Generate a new key
# key = Fernet.generate_key()

# # Save the key to a file named 'kuchbhi.key'
# with open('kuchbhi.key', 'wb') as key_file:
#     key_file.write(key)

# print("Encryption key generated and saved to 'kuchbhi.key'.")

# from cryptography.fernet import Fernet

# # Load the encryption key from the file
# with open('kuchbhi.key', 'rb') as key_file:
#     key = key_file.read()

# # Initialize Fernet with the loaded key
# f = Fernet(key)

# # Read the contents of the file to encrypt
# with open('student.csv', 'rb') as original_file:
#     original_data = original_file.read()

# # Encrypt the file data
# encrypted_data = f.encrypt(original_data)

# # Save the encrypted data to a new file
# with open('enc_student.csv', 'wb') as encrypted_file:
#     encrypted_file.write(encrypted_data)

# print("File successfully encrypted and saved as 'enc_student.csv'.")





from cryptography.fernet import Fernet

# Load the encryption key
with open('kuchbhi.key', 'rb') as key_file:
    key = key_file.read()

f = Fernet(key)

# Read the encrypted file
with open('enc_student.csv', 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()

# Decrypt the data
decrypted_data = f.decrypt(encrypted_data)

# Save the decrypted data
with open('decrypted_student.csv', 'wb') as decrypted_file:
    decrypted_file.write(decrypted_data)

print("File decrypted successfully and saved as 'decrypted_student.csv'.")
