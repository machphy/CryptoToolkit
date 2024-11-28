from cryptography.fernet import Fernet

# Load the encryption key from the key file
with open('key.key', 'rb') as key_file:
    key = key_file.read()

# Initialize Fernet with the loaded key
f = Fernet(key)

# Read the encrypted data from the file (your enc_student.csv)
with open('enc_student.csv', 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()

# Decrypt the data
try:
    decrypted_data = f.decrypt(encrypted_data)

    # Save the decrypted data to a new file
    with open('_student_data.csv', 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print("File successfully decrypted and saved as '_student_data.csv'.")
except Exception as e:
    print(f"Error: {e}")
