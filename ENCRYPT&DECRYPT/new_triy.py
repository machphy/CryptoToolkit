from cryptography.fernet import Fernet

# Generate a new key
key = Fernet.generate_key()

# Save the key to a file named 'kuchbhi.key'
with open('rajeev.key', 'wb') as key_file:
    key_file.write(key)

print("Encryption key generated and saved to 'rajeev.key'.")
