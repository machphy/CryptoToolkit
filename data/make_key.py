from cryptography.fernet import Fernet

# Generate a new key
key = Fernet.generate_key()

# Save the key to a file named 'kuchbhi.key'
with open('make_new.key', 'wb') as key_file:
    key_file.write(key)

print("Encryption key generated and saved to 'make_new.key'.")