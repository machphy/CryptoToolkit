from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Generate RSA Keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()

    # Serialize the private key and public key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)
    
    print("RSA keys generated and saved to 'private_key.pem' and 'public_key.pem'")
    return private_key, public_key

# Encrypt message with the public key
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Decrypt message with the private key
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Main Flow
def main():
    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Encrypt a message using the public key
    message = "This is a secret message"
    encrypted_message = encrypt_message(public_key, message)
    print(f"Encrypted Message: {encrypted_message.hex()}")

    # Step 3: Decrypt the message using the private key
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
