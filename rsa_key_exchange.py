from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

# Encrypt a secret key using the public key (for key exchange)
def encrypt_secret_key(public_key, secret_key):
    encrypted_secret_key = public_key.encrypt(
        secret_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_secret_key

# Decrypt the secret key using the private key
def decrypt_secret_key(private_key, encrypted_secret_key):
    secret_key = private_key.decrypt(
        encrypted_secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return secret_key.decode()

def main():
    # Step 1: Generate RSA keys for both parties
    private_key_A, public_key_A = generate_rsa_keys()
    private_key_B, public_key_B = generate_rsa_keys()

    # Step 2: Party A generates a secret key (e.g., for symmetric encryption)
    secret_key = "ThisIsASecretKey"
    print(f"Party A generated secret key: {secret_key}")

    # Step 3: Party A encrypts the secret key using Party B's public key
    encrypted_secret_key = encrypt_secret_key(public_key_B, secret_key)
    print(f"Encrypted secret key (sent to Party B): {encrypted_secret_key.hex()}")

    # Step 4: Party B decrypts the secret key using their private key
    decrypted_secret_key = decrypt_secret_key(private_key_B, encrypted_secret_key)
    print(f"Party B decrypted the secret key: {decrypted_secret_key}")

if __name__ == "__main__":
    main()
