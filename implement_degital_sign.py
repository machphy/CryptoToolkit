from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA Keys (Private and Public)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    # Serialize the private and public keys
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

# Sign the message (create a digital signature)
def sign_message(private_key, message):
    # Hash the message
    message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    message_hash.update(message.encode())
    hash_value = message_hash.finalize()

    # Sign the hash of the message using the private key
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature

# Verify the digital signature
def verify_signature(public_key, signature, message):
    # Hash the message
    message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    message_hash.update(message.encode())
    hash_value = message_hash.finalize()

    try:
        # Verify the signature using the public key
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid. The message is authentic.")
    except Exception as e:
        print("Signature verification failed:", e)

# Main Flow
def main():
    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Sign a message with the private key
    message = "This is a secret message"
    signature = sign_message(private_key, message)
    print(f"Digital Signature: {signature.hex()}")

    # Step 3: Verify the message signature with the public key
    verify_signature(public_key, signature, message)

if __name__ == "__main__":
    main()
