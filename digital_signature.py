from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

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

# Sign message with the private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Verify message signature with the public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid!")
    except InvalidSignature:
        print("Signature is invalid!")

# Main Flow
def main():
    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Sign a message using the private key
    message = "This is a secret message"
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")

    # Step 3: Verify the signature using the public key
    verify_signature(public_key, message, signature)

if __name__ == "__main__":
    main()
