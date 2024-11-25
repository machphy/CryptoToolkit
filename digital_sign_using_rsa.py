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

    with open("public_key_rajeev.pem", "wb") as public_file:
        public_file.write(public_pem)
    
    return private_key, public_key

# Sign message with the private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Verify the signature with the public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Main Flow
def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Message to be signed
    message = "This is a secret message"

    # Sign the message
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")

    # Verify the signature
    if verify_signature(public_key, message, signature):
        print("Signature is valid!")
    else:
        print("Signature is invalid!")

if __name__ == "__main__":
    main()
