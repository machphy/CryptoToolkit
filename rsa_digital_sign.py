from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA Key Pair
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate 2048-bit RSA key
    private_key = key.export_key()  # Export private key
    public_key = key.publickey().export_key()  # Export public key
    return private_key, public_key

# Step 2: Sign a message with the private key
def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())  # Create a SHA-256 hash of the message
    signature = pkcs1_15.new(key).sign(h)  # Sign the hash with private key
    return signature

# Step 3: Verify the signature with the public key
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())  # Hash the message again
    try:
        pkcs1_15.new(key).verify(h, signature)  # Verify the signature
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

# Main Flow
def main():
    # Step 1: Generate RSA Key Pair
    private_key, public_key = generate_rsa_keys()

    # Step 2: The sender signs the message
    message = "This is a secret message to be signed."
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")

    # Step 3: The receiver verifies the signature
    verify_signature(public_key, message, signature)

if __name__ == "__main__":
    main()
