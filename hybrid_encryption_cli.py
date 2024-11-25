import argparse
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("RSA keys generated and saved to 'private_key.pem' and 'public_key.pem'")

# Function to encrypt a message using hybrid encryption
def hybrid_encrypt(message, rsa_public_key_path):
    # Load RSA public key
    with open(rsa_public_key_path, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())

    # Generate AES key and encrypt the message
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return ciphertext, cipher_aes.nonce, tag, encrypted_aes_key

# Function to decrypt the message using hybrid encryption
def hybrid_decrypt(encrypted_message, nonce, tag, encrypted_aes_key, rsa_private_key_path):
    # Load RSA private key
    with open(rsa_private_key_path, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())

    # Decrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt the message
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(encrypted_message, tag)

    return decrypted_message.decode()

# Main function for the CLI
def main():
    parser = argparse.ArgumentParser(description="Hybrid Encryption CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Sub-command: Generate RSA keys
    subparsers.add_parser("generate-keys", help="Generate RSA key pair")

    # Sub-command: Encrypt a message
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a message")
    encrypt_parser.add_argument("--message", required=True, help="Message to encrypt")
    encrypt_parser.add_argument("--public-key", required=True, help="Path to RSA public key")

    # Sub-command: Decrypt a message
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a message")
    decrypt_parser.add_argument("--private-key", required=True, help="Path to RSA private key")

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_rsa_keys()

    elif args.command == "encrypt":
        ciphertext, nonce, tag, encrypted_aes_key = hybrid_encrypt(args.message, args.public_key)

        # Save encrypted data to files
        with open("encrypted_message.bin", "wb") as f:
            f.write(ciphertext)
        with open("nonce.bin", "wb") as f:
            f.write(nonce)
        with open("tag.bin", "wb") as f:
            f.write(tag)
        with open("encrypted_aes_key.bin", "wb") as f:
            f.write(encrypted_aes_key)

        print("Encryption successful! Encrypted files saved.")

    elif args.command == "decrypt":
        # Load encrypted files
        with open("encrypted_message.bin", "rb") as f:
            encrypted_message = f.read()
        with open("nonce.bin", "rb") as f:
            nonce = f.read()
        with open("tag.bin", "rb") as f:
            tag = f.read()
        with open("encrypted_aes_key.bin", "rb") as f:
            encrypted_aes_key = f.read()

        # Decrypt the message
        decrypted_message = hybrid_decrypt(encrypted_message, nonce, tag, encrypted_aes_key, args.private_key)
        print(f"Decrypted Message: {decrypted_message}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
