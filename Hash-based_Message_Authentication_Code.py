import hmac
import hashlib
import os

# Generate a Secret Key
def generate_secret_key():
    return os.urandom(32)  # Generate a 32-byte secret key

# Create HMAC from message and secret key
def create_hmac(secret_key, message):
    # Create a new HMAC object using SHA256
    hmac_object = hmac.new(secret_key, message.encode(), hashlib.sha256)
    return hmac_object.hexdigest()  # Return the HMAC in hexadecimal format

# Verify HMAC by comparing with the received HMAC
def verify_hmac(secret_key, message, received_hmac):
    calculated_hmac = create_hmac(secret_key, message)
    return hmac.compare_digest(calculated_hmac, received_hmac)

# Main Flow
def main():
    # Step 1: Generate secret key
    secret_key = generate_secret_key()

    # Step 2: Create a message
    message = "This is a secret message for HMAC."

    # Step 3: Sender creates HMAC of the message
    generated_hmac = create_hmac(secret_key, message)
    print(f"Generated HMAC: {generated_hmac}")

    # Step 4: Receiver verifies the HMAC
    is_valid = verify_hmac(secret_key, message, generated_hmac)
    print(f"HMAC valid: {is_valid}")

if __name__ == "__main__":
    main()
