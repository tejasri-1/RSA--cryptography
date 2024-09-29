# Import necessary libraries
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import base64

# Generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt message using AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce, ciphertext, tag

# Decrypt message using AES
def decrypt_message(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message

# Sign message using RSA
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()
    digest.update(message)
    return signer.sign(digest)

# Verify signature using RSA
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()
    digest.update(message)
    return signer.verify(digest, signature)

# Main function
def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Input message
    message = input("Enter your message: ").encode()

    # Encrypt message using AES
    key = get_random_bytes(32)
    nonce, ciphertext, tag = encrypt_message(message, key)

    # Sign encrypted message using RSA
    signature = sign_message(ciphertext, private_key)

    # Print encrypted message and signature
    print("Encrypted Message:", base64.b64encode(ciphertext).decode())
    print("Signature:", base64.b64encode(signature).decode())

    # Verify signature
    if verify_signature(ciphertext, signature, public_key):
        print("Signature verified successfully!")
    else:
        print("Signature verification failed!")

    # Decrypt message using AES
    decrypted_message = decrypt_message(nonce, ciphertext, tag, key)

    # Print decrypted message
    print("Decrypted Message:", decrypted_message.decode())

if __name__ == "__main__":
    main()