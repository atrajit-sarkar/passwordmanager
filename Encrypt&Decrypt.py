from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64

def get_key(password):
    # Derive a 32-byte (256-bit) key from the password using SHA-256
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def encrypt(text, password):
    key = get_key(password)
    cipher = AES.new(key, AES.MODE_ECB)  # Use ECB mode
    padded_text = pad(text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')

def decrypt(encrypted_text, password):
    key = get_key(password)
    cipher = AES.new(key, AES.MODE_ECB)  # Use ECB mode
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted_text.decode('utf-8')

if __name__ == "__main__":
    # Get user input for the text and password
    consent=input("What you want?(encrypt/decrypt)")
    if consent=="encrypt":
        # Encrypt the text
        text = input("Enter the text to encrypt: ")
        password = input("Enter the password: ")
        encrypted_text = encrypt(text, password)
        print(f"Encrypted text: {encrypted_text}")
    elif consent=="decrypt":
        # Decrypt the text
        encrypted_text = input("Enter the encrypted_text: ")
        password = input("Enter the password: ")
        decrypted_text = decrypt(encrypted_text, password)
        print(f"Decrypted text: {decrypted_text}")
