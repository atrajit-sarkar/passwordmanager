from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path: str, password: str):
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key from the password
    key = derive_key(password, salt)
    
    # Initialize Fernet with the derived key
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = fernet.encrypt(file_data)
    
    with open(file_path, 'wb') as file:
        file.write(salt + encrypted_data)
    
    print(f"File encrypted and saved as {file_path}")

if __name__ == "__main__":
    file_path = input("Enter the path of the text file to encrypt: ")
    password = input("Enter the password to use for encryption: ")
    
    encrypt_file(file_path, password)
