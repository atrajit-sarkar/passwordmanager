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

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        encrypted_data = file.read()
    
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except:
        print("Invalid password or corrupted file.")
        return
    
    with open(file_path.replace('.encrypted', ''), 'wb') as file:
        file.write(decrypted_data)
    
    print(f"File decrypted and saved as {file_path.replace('.encrypted', '')}")

if __name__ == "__main__":
    file_path = input("Enter the path of the encrypted file: ")
    password = input("Enter the password to use for decryption: ")
    
    decrypt_file(file_path, password)
