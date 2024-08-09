import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib
import platform
import socket
import subprocess

# Constants
BLOCK_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16
ITERATIONS = 100000

def get_serial_number():
    """Retrieve the hardware serial number."""
    try:
        if platform.system() == "Windows":
            # Windows command to get the serial number
            command = "wmic bios get serialnumber"
            serial_number = subprocess.check_output(command).decode().split("\n")[1].strip()
        elif platform.system() == "Linux":
            # Linux command to get the serial number
            command = "sudo dmidecode -s system-serial-number"
            serial_number = subprocess.check_output(command, shell=True).decode().strip()
        elif platform.system() == "Darwin":
            # macOS command to get the serial number
            command = "system_profiler SPHardwareDataType | awk '/Serial/ {print $4}'"
            serial_number = subprocess.check_output(command, shell=True).decode().strip()
        else:
            serial_number = "UNKNOWN_SERIAL"
    except Exception as e:
        print(f"Error retrieving serial number: {e}")
        serial_number = "UNKNOWN_SERIAL"
    
    return serial_number

def get_device_id():
    """Get a device-specific identifier using multiple hardware characteristics."""
    # Example identifiers: hostname, MAC address, system serial number, and hardware serial number
    hostname = socket.gethostname()
    
    # Using uuid to get the MAC address
    mac_address = hex(uuid.getnode())
    
    system_info = platform.uname()
    serial_number = hashlib.sha256(system_info.node.encode()).hexdigest()
    hardware_serial = get_serial_number()

    # Combine all identifiers into a single string
    combined_id = f"{hostname}-{mac_address}-{serial_number}-{hardware_serial}"
    
    # Hash the combined ID for uniformity and security
    device_id = hashlib.sha256(combined_id.encode()).hexdigest()
    
    return device_id

def derive_key_and_iv(password: str, salt: bytes, device_id: str) -> (bytes, bytes):
    # Combine password with device_id to derive a unique key per device
    password = password + device_id
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    
    # Derive IV deterministically from the key
    iv = hashlib.sha256(key).digest()[:BLOCK_SIZE]  # IV must be BLOCK_SIZE bytes
    return key, iv

def encrypt_text(plain_text: str, password: str) -> str:
    # Use a consistent salt for same password and device (e.g., hash of device_id + password)
    device_id = get_device_id()
    salt = hashlib.sha256((password + device_id).encode()).digest()[:SALT_SIZE]
    
    # Derive the encryption key and IV
    key, iv = derive_key_and_iv(password, salt, device_id)
    
    # Initialize cipher with derived key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), BLOCK_SIZE))
    
    # Encode the encrypted data as base64
    encrypted_data = base64.b64encode(salt + ct_bytes).decode('utf-8')
    
    return encrypted_data

def decrypt_text(encrypted_text: str, password: str) -> str:
    # Decode the base64 encoded data
    encrypted_data = base64.b64decode(encrypted_text)
    
    # Extract the salt and ciphertext
    salt = encrypted_data[:SALT_SIZE]
    ct = encrypted_data[SALT_SIZE:]
    
    # Get the device-specific identifier
    device_id = get_device_id()
    
    # Derive the encryption key and IV
    key, iv = derive_key_and_iv(password, salt, device_id)
    
    # Initialize cipher with derived key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad the plaintext
    plain_text = unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')
    
    return plain_text

if __name__ == "__main__":
    mode = input("Choose mode (encrypt/decrypt): ").strip().lower()
    password = input("Enter the password: ").strip()

    if mode == "encrypt":
        plain_text = input("Enter the text to encrypt: ").strip()
        encrypted_text = encrypt_text(plain_text, password)
        print(f"Encrypted text: {encrypted_text}")
    elif mode == "decrypt":
        encrypted_text = input("Enter the text to decrypt: ").strip()
        try:
            plain_text = decrypt_text(encrypted_text, password)
            print(f"Decrypted text: {plain_text}")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("Invalid mode selected.")
