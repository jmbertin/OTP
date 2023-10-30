import sys
import hmac
import hashlib
import argparse
from cryptography.fernet import Fernet
from datetime import datetime
import qrcode
import base64
import os
import tkinter as tk
from tkinter import messagebox, Entry, Button, Label
from PIL import Image, ImageTk

HOTP_KEY_FILE = 'otp.key'
CIPHER_KEY_FILE = 'otp.cip'
QR_CODE_FILE = 'otp_seed.png'

def is_hex(s):
    """
    Check if the provided string is a valid hexadecimal.
    Args: s (str): The string to be checked.
    Returns: bool: True if the string is a valid hexadecimal, False otherwise.
    """
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def display_qr_code(image_path):
    """
    Initialize the graphical user interface for OTP generation.
    """
    global root
    image = Image.open(image_path)
    photo = ImageTk.PhotoImage(image)

    qr_window = tk.Toplevel(root)
    qr_window.title("QR Code")
    label = Label(qr_window, image=photo)
    label.image = photo
    label.pack(padx=10, pady=10)

def hex_to_base32(hex_str):
    """
    Convert a given hexadecimal string to base32.
    Args: hex_str (str): The hexadecimal string to be converted.
    Returns: str: The converted base32 string.
    """
    raw_bytes = bytes.fromhex(hex_str)
    b32_str = base64.b32encode(raw_bytes).decode('utf-8').rstrip('=')
    return b32_str

def generate_qr(hex_key, gui_mode=False):
    """
    Generate a QR code for the provided hexadecimal key and save it as an image.
    Args: hex_key (str): The hexadecimal key for which the QR code will be generated.
    """
    secret_base32 = hex_to_base32(hex_key)
    label = "otp"
    issuer = "otp"
    otp_auth_url = f"otpauth://totp/{label}?secret={secret_base32}&issuer={issuer}"

    img = qrcode.make(otp_auth_url)
    if not (can_create_or_write_file(QR_CODE_FILE)):
        print("QR-Code file is not writeable.")
        if gui_mode:
            messagebox.showerror("Error", "QR-Code file is not writeable.")
    else:
        img.save(QR_CODE_FILE)
        print("QR code for the key has been saved successfully.")
        if gui_mode:
            display_qr_code(QR_CODE_FILE)

def encrypt_data(data, cipher_key):
    """
    Encrypt the given data using the cipher key.
    Args:
    - data (str):         The data to be encrypted.
    - cipher_key (bytes): The key used for encryption.
    Returns: bytes: Encrypted data.
    """
    cipher = Fernet(cipher_key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, cipher_key):
    """
    Decrypt the given encrypted data using the cipher key.
    Args:
    - encrypted_data (bytes): The data to be decrypted.
    - cipher_key (bytes):     The key used for decryption.
    Returns: str: Decrypted data as a string.
    """
    cipher = Fernet(cipher_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()

def save_key(hex_key, gui_mode=False):
    """
    Encrypt and store the provided hexadecimal key.
    Args: hex_key (str): The hexadecimal key to be encrypted and stored.
    """
    cipher_key = Fernet.generate_key()
    encrypted_key = encrypt_data(hex_key, cipher_key)
    with open(HOTP_KEY_FILE, 'wb') as f:
        f.write(encrypted_key)
    with open(CIPHER_KEY_FILE, 'wb') as f:
        f.write(cipher_key)

    generate_qr(hex_key, gui_mode)

def get_stored_key():
    """
    Retrieve and decrypt the stored hexadecimal key.
    Returns: str: The decrypted hexadecimal key.
    """
    with open(HOTP_KEY_FILE, 'rb') as f:
        encrypted_key = f.read().strip()
    with open(CIPHER_KEY_FILE, 'rb') as f:
        cipher_key = f.read().strip()
    return decrypt_data(encrypted_key, cipher_key)

def hotp(secret, counter):
    """
    Generate a one-time password using the HOTP algorithm.
    Args:
    - secret (str):  The shared secret key in hexadecimal format.
    - counter (int): The counter value used in the HOTP algorithm.
    Returns: str: 6-digit one-time password.
    """
    key = bytes.fromhex(secret)
    msg = counter.to_bytes(8, 'big')
    hs = hmac.new(key, msg, hashlib.sha1).hexdigest()
    offset = int(hs[-1], 16)
    binary_value = int(hs[offset*2:offset*2+8], 16) & 0x7fffffff
    hotp = str(binary_value)[-6:]
    return hotp

def generate_otp():
    """
    Generate a one-time password based on the stored key.
    Returns: str: 6-digit one-time password.
    """
    counter = int(datetime.now().timestamp()) // 30
    secret_key = get_stored_key()
    return hotp(secret_key, counter)

def gui_init():
    """
    Initialize the graphical user interface for OTP generation.
    """
    global hex_key_entry, otp_label, root

    root = tk.Tk()
    root.title("OTP Generator")

    hex_key_label = Label(root, text="Enter the hexadecimal key:")
    hex_key_label.pack(padx=20, pady=5)
    hex_key_entry = Entry(root, width=70)
    hex_key_entry.pack(padx=20, pady=5)

    generate_key_button = Button(root, text="Generate & Save Keys", command=gui_generate_key)
    generate_key_button.pack(pady=20)

    generate_otp_button = Button(root, text="Generate OTP", command=gui_generate_otp)
    generate_otp_button.pack(pady=20)

    otp_label = Label(root, text="", font=("Arial", 24))
    otp_label.pack(pady=20)

    root.mainloop()

def gui_generate_key():
    """
    Generate a key and save it through the GUI, then generate an OTP.
    """
    global hex_key_entry, otp_label
    hex_key = hex_key_entry.get()
    if not is_hex(hex_key):
        messagebox.showerror("Error", "The provided key is not a valid hexadecimal.")
        return
    if len(hex_key) < 64:
        messagebox.showerror("Error", "The provided key is too short.")
        return
    if not (can_create_or_write_file(HOTP_KEY_FILE) and can_create_or_write_file(CIPHER_KEY_FILE)):
        messagebox.showerror("Error", "One or both of the required key files are not writeable.")
        return
    save_key(hex_key, gui_mode=True)
    otp_label.config(text=generate_otp())
    messagebox.showinfo("Success", "Keys saved and OTP generated successfully.")

def gui_generate_otp():
    """
    Generate an OTP through the GUI and display it.
    """
    global otp_label
    otp = generate_otp()
    otp_label.config(text=otp)

def file_writable(filepath):
    """
    Check if a file exists and is writable.
    Args: filepath (str): The path of the file to be checked.
    Returns: bool: True if the file exists and is writable, False otherwise.
    """
    return os.path.exists(filepath) and os.access(filepath, os.W_OK)

def directory_writable(directory_path):
    """
    Check if a directory is writable.
    Args: directory_path (str): The path of the directory to be checked.
    Returns: bool: True if the directory is writable, False otherwise.
    """
    return os.access(directory_path, os.W_OK)

def can_create_or_write_file(filepath):
    """
    Check if a file can be created or written to at the specified path.
    Args: filepath (str): The path where the file will be created or written to.
    Returns: bool: True if the file can be created or written to, False otherwise.
    """
    if os.path.exists(filepath):
        return file_writable(filepath)
    dir_path = os.path.dirname(filepath)
    if dir_path == "":
        dir_path = "."
    return directory_writable(dir_path)

def main():
    """
    Main function to handle command-line arguments and execute the desired action.
    """
    parser = argparse.ArgumentParser(description="One-Time Password Generator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-g', '--generate', metavar="HEX_KEY", help="Store a hexadecimal key.")
    group.add_argument('-k', '--key', action='store_true', help="Generate a new temporary password based on the stored key.")
    group.add_argument('--graphic', action='store_true', help="Launch the graphical interface.")

    args = parser.parse_args()

    if args.graphic:
        gui_init()
        sys.exit(0)
    if args.generate:
        hex_key = args.generate
        if not is_hex(hex_key):
            print("The provided key is not a valid hexadecimal.")
            return
        if len(hex_key) < 64:
            print("The provided key is too short.")
            return
        if not (can_create_or_write_file(HOTP_KEY_FILE) and can_create_or_write_file(CIPHER_KEY_FILE)):
            print("One or both of the required key files are not writeable.")
            return
        save_key(hex_key, gui_mode=False)
        print("Keys saved successfully.")
    elif args.key:
        try:
            get_stored_key()
        except FileNotFoundError:
            print("The key has not been stored yet.")
            return
        otp = generate_otp()
        print(otp)

if __name__ == "__main__":
    main()

