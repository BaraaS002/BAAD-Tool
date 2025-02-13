import os
import struct
import time
import logging
import zipfile
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, StringVar
from tkinterdnd2 import TkinterDnD, DND_FILES  # Drag and drop library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey, InvalidTag
import subprocess

BLOCK_SIZE = 128
KEY_SIZE = 32

# Setup logging
logging.basicConfig(filename='cryptography/encryption_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

def check_password_strength(password):
    """Check the strength of the password."""
    if len(password) < 8:
        messagebox.showerror("Error", "Password too short! Minimum length is 8.")
        return False
    if not any(char.isdigit() for char in password):
        messagebox.showerror("Error", "Password must contain at least one number.")
        return False
    if not any(char.isalpha() for char in password):
        messagebox.showerror("Error", "Password must contain at least one letter.")
        return False
    return True

def generate_key(password, salt):
    """Generate a key using password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def compress_and_encrypt(input_path, password):
    """Compress and encrypt a file or a folder."""
    start_time = time.time()
    try:
        if os.path.isfile(input_path):
            zip_file_path = os.path.join('cryptography', 'encrypt', os.path.basename(input_path) + '.zip')
            os.makedirs(os.path.dirname(zip_file_path), exist_ok=True)
            
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(input_path, os.path.basename(input_path))
                logging.info(f"Compressed file: {input_path} -> {zip_file_path}")
        
        elif os.path.isdir(input_path):
            zip_file_path = os.path.join('cryptography', 'encrypt', os.path.basename(input_path) + '.zip')
            os.makedirs(os.path.dirname(zip_file_path), exist_ok=True)

            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                file_count = 0
                for root, _, files in os.walk(input_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, input_path)
                        zipf.write(file_path, relative_path)
                        logging.info(f"Compressed: {file_path} -> {relative_path}")
                        file_count += 1
                
                if file_count == 0:
                    raise Exception("No files found in the folder! Make sure the folder is not empty.")
        
        else:
            raise Exception("Invalid path! Please provide a valid file or folder.")

        if os.path.getsize(zip_file_path) == 0:
            raise Exception("The zip file is empty! Compression failed.")

        logging.info(f"Zip file created successfully: {zip_file_path} ({os.path.getsize(zip_file_path)} bytes)")

        encrypt_file_gui(zip_file_path, password)
        os.remove(zip_file_path)
        messagebox.showinfo("Success", "Compression and encryption completed successfully.")
    except Exception as e:
        logging.error(f"Error during compression and encryption: {e}")
        messagebox.showerror("Error", f"An error occurred during compression and encryption:\n{e}")
    finally:
        elapsed_time = time.time() - start_time
        logging.info(f"Compression and encryption took {elapsed_time:.2f} seconds.")






def encrypt_file_gui(file_path, password):
    """Encrypt a file using AES-256."""
    start_time = time.time()
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise Exception(f"File {file_path} is empty! Cannot encrypt an empty file.")
        logging.info(f"Encrypting file: {file_path} with size {file_size} bytes")

        salt = os.urandom(16)
        key = generate_key(password, salt)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = os.path.join('cryptography', 'encrypt', os.path.basename(file_path) + '.enc')
        os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
        with open(encrypted_file_path, 'wb') as f:
            file_name = os.path.basename(file_path).encode()
            f.write(salt + iv + struct.pack('I', len(file_name)) + file_name + ciphertext)

        logging.info(f"Encrypted file saved at: {encrypted_file_path} with size {os.path.getsize(encrypted_file_path)} bytes")
        messagebox.showinfo("Encryption Complete", f"File encrypted successfully!\nSaved at: {encrypted_file_path}")
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        messagebox.showerror("Encryption Error", f"An error occurred during encryption:\n{e}")
    finally:
        elapsed_time = time.time() - start_time
        logging.info(f"Encryption took {elapsed_time:.2f} seconds.")



def decrypt_file_gui(file_identifier, password):
    """Decrypt a file using AES-256."""
    start_time = time.time()
    try:
        encrypt_folder = os.path.join('cryptography', 'encrypt')
        if os.path.isfile(file_identifier):
            file_path = file_identifier
        else:
            file_path = os.path.join(encrypt_folder, file_identifier + '.enc')

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")

        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            file_name_length = struct.unpack('I', f.read(4))[0]
            original_file_name = f.read(file_name_length).decode()
            ciphertext = f.read()

        key = generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        decrypted_file_path = os.path.join('cryptography', 'decrypt', original_file_name)

        # التأكد من أن مسار الحفظ ليس مجلدًا
        if os.path.exists(decrypted_file_path) and os.path.isdir(decrypted_file_path):
            raise IsADirectoryError(f"{decrypted_file_path} is a directory!")

        # إنشاء المجلد الخاص بالملف إن لم يكن موجودًا
        os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)

        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        if os.path.getsize(decrypted_file_path) == 0:
            raise Exception("Decrypted file is empty!")

        logging.info(f"Decrypted file saved: {decrypted_file_path} ({os.path.getsize(decrypted_file_path)} bytes)")

        if zipfile.is_zipfile(decrypted_file_path):
            extract_folder = os.path.join('cryptography', 'decrypt', os.path.splitext(original_file_name)[0])
            os.makedirs(extract_folder, exist_ok=True)
            with zipfile.ZipFile(decrypted_file_path, 'r') as zipf:
                zipf.extractall(extract_folder)
                logging.info(f"Extracted files to: {extract_folder}")
            os.remove(decrypted_file_path)
            messagebox.showinfo("Decryption Complete", f"File decrypted and extracted successfully!\nFiles saved at: {extract_folder}")
        else:
            messagebox.showinfo("Decryption Complete", f"File decrypted successfully!\nSaved at: {decrypted_file_path}")
    except IsADirectoryError as e:
        logging.error(f"Decryption failed: {e}")
        messagebox.showerror("Decryption Error", f"Decryption failed due to directory conflict:\n{e}")
    except Exception as e:
        logging.error(f"Error during decryption: {e}")
        messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{e}")
    finally:
        elapsed_time = time.time() - start_time
        logging.info(f"Decryption took {elapsed_time:.2f} seconds.")






def browse_file():
    """Open a file dialog to select files."""
    filename = filedialog.askopenfilename(title="Select file")
    file_path_var.set(filename)

def encrypt_action():
    """Action for the encrypt button."""
    file_path = file_path_var.get()
    password = password_var.get()
    if not check_password_strength(password):
        return
    encrypt_file_gui(file_path, password)

def encrypt_and_compress_action():
    """Action for the compress and encrypt button."""
    folder_path = file_path_var.get()
    password = password_var.get()
    if not check_password_strength(password):
        return
    compress_and_encrypt(folder_path, password)

def decrypt_action():
    """Action for the decrypt button."""
    file_path = file_path_var.get()
    password = password_var.get()
    decrypt_file_gui(file_path, password)

def show_encryption_options():
    """Display encryption options."""
    clear_window()
    Label(root, text="Welcome to the world of encryption Choose an option:", bg='#2e3b4e', fg='white', font=('Arial', 14)).grid(row=0, column=0, columnspan=3, padx=10, pady=10)

    Button(root, text="Encrypt", command=lambda: show_file_input('encrypt'), **button_style).grid(row=1, column=0, padx=10, pady=10)
    Button(root, text="Encrypt & Compress", command=lambda: show_file_input('compress'), **button_style).grid(row=1, column=1, padx=10, pady=10)
    Button(root, text="Decrypt", command=lambda: show_file_input('decrypt'), **button_style).grid(row=1, column=2, padx=10, pady=10)

    # زر "رجوع" للعودة إلى MainApp
    Button(root, text="Back", command=back_to_main, bg='red', fg='white', font=('Arial', 12)).grid(row=3, column=1, padx=10, pady=20)

def back_to_main():
    """Go back to MainApp."""
    root.destroy()
    subprocess.Popen(["python3", "main.py"])

def show_file_input(action):
    """Show file and password input interface."""
    clear_window()
    Label(root, text="File/Folder Path:", bg='#2e3b4e', fg='white').grid(row=0, column=0, padx=10, pady=10)
    Entry(root, textvariable=file_path_var, width=50).grid(row=0, column=1, padx=10, pady=10)
    Button(root, text="Browse", command=browse_file, **button_style).grid(row=0, column=2, padx=10, pady=10)

    Label(root, text="Password:", bg='#2e3b4e', fg='white').grid(row=1, column=0, padx=10, pady=10)
    password_var.set('')  # Reset the password entry
    Entry(root, textvariable=password_var, show="*", width=50).grid(row=1, column=1, padx=10, pady=10)

    if action == 'encrypt':
        Button(root, text="Encrypt", command=encrypt_action, **button_style).grid(row=2, column=1, padx=10, pady=10)
    elif action == 'compress':
        Button(root, text="Encrypt & Compress", command=encrypt_and_compress_action, **button_style).grid(row=2, column=1, padx=10, pady=10)
    elif action == 'decrypt':
        Button(root, text="Decrypt", command=decrypt_action, **button_style).grid(row=2, column=1, padx=10, pady=10)

    # زر "رجوع" للعودة إلى الخيارات
    Button(root, text="Back", command=show_encryption_options, **button_style).grid(row=3, column=1, padx=10, pady=10)

def clear_window():
    """Clear the current user interface."""
    for widget in root.winfo_children():
        widget.destroy()

# User Interface
root = TkinterDnD.Tk()
root.title("File Encryption/Decryption Tool")

# Improve design with colors and attractive buttons
root.configure(bg='#2e3b4e')  # Background
button_style = {'bg': '#003366', 'fg': 'white', 'font': ('Arial', 12, 'bold')}

# Variables
file_path_var = StringVar()
password_var = StringVar()

# Start the application
show_encryption_options()

# Enable drag and drop for files
def drop(event):
    file_path = event.data
    file_path_var.set(file_path)

root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', drop)

root.mainloop()
