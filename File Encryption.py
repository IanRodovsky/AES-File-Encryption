# Run 'pip install pycryptodome' in the terminal if Crypto isn't recognized.
import tkinter as tk
import os
from stat import S_IREAD, S_IRGRP, S_IROTH
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def aes_encryption():
    try:
        # read in the contents of the input file as binary data
        with open(path_label.cget("text"), 'rb') as file:
            file_data = file.read()
    except FileNotFoundError:
        messagebox.showerror("Error", "No file selected!")
    else:
        master_key = 'NA2rDisnDIV@mXth6Vp#Uc3OYa1Y0*faccac7KL!iWkovyil' #384-bit master key
        nonce_size = 11 # 88-bit nonce_size
        salt_size = 32 # 256-bit salt_size
        key_size = 32  # 256-bit key_size
        salt = get_random_bytes(salt_size) # # 256-bit salt
        # Derive a new key from the password and salt using PBKDF2 with SHA256
        key = PBKDF2(master_key, salt, key_size, count=1000000, hmac_hash_module=SHA256) # 256-bit key
        nonce = get_random_bytes(nonce_size) # 88-bit nonce
        input_file = file_label.cget("text")  # input file
        input_file = input_file[15:]
        output_file = input_file + '.encrypted'  # encrypted output file
        # initialize the AES cipher with CCM mode and the given key and nonce
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
        # encrypt the padded file data
        encrypted_data, auth_tag = cipher.encrypt_and_digest(file_data)
        # write the encrypted data to the output file
        with open(output_file, 'wb') as file:
            file.write(encrypted_data)
        with open(input_file + '_salt_nonce.txt', 'wb') as file:
            file.write(b"Keep this file with the salt, nonce, and authentication tag to decrypt:\n")
            file.write(salt + b'\n')
            file.write(nonce + b'\n')
            file.write(auth_tag + b'\n')
            os.chmod(input_file + '_salt_nonce.txt', S_IREAD|S_IRGRP|S_IROTH)


def aes_decryption():
    try:
        # read in the encrypted data from the input file
        with open(path_label.cget("text"), 'rb') as file:
            encrypted_data = file.read()
    except:
        messagebox.showerror("Error", "No file selected!")
    else:
        input_file = file_label.cget("text")  # input file
        input_file = input_file[15:]
        if ".encrypted" in input_file[-10:]:
            output_file = input_file[0:-10]  # decrypted output file
            try:
                with open(output_file + '_salt_nonce.txt', 'rb') as file:
                    file.readline()
                    salt = file.read(33)[:-1]
                    nonce = file.read(12)[:-1]
                    auth_tag = file.read(17)[:-1]
            except FileNotFoundError:
                messagebox.showerror("Error", "File containing salt and nonce not found!")
            else:
                master_key = 'NA2rDisnDIV@mXth6Vp#Uc3OYa1Y0*faccac7KL!iWkovyil'
                key_size = 32
                key = PBKDF2(master_key, salt, key_size, count=1000000, hmac_hash_module=SHA256)
                try:
                    # initialize the AES cipher with CCM mode and the given key and IV
                    cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=16)
                except ValueError:
                    messagebox.showerror("Error", "Key and/or nonce not valid!")
                else:
                    # decrypt the encrypted data and verify the result
                    try:
                        decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
                    except ValueError:
                        messagebox.showerror("Error", "Failed to verify data!")
                    else:
                        # write the decrypted data to the output file
                        with open(output_file, 'wb') as file:
                            file.write(decrypted_data)
        else:
            messagebox.showerror('Error', 'Selected file is not encrypted!')


def select_file():
    # create a file dialog and wait for the user to select a file
    selected_file = filedialog.askopenfilename()
    if selected_file:
        path_label.configure(text=selected_file)
        # get the file name from the selected file path
        file_name = selected_file.split("/")[-1]
        # display the file name
        file_label.configure(text="File Selected: " + file_name)
    else:
        messagebox.showerror("Error", "No file selected!")

if __name__ == '__main__':
    # create the main window
    root = tk.Tk()
    root.title("File Encryption")
    root.geometry('295x115')
    root.resizable(width=False, height=False)
    # create the first tab
    file_display = tk.Frame(root)
    file_display.grid(row=0, column=0, padx=10, pady=10)
    button_display = tk.Frame(root)
    button_display.grid(row=1, column=0, padx=10, pady=10)
    # create a label to display the selected file name
    file_label = tk.Label(file_display, text="File Selected: ")
    file_label.grid(row=0, column=0, padx=10, pady=10)
    path_label = tk.Label(file_display, text="")
    # Add a button to open a file dialog
    file_button = tk.Button(button_display, text="Select File", command=select_file)
    file_button.grid(row=1, column=0, padx=10, pady=10)
    # create the encrypt and decrypt buttons
    enc_button = tk.Button(button_display, text="Encrypt File", command=aes_encryption)
    enc_button.grid(row=1, column=1, padx=10, pady=10)
    dec_button = tk.Button(button_display, text="Decrypt File", command=aes_decryption)
    dec_button.grid(row=1, column=2, padx=10, pady=10)
    # configure grid weights to fill available space
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    root.mainloop()
