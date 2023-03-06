# Run 'pip install pycryptodome' in the terminal if Crypto isn't recognized.
import tkinter as tk
from tkinter import filedialog, messagebox
from secrets import randbelow
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

characters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
              'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
              '0','1','2','3','4','5','6','7','8','9','!','@','#','$','%','^','&','*','(',')','[',']','{','}',':',';',
              ',','.','<','>','/','+','-','*','_','=','`','~','?']

def aes_encryption():
    try:
        # read in the contents of the input file as binary data
        with open(path_label.cget("text"), 'rb') as file:
            file_data = file.read()
    except FileNotFoundError:
        messagebox.showerror("Error", "No file selected!")
    else:
        key = ''
        iv = ''  
        for _ in range(32):
            key += characters[randbelow(len(characters))] # 256-bit secret key
        for _ in range(16):
            iv += characters[randbelow(len(characters))] # 128-bit initialization vector
        input_file = file_label.cget("text")  # input file
        input_file = input_file[15:]
        output_file = input_file + '.encrypted'  # encrypted output file
        with open(input_file + '_key_iv.txt', 'w') as file:
            file.write("Keep this file with the key and initialization vector to decrypt:\n")
            file.write(f'{key}\n')
            file.write(iv)
        # initialize the AES cipher with CBC mode and the given key and IV
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        # pad the file data to the AES block size
        padded_file_data = pad(file_data, AES.block_size)
        # encrypt the padded file data
        encrypted_data = cipher.encrypt(padded_file_data)
        # write the encrypted data to the output file
        with open(output_file, 'wb') as file:
            file.write(encrypted_data)


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
                with open(output_file + '_key_iv.txt', 'r') as file:
                    file.readline().strip('\n')
                    key = file.readline().strip('\n').encode('utf-8')
                    iv = file.readline().strip('\n').encode('utf-8')
            except FileNotFoundError:
                messagebox.showerror("Error", "File containing key and initialization vector not found!")
            else:
                try:
                    # initialize the AES cipher with CBC mode and the given key and IV
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                except ValueError:
                    messagebox.showerror("Error", "Key and/or initialization vector not valid!")
                else:
                    # decrypt the encrypted data and unpad the result
                    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
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
