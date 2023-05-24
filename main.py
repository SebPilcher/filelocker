import time
import os
from hashlib import sha256
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from Crypto.Cipher import AES
import base64

class FileLockerGui: #Created class FileLockerGui for the gui
    def __init__(self, root):
        self.root = root 
        root.title("FileLocker") #Name the window to "FileLocker"

        root.minsize(250, 0) #The minimum width is 400px
        root.resizable(0,0) #You can not resize the window

        self.logo = tk.Label(root)
        self.logo.pack()


        self.file_select = ttk.Button(root, text = "Select File", command = self.select_file)
        self.file_select.pack(pady=5)
    
        self.filepath_display = tk.Label(root, text = "No file selected.")
        self.filepath_display.pack()

        self.password_frame = ttk.Frame(root)
        self.password_frame.pack(padx=10)

        self.password_label = tk.Label(self.password_frame, text = "Enter Password")
        self.password_label.grid(column=1, row=1)

        self.password_entry = tk.Entry(self.password_frame, show = "*")
        self.password_entry.grid(column=1,row=2)

        self.show_password = tk.IntVar()
        self.show_password_checkbox = ttk.Checkbutton(self.password_frame, text = "Show Password", variable=self.show_password, command = self.toggle_password_visibility)
        self.show_password_checkbox.grid(column=2, row=2)



        self.operation = tk.StringVar(value="Choose an Option")
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=5)
        self.encrypt_button = ttk.Radiobutton(self.button_frame, text = "Encrypt", variable = self.operation, value = "Encrypt")
        self.encrypt_button.grid(column=1, row=1)
        self.decrypt_button = ttk.Radiobutton(self.button_frame, text = "Decrypt", variable = self.operation, value = "Decrypt")
        self.decrypt_button.grid(column=2, row=1)


        self.process_button = ttk.Button(root, textvariable=self.operation)
        self.process_button.pack(pady=5)





    def toggle_password_visibility(self):
        """Toggle password visibility based on checkbox state"""
        if self.show_password.get() == 1:
            self.password_entry.configure(show = "")
        else:
            self.password_entry.configure(show = "*")
    
    def select_file(self):

        self.file_path = filedialog.askopenfilename() 
        self.filepath_display.configure(text = self.file_path)
    
    def process(self):

        password = self.password_entry.get()
        if self.file_path and password:
            operation = self.operation_var.get()
            if operation == "Encrypt":
                self.encrypt(self.file_path)
                pass
            elif operation == "Decrypt":
                # Perform decryption on selected file
                pass
            # Display success message
            tk.messagebox.showinfo("Success", f"File {operation}ed successfully!")
        else:
            # Display error message if file path or password is not provided
            tk.messagebox.showerror("Error", "Please provide a file and password.")

    def encrypt(self, filepath):
        plaintext = bytes(input('Enter Data you want to encrypt:\n> '), "utf-8")

        pw = input('Enter Password:\n> ')
        pw = pw.encode("utf-8")
        key = sha256(pw).digest()

        cipher = AES.new(key, AES.MODE_ECB)
        if len(plaintext) % AES.block_size == 0:
            return
        else:
            plaintext = plaintext + b'\0' * (AES.block_size - len(plaintext) % AES.block_size)
        ciphertext = cipher.encrypt(plaintext)
        base64_ciphertextbytes = base64.b64encode(ciphertext)
        base64_ciphertext = base64_ciphertextbytes.decode("utf-8")
        print(base64_ciphertext)

    



def decrypt():
    base64_ciphertext = input('Enter Data you want to decrypt:\n> ')
    ciphertext = base64.b64decode(base64_ciphertext)
    pw = input('Enter Password:\n> ')
    pw = pw.encode("utf-8")
    key = sha256(pw).digest()

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    
    plaintext = plaintext.rstrip(b'\0')

    print(plaintext.decode("utf-8"))   

    
if __name__ == '__main__':
    root = tk.Tk()
    FileLockerGui(root)
    root.mainloop()

#take a password, encrypt it in sha256, then encrypt the file/files with aes256 using the encrypted password string. Give encrypted file .LKD extension. Done using hashlib and pyCryptoDome. Also, apparently it is good to encode the AES encryption with base64 if using 'text-only channels'