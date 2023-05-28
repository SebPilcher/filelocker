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
        root.minsize(300, 0) #The minimum width is 400px
        root.resizable(0,0) #You can not resize the window

        self.file_path = None
        self.file_select = ttk.Button(root, text = "Select File", command = self.select_file) #file select button
        self.file_select.pack(pady=5)
    
        self.filepath_display = tk.Label(root, text = "No file selected.") 
        self.filepath_display.pack()


        self.key_frame = ttk.Frame(root)
        self.key_frame.pack(padx=10)

        self.key_label = tk.Label(self.key_frame, text = "Key:")
        self.key_label.grid(column=1, row=1)

        self.key_entry = tk.Entry(self.key_frame, show = "*")
        self.key_entry.grid(column=2,row=1)

        self.show_key = tk.IntVar()
        self.show_key_checkbox = ttk.Checkbutton(self.key_frame, text = "Show Key", variable=self.show_key, command = self.toggle_key_visibility)
        self.show_key_checkbox.grid(column=2, row=2)

        self.input_frame = ttk.LabelFrame(root, text = "Input Text")
        self.input_frame.pack(pady=5)
        self.input = ttk.Entry(self.input_frame)
        self.input.pack()

        self.operation = tk.StringVar(value="Choose an Option")
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=5)
        self.encrypt_button = ttk.Radiobutton(self.button_frame, text = "Encrypt", variable = self.operation, value = "Encrypt")
        self.encrypt_button.grid(column=1, row=1)
        self.decrypt_button = ttk.Radiobutton(self.button_frame, text = "Decrypt", variable = self.operation, value = "Decrypt")
        self.decrypt_button.grid(column=2, row=1)


        self.process_button = ttk.Button(root, textvariable=self.operation, command=self.process)
        self.process_button.pack(pady=5)


    def toggle_key_visibility(self):
        """Toggle key visibility based on checkbox state"""
        if self.show_key.get() == 1:
            self.key_entry.configure(show = "")
        else:
            self.key_entry.configure(show = "*")
    
    def select_file(self):

        self.file_path = filedialog.askopenfilename() 
        self.filepath_display.configure(text = self.file_path)
    
    def process(self):
        self.inputvalue = self.input.get()
        if self.key_entry.get() != "":
            self.keyvalue = self.key_entry.get()
        if self.file_path and self.keyvalue:
            operation = self.operation.get()
            if operation == "Encrypt":

                self.encrypt()
            elif operation == "Decrypt":
                # Perform decryption on selected file
                pass
            # tk.messagebox.showinfo("Success", f"File {operation}ed successfully!")
        else:
            # Display error message if file path or key is not provided
            tk.messagebox.showerror("Error", "Please provide a file and key.")

    def encrypt(self):    
        #MAKE THIS TAKE A FILE 

        plaintext = self.inputvalue.encode("utf-8")
        key = sha256(self.keyvalue.encode("utf-8")).digest()

        cipher = AES.new(key, AES.MODE_ECB)
        if len(plaintext) % AES.block_size != 0:
            plaintext = plaintext + b'\0' * (AES.block_size - len(plaintext) % AES.block_size)


        ciphertext = cipher.encrypt(plaintext)
        base64_ciphertext = base64.b64encode(ciphertext).decode("utf-8") #Encode the bytes in base64 and decode the base64 bytes into string
        tk.messagebox.showinfo("Success", "Encrypted String: " + base64_ciphertext)

    



def decrypt():
    base64_ciphertext = input('Enter Data you want to decrypt:\n> ')
    ciphertext = base64.b64decode(base64_ciphertext)
    pw = input('Enter key:\n> ')
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