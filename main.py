from hashlib import sha256
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from Crypto.Cipher import AES


class FileLockerGui: 
    """Class used to customise the tkinter gui and process encryption/decryption requests."""
    def __init__(self, root):
        self.root = root 
        root.title("FileLocker") # Name the main window to "FileLocker"
        root.minsize(300, 0) # The minimum width is 400px
        root.resizable(0,0) # You can not resize the window

        self.file_path = None
        self.file_select = ttk.Button(root, text = "Select File", command = self.select_file) #file select button
        self.file_select.pack(pady=5) 
    
        self.filepath_display = tk.Label(root, text = "No file selected.") #displays the filepath of the selected file
        self.filepath_display.pack()


        self.key_frame = ttk.Frame(root)
        self.key_frame.pack(padx=10)

        self.key_label = tk.Label(self.key_frame, text = "Key:") 
        self.key_label.grid(column=1, row=1)

        self.key_entry = tk.Entry(self.key_frame, show = "*") #password entry
        self.key_entry.grid(column=2,row=1)

        self.show_key = tk.IntVar()
        self.show_key_checkbox = ttk.Checkbutton(self.key_frame, text = "Show Key", variable=self.show_key, command = self.toggle_key_visibility) #password show button
        self.show_key_checkbox.grid(column=2, row=2)

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
        """Toggle key visibility based on checkbox state."""
        if self.show_key.get() == 1:
            self.key_entry.configure(show = "")
        else:
            self.key_entry.configure(show = "*")
    
    def select_file(self):
        """Open OS file selection."""
        self.file_path = filedialog.askopenfilename() 
        self.filepath_display.configure(text = self.file_path)
    
    def process(self):
        """Processes the user request."""
        if self.key_entry.get() != "":
            self.keyvalue = self.key_entry.get()
        if self.file_path and self.keyvalue:
            operation = self.operation.get()
            if operation == "Encrypt":

                self.ecb_encrypt()
            elif operation == "Decrypt":
                
                self.ecb_decrypt()
        else:
            # Display error message if file path or key is not provided
            tk.messagebox.showerror("Error", "Please provide a file and key.")

    def ecb_encrypt(self):    
        """Method used to encrypt with AES mode ECB."""

        try:
            filedata = open(self.file_path, "rb").read()
        except:
            tk.messagebox.showerror("Error", "File doesn't exist.")

        key = sha256(self.keyvalue.encode("utf-8")).digest() # Encodes the string given by the user and hashes it with sha256

        cipher = AES.new(key, AES.MODE_ECB) # Creates a new cipher, and specifies the key & AES mode to use.

        padding = (AES.block_size - len(filedata) % AES.block_size)


        if len(filedata) == 0:
            tk.messagebox.showerror("Error", "File is empty.")
            return
        elif len(filedata) % AES.block_size != 0:
            filedata = filedata + b'\0' * padding

        encryptedData = cipher.encrypt(filedata)

        try:
            newfilepath = self.file_path + ".lkd"
            newfile = open(newfilepath, "x").close()
            newfile = open(newfilepath, "wb+")
            padding = int.to_bytes(padding)
            newfile.write(padding + encryptedData)
            tk.messagebox.showinfo("Success", "File has been encrypted!")
        except:
            tk.messagebox.showerror("Error", "File already exists.")


    def ecb_decrypt(self):
        """Method used to decrypt with AES mode ECB."""
        
        encryptedData = open(self.file_path, "rb").read()

        key = sha256(self.keyvalue.encode("utf-8")).digest() # Encodes the string given by the user and hashes it with sha256

        cipher = AES.new(key, AES.MODE_ECB) # Creates a new cipher, and specifies the key & AES mode to use.

        if len(encryptedData) == 0:
            tk.messagebox.showerror("Error", "File is empty.")
            return
        
        padding = int.from_bytes(encryptedData[:1])
        encryptedData = encryptedData[1:]

        filedata = cipher.decrypt(encryptedData)


        filelen = len(filedata) - padding
        filedata = filedata[:filelen]

        try:
            newfilepath = self.file_path.rstrip(".lkd")
            newfile = open(newfilepath, "x").close()
            newfile = open(newfilepath, "wb+")
            newfile.write(filedata)
            tk.messagebox.showinfo("Success", "File has been decrypted!")
        except:
            tk.messagebox.showerror("Error", "File already exists.")
        
        


            
        
if __name__ == "__main__":
    root = tk.Tk()
    FileLockerGui(root)
    root.mainloop()

#take a password, encrypt it in sha256, then encrypt the file/files with aes256 using the encrypted password string. Give encrypted file .LKD extension. Done using hashlib and pyCryptoDome.