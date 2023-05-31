import random
from hashlib import sha256
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from Crypto.Cipher import AES

# Imports all the non-core libraries used to make the program.

class FileLockerGui: 
    """Class used to customise the tkinter gui and process encryption/decryption requests."""

    def __init__(self, root):
        self.root = root 
        root.title("FileLocker") # Name the main window to "FileLocker"
        root.minsize(300, 0) # The minimum width is 300px
        root.resizable(0,0) # You can not resize the window

        self.file_path = None # Defines the variable as null in order to check if it has been changed later on.
        self.file_select = ttk.Button(root, text = "Select File", command = self.select_file) # File select button.
        self.file_select.pack(pady=5) 
    
        self.filepath_display = tk.Label(root, text = "No file selected.") # Displays the path of the selected file.
        self.filepath_display.pack()

        self.key_frame = ttk.Frame(root)
        self.key_frame.pack(padx=10)

        self.key_label = tk.Label(self.key_frame, text = "Key:")
        self.key_label.grid(column=1, row=1)

        self.key_entry = tk.Entry(self.key_frame, show = "*") # Entry box for the key.
        self.key_entry.grid(column=2,row=1)

        self.show_key = tk.IntVar()
        self.show_key_checkbox = ttk.Checkbutton(self.key_frame, text = "Show Key", variable=self.show_key, command = self.toggle_key_visibility) # Key visibility toggle.
        self.show_key_checkbox.grid(column=2, row=2)

        self.operation = tk.StringVar(value="Choose an Option")
        self.button_frame = ttk.Frame(root) # Frame to group the buttons together.
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

        if self.key_entry.get() != "": # Checks if there has been a key inputted into the key_entry box, and makes keyvalue equal to the key if so.
            keyvalue = self.key_entry.get()

        if self.file_path and keyvalue: # If the file has been selected, the key has been provided, and an operation has been chosen, either the encryption or decryption modules will be run.

            operation = self.operation.get()

            if operation == "Encrypt":
                self.cbc_encrypt(keyvalue)
            elif operation == "Decrypt":
                self.cbc_decrypt(keyvalue)

        else:
            # Displays an error message if file path or key is not provided.
            tk.messagebox.showerror("Error", "Please provide a file, key, and operation.")



    def cbc_encrypt(self, keyvalue):    
        """Method used to encrypt with AES mode CBC."""

        try: # Reads the file binary. 
            filedata = open(self.file_path, "rb").read()
        except: # Displays an error message if file can't be read.
            tk.messagebox.showerror("Error", "Something went wrong when opening the file.")
            return


        if self.file_path[-4:] == ".lkd": # Checks if file has the extension .lkd (encrypted).
            tk.messagebox.showerror("Error", "File is already encrypted.")
            return

        
        key = sha256(keyvalue.encode("utf-8")).digest() # Encodes the string given by the user and hashes it with sha256

        iv = random.randbytes(16) # Generates a random initialization vector to be used in the encryption. Used to randomise the encryption and remove patterns.

        cipher = AES.new(key, AES.MODE_CBC, iv) # Creates a new cipher, and specifies the key & AES mode to use.

        padding = (AES.block_size - len(filedata) % AES.block_size) # Calculates the amount of padding to be done.


        if len(filedata) == 0: # Checks if the file contains more than 0 bytes of data, displays an error message if there is no data inside the file.
            tk.messagebox.showerror("Error", "File is empty.")
            return
        elif len(filedata) % AES.block_size != 0: # Checks if the amount of bytes isn't a multiple of 16, and adds the missing amount of bytes to the file in the form of null bytes (\x00).
            filedata = filedata + b'\0' * padding


        encryptedData = cipher.encrypt(filedata) # Encrypts the file.

        try:
            newfilepath = self.file_path + ".lkd" # Adds the .lkd extension to the current filepath.

            newfile = open(newfilepath, "x").close() # Creates the new file at the new filepath.

            newfile = open(newfilepath, "wb+") # Writes the encrypted binary to the file.

            padding = int.to_bytes(padding) # Converts the padding integer to bytes.

            newfile.write(iv + padding + encryptedData) # Adds the iv, along with an 8-bit integer to the start of the file, containing the amount of null bytes. (From 1-16).

            tk.messagebox.showinfo("Success", "File has been encrypted!") # Displays a popup confirming the success of the encryption.
        except: # If the file creation fails, it will display an error message.
            tk.messagebox.showerror("Error", "File already exists.") 
            return



    def cbc_decrypt(self, keyvalue):
        """Method used to decrypt with AES mode CBC."""
        

        if self.file_path[(len(self.file_path)-4):] != ".lkd": # Checks if the selected file's extension is not .lkd (encrypted), and displays an error if so.
            tk.messagebox.showerror("Error", "File is already decrypted.") 
            return


        try: # Copies the encrypted data from the file, and displays an error if the file doesn't exist or can't be viewed.
            encryptedData = open(self.file_path, "rb").read()
        except:
            tk.messagebox.showerror("Error", "Something went wrong when opening the file.")
            return
        
        iv = encryptedData[:16] # Takes the first 16 bytes of the file that contain the iv, and saves it in the iv variable.
        encryptedData = encryptedData[16:] # Removes the iv from the file.

        key = sha256(keyvalue.encode("utf-8")).digest() # Encodes the string given by the user and hashes it with sha256.

        cipher = AES.new(key, AES.MODE_CBC, iv) # Creates a new cipher, and specifies the key & AES mode to use.


        if len(encryptedData) == 0: # Checks if the file contains more than 0 bytes of data, displays an error message if there is no data inside the file.
            tk.messagebox.showerror("Error", "File is empty.")
            return
        

        padding = int.from_bytes(encryptedData[:1]) # Saves the number stored at the start of the encrypted file.

        encryptedData = encryptedData[1:] # Removes the number from the file.

        filedata = cipher.decrypt(encryptedData) # Decrypts the data in the file.

        filedata = filedata[:-padding] # Removes the extra padding.

        try:
            newfilepath = self.file_path[:-4] # Removes the last 4 letters of the encrypted file's path string (encrypted file extension).

            newfile = open(newfilepath, "x").close() # Creates the new file.

            newfile = open(newfilepath, "wb+") # Opens the file and makes it able to be written to in binary.

            newfile.write(filedata) # Writes the binary to the file.

            tk.messagebox.showinfo("Success", "File has been decrypted!")
        except: # If the file creation fails, it will display an error message.
            tk.messagebox.showerror("Error", "File already exists.")
            return
        
        



        
if __name__ == "__main__":
    root = tk.Tk()
    FileLockerGui(root) # Initiates the FileLockerGui class and passes the root variable to the __init__ module.
    root.mainloop() # Opens the gui.