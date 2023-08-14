"""This file is a program that encrypts/decrypts files."""
import random
import time
from hashlib import sha256
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from Crypto.Cipher import AES

# Imports all the libraries used in the program.


class FileLockerGui:
    """GUI and Encryption/Decryption."""

    ERR_MSG1 = 'ERROR'
    # ERR_MSG1 is a constant which defines the title for all of the error popups.
    padding = 5
    # padding is a constant which defines the pixels to pad the widgets in the program.
    mode = AES.MODE_CBC
    # mode is a constant that defines the AES encryption mode used.

    def __init__(self, root):
        """Creation of GUI using tkinter."""
        self.loading()
        self.root = root
        root.title("FileLocker")  # Name the main window to "FileLocker"
        root.minsize(300, 0)  # The minimum width is 300px
        root.resizable(0, 0)  # You can not resize the window

        self.file_path = None
        self.file_select = ttk.Button(root, text="Select File", command=self.select_file)
        # File select button.
        self.file_select.pack(pady=self.padding)

        self.filepath_display = tk.Label(root, text="No file selected.", wraplength=400)
        # Displays the path of the selected file.
        self.filepath_display.pack()

        self.key_frame = ttk.Frame(root)
        self.key_frame.pack(padx=10)

        self.key_label = tk.Label(self.key_frame, text="Key:")
        self.key_label.grid(column=1, row=1)

        self.key_entry = tk.Entry(self.key_frame, show="*")
        # Entry box for the key.
        self.key_entry.grid(column=2, row=1)

        self.show_key = tk.IntVar()
        self.show_key_checkbox = ttk.Checkbutton(self.key_frame, text="Show Key", variable=self.show_key, command=self.toggle_key_visibility)
        # Key visibility toggle.
        self.show_key_checkbox.grid(column=2, row=2)

        self.operation = tk.StringVar(value="Choose an Option")
        self.button_frame = ttk.Frame(root)
        # Frame to group the buttons together.
        self.button_frame.pack(pady=self.padding)

        self.encrypt_button = ttk.Radiobutton(self.button_frame, text="Encrypt", variable=self.operation, value="Encrypt")
        # Encryption and Decryption options.
        self.encrypt_button.grid(column=1, row=1)
        self.decrypt_button = ttk.Radiobutton(self.button_frame, text="Decrypt", variable=self.operation, value="Decrypt")
        self.decrypt_button.grid(column=2, row=1)

        self.process_button = ttk.Button(root, textvariable=self.operation, command=self.process)  # Process button.
        self.process_button.pack(pady=self.padding)

        root.update()
        tk.messagebox.showinfo("Welcome!", "Welcome to filelocker. If you want to encrypt a folder, send it to a .zip file before encrypting.")

    def toggle_key_visibility(self):
        """Toggle key visibility based on checkbox state."""
        if self.show_key.get() == 1:
            self.key_entry.configure(show="")
        else:
            self.key_entry.configure(show="*")

    def select_file(self):
        """Open OS file selection."""
        self.file_path = filedialog.askopenfilename()
        # Uses the OS's inbuilt file selection.

        self.filepath_display.configure(text=self.file_path)

    def process(self):
        """Process the user request."""
        keyvalue = ""

        if self.key_entry.get() != "":
            # Checks if there has been a key inputted into the key_entry box.
            keyvalue = self.key_entry.get()

        if self.file_path and keyvalue:
            # Either the encryption or decryption modules will be run if all conditions are met.

            operation = self.operation.get()

            if operation == "Encrypt":
                self.cbc_encrypt(keyvalue)
            elif operation == "Decrypt":
                self.cbc_decrypt(keyvalue)

        else:
            # Displays an error message if file path or key is not provided.
            tk.messagebox.showerror(self.ERR_MSG1, "Please provide a file, key, and operation.")

    def cbc_encrypt(self, keyvalue):
        """Encrypt with AES mode CBC."""
        try:
            filedata = open(self.file_path, "rb").read()
        except Exception as e:
            # Displays an error message if file can't be read.
            tk.messagebox.showerror(self.ERR_MSG1, f"Something went wrong when opening the file.\n{e}")
            return

        if self.file_path[-4:] == ".lkd":
            # Checks if file has the extension .lkd (encrypted).
            tk.messagebox.showerror(self.ERR_MSG1, "File is already encrypted.")
            return

        key = sha256(keyvalue.encode("utf-8")).digest()
        # Encodes the string given by the user and hashes it with sha256

        iv = random.randbytes(16)
        # Generates a random initialization vector to be used in the encryption. Used to randomise the encryption and remove patterns.

        cipher = AES.new(key, self.mode, iv)
    
        padding = (AES.block_size - len(filedata) % AES.block_size)
        # Calculates the amount of padding to be done.
        if len(filedata) == 0:
            tk.messagebox.showerror(self.ERR_MSG1, "File is empty.")
            return
        elif padding != 16:
            filedata = filedata + b'\0' * padding
        elif padding == 16:
            padding = 0

        encrypteddata = cipher.encrypt(filedata)
        try:
            newfilepath = self.file_path + ".lkd"

            newfile = open(newfilepath, "x").close()

            newfile = open(newfilepath, "wb+")

            padding = int.to_bytes(padding)

            newfile.write(iv + padding + encrypteddata)
            newfile.close()

            tk.messagebox.showinfo("Success", "File has been encrypted!")
            # Displays a popup confirming the success of the encryption.

        except Exception as e:
            # If the file creation fails, it will display an error message.
            tk.messagebox.showerror(self.ERR_MSG1, f"Something went wrong when creating the file.\n{e}")
            return

    def cbc_decrypt(self, keyvalue):
        """Decrypt with AES mode CBC."""
        if self.file_path[(len(self.file_path)-4):] != ".lkd":
            # Checks if the selected file's extension is not .lkd (encrypted), and displays an error if so.
            tk.messagebox.showerror(self.ERR_MSG1, "File is already decrypted.")
            return

        try:
            # Copies the encrypted data from the file, and displays an error if the file doesn't exist or can't be viewed.
            encrypteddata = open(self.file_path, "rb").read()
        except Exception as e:
            tk.messagebox.showerror(self.ERR_MSG1, f"Something went wrong when opening the file.\n{e}")
            return

        if len(encrypteddata) == 0:
            tk.messagebox.showerror(self.ERR_MSG1, "File is empty.")
            return
        elif (len(encrypteddata)-17) % 16 != 0:
            # Checks if there is an iv and padding number present. Every file encrypted by this program will have a file length equal to 16n+17.
            tk.messagebox.showerror(self.ERR_MSG1, "Not a valid file.")
            return

        iv = encrypteddata[:16]
        # Takes the first 16 bytes of the file that contain the iv, and saves it in the iv variable.
        encrypteddata = encrypteddata[16:]
        # Removes the iv from the file.

        key = sha256(keyvalue.encode("utf-8")).digest()
        # Encodes the string given by the user and hashes it with sha256.

        cipher = AES.new(key, self.mode, iv)

        if len(encrypteddata) == 0:
            tk.messagebox.showerror(self.ERR_MSG1, "File is empty.")
            return

        padding = int.from_bytes(encrypteddata[:1])
        # Saves the number stored at the start of the encrypted file.
        encrypteddata = encrypteddata[1:]
        # Removes the number from the file.

        filedata = cipher.decrypt(encrypteddata)

        if padding != 0:
            filedata = filedata[:-padding]
        # Removes the extra padding.
        try:
            newfilepath = self.file_path[:-4]

            newfile = open(newfilepath, "x").close()

            newfile = open(newfilepath, "wb+")

            newfile.write(filedata)

            newfile.close()

        except Exception as e:
            # If the file creation fails, it will display an error message.
            tk.messagebox.showerror(self.ERR_MSG1, f"Something went wrong when creating the file.\n{e}")
            return

        tk.messagebox.showinfo("Success", "File has been decrypted!")

    def loading(self):
        """Load screen for program."""
        number = random.randint(1, 3)
        delay = 0.25
        # delay is a constant.
        while number < 7:
            print("Loading... | ", end="\r")
            time.sleep(delay)
            print("Loading... / ", end="\r")
            time.sleep(delay)
            print("Loading... --", end="\r")
            time.sleep(delay)
            print("Loading... \\ ", end="\r")
            time.sleep(delay)
            number += 1
        print("Program has finished loading!")
        time.sleep(0.5)
        print("""Welcome to:
---------------------------------------------------------------------------
███████╗██╗██╗░░░░░███████╗██╗░░░░░░█████╗░░█████╗░██╗░░██╗███████╗██████╗░
██╔════╝██║██║░░░░░██╔════╝██║░░░░░██╔══██╗██╔══██╗██║░██╔╝██╔════╝██╔══██╗
█████╗░░██║██║░░░░░█████╗░░██║░░░░░██║░░██║██║░░╚═╝█████═╝░█████╗░░██████╔╝
██╔══╝░░██║██║░░░░░██╔══╝░░██║░░░░░██║░░██║██║░░██╗██╔═██╗░██╔══╝░░██╔══██╗
██║░░░░░██║███████╗███████╗███████╗╚█████╔╝╚█████╔╝██║░╚██╗███████╗██║░░██║
╚═╝░░░░░╚═╝╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝
---------------------------------------------------------------------------
""")


if __name__ == "__main__":
    root = tk.Tk()
    FileLockerGui(root)
    root.mainloop()
