import time
from hashlib import sha256
import tkinter
from tkinter import *
from tkinter import ttk
import Crypto.Cipher
from Crypto.Cipher import AES
import base64

def test():
    goto = input("Would you like to encrypt or decrypt data? ")
    if goto == "encrypt" or goto == "Encrypt":
        encrypt()
    elif goto == "decrypt" or goto == "Decrypt":
        decrypt()
    else:
        print("Invalid Answer")
        test()
    
def start():
    print("\n ███████╗██╗██╗     ███████╗██╗      █████╗  █████╗ ██╗  ██╗███████╗██████╗ \n ██╔════╝██║██║     ██╔════╝██║     ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔══██╗\n █████╗  ██║██║     █████╗  ██║     ██║  ██║██║  ╚═╝█████═╝ █████╗  ██████╔╝\n ██╔══╝  ██║██║     ██╔══╝  ██║     ██║  ██║██║  ██╗██╔═██╗ ██╔══╝  ██╔══██╗\n ██║     ██║███████╗███████╗███████╗╚█████╔╝╚█████╔╝██║ ╚██╗███████╗██║  ██║\n ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝ ╚════╝  ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n")
    time.sleep(1)
#    load()
    app()


def load():
    Loading=True
    load=0 
    while Loading==True:
        print("Loading... |", end='\r')
        time.sleep(0.25)
        print("Loading... /", end='\r')
        time.sleep(0.25)
        print("Loading... --", end='\r')
        time.sleep(0.25)
        print("Loading... \ ", end='\r')
        time.sleep(0.25)
        load=load+1
        if load>=2:
            Loading=False
            print("Loading Complete. Launching App!")
            time.sleep(1)
            return

def app():
    mainWindow=Tk()
    mainWindow.geometry('500x300')
    mainWindowFrame=tkinter.Frame(mainWindow)
    mainWindowFrame.grid()

    label = tkinter.Label(mainWindowFrame, text="test").grid(column=0, row=0)
    button = tkinter.Button(mainWindowFrame, text="quit", command=mainWindow.quit).grid(column=0, row=1)
    label2 = tkinter.Label(mainWindowFrame, text="test2").grid(column=1, row=2)
    mainWindowFrame.grid_propagate(1)
    

    mainWindow.mainloop()

def encrypt():
    plaintext = bytes(input('Enter Data you want to encrypt:\n> '), "utf-8")

    pw = input('Enter Password:\n> ')
    pw = pw.encode("utf-8")
    key = sha256(pw).digest()

    cipher = AES.new(key, AES.MODE_ECB)
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
    # start()    
    test()


#take a password, encrypt it in sha256, then encrypt the file/files with aes256 using the encrypted password string. Give encrypted file .LKD extension. Done using hashlib and pyCryptoDome. Also, apparently it is good to encode the AES encryption with base64 if using 'text-only channels'