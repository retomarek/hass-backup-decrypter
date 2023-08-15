# -*- coding: utf-8 -*-
"""
Created on Tue Aug 15 02:03:50 2023

@author: retom
"""

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext
import tarfile
import os
import shutil
from PIL import ImageTk, Image

import sys
import hashlib
import glob

from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

class SecureTarFile:
    def __init__(self, file_name, password):
        self._file = None
        self._name = Path(file_name)

        self._tar = None
        self._tar_mode = "r|gz"

        self._aes = None
        self._key = self._password_to_key(password)

        self._decrypt = None

    def __enter__(self):
        self._file = self._name.open("rb")

        cbc_rand = self._file.read(16)

        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(self._generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )

        self._decrypt = self._aes.decryptor()
        
        try:
            self._tar = tarfile.open(fileobj=self, mode=self._tar_mode)
        except:
            HassBackupDecrypter.update_status(self, "Invalid gzip file, is the password correct?")
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback):
        if self._tar:
            self._tar.close()
        if self._file:
            self._file.close()

    def read(self, size = 0):
        return self._decrypt.update(self._file.read(size))

    @property
    def path(self):
        return self._name

    @property
    def size(self):
        if not self._name.is_file():
            return 0
        return round(self._name.stat().st_size / 1_048_576, 2)  # calc mbyte
    
    def _password_to_key(self, password):
        password = password.encode()
        for _ in range(100):
            password = hashlib.sha256(password).digest()
        return password[:16]

    def _generate_iv(self, key, salt):
        temp_iv = key + salt
        for _ in range(100):
            temp_iv = hashlib.sha256(temp_iv).digest()
        return temp_iv[:16]


class HassBackupDecrypter:
    def __init__(self, root):
        self.root = root
        self.root.title("Home Assistant Backup Decrypter")
        
        self.logo = ImageTk.PhotoImage(Image.open("logo.png"))
        self.logo_label = tk.Label(root, image=self.logo)
        self.logo_label.pack()

        self.file_path_label = tk.Label(root, text="Select a HA Backup TAR-File:")
        self.file_path_label.pack()

        self.file_path_entry = tk.Entry(root, state="readonly", width=80)
        self.file_path_entry.pack()

        self.browse_button = tk.Button(root, text="Browse...", command=self.browse_file)
        self.browse_button.pack()

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.run_button = tk.Button(root, text="Decrypt", command=self.decrypt_tar)
        self.run_button.pack()
        
        self.status_label = tk.Label(root, text="Status:")
        self.status_label.pack()

        self.status_text = scrolledtext.ScrolledText(root, height=6, state="disabled")
        self.status_text.pack()
        
        self.update_status("Please select a file and set a password.")

    def browse_file(self):
        self.update_status("Loading File...")
        file_path = filedialog.askopenfilename(filetypes=[("Select HA Backup tar-file", "*.tar")])
        if file_path:
            self.file_path_entry.configure(state="normal")
            self.file_path_entry.delete(0, "end")
            self.file_path_entry.insert(0, file_path)
            self.file_path_entry.configure(state="readonly")
        self.update_status("File selected")
    
    def update_status(self, message):
        self.status_text.configure(state="normal")
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.configure(state="disabled")
        self.status_text.see(tk.END)
        
    def _extract_tar(self, file_name):
        _dirname = '.'.join(file_name.split('.')[:-1])

        try:
            shutil.rmtree('_dirname')
        except FileNotFoundError:
            pass

        self.update_status(f'Extracting {file_name}...')
        _tar  = tarfile.open(name=file_name, mode="r")
        _tar.extractall(path=_dirname)

        return _dirname

    def _extract_secure_tar(self, file_name, password):
        _dirname = '.'.join(file_name.split('.')[:-2])
        self.update_status(f'Extracting secure tar {file_name.split("/")[-1]}...')
        try:
            with SecureTarFile(file_name, password) as _tar:
                _tar.extractall(path=_dirname)
        except tarfile.ReadError:
            self.update_status("Unable to extract SecureTar - maybe your password is wrong or the tar is not password encrypted?")
            sys.exit(5)

        return _dirname
    
    def decrypt_tar(self):
        self.update_status("Starting decryption...")
        file_path = self.file_path_entry.get()
        file_name = os.path.basename(file_path)
        
        password = self.password_entry.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a tar file and enter the password")
            return
        
        output_dir = os.path.dirname(file_path)
        dir_name = os.path.basename(os.path.normpath(output_dir))
        
        print(f"output_dir = {output_dir}")
        output_dir = os.path.join(output_dir, os.path.splitext(file_name)[0])

        if os.path.exists(output_dir):
            self.update_status("Output folder already exists...")
            result = messagebox.askquestion("Output folder already existing", f"The outputfolder '{dir_name}' is already existing, would you like to replace it?")
            if result == "yes":
                try:
                    self.update_status("Removing existing folder...")
                    shutil.rmtree(output_dir)
                    self.update_status("Existing folder removed")
                except:
                    self.update_status("Error during deletion of the folder.")
            else:
                return

        try:
            self.update_status("Start decryption, this might take a while...")
            _dirname = self._extract_tar(file_name)
            for _secure_tar in glob.glob(f'{_dirname}/*.tar.gz'):
                self.update_status("f'{_dirname}/*.tar.gz'")
                self._extract_secure_tar(_secure_tar, password)
                os.remove(_secure_tar)
            self.update_status("Finished successfully")
            messagebox.showinfo("Success", "tar-file successfully decrypted.")
            
        except Exception as e:
            self.update_status("Error during decryption")
            messagebox.showerror("Error", f"Error during decryption of tar-file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("500x500")
    app = HassBackupDecrypter(root)
    root.mainloop()
