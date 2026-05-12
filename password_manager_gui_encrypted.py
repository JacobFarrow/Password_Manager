import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import hashlib
import os  # Used to generate a secure "salt"
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

PASSWORD_FILE = Path(__file__).parent / "passwords.txt"
MASTER_PW_FILE = Path(__file__).parent / "master.key"
SALT_FILE = Path(__file__).parent / "salt.key"

def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

class PasswordManagerApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        self.title("Password Manager")
        self.encryption_fernet = None

        container = tk.Frame(self)
        container.pack(side = "top", fill = "both", expand = True)
        container.grid_rowconfigure(0, weight = 1)
        container.grid_columnconfigure(0, weight = 1)

        self.frames = {}
        for f in (LoginFrame, MainAppFrame):
            frame = f(container, self)
            self.frames[f] = frame
            frame.grid(row = 0, column = 0, sticky = "nsew")

        self.show_frame(LoginFrame)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.config(padx = 40, pady = 40)

        label = tk.Label(self, text = "Enter Master Password: ", font = ("Arial", 14))
        label.pack(pady = 10)

        self.password_entry = tk.Entry(self, width = 30, show = "*")
        self.password_entry.pack(pady = 20)

        login_button = tk.Button(self, text = "Login/Register", command = self.login)
        login_button.pack(pady = 20)

        self.controller.bind("<Return>", lambda event: self.login())
        self.password_entry.focus()

    def login(self):
        entered_password = self.password_entry.get()
        if not entered_password:
            messagebox.showwarning("Empty", "Please enter a password.")
            return
    
        hashed_password = hashlib.sha256(entered_password.encode()).hexdigest()

        if not MASTER_PW_FILE.exists():
            with open(MASTER_PW_FILE, "w") as f:
                f.write(hashed_password)

            salt = os.urandom(16)
            with open(SALT_FILE, "wb") as f:
                f.write(salt)

            key = generate_key(entered_password, salt)
            self.controller.encryption_fernet = Fernet(key)    

            messagebox.showinfo("Success", "Master password created. Welcome to password manager!")
            self.password_entry.delete(0, tk.END)
            self.controller.show_frame(MainAppFrame)
        else:
            with open(MASTER_PW_FILE, "r") as f:
                stored_hash = f.read()
            
            if hashed_password == stored_hash:
                with open(SALT_FILE, "rb") as f:
                    salt = f.read()

                key = generate_key(entered_password, salt)
                self.controller.encryption_fernet = Fernet(key)

                self.password_entry.delete(0, tk.END)
                self.controller.show_frame(MainAppFrame)
            else:
                messagebox.showerror("Failed", "Incorrect password.")

class MainAppFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.config(padx = 40, pady = 40)

        website_label = tk.Label(self, text = "Website: ")
        website_label.grid(row = 0, column = 0, sticky = "W", pady = 2)
        self.website_entry = tk.Entry(self, width = 35)
        self.website_entry.grid(row = 0, column = 1, columnspan = 2, pady = 2)
        self.website_entry.focus()

        username_label = tk.Label(self, text = "Username/Email: ")
        username_label.grid(row = 1, column = 0, sticky = "W", pady = 2)
        self.username_entry = tk.Entry(self, width=35)
        self.username_entry.grid(row=1, column=1, columnspan=2, pady=2)

        password_label = tk.Label(self, text="Password:")
        password_label.grid(row=2, column=0, sticky="W", pady=2)
        self.password_entry = tk.Entry(self, width=35, show="*")
        self.password_entry.grid(row=2, column=1, columnspan=2, pady=2)

        add_button = tk.Button(self, text = "Add Password", width = 30, command = self.add_password)
        add_button.grid(row = 3, column = 1, columnspan = 2, pady = 10)

        view_button = tk.Button(self, text = "View Password", width = 30, command = self.view_passwords)
        view_button.grid(row = 4, column = 1, columnspan = 2)

    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not website or not username or not password:
            messagebox.showwarning("Oops!", "Please leave no field empty!")
            return
        
        if not self.controller.encryption_fernet:
            messagebox.showerror("Error", "No encryption key detected, please restart Password Manager.")
            return
        
        encrypted_password_bytes = self.controller.encryption_fernet.encrypt(password.encode())
        encrypted_password_str = encrypted_password_bytes.decode()

        try:
            with open(PASSWORD_FILE, "a") as file:
                file.write(f"""{website} | {username} | {encrypted_password_str}
""")
                self.website_entry.delete(0, tk.END)
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                self.website_entry.focus()
                messagebox.showinfo("Success!", "Password added!")

        except IOError as error:
            messagebox.showerror("Error", f"Error occurred : {error}")

    def view_passwords(self):
        try:
            with open(PASSWORD_FILE, "r") as file:
                lines = file.readlines()

            if not lines:
                messagebox.showwarning("Saved Passwords", "There are no saved passwords.")
                return
            
            view_window = tk.Toplevel(self)
            view_window.title("Saved Passwords")
            view_window.config(padx = 20, pady = 20)

            text_area = tk.Text(view_window, height = 15, width = 50)
            text_area.pack()

            fernet = self.controller.encryption_fernet
            if not fernet:
                messagebox.showerror("Error", "No encryption key detected, please restart Password Manager.")
                return
            
            for line in lines:
                try:
                    website, username, encrypted_password_str = line.strip().split(" | ")

                    encrypted_password_bytes = encrypted_password_str.encode()
                    decrypted_password = fernet.decrypt(encrypted_password_bytes).decode()

                    entry = f"""Website: {website}
Username: {username}
Password: {decrypted_password}
{"-" * 20}"""
                    text_area.insert(tk.END, entry)
                except Exception:
                    text_area.insert(tk.END, f"""Decrypting entry failed: {line.split(" | ")[0]}
{"-" * 20}""")

            text_area.config(state = tk.DISABLED)
        except FileNotFoundError:
            messagebox.showwarning("Error with file", "Please save a password first.")
        except IOError as error:
            messagebox.showerror("Error", f"An error has occurred: {error}")

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()