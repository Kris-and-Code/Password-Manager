import tkinter as tk
from tkinter import ttk, messagebox
from password_manager import PasswordManager
import sys

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("600x400")
        self.pm = PasswordManager()
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)
        
        self.setup_login_screen()

    def setup_login_screen(self):
        """Create the login screen"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Master Password:").grid(row=0, column=0, pady=10)
        self.master_password = ttk.Entry(frame, show="*")
        self.master_password.grid(row=0, column=1, pady=10)
        
        ttk.Button(frame, text="Login", command=self.login).grid(row=1, column=0, columnspan=2, pady=10)
        
        self.master_password.focus()
        self.root.bind('<Return>', lambda e: self.login())

    def setup_main_screen(self):
        """Create the main application screen"""
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=0, column=0, pady=10)
        
        buttons = [
            ("Add Password", self.show_add_password),
            ("View Passwords", self.show_passwords),
            ("Generate Password", self.show_generate_password),
            ("Delete Password", self.show_delete_password),
            ("Logout", self.setup_login_screen)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(btn_frame, text=text, command=command).grid(row=i, column=0, pady=5, padx=20)

    def show_add_password(self):
        """Show add password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x250")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Service:").grid(row=0, column=0, pady=5)
        service = ttk.Entry(frame)
        service.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="Username:").grid(row=1, column=0, pady=5)
        username = ttk.Entry(frame)
        username.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=2, column=0, pady=5)
        password = ttk.Entry(frame, show="*")
        password.grid(row=2, column=1, pady=5)
        
        def save():
            try:
                self.pm.add_password(service.get().strip(), 
                                   username.get().strip(), 
                                   password.get())
                messagebox.showinfo("Success", "Password saved successfully!")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(frame, text="Save", command=save).grid(row=3, column=0, columnspan=2, pady=20)

    def show_passwords(self):
        """Show stored passwords"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Stored Passwords")
        dialog.geometry("500x400")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create treeview
        tree = ttk.Treeview(frame, columns=("Service", "Username", "Password"), show="headings")
        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Load passwords
        for service in self.pm.list_services():
            entry = self.pm.get_password(service)
            tree.insert("", tk.END, values=(service, entry["username"], "********"))
        
        tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        def show_password(event):
            item = tree.selection()[0]
            service = tree.item(item)["values"][0]
            entry = self.pm.get_password(service)
            tree.item(item, values=(service, entry["username"], entry["password"]))
            # Hide password after 3 seconds
            self.root.after(3000, lambda: tree.item(item, values=(service, entry["username"], "********")))
        
        tree.bind("<Double-1>", show_password)

    def show_generate_password(self):
        """Show password generator dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Password")
        dialog.geometry("400x200")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Length:").grid(row=0, column=0, pady=5)
        length = ttk.Entry(frame)
        length.insert(0, "16")
        length.grid(row=0, column=1, pady=5)
        
        password_var = tk.StringVar()
        password_label = ttk.Label(frame, textvariable=password_var)
        password_label.grid(row=1, column=0, columnspan=2, pady=20)
        
        def generate():
            try:
                password = self.pm.generate_password(int(length.get()))
                password_var.set(password)
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")
        
        ttk.Button(frame, text="Generate", command=generate).grid(row=2, column=0, columnspan=2, pady=10)

    def show_delete_password(self):
        """Show delete password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Delete Password")
        dialog.geometry("400x200")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Service:").grid(row=0, column=0, pady=5)
        service = ttk.Combobox(frame, values=self.pm.list_services())
        service.grid(row=0, column=1, pady=5)
        
        def delete():
            if self.pm.delete_password(service.get()):
                messagebox.showinfo("Success", "Password deleted successfully!")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Service not found!")
        
        ttk.Button(frame, text="Delete", command=delete).grid(row=1, column=0, columnspan=2, pady=20)

    def login(self):
        """Handle login attempt"""
        try:
            self.pm.load_key(self.master_password.get())
            self.pm.load_passwords()
            self.setup_main_screen()
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 