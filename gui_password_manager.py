import tkinter as tk
from tkinter import ttk, messagebox
from password_manager import PasswordManager
import pyperclip  # For copy functionality
from typing import Optional
import logging

class PasswordManagerGUI:
    def __init__(self, root: tk.Tk):
        """Initialize the GUI application"""
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.pm = PasswordManager()
        
        # Configure logging
        logging.basicConfig(
            filename='password_manager.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Configure styles
        self.setup_styles()
        
        # Center window
        self.center_window()
        
        # Initialize login screen
        self.setup_login_screen()

    def setup_styles(self):
        """Configure ttk styles"""
        self.style = ttk.Style()
        self.style.configure('TButton', padding=10, font=('Helvetica', 10))
        self.style.configure('TLabel', padding=5, font=('Helvetica', 10))
        self.style.configure('TEntry', padding=5, font=('Helvetica', 10))
        self.style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))
        
    def center_window(self):
        """Center the window on the screen"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - 800) // 2
        y = (screen_height - 600) // 2
        self.root.geometry(f"800x600+{x}+{y}")

    def setup_login_screen(self):
        """Create the login screen"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header
        header = ttk.Label(frame, text="Secure Password Manager", style='Header.TLabel')
        header.grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        ttk.Label(frame, text="Master Password:").grid(row=1, column=0, pady=10)
        self.master_password = ttk.Entry(frame, show="•")
        self.master_password.grid(row=1, column=1, pady=10, padx=10, sticky='ew')
        
        # Login button with improved style
        login_btn = ttk.Button(frame, text="Login", command=self.login, style='TButton')
        login_btn.grid(row=2, column=0, columnspan=2, pady=20)
        
        # Configure grid weights
        frame.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        self.master_password.focus()
        self.root.bind('<Return>', lambda e: self.login())

    def setup_main_screen(self):
        """Create the main application screen"""
        self.clear_window()
        
        # Create main container
        container = ttk.Frame(self.root, padding="20")
        container.grid(sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header
        header = ttk.Label(container, text="Password Manager Dashboard", style='Header.TLabel')
        header.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Left panel for buttons
        btn_frame = ttk.Frame(container)
        btn_frame.grid(row=1, column=0, padx=(0, 20), sticky='n')
        
        buttons = [
            ("🔐 Add Password", self.show_add_password),
            ("👁 View Passwords", self.show_passwords),
            ("🎲 Generate Password", self.show_generate_password),
            ("❌ Delete Password", self.show_delete_password),
            ("🔄 Update Password", self.show_update_password),
            ("📋 Copy Password", self.show_copy_password),
            ("↪ Logout", self.setup_login_screen)
        ]
        
        for i, (text, command) in enumerate(buttons):
            btn = ttk.Button(btn_frame, text=text, command=command, width=20)
            btn.grid(row=i, column=0, pady=5)
        
        # Right panel for quick info
        info_frame = ttk.Frame(container)
        info_frame.grid(row=1, column=1, sticky='nsew')
        
        # Show statistics
        self.update_statistics(info_frame)
        
        # Configure weights
        container.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

    def update_statistics(self, frame: ttk.Frame):
        """Update and display password statistics"""
        services = self.pm.list_services()
        
        ttk.Label(frame, text="Statistics", style='Header.TLabel').grid(row=0, column=0, pady=(0, 10))
        ttk.Label(frame, text=f"Total passwords stored: {len(services)}").grid(row=1, column=0, sticky='w')
        
        if services:
            ttk.Label(frame, text="Recent services:").grid(row=2, column=0, sticky='w', pady=(10, 5))
            for i, service in enumerate(sorted(services)[:5]):
                ttk.Label(frame, text=f"• {service}").grid(row=i+3, column=0, sticky='w')

    def show_copy_password(self):
        """Show dialog to copy password to clipboard"""
        dialog = self.create_dialog("Copy Password", "400x200")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Select Service:").grid(row=0, column=0, pady=5)
        service = ttk.Combobox(frame, values=sorted(self.pm.list_services()))
        service.grid(row=0, column=1, pady=5, padx=5)
        
        def copy():
            if service.get():
                entry = self.pm.get_password(service.get())
                if entry:
                    pyperclip.copy(entry["password"])
                    messagebox.showinfo("Success", "Password copied to clipboard!")
                    # Clear clipboard after 30 seconds
                    self.root.after(30000, lambda: pyperclip.copy(''))
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Service not found!")
        
        ttk.Button(frame, text="Copy", command=copy).grid(row=1, column=0, columnspan=2, pady=20)

    def show_update_password(self):
        """Show dialog to update existing password"""
        dialog = self.create_dialog("Update Password", "400x300")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Select Service:").grid(row=0, column=0, pady=5)
        service = ttk.Combobox(frame, values=sorted(self.pm.list_services()))
        service.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(frame, text="New Password:").grid(row=1, column=0, pady=5)
        password = ttk.Entry(frame, show="•")
        password.grid(row=1, column=1, pady=5, padx=5)
        
        def update():
            try:
                self.pm.update_password(service.get(), password.get())
                messagebox.showinfo("Success", "Password updated successfully!")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(frame, text="Update", command=update).grid(row=2, column=0, columnspan=2, pady=20)

    def create_dialog(self, title: str, geometry: str) -> tk.Toplevel:
        """Create a standard dialog window"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry(geometry)
        dialog.transient(self.root)
        dialog.grab_set()
        return dialog

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
            logging.info("User logged in successfully")
            self.setup_main_screen()
        except ValueError as e:
            logging.warning(f"Login failed: {str(e)}")
            messagebox.showerror("Error", str(e))
        except Exception as e:
            logging.error(f"Unexpected error during login: {str(e)}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

def main():
    try:
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application crashed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 