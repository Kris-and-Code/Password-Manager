import json
import secrets
import string
from cryptography.fernet import Fernet
import base64
from getpass import getpass

class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = "passwords.json"
        self.password_dict = {}
        
    def create_key(self):
        """Create a key for encryption"""
        self.key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(self.key)

    def load_key(self):
        """Load the previously created key"""
        try:
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.create_key()

    def load_passwords(self):
        """Load passwords from file"""
        try:
            with open(self.password_file, "r") as f:
                self.password_dict = json.load(f)
        except FileNotFoundError:
            self.password_dict = {}

    def save_passwords(self):
        """Save passwords to file"""
        with open(self.password_file, "w") as f:
            json.dump(self.password_dict, f)

    def encrypt_password(self, password):
        """Encrypt a password"""
        f = Fernet(self.key)
        return f.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        f = Fernet(self.key)
        return f.decrypt(encrypted_password.encode()).decode()

    def add_password(self, service, username, password):
        """Add a new password"""
        self.password_dict[service] = {
            "username": username,
            "password": self.encrypt_password(password)
        }
        self.save_passwords()

    def get_password(self, service):
        """Retrieve a password"""
        if service in self.password_dict:
            entry = self.password_dict[service]
            return {
                "username": entry["username"],
                "password": self.decrypt_password(entry["password"])
            }
        return None

    def generate_password(self, length=16):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    pm = PasswordManager()
    pm.load_key()
    pm.load_passwords()

    while True:
        print("\n=== Password Manager ===")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Generate Password")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")

        if choice == "1":
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = getpass("Enter password: ")
            pm.add_password(service, username, password)
            print("Password saved successfully!")

        elif choice == "2":
            service = input("Enter service name: ")
            result = pm.get_password(service)
            if result:
                print(f"\nUsername: {result['username']}")
                print(f"Password: {result['password']}")
            else:
                print("Service not found!")

        elif choice == "3":
            length = int(input("Enter password length (default 16): ") or 16)
            print(f"Generated Password: {pm.generate_password(length)}")

        elif choice == "4":
            break

        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main() 