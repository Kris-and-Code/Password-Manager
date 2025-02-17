import json
import secrets
import string
import hashlib
from cryptography.fernet import Fernet
import base64
from getpass import getpass

class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = "passwords.json"
        self.password_dict = {}
        self.master_password_hash = None
        self.master_password_file = "master.key"
        
    def create_key(self, master_password):
        """Create a key for encryption derived from master password"""
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
        self.key = base64.urlsafe_b64encode(key)
        # Save salt and master password hash
        master_hash = hashlib.sha256(master_password.encode()).hexdigest()
        with open(self.master_password_file, "w") as f:
            json.dump({"salt": base64.b64encode(salt).decode(), 
                      "hash": master_hash}, f)

    def load_key(self, master_password):
        """Load the key using master password"""
        try:
            with open(self.master_password_file, "r") as f:
                data = json.load(f)
                salt = base64.b64decode(data["salt"])
                stored_hash = data["hash"]
                
            # Verify master password
            if hashlib.sha256(master_password.encode()).hexdigest() != stored_hash:
                raise ValueError("Invalid master password")
                
            # Derive key from master password and salt
            key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
            self.key = base64.urlsafe_b64encode(key)
        except FileNotFoundError:
            self.create_key(master_password)

    def check_password_strength(self, password):
        """Check if password meets minimum requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        if not any(c in string.punctuation for c in password):
            return False, "Password must contain at least one special character"
        return True, "Password meets requirements"

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
        is_strong, msg = self.check_password_strength(password)
        if not is_strong:
            raise ValueError(msg)
            
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

    def delete_password(self, service):
        """Delete a password entry"""
        if service in self.password_dict:
            del self.password_dict[service]
            self.save_passwords()
            return True
        return False

    def update_password(self, service, new_password):
        """Update password for existing service"""
        if service not in self.password_dict:
            raise ValueError("Service not found")
            
        is_strong, msg = self.check_password_strength(new_password)
        if not is_strong:
            raise ValueError(msg)
            
        self.password_dict[service]["password"] = self.encrypt_password(new_password)
        self.save_passwords()

    def list_services(self):
        """List all stored services"""
        return sorted(self.password_dict.keys())

    def generate_password(self, length=16):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    pm = PasswordManager()
    
    # Get master password
    master_password = getpass("Enter master password: ")
    try:
        pm.load_key(master_password)
        pm.load_passwords()
    except ValueError as e:
        print(f"Error: {e}")
        return

    while True:
        print("\n=== Password Manager ===")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Generate Password")
        print("4. List Services")
        print("5. Delete Password")
        print("6. Update Password")
        print("7. Exit")
        
        choice = input("Enter your choice (1-7): ")

        try:
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
                services = pm.list_services()
                if services:
                    print("\nStored services:")
                    for service in services:
                        print(f"- {service}")
                else:
                    print("No services stored yet!")

            elif choice == "5":
                service = input("Enter service name to delete: ")
                if pm.delete_password(service):
                    print("Password deleted successfully!")
                else:
                    print("Service not found!")

            elif choice == "6":
                service = input("Enter service name: ")
                if service in pm.password_dict:
                    new_password = getpass("Enter new password: ")
                    pm.update_password(service, new_password)
                    print("Password updated successfully!")
                else:
                    print("Service not found!")

            elif choice == "7":
                break

            else:
                print("Invalid choice!")
                
        except ValueError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main() 