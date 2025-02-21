# Secure Password Manager

A command-line password manager that securely stores and manages your passwords using strong encryption.

## Features

- Master password protection with PBKDF2 key derivation
- Strong password encryption using Fernet (symmetric encryption)
- Password strength validation
- Generate secure random passwords
- Store username/password combinations for different services
- List, add, update, and delete password entries
- All data stored locally and encrypted

## Requirements

- Python 3.x
- cryptography library
- getpass library

## Installation

1. Install requirements:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the program:

```bash
python password_manager.py
```

2. On first run, you'll be prompted to create a master password. Remember this password - it's required to access your stored passwords!

3. Available commands:
   - Add Password: Store new service credentials
   - Get Password: Retrieve stored credentials
   - Generate Password: Create a secure random password
   - List Services: View all stored services
   - Delete Password: Remove stored credentials
   - Update Password: Change password for existing service
   
## Password Requirements

All passwords must have:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## Security Features

- Master password is never stored in plain text
- Passwords are encrypted using Fernet symmetric encryption
- Key derivation uses PBKDF2 with SHA-256
- Salt is used to prevent rainbow table attacks
- All sensitive data is encrypted before storage

## Files Created

- `passwords.json`: Encrypted password storage
- `master.key`: Stores salt and master password verification data

## Warning

Keep your master password safe! If you lose it, you won't be able to recover your stored passwords.

## GUI Version

The password manager now includes a graphical user interface! To run the GUI version:

```bash
python gui_password_manager.py
```

GUI Features:
- User-friendly interface
- Easy password management
- Password generator with customizable length
- Secure password viewing with auto-hide
- Simple service deletion
- Master password protection    