# Password Manager

This is a simple password manager that securely stores and manages your passwords. It uses encryption to protect your passwords and requires a master password to access the saved passwords.

## How it works

The password manager uses a SQLite database to store the encrypted passwords. The passwords are encrypted using the Fernet symmetric encryption algorithm provided by the `cryptography` library. The master password is hashed and salted using PBKDF2-HMAC-SHA256 for added security.

When you run the password manager, you will have several options to manage your passwords:

1. **Save a New Password**: You can save a new password for a service. It will prompt you to enter the service name, your username, and the password. The password will be encrypted and saved to the database.

2. **Retrieve a Saved Password**: If you want to retrieve a saved password, you can enter the service name, and the password will be decrypted and displayed for you.

3. **Edit an Existing Password**: If you need to update a password or change the username associated with a service, you can do so using this option.

4. **Delete an Existing Password**: If you want to remove a saved password from the database, you can use this option.

5. **Reset Master Password**: If you forget your master password or want to change it, you can reset it. Please note that this will remove all saved passwords from the database, and you will need to start over.

6. **Quit**: Exit the password manager.

## Installation

1. Make sure you have Python installed on your system.

2. Install the required libraries by running:

```
pip install cryptography
```

3. Run the script:

```
python password_manager.py
```

## Security Note

Please ensure that you keep your master password safe and never share it with anyone. Losing the master password means losing access to your saved passwords. Also, consider choosing a secure database name to prevent unauthorized access to your password database file.

**Disclaimer**: While this password manager employs encryption and hashing techniques to enhance security, it is important to understand that no system is completely foolproof. Use this password manager at your own risk, and always follow best security practices for managing your passwords.
