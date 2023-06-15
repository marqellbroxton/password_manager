import base64
import os
import getpass
from cryptography.fernet import Fernet
import sqlite3
from hashlib import pbkdf2_hmac, sha256

MASTER_PASSWORD_FILE = "password.txt"
SALT_SIZE = 16
ITERATIONS = 100000
KEY_LENGTH = 32

# Generate a key for encryption
def generate_key():
    return base64.urlsafe_b64encode(os.urandom(KEY_LENGTH))

# Encrypt the password
def encrypt_password(key, password):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

# Initialize the database and table
def initialize_database(database_name):
    conn = sqlite3.connect(database_name)
    c = conn.cursor()

    # Create the table
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (service TEXT PRIMARY KEY, username TEXT, password BLOB)''')

    conn.commit()
    conn.close()

# Save a new password to the database
def save_password(service, username, password, key, database_name):
    conn = sqlite3.connect(database_name)
    c = conn.cursor()

    # Encrypt the password
    encrypted_password = encrypt_password(key, password)

    # Insert or update the password for the given service
    c.execute("INSERT OR REPLACE INTO passwords (service, username, password) VALUES (?, ?, ?)",
              (service, username, encrypted_password))

    conn.commit()
    conn.close()

    print("Password saved successfully.")

# Retrieve a saved password from the database
def retrieve_password(service, key, database_name):
    conn = sqlite3.connect(database_name)
    c = conn.cursor()

    # Retrieve the encrypted password for the given service
    c.execute("SELECT username, password FROM passwords WHERE service=?", (service,))
    result = c.fetchone()

    if result:
        username = result[0]
        encrypted_password = result[1]
        decrypted_password = decrypt_password(key, encrypted_password)
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print("Password not found.")

    conn.close()

# Delete a saved password from the database
def delete_password(service, database_name):
    conn = sqlite3.connect(database_name)
    c = conn.cursor()

    # Delete the password for the given service
    c.execute("DELETE FROM passwords WHERE service=?", (service,))

    if c.rowcount > 0:
        print("Password deleted successfully.")
    else:
        print("Password not found.")

    conn.commit()
    conn.close()

# Edit a saved password in the database
def edit_password(service, username, password, key, database_name):
    conn = sqlite3.connect(database_name)
    c = conn.cursor()

    # Encrypt the password
    encrypted_password = encrypt_password(key, password)

    # Update the password for the given service
    c.execute("UPDATE passwords SET username=?, password=? WHERE service=?", (username, encrypted_password, service))

    if c.rowcount > 0:
        print("Password edited successfully.")
    else:
        print("Password not found.")

    conn.commit()
    conn.close()

# Get the master password from the user
def get_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        with open(MASTER_PASSWORD_FILE, "rb") as file:
            hashed_master_password = file.read().strip()
            return hashed_master_password

    print("Master password not found. Please create a new master password.")
    master_password = getpass.getpass("Create a master password: ")

    verify_password = getpass.getpass("Verify the master password: ")
    while master_password != verify_password:
        print("Passwords do not match. Please try again.")
        master_password = getpass.getpass("Create a master password: ")
        verify_password = getpass.getpass("Verify the master password: ")

    hashed_master_password = hash_master_password(master_password)
    with open(MASTER_PASSWORD_FILE, "wb") as file:
        file.write(hashed_master_password)

    return hashed_master_password

def hash_master_password(master_password):
    salt = os.urandom(SALT_SIZE)
    hashed_password = pbkdf2_hmac('sha256', master_password.encode(), salt, ITERATIONS)
    return salt + hashed_password

def verify_master_password(entered_password, hashed_master_password):
    salt = hashed_master_password[:SALT_SIZE]
    entered_hashed_password = pbkdf2_hmac('sha256', entered_password.encode(), salt, ITERATIONS)
    return hashed_master_password == salt + entered_hashed_password

def reset_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        os.remove(MASTER_PASSWORD_FILE)
        print("Master password has been reset.")
    else:
        print("Master password not found.")

def main():
    database_name = "database.db"  # Change this to a more secret database name
    initialize_database(database_name)
    master_password = get_master_password()

    entered_password = getpass.getpass("Enter your master password: ")
    if verify_master_password(entered_password, master_password):
        print("Master password verified.")
        key = generate_key()

        while True:
            print("\nMenu:")
            print("1. Save a new password")
            print("2. Retrieve a saved password")
            print("3. Edit an existing password")
            print("4. Delete an existing password")
            print("5. Reset master password")
            print("6. Quit")

            choice = input("Enter your choice (1-6): ")

            if choice == "1":
                service = input("Enter the service name: ")
                username = input("Enter your username: ")
                password = getpass.getpass("Enter your password: ")
                save_password(service, username, password, key, database_name)
            elif choice == "2":
                service = input("Enter the service name: ")
                retrieve_password(service, key, database_name)
            elif choice == "3":
                service = input("Enter the service name: ")
                username = input("Enter the new username: ")
                password = getpass.getpass("Enter the new password: ")
                edit_password(service, username, password, key, database_name)
            elif choice == "4":
                service = input("Enter the service name: ")
                delete_password(service, database_name)
            elif choice == "5":
                reset_master_password()
                break
            elif choice == "6":
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

























