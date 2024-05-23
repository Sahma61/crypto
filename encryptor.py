#!/usr/bin/python3
"""
Encryptor Module.

encrypts and decrypts plaintext
using AES.
a user supplied password is used as the key
"""
import sys
import getpass

from io import BytesIO
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES


def encrypt(password: str, text: str, create_file: bool = False) -> str:
    """
    Encryption Function.

    encrypts plaintext using AES.
    a user supplied password is used as the key
    """
    for _ in range(16 - len(password) % 16):
        password = password + "0"

    key = password.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(text.encode()))

    if create_file:
        with open("encrypted.bin", "wb") as file_out:
            for info in (cipher.nonce, tag, ciphertext):
                file_out.write(info)

    # Write to string as file
    file_out = BytesIO()
    for info in (cipher.nonce, tag, ciphertext):
        file_out.write(info)

    return b64encode(file_out.getvalue()).decode()


def decrypt(password: str, text: str) -> str:
    """
    Decryption Function.

    decrypts plaintext using AES.
    a user supplied password is used as the key
    """
    for _ in range(16 - len(password) % 16):
        password = password + "0"

    file_in = BytesIO(bytes(b64decode(text.encode())))

    key = password.encode()
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as exp:
        print(exp)
        sys.exit(0)
    return data.decode()


def get_password() -> str:
    """
    Get Password  Function.

    accepts a passowrd via user input and
    confirms it
    """
    while True:
        password1 = getpass.getpass("Enter the password:")
        password2 = getpass.getpass("Enter the password to confirm:")
        if password1 != password2:
            print("Passwords don't match")
            continue
        break
    return password1


if __name__ == "__main__":
    option = input("Enter encrypt/decrypt Option:")
    if option not in ["encrypt", "decrypt"]:
        print("Option not supported!")
        sys.exit(0)

    txt = input("Enter Text:")

    passwrd = get_password()

    if option == "encrypt":
        print(encrypt(passwrd, txt))
    else:
        print(decrypt(passwrd, txt))
