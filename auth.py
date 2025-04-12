import json
import hashlib
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import base64
import os
import hashlib

# Load or generate key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("secret.key", "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# Password hashing using PBKDF2
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(password, hashed_pass):
    hashed_pass_bytes = base64.b64decode(hashed_pass.encode())
    salt = hashed_pass_bytes[:16]
    return hash_password(password, salt) == hashed_pass

# Encrypt/Decrypt functions
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()
