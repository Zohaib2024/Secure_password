import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- Constants ---
DATA_FILE = "data.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # in seconds

# --- Utilities ---
def generate_key(passphrase: str) -> bytes:
    salt = b'streamlit_salt'
    kdf = pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, dklen=32)
    return urlsafe_b64encode(kdf)

def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as file:
        return json.load(file)

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# --- Initialize ---
if "data" not in st.session_state:
    st.session_state.data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

if "lockout_start" not in st.session_state:
    st.session_state.lockout_start = {}

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Register", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Pages ---
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using encryption.")

elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Register"):
        if username and password:
            if username in st.session_state.data:
                st.warning("⚠️ Username already exists!")
            else:
                st.session_state.data[username] = {
                    "password": hashlib.sha256(password.encode()).hexdigest(),
                    "data": []
                }
                save_data(st.session_state.data)
                st.success("✅ Registered successfully!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    user_data = st.text_area("Enter Data to Encrypt:")

    if st.button("Encrypt & Store"):
        users = st.session_state.data
        if username in users and users[username]["password"] == hashlib.sha256(password.encode()).hexdigest():
            key = generate_key(password)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(user_data.encode()).decode()
            users[username]["data"].append(encrypted)
            save_data(users)
            st.success("✅ Data encrypted and stored!")
        else:
            st.error("❌ Invalid username or password!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    now = time.time()
    locked = st.session_state.lockout_start.get(username, 0)
    if now - locked < LOCKOUT_TIME:
        remaining = int(LOCKOUT_TIME - (now - locked))
        st.warning(f"🔒 Too many failed attempts. Try again in {remaining} seconds.")
    else:
        if st.button("Show Data"):
            users = st.session_state.data
            if username in users and users[username]["password"] == hashlib.sha256(password.encode()).hexdigest():
                key = generate_key(password)
                cipher = Fernet(key)
                decrypted_data = []
                for enc in users[username]["data"]:
                    try:
                        decrypted = cipher.decrypt(enc.encode()).decode()
                        decrypted_data.append(decrypted)
                    except:
                        decrypted_data.append("❌ Decryption failed.")
                st.success("✅ Decrypted Data:")
                for idx, item in enumerate(decrypted_data, start=1):
                    st.code(f"{idx}. {item}")
                st.session_state.failed_attempts[username] = 0
            else:
                st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
                attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts[username]
                if attempts_left <= 0:
                    st.session_state.lockout_start[username] = time.time()
                    st.error("❌ Too many failed attempts! Locked for 60 seconds.")
                else:
                    st.error(f"❌ Invalid credentials! Attempts left: {attempts_left}")

elif choice == "Login":
    st.subheader("🔐 Admin Login")
    admin_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if admin_password == "admin123":
            st.success("✅ Admin login successful!")
            st.write("### 🔍 All Users' Encrypted Data:")
            for user, info in st.session_state.data.items():
                st.write(f"**User:** {user}")
                for idx, d in enumerate(info['data'], 1):
                    st.code(f"{idx}. {d}")
        else:
            st.error("❌ Incorrect master password!")
