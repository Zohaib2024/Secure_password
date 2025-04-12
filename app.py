import streamlit as st
from auth import encrypt, decrypt, hash_password, verify_password
from utils import load_json, save_json
from datetime import datetime, timedelta

# Load data
users = load_json("users.json")
data = load_json("data.json")
lockout = st.session_state.get("lockout", None)

# Lockout Logic
if lockout and datetime.now() < datetime.fromisoformat(lockout):
    st.error("🔒 You're locked out due to too many failed attempts. Try again later.")
    st.stop()

st.title("🔐 Secure Data Encryption System")

# Pages
menu = ["Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

# User session state
if "username" not in st.session_state:
    st.session_state.username = None
if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# Register Page
if choice == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user in users:
            st.error("❌ User already exists!")
        else:
            users[new_user] = hash_password(new_pass)
            save_json("users.json", users)
            st.success("✅ Registered successfully!")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Login")
    user = st.text_input("Username")
    passwd = st.text_input("Password", type="password")
    if st.button("Login"):
        if user in users and verify_password(passwd, users[user]):
            st.success("✅ Logged in successfully")
            st.session_state.username = user
            st.session_state.attempts = 0
        else:
            st.session_state.attempts += 1
            st.error(f"❌ Login failed! Attempts left: {3 - st.session_state.attempts}")
            if st.session_state.attempts >= 3:
                st.session_state.lockout = (datetime.now() + timedelta(minutes=1)).isoformat()
                st.experimental_rerun()

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.username:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("📦 Store Your Data")
        text = st.text_area("Enter data:")
        if st.button("Encrypt & Save"):
            encrypted = encrypt(text)
            user_data = data.get(st.session_state.username, [])
            user_data.append(encrypted)
            data[st.session_state.username] = user_data
            save_json("data.json", data)
            st.success("✅ Data encrypted and stored!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.username:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = data.get(st.session_state.username, [])
        if not user_data:
            st.info("No data stored yet.")
        else:
            for idx, enc in enumerate(user_data):
                with st.expander(f"Data #{idx+1}"):
                    if st.button(f"Decrypt #{idx+1}"):
                        try:
                            st.success(f"🔓 {decrypt(enc)}")
                        except:
                            st.error("❌ Failed to decrypt")
