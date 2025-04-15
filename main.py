import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import json
import os
import time

# FILE CONSTANTS
DATA_FILE = "secure_data.json"
LOCK_FILE = "lock_status.json"
KEY_FILE = "ferrnet_key.key"
LOCK_DURATION = 300     #seconds(5 mins)

# Load or Generate Encryption Key
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    
KEY = load_key()
cipher = Fernet(KEY)

# Helper functions
# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    return cipher.encrypt(encrypted_text.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data,f)
        
def load_lock_status():
    if os.path.exists(LOCK_FILE):
        with open(LOCK_FILE, "r") as f:
            return json.load(f)
    return {"failed attempts": 0, "lock_time": 0}

def save_lock_status(status):
    with open(LOCK_FILE, "w") as f:
        json.dump(status, f)
        
# Load States
stored_data = load_data()
lock_status = load_lock_status()
current_time = time.time()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data page
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

# Retrieve Data page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # lock check
    if lock_status["failed_attempts"] >= 3:
        time_elapsed = current_time - lock_status["lock_time"]
        if time_elapsed < LOCK_DURATION:
            remaining = int(LOCK_DURATION - time_elapsed)
            st.warning(f"🔒 Too many failed attempts. Try again in {remaining} seconds.")
            st.stop()
            
        else:
            lock_status = {"failed_attempts": 0, "lock_time": 0}
            save_lock_status(lock_status)
            
    encrypted_text = st.text_area("Enter Encrypted Data:", key="retrieve_data_input")
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                hashed_passkey = hash_passkey(passkey)
                record = stored_data.get(encrypted_text)
                
                if record and record["passkey"] == hashed_passkey:
                    decrypted_text = decrypt_data(encrypted_text)
                    lock_status = {"failed_attempts": 0, "lock_time": 0}
                    save_lock_status(lock_status)
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    lock_status["failed_attempts"] += 1
                    if lock_status["failed_attempts"] >= 3:
                        lock_status["lock_time"] = time.time()
                        st.warning(f"🔒 Too many failed attempts!\nData locked for 5 minutes.")
                        
                    else:
                        attempts_left = 3 - lock_status["failed_attempts"]
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                        save_lock_status(lock_status)
                        
            except InvalidToken:
                st.error("❌ Invalid encrypted data!")
        else:
            st.error("⚠️ Both fields are required!")

# login page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="admin_passkey")
    
    if st.button("Login"):
        if login_pass == "admin123":
            lock_status = {"failed_attempts": 0, "lock_time": 0}
            save_lock_status(lock_status)
            st.success("✅ Reauthorized successfully!")
            
        else:
            st.error("❌ Incorrect password!")
    
        
