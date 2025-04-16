import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (this should be stored securely in production)
if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
cipher = Fernet(st.session_state.KEY)

# Initialize session state for data storage and failed attempts
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True  # Start as authorized

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Check authorization before showing main content
if st.session_state.failed_attempts >= 3:
    st.session_state.authorized = False

if not st.session_state.authorized:
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully!")
        else:
            st.error("❌ Incorrect password!")
    st.stop()  # Stop execution here if not authorized

# Main app content (only shown if authorized)
st.title("🔒 Secure Data Encryption System)")
st.header("Created by Owais Qazi")
st.subheader("(Q3 - Assignment No. 5)")


# Navigation
menu = ["Home", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            # Use a unique identifier as the key instead of the encrypted text
            unique_id = f"data_{len(st.session_state.stored_data)}"
            st.session_state.stored_data[unique_id] = {
                "encrypted_text": encrypted_text, 
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(f"Your encrypted data (save this for retrieval):\n{encrypted_text}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Data decrypted successfully!")
                st.text_area("Decrypted Data:", value=decrypted_text, height=200)
            else:
                attempts_remaining = 3 - st.session_state.failed_attempts
                if attempts_remaining > 0:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_remaining}")
                else:
                    st.error("❌ Too many failed attempts! Please reauthorize.")
                    st.session_state.authorized = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")