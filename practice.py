import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)


stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    entry = stored_data.get(encrypted_text)

    if entry and entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0  # Reset on success
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None


st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📂 Navigation", menu)


if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("This app allows you to securely **store and retrieve data** using encryption and passkeys.")


elif choice == "Store Data":
    st.subheader("📥 Store Data Securely")
    user_data = st.text_area("Enter data to store:")
    passkey = st.text_input("Set a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.text_area("🔐 Your Encrypted Data (Save this to retrieve later):", encrypted, height=100)
        else:
            st.error("⚠️ Both fields are required.")

elif choice == "Retrieve Data":
    if not st.session_state.is_logged_in:
        st.warning("🔒 Too many failed attempts. Please log in first.")
        st.experimental_rerun()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("🚫 Too many failed attempts! Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")


elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if hash_passkey(login_pass) == hash_passkey("admin123"): 
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Login successful. You can now retrieve data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
