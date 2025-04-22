import streamlit as st
import json
import os
import time
from datetime import datetime
from security import SecurityManager
from config import *

# Initialize security manager
security = SecurityManager()

# Set page config
st.set_page_config(**PAGE_CONFIG)

# Load custom CSS
with open(STYLE_FILE) as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state
if 'encrypted_data' not in st.session_state:
    st.session_state.encrypted_data = {}
if 'last_activity' not in st.session_state:
    st.session_state.last_activity = time.time()

def get_client_ip():
    """Get client IP address"""
    return st.experimental_get_query_params().get('ip', ['127.0.0.1'])[0]

def check_session_timeout():
    """Check if session has timed out"""
    if time.time() - st.session_state.last_activity > 1800:  # 30 minutes
        st.session_state.clear()
        st.experimental_rerun()

def save_encrypted_data():
    """Save encrypted data to JSON file"""
    try:
        with open(ENCRYPTED_DATA_FILE, 'w') as f:
            json.dump(st.session_state.encrypted_data, f)
        st.success("Data saved successfully!")
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

def load_encrypted_data():
    """Load encrypted data from JSON file"""
    if ENCRYPTED_DATA_FILE.exists():
        try:
            with open(ENCRYPTED_DATA_FILE, 'r') as f:
                st.session_state.encrypted_data = json.load(f)
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")

# Load existing data
load_encrypted_data()

# Sidebar navigation
with st.sidebar:
    st.title("🔐 Navigation")
    st.markdown("---")
    page = st.radio("", ["Home", "Store Data", "Retrieve Data", "Login", "Settings"])
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    A secure data encryption application that provides:
    - Strong encryption using Fernet
    - Secure passkey management
    - Data persistence
    - Advanced security features
    """)

# Update last activity
st.session_state.last_activity = time.time()

if page == "Home":
    st.title("🔐 Secure Data Encryption App")
    
    # Hero section
    st.markdown("""
    <div style="text-align: center; padding: 2rem; background-color: white; border-radius: 12px; margin-bottom: 2rem;">
        <h2 style="color: #2563eb;">Protect Your Sensitive Data</h2>
        <p style="color: #64748b;">Secure encryption and storage for your confidential information</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Features grid
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div style="background-color: white; padding: 1.5rem; border-radius: 12px; text-align: center;">
            <h3>🔒 Secure</h3>
            <p>Military-grade encryption</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div style="background-color: white; padding: 1.5rem; border-radius: 12px; text-align: center;">
            <h3>🔑 Easy Access</h3>
            <p>Simple passkey management</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div style="background-color: white; padding: 1.5rem; border-radius: 12px; text-align: center;">
            <h3>💾 Persistent</h3>
            <p>Reliable data storage</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Statistics
    st.markdown("### 📊 Statistics")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Encrypted Items", len(st.session_state.encrypted_data))
    with col2:
        st.metric("Security Level", "High")
    with col3:
        st.metric("Encryption Type", "AES-128 + HMAC")

elif page == "Store Data":
    st.title("💾 Store Data")
    
    with st.container():
        st.markdown("""
        <div style="background-color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
            <h3>Encrypt Your Data</h3>
            <p>Enter your sensitive information and create a secure passkey</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("store_data_form"):
            text = st.text_area("Enter text to encrypt", height=200, 
                              placeholder="Enter your sensitive information here...")
            col1, col2 = st.columns(2)
            with col1:
                passkey = st.text_input("Enter passkey", type="password",
                                      placeholder="Create a strong passkey")
            with col2:
                confirm_passkey = st.text_input("Confirm passkey", type="password",
                                              placeholder="Confirm your passkey")
            
            if st.form_submit_button("Encrypt and Store", use_container_width=True):
                if text and passkey and confirm_passkey:
                    if passkey != confirm_passkey:
                        st.error("Passkeys do not match!")
                    else:
                        is_valid, message = security.validate_passkey(passkey)
                        if not is_valid:
                            st.error(message)
                        else:
                            try:
                                encrypted_text, hashed_passkey = security.encrypt_data(text, passkey)
                                st.session_state.encrypted_data[hashed_passkey] = encrypted_text
                                save_encrypted_data()
                                st.success("Data encrypted and stored successfully!")
                            except Exception as e:
                                st.error(f"Encryption failed: {str(e)}")
                else:
                    st.error("Please fill in all fields")

elif page == "Retrieve Data":
    st.title("🔍 Retrieve Data")
    
    client_ip = get_client_ip()
    if security.check_lockout(client_ip):
        st.warning(f"Too many failed attempts. Please try again in {int((LOCKOUT_DURATION - (time.time() - security.lockout_times[client_ip])) / 60)} minutes.")
    else:
        with st.container():
            st.markdown("""
            <div style="background-color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
                <h3>Decrypt Your Data</h3>
                <p>Enter your encrypted data and passkey to retrieve your information</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("retrieve_data_form"):
                encrypted_text = st.text_area("Enter encrypted text", height=200,
                                           placeholder="Paste your encrypted data here...")
                passkey = st.text_input("Enter passkey", type="password",
                                      placeholder="Enter your passkey")
                
                if st.form_submit_button("Decrypt", use_container_width=True):
                    if encrypted_text and passkey:
                        try:
                            decrypted_text = security.decrypt_data(encrypted_text, passkey)
                            if decrypted_text:
                                st.success("Decryption successful!")
                                st.text_area("Decrypted text", decrypted_text, height=200)
                            else:
                                st.error("Decryption failed. Please check your passkey.")
                                if security.record_failed_attempt(client_ip):
                                    st.warning("Too many failed attempts. System locked.")
                        except Exception as e:
                            st.error(f"Error during decryption: {str(e)}")
                    else:
                        st.error("Please enter both encrypted text and passkey")

elif page == "Login":
    st.title("🔐 Login")
    
    client_ip = get_client_ip()
    if security.check_lockout(client_ip):
        st.warning(f"System locked. Please try again in {int((LOCKOUT_DURATION - (time.time() - security.lockout_times[client_ip])) / 60)} minutes.")
    else:
        with st.container():
            st.markdown("""
            <div style="background-color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
                <h3>Access Your Data</h3>
                <p>Enter your passkey to unlock the system</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("login_form"):
                passkey = st.text_input("Enter passkey", type="password",
                                      placeholder="Enter your passkey")
                
                if st.form_submit_button("Login", use_container_width=True):
                    if passkey:
                        try:
                            hashed_passkey = security.hash_passkey(passkey)[0].decode()
                            if hashed_passkey in st.session_state.encrypted_data:
                                st.success("Login successful!")
                                security.failed_attempts[client_ip] = 0
                            else:
                                st.error("Invalid passkey")
                                if security.record_failed_attempt(client_ip):
                                    st.warning("Too many failed attempts. System locked.")
                        except Exception as e:
                            st.error(f"Login failed: {str(e)}")
                    else:
                        st.error("Please enter a passkey")

elif page == "Settings":
    st.title("⚙️ Settings")
    
    with st.container():
        st.markdown("""
        <div style="background-color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
            <h3>Security Configuration</h3>
            <p>Manage your security settings and encryption keys</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Security Settings")
            st.write(f"Maximum failed attempts: {MAX_FAILED_ATTEMPTS}")
            st.write(f"Lockout duration: {LOCKOUT_DURATION // 60} minutes")
        
        with col2:
            st.subheader("Passkey Requirements")
            st.write(f"Minimum length: {PASSKEY_REQUIREMENTS['min_length']} characters")
            st.write("Must contain:")
            st.write("- Uppercase letters" if PASSKEY_REQUIREMENTS['require_uppercase'] else "")
            st.write("- Lowercase letters" if PASSKEY_REQUIREMENTS['require_lowercase'] else "")
            st.write("- Numbers" if PASSKEY_REQUIREMENTS['require_numbers'] else "")
            st.write("- Special characters" if PASSKEY_REQUIREMENTS['require_special'] else "")
        
        if st.button("Rotate Encryption Key", use_container_width=True):
            try:
                security._rotate_key()
                st.success("Encryption key rotated successfully!")
            except Exception as e:
                st.error(f"Error rotating key: {str(e)}")

# Check for session timeout
check_session_timeout() 