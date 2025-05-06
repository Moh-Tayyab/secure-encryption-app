import streamlit as st
import json
import os
import time
import base64
import hashlib
from datetime import datetime
from security import SecurityManager
from config import *
import logging

# Initialize security manager
security = SecurityManager()

# Set page config
st.set_page_config(
    page_title="Secure Data Storage",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/yourusername/secure-encryption-app',
        'Report a bug': 'https://github.com/yourusername/secure-encryption-app/issues',
        'About': 'A secure data encryption application'
    }
)

# Load custom CSS
with open(STYLE_FILE, 'r', encoding='utf-8') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None

# ===================== DATA MANAGEMENT FUNCTIONS =====================

def get_client_ip():
    """Get client IP address"""
    return st.query_params.get('ip', '127.0.0.1')

def generate_encryption_key():
    """Generate a new encryption key"""
    return base64.b64encode(os.urandom(32)).decode()

def save_encryption_key(key):
    """Save encryption key to session state"""
    st.session_state.encryption_key = key

def save_encrypted_data(hashed_passkey, encrypted_text):
    """Save encrypted data to JSON file"""
    try:
        # Load existing data
        data = {}
        if os.path.exists(ENCRYPTED_DATA_FILE):
            with open(ENCRYPTED_DATA_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
        
        # Add new data
        data[hashed_passkey] = {
            'encrypted_text': encrypted_text,
            'encryption_key': st.session_state.encryption_key
        }
        
        # Save updated data
        with open(ENCRYPTED_DATA_FILE, 'w') as f:
            json.dump(data, f)
        return True
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")
        return False

def load_encrypted_data():
    """Load encrypted data from JSON file"""
    if os.path.exists(ENCRYPTED_DATA_FILE):
        try:
            with open(ENCRYPTED_DATA_FILE, 'r') as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")
    return {}

# ===================== MAIN APP =====================

def show_main_app():
    # Sidebar navigation
    with st.sidebar:
        st.title("🔐 Secure Data Storage")
        st.markdown("---")
        page = st.radio("Menu", ["Home", "Save Data", "Get Data"])
        st.markdown("---")
        st.markdown("""
        <div class="info-box">
            <h3 style="color: white; margin-bottom: 1rem;">How to Use</h3>
            <ol style="color: white; margin: 0; padding-left: 1.5rem;">
                <li>Generate an encryption key</li>
                <li>Enter your data and create a password</li>
                <li>Save your encryption key and password</li>
                <li>Use them to retrieve your data later</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

    if page == "Home":
        st.title("🏠 Welcome to Secure Data Storage")
        
        # Welcome message
        st.markdown("""
        <div class="info-box">
            <h2 style="color: white; text-align: center; margin-bottom: 1rem;">Keep Your Data Safe and Secure</h2>
            <p style="color: white; text-align: center; font-size: 1.2rem; opacity: 0.9;">Your trusted solution for storing sensitive information</p>
        </div>
        """, unsafe_allow_html=True)
    
        # Features grid
        st.markdown("""
        <div class="form-section">
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem;">
                <div class="step-indicator">
                    <div class="step-number">1</div>
                    <div>
                        <h3 style="margin: 0;">🔐 Secure Storage</h3>
                        <p style="margin: 0.5rem 0 0 0;">Safeguard your sensitive data with top-tier encryption</p>
                    </div>
                </div>
                <div class="step-indicator">
                    <div class="step-number">2</div>
                    <div>
                        <h3 style="margin: 0;">💾 Easy Storage</h3>
                        <p style="margin: 0.5rem 0 0 0;">Store confidential information in a secure environment</p>
                    </div>
                </div>
                <div class="step-indicator">
                    <div class="step-number">3</div>
                    <div>
                        <h3 style="margin: 0;">🔓 Quick Access</h3>
                        <p style="margin: 0.5rem 0 0 0;">Effortlessly retrieve your data when needed</p>
                    </div>
                </div>
                <div class="step-indicator">
                    <div class="step-number">4</div>
                    <div>
                        <h3 style="margin: 0;">🛡️ Protected</h3>
                        <p style="margin: 0.5rem 0 0 0;">Designed for privacy, reliability, and peace of mind</p>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    elif page == "Save Data":
        st.title("💾 Save Your Data")
        
        with st.container():
            # Step 1: Generate Key
            st.markdown("""
            <div class="form-section">
                <div class="step-indicator">
                    <div class="step-number">1</div>
                    <div>
                        <h3 style="margin: 0;">Generate Encryption Key</h3>
                        <p style="margin: 0.5rem 0 0 0;">Generate a new encryption key to secure your data</p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔑 Generate New Key", use_container_width=True):
                    new_key = generate_encryption_key()
                    save_encryption_key(new_key)
                    st.experimental_rerun()
            
            with col2:
                if st.session_state.encryption_key:
                    st.markdown("""
                    <div class="info-box">
                        <p style="margin-bottom: 0.5rem;"><strong>Current Key:</strong></p>
                        <code style="word-break: break-all;">{key}</code>
                        <p style="margin-top: 0.5rem; color: white;">⚠️ Save this key! You'll need it to retrieve your data.</p>
                    </div>
                    """.format(key=st.session_state.encryption_key), unsafe_allow_html=True)
            
            # Step 2: Enter Data
            st.markdown("""
            <div class="form-section">
                <div class="step-indicator">
                    <div class="step-number">2</div>
                    <div>
                        <h3 style="margin: 0;">Enter Your Information</h3>
                        <p style="margin: 0.5rem 0 0 0;">Type or paste the information you want to keep safe</p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("store_data_form"):
                text = st.text_area("Your Information", height=200, 
                                  placeholder="Type or paste your information here...",
                                  help="This will be encrypted and stored safely")
                
                # Step 3: Create Password
                st.markdown("""
                <div class="form-section">
                    <div class="step-indicator">
                        <div class="step-number">3</div>
                        <div>
                            <h3 style="margin: 0;">Create a Password</h3>
                            <p style="margin: 0.5rem 0 0 0;">Create a password to protect your information</p>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                with col1:
                    passkey = st.text_input("Create Password", type="password",
                                          placeholder="Enter your password",
                                          help="Create a strong password")
                with col2:
                    confirm_passkey = st.text_input("Confirm Password", type="password",
                                                  placeholder="Enter password again",
                                                  help="Type the same password again")
                
                if st.form_submit_button("🔒 Save Securely", use_container_width=True):
                    if text and passkey and confirm_passkey and st.session_state.encryption_key:
                        if passkey != confirm_passkey:
                            st.error("❌ Passwords don't match! Please make sure they're the same.")
                        else:
                            is_valid, message = security.validate_passkey(passkey)
                            if not is_valid:
                                st.error(f"❌ {message}")
                            else:
                                try:
                                    with st.spinner("Saving your information securely..."):
                                        encrypted_text, hashed_passkey = security.encrypt_data(text, passkey)
                                        if save_encrypted_data(hashed_passkey, encrypted_text):
                                            st.success("✅ Your information has been saved securely!")
                                            st.markdown("""
                                            <div class="info-box">
                                                <h3 style="color: white; margin-bottom: 1rem;">Important Information</h3>
                                                <ol style="color: white; margin: 0; padding-left: 1.5rem;">
                                                    <li>Remember your password</li>
                                                    <li>Save your encryption key: {key}</li>
                                                    <li>You'll need both to get your information back</li>
                                                </ol>
                                            </div>
                                            """.format(key=st.session_state.encryption_key), unsafe_allow_html=True)
                                except Exception as e:
                                    st.error(f"❌ Error saving: {str(e)}")
                    else:
                        st.error("❌ Please fill in all fields and generate an encryption key")

    elif page == "Get Data":
        st.title("🔍 Get Your Data")
        
        client_ip = get_client_ip()
        if security.check_lockout(client_ip):
            st.markdown("""
            <div class="warning-box">
                <h3 style="color: white; margin-bottom: 0.5rem;">⚠️ Too Many Attempts</h3>
                <p style="color: white; margin: 0;">Please wait {minutes} minutes before trying again.</p>
            </div>
            """.format(minutes=int((LOCKOUT_DURATION - (time.time() - security.lockout_times[client_ip])) / 60)), unsafe_allow_html=True)
        else:
            with st.container():
                st.markdown("""
                <div class="get-data-section">
                    <div class="get-data-instructions">
                        <h3>How to Get Your Data</h3>
                        <ol>
                            <li>Enter your encryption key from when you saved your data</li>
                            <li>Enter the password you used when saving your data</li>
                            <li>Your information will be retrieved automatically</li>
                        </ol>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                with st.form("retrieve_data_form"):
                    st.markdown("""
                    <div class="get-data-form">
                        <h3>Enter Your Encryption Key</h3>
                        <p>Paste the encryption key you got when saving your data</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    encryption_key = st.text_area("Your Encryption Key", 
                                                height=100,
                                                placeholder="Paste your encryption key here...",
                                                help="This is the key you got when saving your data",
                                                key="encryption_key_input")
                    
                    st.markdown("""
                    <div class="get-data-form">
                        <h3>Enter Your Password</h3>
                        <p>Enter the password you used when saving your data</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    passkey = st.text_input("Your Password", type="password",
                                          placeholder="Enter your password",
                                          help="Enter the password you used to save your data",
                                          key="password_input")
                    
                    if st.form_submit_button("🔓 Get My Information", use_container_width=True):
                        if passkey and encryption_key:
                            try:
                                with st.spinner("Getting your information..."):
                                    # Load all encrypted data
                                    encrypted_data = load_encrypted_data()
                                    
                                    # Try to decrypt with the provided password
                                    decrypted_text = None
                                    for hashed_key, data in encrypted_data.items():
                                        try:
                                            # Check if this is the correct data entry
                                            if isinstance(data, dict) and data.get('encryption_key') == encryption_key:
                                                # Try to decrypt the data
                                                decrypted = security.decrypt_data(data['encrypted_text'], passkey)
                                                if decrypted:
                                                    decrypted_text = decrypted
                                                    break
                                        except Exception as e:
                                            logging.error(f"Error decrypting data: {str(e)}")
                                            continue
                                    
                                    if decrypted_text:
                                        st.success("✅ Success! Here's your information:")
                                        st.markdown("""
                                        <div class="get-data-result">
                                            <pre>{decrypted_text}</pre>
                                        </div>
                                        """.format(decrypted_text=decrypted_text), unsafe_allow_html=True)
                                    else:
                                        st.error("❌ Wrong password or encryption key. Please try again.")
                                        if security.record_failed_attempt(client_ip):
                                            st.markdown("""
                                            <div class="warning-box">
                                                <h3 style="color: white; margin-bottom: 0.5rem;">⚠️ Too Many Attempts</h3>
                                                <p style="color: white; margin: 0;">Please wait a few minutes before trying again.</p>
                                            </div>
                                            """, unsafe_allow_html=True)
                            except Exception as e:
                                st.error(f"❌ Error: {str(e)}")
                                logging.error(f"Error retrieving data: {str(e)}")
                        else:
                            st.error("❌ Please enter both your encryption key and password")

# Main app logic
show_main_app() 