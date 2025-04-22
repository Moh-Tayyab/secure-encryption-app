import os
import json
import time
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import re
from datetime import datetime, timedelta
from config import *

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecurityManager:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self.failed_attempts = {}
        self.lockout_times = {}

    def _load_or_create_key(self):
        """Load existing key or create a new one with rotation check"""
        if ENCRYPTION_KEY_FILE.exists():
            with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
                key_data = json.load(key_file)
                key = base64.b64decode(key_data['key'])
                created_at = datetime.fromisoformat(key_data['created_at'])
                
                # Rotate key if older than specified days
                if (datetime.now() - created_at).days > KEY_ROTATION_DAYS:
                    return self._rotate_key()
                return key
        return self._rotate_key()

    def _rotate_key(self):
        """Generate a new encryption key"""
        key = Fernet.generate_key()
        key_data = {
            'key': base64.b64encode(key).decode(),
            'created_at': datetime.now().isoformat()
        }
        with open(ENCRYPTION_KEY_FILE, 'w') as key_file:
            json.dump(key_data, key_file)
        return key

    def validate_passkey(self, passkey):
        """Validate passkey against security requirements"""
        if len(passkey) < PASSKEY_REQUIREMENTS['min_length']:
            return False, "Passkey must be at least 8 characters long"
        
        if PASSKEY_REQUIREMENTS['require_uppercase'] and not re.search(r'[A-Z]', passkey):
            return False, "Passkey must contain at least one uppercase letter"
        
        if PASSKEY_REQUIREMENTS['require_lowercase'] and not re.search(r'[a-z]', passkey):
            return False, "Passkey must contain at least one lowercase letter"
        
        if PASSKEY_REQUIREMENTS['require_numbers'] and not re.search(r'[0-9]', passkey):
            return False, "Passkey must contain at least one number"
        
        if PASSKEY_REQUIREMENTS['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', passkey):
            return False, "Passkey must contain at least one special character"
        
        return True, "Passkey is valid"

    def hash_passkey(self, passkey, salt=None):
        """Hash the passkey with salt using PBKDF2"""
        if salt is None:
            salt = os.urandom(SALT_LENGTH)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS
        )
        key = base64.b64encode(kdf.derive(passkey.encode()))
        return key, salt

    def encrypt_data(self, text, passkey):
        """Encrypt data using Fernet with additional security"""
        try:
            # Generate salt and hash passkey
            key, salt = self.hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_text = self.cipher.encrypt(text.encode())
            
            # Combine salt and encrypted text
            combined = salt + encrypted_text
            
            # Log the encryption
            logging.info(f"Data encrypted successfully")
            
            return base64.b64encode(combined).decode(), key.decode()
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt_data(self, encrypted_data, passkey):
        """Decrypt data with additional security checks"""
        try:
            # Decode the combined data
            combined = base64.b64decode(encrypted_data.encode())
            
            # Extract salt and encrypted text
            salt = combined[:SALT_LENGTH]
            encrypted_text = combined[SALT_LENGTH:]
            
            # Hash the passkey with the original salt
            key, _ = self.hash_passkey(passkey, salt)
            
            # Decrypt the data
            decrypted_text = self.cipher.decrypt(encrypted_text)
            
            logging.info("Data decrypted successfully")
            return decrypted_text.decode()
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            return None

    def check_lockout(self, ip_address):
        """Check if an IP address is locked out"""
        if ip_address in self.lockout_times:
            if time.time() - self.lockout_times[ip_address] < LOCKOUT_DURATION:
                return True
            else:
                del self.lockout_times[ip_address]
                del self.failed_attempts[ip_address]
        return False

    def record_failed_attempt(self, ip_address):
        """Record a failed attempt and handle lockout"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = 0
        self.failed_attempts[ip_address] += 1
        
        if self.failed_attempts[ip_address] >= MAX_FAILED_ATTEMPTS:
            self.lockout_times[ip_address] = time.time()
            logging.warning(f"IP {ip_address} locked out due to too many failed attempts")
            return True
        return False 