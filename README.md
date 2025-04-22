# 🔐 Secure Data Encryption Web App

![Security](https://img.shields.io/badge/Security-High-success)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32.0-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A professional-grade secure data encryption web application built with Streamlit and Python that provides military-grade encryption for your sensitive data.

## ✨ Features

- 🔒 **Military-Grade Encryption**
  - AES-128 + HMAC encryption
  - PBKDF2 key derivation
  - Salted passkey hashing
  - Automatic key rotation

- 🛡️ **Advanced Security**
  - IP-based lockout system
  - Session timeout
  - Passkey complexity requirements
  - Failed attempt tracking
  - Detailed security logging

- 💾 **Data Management**
  - Secure data storage
  - Easy data retrieval
  - Persistent storage
  - Automatic backups

- 🎨 **Professional UI**
  - Modern, clean interface
  - Responsive design
  - Intuitive navigation
  - Real-time feedback

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Moh-Tayyab/secure-encryption-app.git
cd secure-encryption-app
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run index.py
```

## 📖 Usage Guide

### Storing Data
1. Navigate to "Store Data" in the sidebar
2. Enter your sensitive information
3. Create a strong passkey
4. Click "Encrypt and Store"

### Retrieving Data
1. Navigate to "Retrieve Data" in the sidebar
2. Enter your encrypted data
3. Provide your passkey
4. Click "Decrypt"

### Security Settings
1. Navigate to "Settings" in the sidebar
2. View current security configuration
3. Rotate encryption keys if needed

## 🔧 Configuration

The application can be configured through `config.py`:

- Security settings
- UI theme
- Encryption parameters
- Session timeout
- Passkey requirements

## 🛡️ Security Features

- **Two-Factor Security**
  - Knowledge (passkey)
  - Possession (encryption key)

- **Brute-Force Protection**
  - IP-based lockout
  - Maximum attempt limits
  - Lockout duration

- **Data Protection**
  - End-to-end encryption
  - Secure key storage
  - Regular key rotation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## 📚 Documentation

For detailed documentation, please visit our [Wiki](https://github.com/yourusername/secure-encryption-app/wiki).

## File Structure

- `index.py`: Main application file
- `encryption_key.key`: Stores the encryption key
- `encrypted_data.json`: Stores encrypted data and hashed passkeys
- `requirements.txt`: Project dependencies

## Security Notes

- Keep your passkey secure and never share it
- The encryption key is stored locally
- Failed attempts are tracked and limited
- Data is encrypted before storage
