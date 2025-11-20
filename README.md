# 🔒 Secure File Sharing System

---

## 🌟 Project Overview

This project delivers a **cryptographically secure platform** for file sharing, focusing on maximizing **confidentiality** and **access control**. The system ensures that files are encrypted immediately upon upload using **AES-256**, and the symmetric keys required for decryption are securely managed and distributed using **RSA asymmetric encryption** (a process known as key wrapping).

This architecture guarantees that the server only stores encrypted data and encrypted keys, ensuring a **zero-trust environment**. Only the intended recipient, possessing the correct private RSA key, can successfully access the file.

---

## ✨ Features and Technology Stack
| **Component** | **Technology** | **Description** |
| --- | --- | --- |
| **Primary Language** | Python 3.x | Core backend development language. |
| **Web Framework** | Flask | Lightweight framework for routing and API creation. |
| **Database** | PostgreSQL ($\text{SQLAlchemy}$) | Stores user credentials (hashed), file metadata, and RSA-encrypted AES keys. |
| **Authentication** | Flask-Bcrypt | Secure hashing of user passwords using the $\text{Bcrypt}$ algorithm. |
| **File Encryption** | Python `cryptography` | Handles high-level $\text{AES-256}$ (GCM mode) for file data encryption.|
| **Key Exchange** | Python `cryptography` | Uses $\text{RSA}$ (2048-bit) for secure key wrapping/unwrapping. |
| **Secure Transfer** | $\text{HTTPS/SSL}$ | Ensures all data in transit is protected by $\text{**TLS**}$. |

---

## 🛡️ The Multi-Layered Security Strategy
Security is implemented at every layer, adhering to the principle of "encrypt everything."

Layer 1: User & Key Management
* User Registration: Passwords are cryptographically hashed using $\text{Bcrypt}$ before storage.
* RSA Key Generation: Upon registration, each user generates a unique RSA key pair ($\text{Public Key}$ and $\text{Private Key}$). The Private Key is essential for the user to decrypt keys shared with them.

Layer 2: File Confidentiality
* Pre-Storage Encryption: The file data is encrypted using $\text{AES-256 in GCM}$ (Galois/Counter Mode) to ensure both confidentiality and integrity (via the GCM tag).
* Key Wrapping: The symmetric AES key used to encrypt the file is immediately encrypted ("wrapped") using the recipient's Public RSA Key before being stored in the database.

Simplified Sharing Flow:
1. Owner Decrypts AES Key: Owner uses their Private RSA Key to unwrap the AES key for the file.
2. Owner Re-Wraps Key: Owner uses the intended Recipient's Public RSA Key to wrap the same AES key again.
3. Key Transfer: The new, recipient-specific wrapped key is saved to the database. Only the Recipient can now unwrap this key using their corresponding Private RSA Key.

---

## 📁 Project Structure
```
Secure-File-Sharing-System/
├── src/
│   ├── auth/
│   │   └── user_manager.py      # User registration logic & RSA key setup
│   ├── crypto/
│   │   ├── aes_handler.py       # AES encryption/decryption functions
│   │   └── rsa_handler.py       # RSA key generation and key wrapping/unwrapping
│   ├── db/
│   │   └── models.py            # SQLAlchemy database models (User, File, SharedKey)
│   └── utils/
│       └── file_storage.py      # Abstract layer for saving/retrieving encrypted files
├── app/
│   ├── templates/
│   │   └── ...                  # HTML Templates (base.html, index.html, dashboard.html, share.html)
│   └── routes.py                # Flask routes and view logic (Auth, Upload, Download, Share)
├── config.py                    # Application configuration
├── run.py                       # Application entry point
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation.
```

---

🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### **Prerequisites**
* $\text{Python 3.8+}$
* $\text{pip}$ (Python package installer)
* A running PostgreSQL Database Server.

### **Installation and Setup**

1. Clone the repository:
```
git clone [https://github.com/your-username/Secure-File-Sharing-System.git](https://github.com/your-username/Secure-File-Sharing-System.git)
cd Secure-File-Sharing-System
```

2. Create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate 
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Configuration:
  * Set up your PostgreSQL/MySql database (create a DB, user, and password).
  * Create a `.env` file based on `.env.example` and fill in your `SECRET_KEY` and `DATABASE_URL`.

### **Running the Application**
1. Start the $\text{Flask}$ web server:
The database tables are automatically created on initial run via `db.create_all()` in `run.py`.
```
python run.py
```

2. Access the Application:
Navigate to `http://127.0.0.1:5000/`.

---

## 🤝 Contributing
We highly value contributions! Please focus on improving security features, testing, and robustness.

**Contribution Points**
* **Key Security**: Implement private key protection by encrypting the rsa_private_key column in the database using the user's password (or a derivative) as the key.
* **Access Revocation**: Add a feature to delete a SharedKey entry, effectively revoking a user's access to a file.
* **Integrity Checks**: Add logging and monitoring to detect and report InvalidTag exceptions during decryption, indicating possible file tampering.

---

## 📝 License
This project is open-source and available under the [MIT License](
LICENSE).
