import os
from dotenv import load_dotenv

# Load environment variables from a .env file (if present)
load_dotenv()

class Config:
    """
    Base configuration class for the Flask application. 
    It loads secrets and settings from environment variables.
    """
    
    # ------------------
    # FLASK CORE CONFIG
    # ------------------
    
    # Secret Key is crucial for session security, flashing messages, and CSRF protection.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-secret-key-for-secure-app-v3')
    
    # ------------------
    # DATABASE CONFIG (MySQL)
    # ------------------
    
    # Connection string for SQLAlchemy. Using mysql+pymysql for the MySQL driver.
    # Format: mysql+pymysql://user:password@host:port/database_name
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        'mysql+pymysql://user:password@localhost:3306/secure_fileshare_db' # Default MySQL example
    )
    
    # Disable modification tracking as it consumes extra memory
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ------------------
    # FILE STORAGE CONFIG
    # ------------------

    # Directory where encrypted files are stored on the server's file system.
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'upload_storage')
    
    # Maximum file size limit (16MB)
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
