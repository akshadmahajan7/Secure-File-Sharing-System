from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt

# Initialize the extensions outside the app context
db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # RSA Keys stored as PEM strings
    rsa_public_key = db.Column(db.Text, nullable=False)
    rsa_private_key = db.Column(db.Text, nullable=False) 
    
    # Relationships
    owned_files = db.relationship('File', backref='owner', lazy=True)
    shared_keys = db.relationship('SharedKey', backref='user', lazy=True)

    def set_password(self, password):
        """Hashes the password using Bcrypt."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks the provided password against the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    mimetype = db.Column(db.String(100), nullable=False)
    storage_path = db.Column(db.String(255), unique=True, nullable=False)
    
    # The file owner
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationship to shared keys for this file
    # CRITICAL: Ensures SharedKey records are deleted when the File is deleted.
    keys = db.relationship('SharedKey', backref='file', cascade="all, delete-orphan", lazy=True)

class SharedKey(db.Model):
    __tablename__ = 'shared_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    
    # The AES key, encrypted using the recipient's RSA Public Key
    wrapped_aes_key = db.Column(db.LargeBinary, nullable=False)
    
    # Constraint to ensure one wrapped key per user/file pair
    __table_args__ = (db.UniqueConstraint('user_id', 'file_id', name='_user_file_uc'),)
