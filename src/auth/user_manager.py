from src.db.models import db, User
from src.crypto.rsa_handler import generate_rsa_key_pair

class UserManager:
    """
    Manages user-related business logic, such as registration and 
    key setup, separate from the database model definition.
    """
    
    @staticmethod
    def register_new_user(username: str, email: str, password: str) -> User | None:
        """
        Creates a new user, generates their RSA key pair, and saves them to the database.
        Returns the new User object or None if the user already exists.
        """
        if User.query.filter_by(username=username).first() or \
           User.query.filter_by(email=email).first():
            return None # User already exists

        # Generate cryptographic keys
        public_key, private_key = generate_rsa_key_pair()
        
        # Create and configure the user object
        new_user = User(
            username=username, 
            email=email,
            rsa_public_key=public_key,
            rsa_private_key=private_key
        )
        new_user.set_password(password) # Hash the password
        
        db.session.add(new_user)
        db.session.commit()
        return new_user
