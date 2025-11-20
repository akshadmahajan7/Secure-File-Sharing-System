import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from src.db.models import db, bcrypt, User 
from app.routes import main

# Define the absolute path to the 'templates' directory
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'templates')

def create_app():
    # FIX: Explicitly tell Flask where to find the template folder.
    # We use template_folder=template_dir to point Flask to 'Secure File Sharing System/app/templates'
    app = Flask(__name__, template_folder=template_dir)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'main.index'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        """Used by Flask-Login to reload the user object from the user ID stored in the session."""
        return User.query.get(int(user_id))

    # Create the upload directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Register blueprints
    app.register_blueprint(main)

    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
