import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from src.db.models import db, User, File, SharedKey 
from src.auth.user_manager import UserManager
from src.crypto import aes_handler, rsa_handler
from src.utils.file_storage import save_encrypted_file, load_encrypted_file

main = Blueprint('main', __name__)

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')

# --- AUTH ROUTES ---

@main.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    try:
        user = UserManager.register_new_user(username, email, password)
        
        if user:
            flash('Registration successful! Please log in. Your RSA key pair has been generated.', 'success')
        else:
            flash('Username or email already exists.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred during registration: {e}', 'danger')
        
    return redirect(url_for('main.index'))

@main.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
        return redirect(url_for('main.dashboard'))
    else:
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('main.index'))

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

# --- FILE ROUTES ---

@main.route('/dashboard')
@login_required
def dashboard():
    # Files owned by the user
    owned_files = File.query.filter_by(owner_id=current_user.id).all()
    
    # Files shared with the user (where a SharedKey exists for the user)
    shared_keys = SharedKey.query.filter_by(user_id=current_user.id).all()
    shared_files = [sk.file for sk in shared_keys]
    
    # Combine and remove duplicates if any file is both owned and shared
    files = list(set(owned_files + shared_files))
    
    return render_template('dashboard.html', files=files)


@main.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('main.dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('main.dashboard'))

    # 1. File Handling & Key Generation
    original_filename = secure_filename(file.filename)
    file_data = file.read()
    aes_key = aes_handler.generate_aes_key()
    
    # 2. Encryption
    # The file data is encrypted using AES-256 GCM
    encrypted_data = aes_handler.encrypt_file_data(file_data, aes_key)
    
    # 3. Secure Key Wrapping for the OWNER 
    # The AES key is wrapped (encrypted) with the OWNER's Public RSA Key
    wrapped_aes_key = rsa_handler.wrap_aes_key(aes_key, current_user.rsa_public_key)
    
    # 4. Storage & DB Entry
    storage_path_name = f"{current_user.id}_{os.urandom(8).hex()}_{original_filename}.enc"
    storage_path = save_encrypted_file(encrypted_data, storage_path_name)
    
    try:
        new_file = File(
            filename=original_filename, 
            mimetype=file.mimetype, 
            storage_path=storage_path, 
            owner_id=current_user.id
        )
        db.session.add(new_file)
        db.session.flush() 
        
        # Add the owner's wrapped key entry
        owner_key = SharedKey(
            user_id=current_user.id, 
            file_id=new_file.id, 
            wrapped_aes_key=wrapped_aes_key
        )
        db.session.add(owner_key)
        db.session.commit()
        
        flash(f'File "{original_filename}" uploaded and securely encrypted!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Database error during file upload.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Encryption/Storage error: {e}', 'danger')

    return redirect(url_for('main.dashboard'))


@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    # Check if the current user has a SharedKey for this file
    shared_key_entry = SharedKey.query.filter_by(
        user_id=current_user.id, 
        file_id=file_id
    ).first()
    
    if not shared_key_entry:
        flash('Access denied. You do not have the required key for this file.', 'danger')
        return redirect(url_for('main.dashboard'))
        
    file_record = shared_key_entry.file
    
    try:
        # 1. Key Unwrap (Decrypt the AES Key using the user's PRIVATE RSA key)
        aes_key = rsa_handler.unwrap_aes_key(
            shared_key_entry.wrapped_aes_key, 
            current_user.rsa_private_key
        )
        
        # 2. Load Encrypted File
        encrypted_data = load_encrypted_file(file_record.storage_path)
        
        # 3. File Decryption
        decrypted_data = aes_handler.decrypt_file_data(encrypted_data, aes_key)

        # 4. Serve the Decrypted File (in-memory serving)
        from io import BytesIO
        return send_file(
            BytesIO(decrypted_data), 
            as_attachment=True, 
            download_name=file_record.filename, 
            mimetype=file_record.mimetype
        )

    except FileNotFoundError:
        flash('File not found on storage server.', 'danger')
    except Exception as e:
        # This catches cryptography.exceptions.InvalidTag on decryption failure
        flash(f'Decryption failed (File is corrupted or key is invalid): {e}', 'danger')

    return redirect(url_for('main.dashboard'))


@main.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner_id != current_user.id:
        flash('You can only share files you own.', 'danger')
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        recipient_username = request.form.get('recipient_username')
        recipient = User.query.filter_by(username=recipient_username).first()
        
        if not recipient:
            flash('Recipient user not found.', 'danger')
            return render_template('share.html', file=file_record)
            
        # 1. Retrieve the Owner's wrapped key to get the original AES key
        owner_key_entry = SharedKey.query.filter_by(
            user_id=current_user.id, 
            file_id=file_id
        ).first()
        
        try:
            # Unwrap the key using the owner's PRIVATE key to get the plaintext AES key
            aes_key = rsa_handler.unwrap_aes_key(
                owner_key_entry.wrapped_aes_key, 
                current_user.rsa_private_key
            )
            
            # 2. Re-Wrap the AES key for the Recipient
            # The plaintext AES key is encrypted using the recipient's PUBLIC RSA key
            wrapped_key_for_recipient = rsa_handler.wrap_aes_key(
                aes_key, 
                recipient.rsa_public_key
            )
            
            # 3. Save the new SharedKey entry
            new_share = SharedKey(
                user_id=recipient.id,
                file_id=file_id,
                wrapped_aes_key=wrapped_key_for_recipient
            )
            db.session.add(new_share)
            db.session.commit()
            
            flash(f'File "{file_record.filename}" successfully shared with {recipient.username}!', 'success')
            return redirect(url_for('main.dashboard'))
            
        except IntegrityError:
            flash(f'File is already shared with {recipient.username}.', 'warning')
            db.session.rollback()
        except Exception as e:
            flash(f'Sharing failed: {e}', 'danger')
            db.session.rollback()

    # GET request
    return render_template('share.html', file=file_record)


@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Security check: Only the owner can delete the file
    if file_record.owner_id != current_user.id:
        flash('Access denied. You can only delete files you own.', 'danger')
        return redirect(url_for('main.dashboard'))
        
    try:
        # 1. Delete the physical file from disk
        os.remove(file_record.storage_path)
        
        # 2. Delete the database record
        # Due to 'cascade="all, delete-orphan"' in models.py, deleting the File 
        # record automatically deletes all associated SharedKey records.
        db.session.delete(file_record)
        db.session.commit()
        
        flash(f'File "{file_record.filename}" and all access keys have been securely deleted.', 'success')
        
    except FileNotFoundError:
        # If the file was already deleted from disk but still in DB
        db.session.delete(file_record)
        db.session.commit()
        flash(f'File metadata deleted, but physical file was already missing.', 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting file: {e}', 'danger')

    return redirect(url_for('main.dashboard'))
