from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, send_file, session, g
import os
import cv2
import numpy as np
import sqlite3
import hashlib
import json
import datetime
import re
import secrets
import string
from werkzeug.utils import secure_filename
from PIL import Image
import io
import bcrypt
from functools import wraps
from datetime import timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
#from qiskit import QuantumCircuit, transpile, Aer, assemble
#from qiskit.visualization import plot_histogram

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Set session lifetime to 30 minutes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_records.db'

def validate_password_strength(password):
    """
    Validate password strength according to common security guidelines.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for at least one digit
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    # Check for at least one special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    
    # Check for common weak patterns
    common_patterns = [
        'password', '123456', 'qwerty', 'admin', 'user', 'test',
        'abc123', 'password123', 'admin123', 'user123'
    ]
    
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            return False, "Password contains common weak patterns"
    
    # Check for repeated characters (more than 3 consecutive)
    if re.search(r'(.)\1{3,}', password):
        return False, "Password contains too many repeated characters"
    
    # Check for sequential characters
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789|890)', password_lower):
        return False, "Password contains sequential characters"
    
    return True, "Password is strong"

def check_password_history(user_id, new_password):
    """
    Check if the new password is not in the user's recent password history.
    For now, we'll implement a simple check against the current password.
    In a production system, you'd want to store password history.
    """
    db = get_db()
    c = db.cursor()
    
    # Get current password
    c.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    current_hashed = c.fetchone()
    
    if current_hashed and bcrypt.checkpw(new_password.encode('utf-8'), current_hashed[0]):
        return False, "New password cannot be the same as your current password"
    
    return True, "Password is different from current password"

def generate_secure_password():
    """
    Generate a secure random password for users who want to reset their password.
    """
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]
    
    # Fill the rest with random characters
    all_chars = lowercase + uppercase + digits + special_chars
    for _ in range(8):  # Total length will be 12 characters
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            session.clear()
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('user_type') != 'admin':
            flash('You need to be logged in as an administrator to access this page.', 'error')
            session.clear()
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Add after app initialization
@app.template_filter('from_json')
def from_json(value):
    try:
        return json.loads(value)
    except:
        return {}

DATABASE = 'medical_records.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

app.config['MODEL_FOLDER'] = 'models'
admin_username = 'admin'
admin_password = 'password'
# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
# Function to encrypt an image
def encrypt_image(image_path, key):
    # Open the image file
    with open(image_path, 'rb') as f:
        image_bytes = f.read()

    # Encrypt the image bytes
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.iv + cipher.encrypt(pad(image_bytes, AES.block_size))
    

    return encrypted_data

# Function to decrypt an image
def decrypt_image(encrypted_data, key):
    # Extract the initialization vector from the encrypted data
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]

    # Decrypt the image bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    return decrypted_data

def hash_block(block):
    return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

def create_genesis_block():
    return {
        'index': 0,
        'timestamp': str(datetime.datetime.now()),
        'previous_hash': '0',
        'transactions': [],
        'nonce': 0
    }

def proof_of_work(block):
    while True:
        block_hash = hash_block(block)
        if block_hash[:4] == '0000':
            return block_hash
        else:
            block['nonce'] += 1

def create_block(prev_block_hash, transactions):
    block = {
        'index': len(get_blockchain()),
        'timestamp': str(datetime.datetime.now()),
        'previous_hash': prev_block_hash,
        'transactions': transactions,
        'nonce': 0
    }
    proof_of_work(block)
    return block

def add_block(block):
    db = get_db()
    c = db.cursor()
    c.execute('''INSERT INTO blockchain (timestamp, previous_hash, transactions, nonce)
                 VALUES (?, ?, ?, ?)''', (block['timestamp'], block['previous_hash'], json.dumps(block['transactions']), block['nonce']))
    db.commit()

def get_blockchain():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT * FROM blockchain ORDER BY block_index ASC''')
    return c.fetchall()

def cleanup_missing_files():
    db = get_db()
    c = db.cursor()
    
    # Get all file records
    c.execute('SELECT id, file_path FROM files')
    files = c.fetchall()
    
    for file_id, file_path in files:
        if not os.path.exists(file_path):
            # Delete related records
            c.execute('DELETE FROM shared_files WHERE file_id = ?', (file_id,))
            c.execute('DELETE FROM files WHERE id = ?', (file_id,))
            
            # Create cleanup transaction
            cleanup_transaction = {
                'type': 'file_cleanup',
                'file_id': file_id,
                'timestamp': str(datetime.datetime.now()),
                'reason': 'File not found in uploads directory'
            }
            
            # Get the last block's hash
            c.execute('SELECT previous_hash FROM blockchain ORDER BY block_index DESC LIMIT 1')
            last_block = c.fetchone()
            prev_hash = last_block[0] if last_block else '0'
            
            # Create and add new block for cleanup
            new_block = create_block(prev_hash, [cleanup_transaction])
            add_block(new_block)
    
    db.commit()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password TEXT,
                        email TEXT,
                        full_name TEXT,
                        user_type TEXT,
                        age INTEGER,
                        gender TEXT,
                        phone TEXT,
                        edit_status TEXT DEFAULT NULL,
                        pending_changes TEXT DEFAULT NULL,
                        notification_preference BOOLEAN DEFAULT TRUE,
                        profile_photo TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        filename TEXT,
                        file_path TEXT,
                        timestamp TEXT,
                        hash TEXT,
                        key TEXT,
                        original_filename TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS blockchain (
                        block_index INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        previous_hash TEXT,
                        transactions TEXT,
                        nonce INTEGER
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id INTEGER,
                        recipient_id INTEGER,
                        FOREIGN KEY (file_id) REFERENCES files(id),
                        FOREIGN KEY (recipient_id) REFERENCES users(id)
                    )''')
        # New table for face enrollments
        c.execute('''CREATE TABLE IF NOT EXISTS face_enrollments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        image_path TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
        
        # Ensure all new columns exist
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        
        # Add missing columns if they don't exist
        if 'full_name' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN full_name TEXT')
        if 'user_type' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN user_type TEXT')
        if 'age' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN age INTEGER')
        if 'gender' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN gender TEXT')
        if 'phone' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN phone TEXT')
        if 'edit_status' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN edit_status TEXT DEFAULT NULL')
        if 'pending_changes' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN pending_changes TEXT DEFAULT NULL')
        if 'notification_preference' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN notification_preference BOOLEAN DEFAULT TRUE')
        if 'profile_photo' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN profile_photo TEXT')
        
        db.commit()
        
        # Clean up any missing files
        cleanup_missing_files()

# Initialize database when the application starts
init_db()

# Function to check if a filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_user_data():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT fe.id, u.full_name, fe.image_path FROM face_enrollments fe JOIN users u ON fe.user_id = u.id")
    users = c.fetchall()
    return users

def load_model():
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.read(os.path.join(app.config['MODEL_FOLDER'], 'model.yml'))
    return recognizer


# Train the face recognition model
def train_model():
    db = get_db()
    c = db.cursor()
    # Select user_id and image_path from face_enrollments table
    c.execute('SELECT user_id, image_path FROM face_enrollments')
    enrollments = c.fetchall()
    
    faces = []
    ids = []

    for enrollment in enrollments:
        user_id = enrollment[0]
        image_path = enrollment[1]

        try:
            # Read the image in grayscale
            img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
            if img is None:
                print(f"Warning: Could not read image from {image_path}")
                continue

            # Detect faces in the image
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            detected_faces = face_cascade.detectMultiScale(img, scaleFactor=1.1, minNeighbors=5)
            
            if len(detected_faces) > 0:
                for (x, y, w, h) in detected_faces:
                    roi_gray = img[y:y+h, x:x+w]
                    roi_gray = cv2.resize(roi_gray, (100, 100)) # Resize to a consistent size
                    faces.append(roi_gray)
                    ids.append(user_id)
            else:
                print(f"Warning: No face detected in image {image_path}")

        except Exception as e:
            print(f"Error processing image {image_path}: {e}")
            continue

    if faces:
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.train(np.array(faces), np.array(ids))
        recognizer.save(os.path.join(app.config['MODEL_FOLDER'], 'model.yml'))
        return True
    else:
        print("No faces found for training.")
        return False

def recognize_face(face_img):
    recognizer = load_model()
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    users = load_user_data() # This now returns (fe.id, u.full_name, fe.image_path)

    gray = cv2.cvtColor(face_img, cv2.COLOR_BGR2GRAY)
    faces_detected = face_cascade.detectMultiScale(gray, 1.3, 5)
    
    for (x,y,w,h) in faces_detected:
        roi_gray = gray[y:y+h, x:x+w]
        roi_gray = cv2.resize(roi_gray, (100, 100))
        id_, conf = recognizer.predict(roi_gray)
        
        if conf < 100:  # Adjust threshold as needed (lower confidence is better match)
            # Find the user's full_name based on the id_ (which is user_id from face_enrollments)
            name = "Unknown"
            for user_enrollment in users:
                # user_enrollment is (fe.id, u.full_name, fe.image_path)
                if user_enrollment[0] == id_:
                    name = user_enrollment[1] # full_name
                    break
            
            cv2.putText(face_img, f'Name: {name}', (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
            cv2.rectangle(face_img, (x, y), (x+w, y+h), (255, 0, 0), 2)
            return name # Return the recognized name
        else:
            cv2.putText(face_img, 'Unknown', (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 255), 2)
            cv2.rectangle(face_img, (x, y), (x+w, y+h), (255, 0, 0), 2)
    return None # No face recognized

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('upload_file1'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        if session.get('user_type', '').lower() == 'admin':
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('user_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        c.execute('''SELECT id, username, password, user_type FROM users WHERE username = ?''', (username,))
        user = c.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session.clear()
            session['username'] = username
            session['user_type'] = user[3].lower()
            session.permanent = True
            if user[3].lower() == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('user_login.html')
    return render_template('user_login.html', message='')


# Function to fetch shared files
def get_shared_files(current_user_id):
    db = get_db()
    c = db.cursor()

    # Files uploaded by the current user
    c.execute('''
        SELECT f.id, f.original_filename, u.full_name, f.timestamp, f.hash
        FROM files AS f
        INNER JOIN users AS u ON f.user_id = u.id
        WHERE f.user_id = ?
    ''', (current_user_id,))
    uploaded_files = c.fetchall()

    # Files shared with the current user
    c.execute('''
        SELECT f.id, f.original_filename, uploader.full_name, f.timestamp, f.hash
        FROM files AS f
        INNER JOIN shared_files AS sf ON f.id = sf.file_id
        INNER JOIN users AS uploader ON f.user_id = uploader.id
        WHERE sf.recipient_id = ?
    ''', (current_user_id,))
    received_files = c.fetchall()

    # Combine and remove duplicates (if a user uploads a file and also shares it with themselves, or if the same file is shared multiple times)
    all_files = uploaded_files + received_files
    unique_files = list({file[0]: file for file in all_files}.values())

    return unique_files

# Route to display shared files
@app.route('/shared_files')
def shared_files():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    current_user_id = get_user_id(session['username'])
    if current_user_id is None:
        flash('User not found. Please log in again.', 'error')
        session.clear() # Clear session if user ID not found
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    files = get_shared_files(current_user_id)
    response = make_response(render_template('shared_medical_records.html', files=files))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# Function to fetch blockchain details
def get_blockchain_details(current_user_id):
    db = get_db()
    c = db.cursor()
    
    # Get all blocks
    c.execute('''SELECT * FROM blockchain ORDER BY block_index ASC''')
    blocks = c.fetchall()
    
    # Filter transactions based on user access
    filtered_blocks = []
    for block in blocks:
        transactions = json.loads(block[3])  # block[3] contains transactions JSON
        filtered_transactions = []
        
        for transaction in transactions:
            # Always show cleanup transactions
            if transaction['type'] in ['file_cleanup', 'bulk_cleanup']:
                filtered_transactions.append(transaction)
                continue
            # For file operations, check user access
            if transaction['type'] in ['file_upload', 'file_share']:
                file_id = transaction['file_id']
                # Check if user is the owner (even if file is deleted)
                c.execute('SELECT user_id FROM files WHERE id = ?', (file_id,))
                file_owner = c.fetchone()
                if file_owner and file_owner[0] == current_user_id:
                    filtered_transactions.append(transaction)
                    continue
                elif file_owner is None and transaction.get('user_id') == current_user_id:
                    # File is deleted, but user was the owner in the transaction
                    t = dict(transaction)
                    t['file_missing'] = True
                    filtered_transactions.append(t)
                    continue
                # Check if file is/was shared with user
                c.execute('SELECT 1 FROM shared_files WHERE file_id = ? AND recipient_id = ?', 
                         (file_id, current_user_id))
                is_shared = c.fetchone()
                if is_shared:
                    filtered_transactions.append(transaction)
                    continue
                elif file_owner is None and transaction.get('to_user_id') == current_user_id:
                    # File is deleted, but user was the recipient in the transaction
                    t = dict(transaction)
                    t['file_missing'] = True
                    filtered_transactions.append(t)
                    continue
        
        if filtered_transactions:  # Only add block if it has visible transactions
            filtered_blocks.append((
                block[0],  # block_index
                block[1],  # timestamp
                block[2],  # previous_hash
                json.dumps(filtered_transactions),  # filtered transactions
                block[4]   # nonce
            ))
    
    return filtered_blocks

# Route to display blockchain details
@app.route('/blockchain_details')
def blockchain_details():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    current_user_id = get_user_id(session['username'])
    if current_user_id is None:
        flash('User not found. Please log in again.', 'error')
        session.clear()
        return redirect(url_for('login'))
    
    blockchain = get_blockchain_details(current_user_id)
    response = make_response(render_template('blockchain_transactions.html', blockchain=blockchain))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def get_users(current_user_id=None, user_type=None, target_type=None):
    db = get_db()
    c = db.cursor()
    
    # Get current user's type
    current_user_type = None
    if current_user_id:
        c.execute('SELECT user_type FROM users WHERE id = ?', (current_user_id,))
        result = c.fetchone()
        if result: 
            current_user_type = result[0].lower() # Convert to lowercase for consistent comparison
        else:
            pass

    if current_user_type == 'patient': 
        # Patients can only see doctors
        c.execute('SELECT id, full_name FROM users WHERE LOWER(user_type) = ?', ('doctor',))
    elif current_user_type == 'doctor': 
        # Doctors can see both patients and doctors
        if target_type:
            # Convert target_type to lowercase for consistent comparison
            lower_target_type = target_type.lower()
            c.execute('SELECT id, full_name FROM users WHERE LOWER(user_type) = ? AND id != ?', (lower_target_type, current_user_id))
        else:
            c.execute('SELECT id, full_name FROM users WHERE id != ?', (current_user_id,))
    else:
        # Default for non-logged-in or other user types, or for admin view
        if target_type:
            # Convert target_type to lowercase for consistent comparison
            lower_target_type = target_type.lower()
            c.execute('SELECT id, full_name FROM users WHERE LOWER(user_type) = ?', (lower_target_type,))
        else:
            c.execute('SELECT id, full_name FROM users')
    
    users = c.fetchall()
    return users


# Function to fetch user id by username
def get_user_id(username):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if user:
        return user[0]
    return None

@app.route('/get_users/<user_type>')
def get_filtered_users(user_type):
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(jsonify([]))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    current_user_id = get_user_id(session['username'])
    users = get_users(current_user_id, target_type=user_type)
    response = make_response(jsonify(users))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/upload_file1', methods=['GET', 'POST'])
@login_required
def upload_file1():
    if 'username' not in session:
        session.clear()
        return redirect(url_for('login'))

    current_user_id = get_user_id(session['username'])
    if current_user_id is None:
        session.clear()
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    user_type = session.get('user_type')
    if not user_type:
        db = get_db()
        c = db.cursor()
        c.execute('SELECT user_type FROM users WHERE id = ?', (current_user_id,))
        result = c.fetchone()
        if result:
            user_type = result[0].lower()
            session['user_type'] = user_type
        else:
            session.clear()
            flash('User type not found. Please log in again.', 'error')
            return redirect(url_for('login'))

    if user_type == 'patient':
        print(f"[Debug] upload_file1: Current user is a patient. Fetching doctors...")
        users = get_users(current_user_id, target_type='doctor')
        print(f"[Debug] upload_file1: For patient, fetched {len(users)} doctors: {users}")
    elif user_type == 'doctor':
        users = []
        print(f"[Debug] upload_file1: Current user is a doctor. Initializing empty user list.")
    else:
        users = []
        print(f"[Debug] upload_file1: Unknown user type ({user_type}). Initializing empty user list.")

    if request.method == 'POST':
        file = request.files['file']
        if not file or file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload_file1'))

        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

        db = get_db()
        c = db.cursor()
        key = get_random_bytes(16)
        encrypted_data = encrypt_image(file_path, key)
        
        # Insert file record
        c.execute('''INSERT INTO files (user_id, filename, file_path, timestamp, hash, key, original_filename)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                     (current_user_id, encrypted_data, file_path, str(datetime.datetime.now()), file_hash, key, filename))
        file_id = c.lastrowid
        
        # Create blockchain transaction
        transaction = {
            'type': 'file_upload',
            'file_id': file_id,
            'user_id': current_user_id,
            'filename': filename,
            'timestamp': str(datetime.datetime.now()),
            'hash': file_hash
        }
        
        # Get the last block's hash
        c.execute('SELECT previous_hash FROM blockchain ORDER BY block_index DESC LIMIT 1')
        last_block = c.fetchone()
        prev_hash = last_block[0] if last_block else '0'
        
        # Create and add new block
        new_block = create_block(prev_hash, [transaction])
        add_block(new_block)
        
        recipient_id = request.form.get('recipient')
        if recipient_id:
            try:
                recipient_id = int(recipient_id)
                c.execute('''INSERT INTO shared_files (file_id, recipient_id) VALUES (?, ?)''', (file_id, recipient_id))
                # Add notification for recipient only if enabled
                if get_notification_preference(recipient_id):
                    c.execute('''INSERT INTO notifications (user_id, message, timestamp, link) VALUES (?, ?, ?, ?)''', 
                        (recipient_id, f"You received a new file: {filename}", datetime.datetime.now(), url_for('shared_files')))
                # Create sharing transaction
                share_transaction = {
                    'type': 'file_share',
                    'file_id': file_id,
                    'from_user_id': current_user_id,
                    'to_user_id': recipient_id,
                    'timestamp': str(datetime.datetime.now())
                }
                # Create and add new block for sharing
                new_share_block = create_block(hash_block(new_block), [share_transaction])
                add_block(new_share_block)
                db.commit()
                flash('Report sent successfully', 'success')
            except ValueError:
                flash('Invalid recipient ID', 'error')
            except sqlite3.IntegrityError:
                flash('File already shared with this recipient.', 'error')
            except Exception as e:
                flash(f'Error sharing file: {e}', 'error')
        return redirect(url_for('upload_file1'))

    return render_template('medical_record_upload.html', users=users, user_type=user_type)

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    # Fetch file path from the database using file_id
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT file_path FROM files WHERE id = ?''', (file_id,))
    file_path = c.fetchone()[0]

    response = make_response(send_file(file_path, as_attachment=True))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_type = request.form['user_type']
        age = request.form.get('age')
        gender = request.form.get('gender')
        phone = request.form.get('phone')
        db = get_db()
        c = db.cursor()
        c.execute('''INSERT INTO users (username, password, email, full_name, user_type, age, gender, phone) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                    (username, hashed_password, email, full_name, user_type, age, gender, phone))
        db.commit()
        return redirect(url_for('login'))
    return render_template('user_registration.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        # Look for an admin user with the given username
        c.execute("SELECT id, username, password, user_type FROM users WHERE LOWER(username) = LOWER(?) AND LOWER(user_type) LIKE '%admin%'", (username,))
        user = c.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['username'] = user[1]
            session['user_type'] = user[3].lower()
            session.permanent = True
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('admin_auth.html')
    return render_template('admin_auth.html')

@app.route('/admin_panel')
@admin_required
def admin_panel():
    db = get_db()
    c = db.cursor()
    # System stats
    c.execute('SELECT COUNT(*) FROM files')
    total_files = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    total_size = 0
    c.execute('SELECT file_path FROM files')
    files = c.fetchall()
    for file_path in files:
        if os.path.exists(file_path[0]):
            total_size += os.path.getsize(file_path[0])
    def sizeof_fmt(num, suffix='B'):
        for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"
    storage_used = sizeof_fmt(total_size)
    # Blockchain stats
    c.execute('SELECT COUNT(*) FROM blockchain')
    total_blocks = c.fetchone()[0]
    return render_template('admin_dashboard.html',
        total_files=total_files,
        total_users=total_users,
        storage_used=storage_used,
        total_blocks=total_blocks)

@app.route('/admin/users')
@admin_required
def admin_users():
    user_type = request.args.get('user_type', None)
    db = get_db()
    c = db.cursor()
    try:
        if user_type:
            lower_user_type = user_type.lower()
            c.execute('''SELECT id, username, email, full_name, user_type, age, gender, phone, edit_status, pending_changes 
                        FROM users WHERE LOWER(user_type) = ?''', (lower_user_type,))
            users = c.fetchall()
        else:
            c.execute('''SELECT id, username, email, full_name, user_type, age, gender, phone, edit_status, pending_changes 
                        FROM users''')
            users = c.fetchall()
        
        # Build a list of user dicts with highlight info
        user_list = []
        for user in users:
            user_dict = {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'full_name': user[3],
                'user_type': user[4],
                'age': user[5],
                'gender': user[6],
                'phone': user[7],
                'edit_status': user[8],
                'pending_changes': user[9],
                'changed_fields': {}
            }
            if user[9]:  # pending_changes exists
                try:
                    pending = json.loads(user[9])
                    for field, new_value in pending.items():
                        if str(new_value) != str(user_dict.get(field, '')):
                            user_dict['changed_fields'][field] = new_value
                except Exception as e:
                    user_dict['changed_fields'] = {}
            user_list.append(user_dict)
        
        return render_template('admin_user_management.html', users=user_list, user_type=user_type)
    except Exception as e:
        flash(f"Error fetching users: {e}", 'error')
        return render_template('admin_user_management.html', users=[], user_type=user_type)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    c = db.cursor()
    try:
        # Delete associated shared files first (if any)
        c.execute('DELETE FROM shared_files WHERE recipient_id = ? OR file_id IN (SELECT id FROM files WHERE user_id = ?)', (user_id, user_id))
        # Delete files uploaded by the user
        c.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        # Finally, delete the user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash(f'User with ID {user_id} and associated data deleted successfully.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error deleting user: {e}', 'error')
    response = make_response(redirect(url_for('admin_users')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/register_face', methods=['GET', 'POST'])
def register_face():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    if request.method == 'POST':
        username = session['username'] # Get username from session
        
        db = get_db()
        c = db.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_id = c.fetchone()[0] # Get user_id from users table

        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            c.execute('''INSERT INTO face_enrollments (user_id, image_path)
                              VALUES (?, ?)''', (user_id, filepath))
            db.commit()

            flash('Face registered successfully', 'success')
            response = make_response(redirect(url_for('register_face')))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response

    response = make_response(render_template('register_face.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/train_model')
def train_model_route():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    train_model()
    flash('Model trained successfully', 'success')
    response = make_response(redirect(url_for('admin_panel')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/recognize_face')
def recognize_face():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    recognizer = load_model()
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    users = load_user_data()

    camera = cv2.VideoCapture(0)

    while True:
        ret, frame = camera.read()
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)

        for (x, y, w, h) in faces:
            roi_gray = gray[y:y+h, x:x+w]
            label, confidence = recognizer.predict(roi_gray)

            if confidence < 100:  # Adjust threshold as needed
                name = [user[1] for user in users if user[0] == label][0]
                
                cv2.putText(frame, f'Name: {name}', (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
                response = make_response(redirect(url_for('login')))
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
                return response
                
            else:
                cv2.putText(frame, 'Unknown', (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 255), 2)

            cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)

        cv2.imshow('Face Recognition', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    camera.release()
    cv2.destroyAllWindows()

    response = make_response(redirect(url_for('admin_panel')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT id, username, email, full_name, user_type, age, gender, phone, edit_status, 
                 notification_preference, profile_photo FROM users WHERE username = ?''', (session['username'],))
    user = c.fetchone()
    
    if user:
        user_dict = {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'full_name': user[3],
            'user_type': user[4],
            'age': user[5],
            'gender': user[6],
            'phone': user[7],
            'edit_status': user[8],
            'notification_preference': (str(user[9]) == '1') if user[9] is not None else True,
            'profile_photo': user[10] if user[10] is not None else 'default_profile.png'
        }
        response = make_response(render_template('user_profile.html', user=user_dict))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        session.clear()
        flash('User not found.', 'error')
        response = make_response(redirect(url_for('login')))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        session.clear() # Clear session on unauthorized access
        response = make_response(redirect('/login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    db = get_db()
    c = db.cursor()
    
    # Get current user data
    c.execute('SELECT id, full_name, email, age, gender, phone FROM users WHERE username = ?', (session['username'],))
    user_row = c.fetchone()
    user_id = user_row[0]
    current_data = {
        'full_name': user_row[1] or '',
        'email': user_row[2] or '',
        'age': str(user_row[3]) if user_row[3] is not None else '',
        'gender': user_row[4] or '',
        'phone': user_row[5] or ''
    }
    
    # Get form data
    full_name = request.form['full_name']
    email = request.form['email']
    age = request.form['age']
    gender = request.form['gender']
    phone = request.form['phone']
    
    # Store changes in pending_changes
    changes = {
        'full_name': full_name,
        'email': email,
        'age': age,
        'gender': gender,
        'phone': phone
    }
    # Check if any field is actually changed
    changed = False
    for key in changes:
        if str(changes[key]) != str(current_data.get(key, '')):
            changed = True
            break
    if not changed:
        flash('No changes detected in your profile.', 'error')
        response = make_response(redirect('/profile'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    # Update user record with pending status
    c.execute('''UPDATE users 
                 SET edit_status = 'pending', 
                     pending_changes = ? 
                 WHERE id = ?''', (json.dumps(changes), user_id))
    # Notify all admins with notifications enabled
    c.execute("SELECT id, username FROM users WHERE LOWER(user_type) = 'admin' AND notification_preference = 1")
    admins = c.fetchall()
    for admin in admins:
        admin_id, admin_username = admin
        message = f"User {session['username']} has requested approval for a profile update."
        c.execute('INSERT INTO notifications (user_id, message, timestamp, link) VALUES (?, ?, ?, ?)',
                  (admin_id, message, datetime.datetime.now(), url_for('admin_users')))
    db.commit()
    
    flash('Profile update submitted for approval', 'success')
    response = make_response(redirect('/profile'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if 'username' not in session:
        session.clear()
        flash('Please log in to change your password.', 'error')
        return redirect(url_for('login'))
    
    # Get form data
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Basic validation
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required.', 'error')
        return redirect(url_for('profile'))
    
    # Check if new password matches confirmation
    if new_password != confirm_password:
        flash('New password and confirmation password do not match.', 'error')
        return redirect(url_for('profile'))
    
    # Check if new password is different from current password
    if current_password == new_password:
        flash('New password must be different from your current password.', 'error')
        return redirect(url_for('profile'))
    
    # Validate password strength
    is_valid, error_message = validate_password_strength(new_password)
    if not is_valid:
        flash(f'Password strength error: {error_message}', 'error')
        return redirect(url_for('profile'))
    
    db = get_db()
    c = db.cursor()
    
    try:
        # Get admin user from DB (robust: any user_type containing 'admin', case-insensitive)
        c.execute("SELECT id, password FROM users WHERE LOWER(user_type) LIKE '%admin%' LIMIT 1")
        user_data = c.fetchone()
        if not user_data:
            flash('Admin user not found.', 'error')
            return redirect(url_for('admin_panel'))
        user_id, stored_hashed_password = user_data
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hashed_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('profile'))
        
        # Check password history
        history_valid, history_error = check_password_history(user_id, new_password)
        if not history_valid:
            flash(history_error, 'error')
            return redirect(url_for('profile'))
        
        # Hash the new password
        new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update password in database
        c.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed_password, user_id))
        
        # Create a blockchain transaction for password change
        password_change_transaction = {
            'type': 'password_change',
            'user_id': user_id,
            'timestamp': str(datetime.datetime.now()),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }
        
        # Get the last block's hash
        c.execute('SELECT previous_hash FROM blockchain ORDER BY block_index DESC LIMIT 1')
        last_block = c.fetchone()
        prev_hash = last_block[0] if last_block else '0'
        
        # Create and add new block for password change
        new_block = create_block(prev_hash, [password_change_transaction])
        add_block(new_block)
        
        db.commit()
        
        # Clear session and require re-login for security
        session.clear()
        flash('Password changed successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        db.rollback()
        flash(f'An error occurred while changing your password. Please try again.', 'error')
        print(f"Password change error: {e}")
        return redirect(url_for('profile'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')
        
        db = get_db()
        c = db.cursor()
        
        # Check if email exists
        c.execute('SELECT id, username FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user:
            # Generate a secure temporary password
            temp_password = generate_secure_password()
            temp_hashed_password = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt())
            
            # Update user's password
            c.execute('UPDATE users SET password = ? WHERE id = ?', (temp_hashed_password, user[0]))
            
            # Create blockchain transaction
            reset_transaction = {
                'type': 'password_reset',
                'user_id': user[0],
                'timestamp': str(datetime.datetime.now()),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
            # Get the last block's hash
            c.execute('SELECT previous_hash FROM blockchain ORDER BY block_index DESC LIMIT 1')
            last_block = c.fetchone()
            prev_hash = last_block[0] if last_block else '0'
            
            # Create and add new block
            new_block = create_block(prev_hash, [reset_transaction])
            add_block(new_block)
            
            db.commit()
            
            # In a real application, you would send this via email
            # For now, we'll just show it (NOT recommended for production)
            flash(f'Your temporary password is: {temp_password}. Please change it after logging in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email address not found in our system.', 'error')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/password_strength_check', methods=['POST'])
def password_strength_check():
    """AJAX endpoint to check password strength in real-time"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    password = data.get('password', '')
    
    is_valid, message = validate_password_strength(password)
    
    # Calculate strength score (0-100)
    score = 0
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if re.search(r'[A-Z]', password):
        score += 20
    if re.search(r'[a-z]', password):
        score += 20
    if re.search(r'\d', password):
        score += 20
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        score += 10
    
    return jsonify({
        'is_valid': is_valid,
        'message': message,
        'score': score,
        'strength': 'weak' if score < 40 else 'medium' if score < 70 else 'strong'
    })

@app.route('/dashboard')
@login_required
def user_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    current_user_id = get_user_id(session['username'])
    if current_user_id is None:
        session.clear()
        return redirect(url_for('login'))
    user_type = session.get('user_type', '').lower()
    if user_type == 'admin':
        return redirect(url_for('admin_panel'))
    db = get_db()
    c = db.cursor()
    # Fetch user info including profile photo
    c.execute('SELECT full_name, email, user_type, last_login, profile_photo FROM users WHERE id = ?', (current_user_id,))
    user = c.fetchone()
    user_full_name = user[0] if user else ''
    user_email = user[1] if user else ''
    user_type = user[2] if user else ''
    last_login = user[3] if user else ''
    profile_photo = user[4] if user and user[4] else 'default_profile.png'
    # Fetch notifications
    c.execute('SELECT message, timestamp FROM notifications WHERE user_id = ? ORDER BY timestamp DESC', (current_user_id,))
    notifications = [{'message': row[0], 'timestamp': row[1]} for row in c.fetchall()]
    # Fetch recent files (uploaded or shared)
    c.execute('''SELECT f.id, f.original_filename, u.full_name, f.timestamp, f.hash
                 FROM files AS f
                 INNER JOIN users AS u ON f.user_id = u.id
                 WHERE f.user_id = ?
                 ORDER BY f.timestamp DESC''', (current_user_id,))
    uploaded_files = c.fetchall()
    c.execute('''SELECT f.id, f.original_filename, uploader.full_name, f.timestamp, f.hash
                 FROM files AS f
                 INNER JOIN shared_files AS sf ON f.id = sf.file_id
                 INNER JOIN users AS uploader ON f.user_id = uploader.id
                 WHERE sf.recipient_id = ?
                 ORDER BY f.timestamp DESC''', (current_user_id,))
    received_files = c.fetchall()
    all_files = uploaded_files + received_files
    recent_files = list({file[0]: file for file in all_files}.values())
    # Stats
    c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (current_user_id,))
    total_files = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM shared_files WHERE recipient_id = ?', (current_user_id,))
    total_shared = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ?', (current_user_id,))
    total_notifications = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM blockchain')
    global_block_count = c.fetchone()[0]
    user_blocks = get_blockchain_details(current_user_id)
    user_block_count = len(user_blocks)
    stats = {
        'total_files': total_files,
        'total_shared': total_shared,
        'total_notifications': total_notifications,
        'global_block_count': global_block_count,
        'user_block_count': user_block_count
    }
    return render_template('user_dashboard.html',
        user_full_name=user_full_name,
        user_email=user_email,
        user_type=user_type,
        last_login=last_login,
        profile_photo=profile_photo,
        notifications=notifications,
        recent_files=recent_files,
        stats=stats)

# Add these constants for profile photo upload
PROFILE_PHOTO_FOLDER = 'static/profile_photos'
PROFILE_PHOTO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create profile photo folder if it doesn't exist
os.makedirs(PROFILE_PHOTO_FOLDER, exist_ok=True)

def allowed_profile_photo(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in PROFILE_PHOTO_EXTENSIONS

@app.route('/upload_profile_photo', methods=['POST'])
@login_required
def upload_profile_photo():
    if 'profile_photo' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    
    file = request.files['profile_photo']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    if file and allowed_profile_photo(file.filename):
        # Generate unique filename
        from werkzeug.utils import secure_filename
        filename = secure_filename(f"{session['username']}_{file.filename}")
        filepath = os.path.join(PROFILE_PHOTO_FOLDER, filename)
        
        # Save file
        file.save(filepath)
        
        # Update user's profile photo in database
        db = get_db()
        c = db.cursor()
        c.execute('UPDATE users SET profile_photo = ? WHERE username = ?', (filename, session['username']))
        db.commit()
        
        return jsonify({
            'success': True,
            'photo_url': url_for('static', filename=f'profile_photos/{filename}')
        })
    
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/update_notification_preference', methods=['POST'])
@login_required
def update_notification_preference():
    data = request.get_json()
    if 'enabled' not in data:
        return jsonify({'success': False, 'error': 'Missing enabled parameter'})
    
    try:
        db = get_db()
        c = db.cursor()
        print(f"[DEBUG] Writing notification_preference for {session['username']}: {1 if data['enabled'] else 0}")
        c.execute('UPDATE users SET notification_preference = ? WHERE username = ?', 
                 (1 if data['enabled'] else 0, session['username']))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        db = get_db()
        c = db.cursor()
        
        # Get user ID
        c.execute('SELECT id, profile_photo FROM users WHERE username = ?', (session['username'],))
        user_data = c.fetchone()
        if not user_data:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user_id, profile_photo = user_data
        
        # Delete user's profile photo if it exists and is not the default
        if profile_photo and profile_photo != 'default_profile.png':
            photo_path = os.path.join(PROFILE_PHOTO_FOLDER, profile_photo)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        # Delete user's medical records
        c.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        
        # Delete user's shared file records (fix: use correct columns)
        c.execute('DELETE FROM shared_files WHERE recipient_id = ? OR file_id IN (SELECT id FROM files WHERE user_id = ?)', (user_id, user_id))
        
        # Delete the user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        
        # Clear session and logout
        session.clear()
        
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/notifications/json')
@login_required
def notifications_json():
    db = get_db()
    c = db.cursor()
    # Get the current user's ID
    c.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
    user_row = c.fetchone()
    if not user_row:
        return {'notifications': []}
    user_id = user_row[0]
    # Fetch notifications for the current user
    c.execute('SELECT id, message, timestamp, link FROM notifications WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
    notifications = []
    for row in c.fetchall():
        notif_id = row[0]
        message = row[1]
        timestamp = row[2]
        link = row[3] if len(row) > 3 and row[3] is not None else ''
        notifications.append({'id': notif_id, 'message': message, 'timestamp': timestamp, 'link': link})
    return {'notifications': notifications}

@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def notifications_mark_all_read():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
    user_id = c.fetchone()[0]
    # For now, just delete all notifications for the user (or you can add a 'read' flag if you want to keep them)
    c.execute('DELETE FROM notifications WHERE user_id = ?', (user_id,))
    db.commit()
    return '', 204

@app.route('/notifications/mark_read/<int:notif_id>', methods=['POST'])
@login_required
def notifications_mark_read(notif_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
    user_id = c.fetchone()[0]
    c.execute('DELETE FROM notifications WHERE id = ? AND user_id = ?', (notif_id, user_id))
    db.commit()
    return '', 204

def get_notification_preference(user_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT notification_preference FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    return bool(row[0]) if row is not None else True

@app.route('/admin/approve_changes/<int:user_id>', methods=['POST'])
@admin_required
def approve_changes(user_id):
    db = get_db()
    c = db.cursor()
    # Get pending changes
    c.execute('SELECT pending_changes FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    if not row or not row[0]:
        flash('No pending changes to approve.', 'error')
        return redirect(url_for('admin_users'))
    changes = json.loads(row[0])
    # Build update statement
    updates = []
    params = []
    for key, value in changes.items():
        updates.append(f"{key} = ?")
        params.append(value)
    params.append(user_id)
    c.execute(f'UPDATE users SET {", ".join(updates)}, edit_status = "approved", pending_changes = NULL WHERE id = ?', params)
    # Notify the user
    c.execute('INSERT INTO notifications (user_id, message, timestamp, link) VALUES (?, ?, ?, ?)',
              (user_id, 'Your profile update has been approved by the admin.', datetime.datetime.now(), url_for('profile')))
    db.commit()
    flash('User changes approved successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/system_management')
@admin_required
def system_management():
    db = get_db()
    c = db.cursor()
    # Get total files
    c.execute('SELECT COUNT(*) FROM files')
    total_files = c.fetchone()[0]
    # Get total users
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    # Calculate storage used
    total_size = 0
    c.execute('SELECT file_path FROM files')
    files = c.fetchall()
    for file_path in files:
        if os.path.exists(file_path[0]):
            total_size += os.path.getsize(file_path[0])
    # Convert to human-readable format
    def sizeof_fmt(num, suffix='B'):
        for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"
    storage_used = sizeof_fmt(total_size)
    return render_template('system_management.html',
                         total_files=total_files,
                         total_users=total_users,
                         storage_used=storage_used)

@app.route('/admin/clear_uploads', methods=['POST'])
@admin_required
def clear_uploads():
    db = get_db()
    c = db.cursor()
    try:
        # Get all file records
        c.execute('SELECT id, file_path FROM files')
        files = c.fetchall()
        # Create a cleanup transaction for all files
        cleanup_transaction = {
            'type': 'bulk_cleanup',
            'timestamp': str(datetime.datetime.now()),
            'reason': 'Admin initiated bulk cleanup',
            'affected_files': len(files)
        }
        # Get the last block's hash
        c.execute('SELECT previous_hash FROM blockchain ORDER BY block_index DESC LIMIT 1')
        last_block = c.fetchone()
        prev_hash = last_block[0] if last_block else '0'
        # Create and add new block for cleanup
        new_block = create_block(prev_hash, [cleanup_transaction])
        add_block(new_block)
        # Delete all files from uploads directory
        for file_id, file_path in files:
            if os.path.exists(file_path):
                os.remove(file_path)
        # Delete all records from shared_files and files tables
        c.execute('DELETE FROM shared_files')
        c.execute('DELETE FROM files')
        db.commit()
        flash('All uploads have been cleared successfully', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error clearing uploads: {e}', 'error')
    return redirect(url_for('system_management'))

@app.route('/admin/blockchain_details')
@admin_required
def admin_blockchain_details():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM blockchain ORDER BY block_index ASC')
    blocks = c.fetchall()
    # For consistency with user view, pass as 'blockchain' variable
    return render_template('blockchain_transactions.html', blockchain=blocks)

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    db = get_db()
    c = db.cursor()
    # Fetch the admin user by session username (not just user_type)
    c.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
    user_row = c.fetchone()
    user = None
    if user_row:
        print(f"[DEBUG] Full user_row for {user_row[1]}: {user_row}")
        profile_photo = user_row[13]
        print(f"[DEBUG] Reading notification_preference for {user_row[1]}: {user_row[12]}")
        user = {
            'id': user_row[0],
            'username': user_row[1],
            'password': user_row[2],
            'email': user_row[3],
            'full_name': user_row[4],
            'user_type': user_row[5],
            'age': user_row[6],
            'gender': user_row[7],
            'phone': user_row[8],
            'edit_status': user_row[9],
            'pending_changes': user_row[10],
            'notification_preference': (str(user_row[12]) == '1') if user_row[12] is not None else True,
            'profile_photo': profile_photo
        }
    if request.method == 'POST':
        changed = False
        # Password change logic
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        if current_password or new_password or confirm_password:
            # All fields must be filled
            if not current_password or not new_password or not confirm_password:
                flash('Please fill in all password fields.', 'error')
                return redirect(url_for('admin_settings'))
            # Get admin user from DB (already fetched above)
            if not user:
                flash('Admin user not found.', 'error')
                return redirect(url_for('admin_panel'))
            user_id, stored_hashed_password = user['id'], user['password']
            # Check current password
            if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hashed_password):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('admin_settings'))
            # Check new password strength
            valid, msg = validate_password_strength(new_password)
            if not valid:
                flash(msg, 'error')
                return redirect(url_for('admin_settings'))
            # Check new password != current
            if bcrypt.checkpw(new_password.encode('utf-8'), stored_hashed_password):
                flash('New password cannot be the same as your current password.', 'error')
                return redirect(url_for('admin_settings'))
            # Check new password == confirm
            if new_password != confirm_password:
                flash('New password and confirmation do not match.', 'error')
                return redirect(url_for('admin_settings'))
            # All good, update password
            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            c.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed_password, user_id))
            db.commit()
            changed = True
            flash('Password changed successfully!', 'success')
        # Profile info update logic
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        phone = request.form.get('phone', '').strip()
        # Only update if at least one field is present and different
        if user and (full_name or email or age or gender or phone):
            updates = []
            params = []
            if full_name and full_name != (user['full_name'] or ''):
                updates.append('full_name = ?')
                params.append(full_name)
            if email and email != (user['email'] or ''):
                updates.append('email = ?')
                params.append(email)
            if age and str(age) != str(user['age'] or ''):
                updates.append('age = ?')
                params.append(age)
            if gender and gender != (user['gender'] or ''):
                updates.append('gender = ?')
                params.append(gender)
            if phone and phone != (user['phone'] or ''):
                updates.append('phone = ?')
                params.append(phone)
            if updates:
                params.append(user['id'])
                c.execute(f'UPDATE users SET {", ".join(updates)} WHERE id = ?', params)
                db.commit()
                changed = True
                flash('Profile updated successfully!', 'success')
        if not changed:
            flash('No changes made.', 'info')
        # Refetch the admin user to get the latest notification_preference and other fields
        c.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
        user_row = c.fetchone()
        user = None
        if user_row:
            print(f"[DEBUG] Full user_row for {user_row[1]}: {user_row}")
            profile_photo = user_row[13]
            print(f"[DEBUG] Reading notification_preference for {user_row[1]}: {user_row[12]}")
            user = {
                'id': user_row[0],
                'username': user_row[1],
                'password': user_row[2],
                'email': user_row[3],
                'full_name': user_row[4],
                'user_type': user_row[5],
                'age': user_row[6],
                'gender': user_row[7],
                'phone': user_row[8],
                'edit_status': user_row[9],
                'pending_changes': user_row[10],
                'notification_preference': (str(user_row[12]) == '1') if user_row[12] is not None else True,
                'profile_photo': profile_photo
            }
    # Final fallback: always return a valid response
    if not user:
        flash('Admin user not found.', 'error')
        return redirect(url_for('admin_panel'))
    return render_template('admin_settings.html', user=user)

@app.route('/debug/notification_prefs')
def debug_notification_prefs():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT username, notification_preference FROM users')
    rows = c.fetchall()
    output = '\n'.join([f"{row[0]}: {row[1]}" for row in rows])
    return f'<pre>{output}</pre>'

@app.route('/debug/notifications')
@login_required
def debug_notifications():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
    user_row = c.fetchone()
    if not user_row:
        return '<pre>No user found.</pre>'
    user_id = user_row[0]
    c.execute('SELECT message, timestamp, link FROM notifications WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
    rows = c.fetchall()
    if not rows:
        return '<pre>No notifications found for this user.</pre>'
    output = '\n'.join([f"{row[1]} | {row[0]} | {row[2]}" for row in rows])
    return f'<pre>{output}</pre>'

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)