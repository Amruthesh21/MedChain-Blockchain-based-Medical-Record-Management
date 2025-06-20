from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import text
import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/medical_records.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

DB_PATH = 'medical_records.db'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    edit_status = db.Column(db.String(20), default='pending')
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    notification_preference = db.Column(db.Boolean, default=True)
    profile_photo = db.Column(db.String(255), default='default_profile.png')

def add_notification_preference():
    with app.app_context():
        try:
            # Check if columns already exist
            cursor = db.session.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'notification_preference' not in columns:
                db.session.execute(text('ALTER TABLE users ADD COLUMN notification_preference BOOLEAN DEFAULT 1'))
            
            if 'profile_photo' not in columns:
                db.session.execute(text('ALTER TABLE users ADD COLUMN profile_photo VARCHAR(255) DEFAULT "default_profile.png"'))
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()

def add_link_column():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Add the 'link' column if it does not exist
    c.execute("PRAGMA table_info(notifications)")
    columns = [row[1] for row in c.fetchall()]
    if 'link' not in columns:
        c.execute("ALTER TABLE notifications ADD COLUMN link TEXT")
    else:
        print("'link' column already exists in notifications table.")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    add_notification_preference()
    add_link_column() 