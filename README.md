# MedChain: Blockchain-based Medical Record Management

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

MedChain is a secure, blockchain-based medical records management system designed for healthcare providers, patients, and administrators. It enables users to upload, share, and manage encrypted health records with full audit trails, notifications, and a modern, user-friendly web interface.

---

## Table of Contents
- [Description](#description)
- [Badges](#badges)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Security Notes](#security-notes)
- [Planned Features](#planned-features)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)
- [Contact](#contact)

---

## Description
MedChain is a secure, blockchain-based medical records management system. It enables patients, doctors, and administrators to upload, share, and manage encrypted health records with full audit trails, notifications, and a modern, user-friendly web interface.

---

## Badges
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

---

## Features
- **User Management**
  - Registration and login for patients, doctors, and admins
  - Strong password enforcement and reset
  - Profile editing with admin approval
  - Profile photo upload
- **Medical Records**
  - Secure file upload (AES-encrypted)
  - File sharing between users (e.g., patient to doctor)
  - Download and audit of medical records
  - Blockchain logging of all file actions
- **Notifications**
  - In-app notifications for file sharing, approvals, and more
  - User notification preferences
- **Admin Dashboard**
  - System stats (users, files, storage, blockchain blocks)
  - User management (approve, delete, view)
  - System management (clear uploads, view blockchain)
- **Security**
  - Password hashing (bcrypt)
  - Session management
  - File type validation
  - Encrypted file storage

---

## Architecture
MedChain is built using a modular, extensible architecture:
- **Backend:** Python, Flask, SQLite (easy to migrate to PostgreSQL/MySQL for production)
- **Frontend:** Jinja2 templates, HTML5, CSS3 (glassmorphism design), JavaScript for interactivity
- **Encryption:** PyCryptodome for AES encryption of files
- **Password Security:** bcrypt for password hashing
- **Blockchain:** Custom implementation for immutable audit trails
- **Notifications:** In-app, with user preferences

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation
1. **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/medchain.git
    cd medchain
    ```
2. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```
3. **Set up the database**
    - The app will auto-create the SQLite database and tables on first run.
4. **Run the application**
    ```bash
    python medical_blockchain_app.py
    ```
    - The app will be available at `http://127.0.0.1:5000/`

---

## Usage
### For Users (Patients/Doctors)
- Register for an account and select your role.
- Login to access your personalized dashboard.
- Upload medical records securely and share them with other users as needed.
- Edit your profile and request changes (subject to admin approval).
- Manage notifications and view your notification history.
- Download your medical records at any time.

### For Admin
- Access the admin dashboard for a comprehensive overview of the system.
- Manage users: Approve profile changes, delete users, and view user details.
- Monitor system stats: Track files, users, storage, and blockchain activity.
- Clear uploads: Remove all uploaded files and reset the system as needed.
- View blockchain transactions: Audit all critical actions for transparency.

---

## Configuration

MedChain is designed to be easy to set up, but you can customize several aspects to fit your needs. Below are the main configuration options and how to change them:

### 1. Application Settings
All main settings are found at the top of `medical_blockchain_app.py`:
- **Secret Key:**  
  Change `app.secret_key` to a strong, random value for production.
  ```python
  app.secret_key = 'your-very-secret-key'
  ```
- **Upload Folder:**  
  Default is `uploads/`. Change with:
  ```python
  app.config['UPLOAD_FOLDER'] = 'uploads'
  ```
- **Profile Photo Folder:**  
  Default is `static/profile_photos/`. Change with:
  ```python
  PROFILE_PHOTO_FOLDER = 'static/profile_photos'
  ```
- **Max Upload Size:**  
  Default is 16MB. Change with:
  ```python
  app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
  ```
- **Session Lifetime:**  
  Default is 30 minutes. Change with:
  ```python
  app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
  ```

### 2. Database
- **Default:**  
  Uses SQLite (`medical_records.db` in the project root).
- **Change Database:**  
  To use another database (e.g., PostgreSQL), update:
  ```python
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_records.db'
  ```
  to something like:
  ```python
  app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost/dbname'
  ```
  (You'll need to add SQLAlchemy and update the code for full support.)

### 3. Allowed File Types
- **Medical Records:**  
  Allowed extensions are set in:
  ```python
  ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
  ```
  Add or remove as needed.
- **Profile Photos:**  
  Allowed extensions are set in:
  ```python
  PROFILE_PHOTO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
  ```

### 4. Email/Notifications
- **Email notifications** are not yet implemented, but you can add your SMTP settings in the future for password resets and alerts.

### 5. Face Recognition (Planned)
- **Model files** are stored in the `models/` directory.  
  When implemented, you'll be able to configure model paths and training parameters.

### 6. Environment Variables (Recommended for Production)
For better security, consider using environment variables for sensitive settings:
- `SECRET_KEY`
- `DATABASE_URL`
- `UPLOAD_FOLDER`
- etc.

You can use a `.env` file and the `python-dotenv` package for this.

**Example `.env` file:**
```
SECRET_KEY=your-very-secret-key
DATABASE_URL=sqlite:///medical_records.db
UPLOAD_FOLDER=uploads
```

**To load environment variables:**
```python
from dotenv import load_dotenv
load_dotenv()
import os
app.secret_key = os.getenv('SECRET_KEY')
```

---

## Project Structure
```
medchain/
  ├── medical_blockchain_app.py         # Main Flask application
  ├── models/                          # Face recognition models (future)
  ├── static/                          # Static files (CSS, JS, images, profile photos)
  ├── templates/                       # Jinja2 HTML templates
  ├── uploads/                         # Encrypted uploaded medical files
  ├── instance/                        # SQLite database file
  ├── migrations/                      # Database migration scripts
  └── requirements.txt                 # Python dependencies
```

---

## Security Notes
- **Passwords:** All passwords are hashed using bcrypt before storage.
- **File Encryption:** All uploaded files are encrypted with AES for privacy.
- **Blockchain Logging:** All critical actions are logged in a blockchain table for auditability.
- **Session Security:** Sessions are protected and have a configurable timeout.
- **Input Validation:** Only allowed file types are accepted; user input is validated throughout.
- **Production Tips:** Use a strong secret key, enable HTTPS, and consider a production-ready database.

---

## Planned Features
- **Face Recognition:**  
  Face recognition for user verification is planned for a future release. The codebase is structured to support this feature, and related files are present, but it is not yet active.
- **Email Notifications:**  
  Integration with email services for password resets and notifications.
- **Advanced Analytics:**  
  More detailed analytics and reporting for admins.
- **API Endpoints:**  
  RESTful API for integration with other systems.
- **Role-Based Access Control:**  
  More granular permissions for different user roles.

---

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a pull request

For major changes, please open an issue first to discuss what you would like to change.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Credits
- [Flask](https://flask.palletsprojects.com/)
- [PyCryptodome](https://www.pycryptodome.org/)
- [bcrypt](https://pypi.org/project/bcrypt/)
- [OpenCV](https://opencv.org/) (for future face recognition)
- [Font Awesome](https://fontawesome.com/) (icons)
- Unsplash (background images)

---

## Contact
For questions, support, or feedback, please open an issue or contact [theofficialamruthesh@gmail.com](mailto:theofficialamruthesh@gmail.com). 
