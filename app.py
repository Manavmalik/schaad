"""
RSA File Encryption Web Application
This module intentionally contains security weaknesses for educational purposes
to demonstrate SonarQube's security vulnerability detection capabilities.
"""

import os
import logging
from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from rsa_utils import generate_keys, encrypt_file, decrypt_file

# Initialize Flask application
app = Flask(__name__)

# WEAKNESS 1: Hardcoded credentials in source code - SonarQube will flag this
users = {
    "admin": "Admin@123",
    "user": "password123",  # Weak password
    "test": "test123"
}

# WEAKNESS 2: Insecure secret key configuration
app.secret_key = "hardcoded_secret_key_12345"  # SonarQube will detect hardcoded secret

# WEAKNESS 3: No upload file size limit configuration
UPLOAD_FOLDER = "./"
ALLOWED_EXTENSIONS = {"txt", "pdf", "doc", "docx", "png", "jpg", "jpeg"}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # But this can be bypassed

# Generate RSA keys at startup - WEAKNESS: Keys stored in memory without rotation
private_key, public_key = generate_keys()
logger = None

def init_logging():
    """Initialize logging configuration"""
    global logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    logger.info("Application initialized")

def allowed_file(filename):
    """
    Check if file extension is allowed
    WEAKNESS: Extension-based validation is insufficient for security
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_credentials(username, password):
    """
    Validate user credentials
    WEAKNESS 1: Plain text password comparison (no hashing)
    WEAKNESS 2: Timing attack vulnerability (direct string comparison)
    """
    if username in users:
        if users[username] == password:  # Direct comparison, vulnerable to timing attacks
            return True
    return False

@app.route("/", methods=["GET"])
def index():
    """Home endpoint"""
    return jsonify({"message": "RSA File Encryption API", "version": "1.0"})

@app.route("/login", methods=["POST"])
def login():
    """
    User login endpoint
    WEAKNESSES:
    - No rate limiting (vulnerable to brute force attacks)
    - Credentials sent in JSON without validation
    - No session timeout mechanism
    - SQL Injection risk if database is used
    """
    try:
        data = request.json
        
        # WEAKNESS: No input validation
        username = data["username"]
        password = data["password"]
        
        # WEAKNESS: No logging of failed attempts (no audit trail)
        if validate_credentials(username, password):
            logger.info(f"User {username} logged in successfully")
            return jsonify({"status": "ok", "message": "Login successful"})
        
        logger.warning(f"Failed login attempt for user {username}")
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401
    
    except KeyError:
        # WEAKNESS: Generic error handling revealing structure
        return jsonify({"status": "fail", "message": "Missing required fields"}), 400
    except Exception as e:
        # WEAKNESS: Exception details exposed to client
        logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/upload", methods=["POST"])
def upload():
    """
    File upload and encryption endpoint
    WEAKNESSES:
    - No authentication check before upload
    - No file size validation before processing
    - Uploaded files stored with predictable names
    - No virus scanning
    - Resource exhaustion attack possible
    - Files stored in application directory
    """
    try:
        if "file" not in request.files:
            return jsonify({"status": "fail", "message": "No file part"}), 400
        
        f = request.files["file"]
        
        if f.filename == "":
            return jsonify({"status": "fail", "message": "No selected file"}), 400
        
        # WEAKNESS: Filename not properly sanitized (path traversal risk)
        filename = secure_filename(f.filename)
        
        # Read file data
        data = f.read()
        
        # WEAKNESS: No size validation on actual file content
        if len(data) == 0:
            return jsonify({"status": "fail", "message": "Empty file"}), 400
        
        logger.info(f"Encrypting file: {filename}, size: {len(data)} bytes")
        
        # Encrypt the file
        encrypted = encrypt_file(data, public_key)
        
        # WEAKNESS: Predictable output filename and location
        output_filename = "encrypted.enc"
        
        # WEAKNESS: No file locking mechanism for concurrent access
        with open(output_filename, "wb") as out:
            out.write(encrypted)
        
        logger.info(f"File encrypted and saved to {output_filename}")
        
        return jsonify({
            "status": "encrypted",
            "message": "File encrypted successfully",
            "original_size": len(data),
            "encrypted_size": len(encrypted)
        })
    
    except MemoryError:
        logger.error("Memory error during encryption")
        return jsonify({"status": "error", "message": "File too large"}), 413
    except Exception as e:
        logger.error(f"Upload/Encryption error: {str(e)}")
        # WEAKNESS: Exception details exposed
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/download_enc", methods=["GET"])
def download_enc():
    """
    Download encrypted file endpoint
    WEAKNESSES:
    - No authentication check
    - No access control (anyone can download)
    - Predictable file location
    - No audit logging of downloads
    """
    try:
        # WEAKNESS: No authentication or authorization check
        if not os.path.exists("encrypted.enc"):
            return jsonify({"status": "fail", "message": "File not found"}), 404
        
        logger.info("Encrypted file downloaded")
        return send_file("encrypted.enc", as_attachment=True)
    
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt():
    """
    File decryption endpoint
    WEAKNESSES:
    - No authentication before decryption
    - Any user can decrypt any file
    - No validation of input file format
    - Resource exhaustion possible with malformed data
    """
    try:
        if "file" not in request.files:
            return jsonify({"status": "fail", "message": "No file part"}), 400
        
        f = request.files["file"]
        
        if f.filename == "":
            return jsonify({"status": "fail", "message": "No selected file"}), 400
        
        # Read encrypted data
        data = f.read()
        
        if len(data) == 0:
            return jsonify({"status": "fail", "message": "Empty file"}), 400
        
        logger.info(f"Decrypting file: {f.filename}, size: {len(data)} bytes")
        
        # WEAKNESS: No error handling for corrupted encrypted data
        decrypted = decrypt_file(data, private_key)
        
        # WEAKNESS: Predictable output filename
        output_filename = "decrypted.dec"
        
        # WEAKNESS: No file locking for concurrent access
        with open(output_filename, "wb") as out:
            out.write(decrypted)
        
        logger.info(f"File decrypted and saved to {output_filename}")
        
        return jsonify({
            "status": "decrypted",
            "message": "File decrypted successfully",
            "encrypted_size": len(data),
            "decrypted_size": len(decrypted)
        })
    
    except ValueError as ve:
        # WEAKNESS: Decryption errors not properly handled
        logger.error(f"Decryption error: {str(ve)}")
        return jsonify({"status": "error", "message": "Decryption failed"}), 400
    except Exception as e:
        logger.error(f"Decrypt error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/download_dec", methods=["GET"])
def download_dec():
    """
    Download decrypted file endpoint
    WEAKNESSES:
    - No authentication required
    - No access control implemented
    - Predictable file paths
    - No rate limiting
    """
    try:
        # WEAKNESS: No authentication or authorization
        if not os.path.exists("decrypted.dec"):
            return jsonify({"status": "fail", "message": "File not found"}), 404
        
        logger.info("Decrypted file downloaded")
        return send_file("decrypted.dec", as_attachment=True)
    
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/status", methods=["GET"])
def status():
    """
    Application status endpoint
    WEAKNESS: Exposes internal application details
    """
    return jsonify({
        "status": "running",
        "version": "1.0",
        "debug_mode": app.debug,
        "secret_key": app.secret_key  # CRITICAL WEAKNESS: Exposing secret key
    })

@app.route("/cleanup", methods=["POST"])
def cleanup():
    """
    Cleanup temporary files - WEAKNESS: No authentication
    """
    try:
        # WEAKNESS: No authentication check
        for filename in ["encrypted.enc", "decrypted.dec"]:
            if os.path.exists(filename):
                os.remove(filename)
                logger.info(f"Deleted {filename}")
        
        return jsonify({"status": "ok", "message": "Cleanup completed"})
    
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"status": "error", "message": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors - WEAKNESS: Exposing error details"""
    return jsonify({
        "status": "error", 
        "message": "Internal server error",
        "error_details": str(error)  # WEAKNESS: Exposing error details
    }), 500

if __name__ == "__main__":
    init_logging()
    logger.info("Starting RSA File Encryption Server on port 5000")
    # WEAKNESS: Running in debug mode exposes internal errors and enables remote debugging
    app.run(host="0.0.0.0", port=5000, debug=True)
