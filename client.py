"""
RSA File Encryption Client Application
This client intentionally contains security and code quality weaknesses
for demonstration of SonarQube vulnerability detection.
"""

import requests
import os
import sys
import time

# WEAKNESS: Hardcoded server address without configuration
base = "http://127.0.0.1:5000"
MAX_RETRIES = 3
RETRY_DELAY = 1

class ClientException(Exception):
    """Custom exception for client errors"""
    pass

def check_server_health():
    """
    Check if server is accessible
    WEAKNESS: No timeout specified on request
    """
    try:
        # WEAKNESS: No timeout - can hang indefinitely
        r = requests.get(base)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to server at", base)
        return False
    except Exception as e:
        # WEAKNESS: Generic exception handling
        print(f"Server check failed: {e}")
        return False

def login():
    """
    Login to the application
    WEAKNESSES:
    - Credentials entered at runtime (could be logged)
    - No password masking on input
    - No session token management
    - Credentials sent over plain HTTP
    - No rate limiting on client side
    """
    try:
        print("\n--- LOGIN ---")
        u = input("Username: ")
        p = input("Password: ")  # WEAKNESS: Password visible in terminal
        
        # WEAKNESS: Credentials sent without TLS/SSL
        r = requests.post(
            base + "/login",
            json={"username": u, "password": p}
        )
        
        print(r.text)
        
        # WEAKNESS: No token storage or session management
        if "ok" in r.text:
            print("✓ Login successful")
            return True
        else:
            print("✗ Login failed")
            return False
    
    except requests.exceptions.RequestException as re:
        # WEAKNESS: Connection errors not properly handled
        print(f"Request error: {re}")
        return False
    except Exception as e:
        # WEAKNESS: Broad exception handling
        print(f"Login error: {e}")
        return False

def upload():
    """
    Upload file to server
    WEAKNESSES:
    - No file validation before upload
    - No size checking on client side
    - File handle not properly closed in some cases
    - No upload progress indicator
    - Exception handling too broad
    """
    try:
        print("\n--- UPLOAD FILE ---")
        f = input("Enter file name to upload: ")
        
        # WEAKNESS: No file existence check
        if not os.path.exists(f):
            print(f"ERROR: File '{f}' not found")
            return
        
        # WEAKNESS: No file size validation before upload
        file_size = os.path.getsize(f)
        print(f"Uploading file: {f} (size: {file_size} bytes)")
        
        # WEAKNESS: File handle not guaranteed to close if exception occurs
        file_handle = open(f, "rb")
        r = requests.post(base + "/upload", files={"file": file_handle})
        print(r.text)
        file_handle.close()  # May not execute if exception occurs
        
    except FileNotFoundError:
        print(f"ERROR: File not found: {f}")
    except IOError as io_e:
        # WEAKNESS: IO errors not properly logged
        print(f"IO Error: {io_e}")
    except requests.exceptions.Timeout:
        # WEAKNESS: No retry logic
        print("ERROR: Upload timeout")
    except requests.exceptions.RequestException as re:
        print(f"Request error during upload: {re}")
    except Exception as e:
        print(f"Upload error: {e}")

def download_enc():
    """
    Download encrypted file
    WEAKNESSES:
    - No authentication verification
    - No file size limit check on downloaded file
    - No integrity verification of downloaded file
    - Overwrites existing file without confirmation
    - No download progress indication
    """
    try:
        print("\n--- DOWNLOAD ENCRYPTED FILE ---")
        
        # WEAKNESS: No timeout on request
        r = requests.get(base + "/download_enc")
        
        # WEAKNESS: No content-length validation
        if r.status_code == 200:
            # WEAKNESS: File overwritten without user confirmation
            output_file = "downloaded.enc"
            
            # WEAKNESS: File written without proper error handling
            with open(output_file, "wb") as f:
                f.write(r.content)
            
            print(f"✓ Encrypted file downloaded to {output_file}")
            print(f"File size: {len(r.content)} bytes")
        else:
            print(f"ERROR: Failed to download (status: {r.status_code})")
            print(r.text)
    
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to server")
    except IOError as io_e:
        print(f"ERROR: Cannot write file: {io_e}")
    except Exception as e:
        print(f"Download error: {e}")

def decrypt():
    """
    Decrypt file on server
    WEAKNESSES:
    - No file format validation
    - No error handling for corrupted files
    - No user confirmation before decryption
    - No authentication check
    - Exception details exposed
    """
    try:
        print("\n--- DECRYPT FILE ---")
        
        enc_file = "downloaded.enc"
        
        # WEAKNESS: No file existence check
        if not os.path.exists(enc_file):
            print(f"ERROR: Encrypted file '{enc_file}' not found")
            print("Please download encrypted file first")
            return
        
        print(f"Sending {enc_file} for decryption...")
        
        # WEAKNESS: File handle not guaranteed to close
        file_handle = open(enc_file, "rb")
        r = requests.post(base + "/decrypt", files={"file": file_handle})
        print(r.text)
        file_handle.close()
        
    except FileNotFoundError:
        print(f"ERROR: File not found: {enc_file}")
    except IOError as io_e:
        print(f"IO Error: {io_e}")
    except requests.exceptions.Timeout:
        print("ERROR: Decryption timeout")
    except requests.exceptions.RequestException as re:
        print(f"Request error: {re}")
    except Exception as e:
        print(f"Decrypt error: {e}")

def download_dec():
    """
    Download decrypted file
    WEAKNESSES:
    - No authentication verification
    - No file integrity checking
    - No size limit validation
    - File overwrite without confirmation
    """
    try:
        print("\n--- DOWNLOAD DECRYPTED FILE ---")
        
        # WEAKNESS: No timeout
        r = requests.get(base + "/download_dec")
        
        if r.status_code == 200:
            output_file = "downloaded.dec"
            
            # WEAKNESS: Direct file overwrite without confirmation
            with open(output_file, "wb") as f:
                f.write(r.content)
            
            print(f"✓ Decrypted file downloaded to {output_file}")
            print(f"File size: {len(r.content)} bytes")
        else:
            print(f"ERROR: Failed to download (status: {r.status_code})")
            print(r.text)
    
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to server")
    except IOError as io_e:
        print(f"ERROR: Cannot write file: {io_e}")
    except Exception as e:
        print(f"Download error: {e}")

def display_menu():
    """Display main menu"""
    print("\n" + "="*50)
    print("RSA FILE ENCRYPTION CLIENT".center(50))
    print("="*50)
    print("1.  Login")
    print("2.  Upload file")
    print("3.  Encrypt the file (done automatically on upload)")
    print("4.  Download encrypted file")
    print("5.  Decrypt the file")
    print("6.  Download decrypted file")
    print("7.  Check server status")
    print("8.  Exit")
    print("="*50)

def handle_menu_choice(ch):
    """
    Handle user menu selection
    WEAKNESS: No input validation on choice
    """
    if ch == "1":
        login()
    elif ch == "2":
        upload()
    elif ch == "3":
        print("Encryption happens automatically during upload")
    elif ch == "4":
        download_enc()
    elif ch == "5":
        decrypt()
    elif ch == "6":
        download_dec()
    elif ch == "7":
        if check_server_health():
            print("✓ Server is running")
        else:
            print("✗ Server is offline")
    elif ch == "8":
        print("Exiting...")
        return False
    else:
        # WEAKNESS: Invalid input not handled gracefully
        print("ERROR: Invalid choice. Please try again.")
    
    return True

def main():
    """
    Main application loop
    WEAKNESSES:
    - No error recovery
    - No configuration file support
    - Infinite loop without proper exit handling
    - No logging to file
    """
    print("Connecting to server at", base)
    
    # WEAKNESS: No server availability check before starting
    if not check_server_health():
        print("WARNING: Server may not be available")
        time.sleep(1)
    
    running = True
    
    # WEAKNESS: Infinite loop without proper exception handling
    while running:
        try:
            display_menu()
            ch = input("Choose: ").strip()
            
            # WEAKNESS: User input not validated
            if not handle_menu_choice(ch):
                break
        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            break
        except EOFError:
            print("\nEnd of input reached")
            break
        except Exception as e:
            # WEAKNESS: Broad exception handling
            print(f"ERROR: Unexpected error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    # WEAKNESS: No command-line argument handling
    # WEAKNESS: No configuration file support
    try:
        main()
    except Exception as e:
        # WEAKNESS: No proper error recovery
        print(f"Fatal error: {e}")
        sys.exit(1)
