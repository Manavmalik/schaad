import requests

base = "http://127.0.0.1:5000"

def login():
    u = input("Username: ")
    p = input("Password: ")
    r = requests.post(base + "/login", json={"username":u,"password":p})
    print(r.text)

def upload():
    f = input("Enter file name to upload: ")
    r = requests.post(base + "/upload", files={"file":open(f,"rb")})
    print(r.text)

def download_enc():
    r = requests.get(base + "/download_enc")
    open("downloaded.enc","wb").write(r.content)
    print("Encrypted file downloaded")

def decrypt():
    r = requests.post(base + "/decrypt", files={"file":open("downloaded.enc","rb")})
    print(r.text)

def download_dec():
    r = requests.get(base + "/download_dec")
    open("downloaded.dec","wb").write(r.content)
    print("Decrypted file downloaded")

while True:
    print("1. Login")
    print("2. Upload file")
    print("3. Encrypt the file (done automatically on upload)")
    print("4. Download encrypted file")
    print("5. Decrypt the file")
    print("6. Download decrypted file")
    print("7. Exit")
    ch = input("Choose: ")

    if ch == "1":
        login()
    elif ch == "2":
        upload()
    elif ch == "3":
        print("Encryption happens during upload")
    elif ch == "4":
        download_enc()
    elif ch == "5":
        decrypt()
    elif ch == "6":
        download_dec()
    elif ch == "7":
        break
