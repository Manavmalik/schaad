from flask import Flask, request, send_file
from rsa_utils import generate_keys, encrypt_file, decrypt_file

app = Flask(__name__)
users = {"admin":"Admin@123"}
private_key, public_key = generate_keys()

@app.post("/login")
def login():
    data = request.json
    if data["username"] in users and users[data["username"]] == data["password"]:
        return {"status":"ok"}
    return {"status":"fail"}

@app.post("/upload")
def upload():
    f = request.files["file"]
    data = f.read()
    encrypted = encrypt_file(data, public_key)
    with open("encrypted.enc","wb") as out:
        out.write(encrypted)
    return {"status":"encrypted"}

@app.get("/download_enc")
def download_enc():
    return send_file("encrypted.enc", as_attachment=True)

@app.post("/decrypt")
def decrypt():
    f = request.files["file"]
    data = f.read()
    decrypted = decrypt_file(data, private_key)
    with open("decrypted.dec","wb") as out:
        out.write(decrypted)
    return {"status":"decrypted"}

@app.get("/download_dec")
def download_dec():
    return send_file("decrypted.dec", as_attachment=True)

app.run(port=5000)
