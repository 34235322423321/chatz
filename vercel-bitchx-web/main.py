from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form, HTTPException
from fastapi.responses import HTMLResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import json

app = FastAPI()

users = {}                    # username -> {"pw_hash": , "aes_key": bytes}
connected = {}                # websocket -> username

def encrypt(msg: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(msg.encode()) + padder.finalize()
    return (iv + encryptor.update(padded) + encryptor.finalize()).hex()

def decrypt(hex_data: str, key: bytes) -> str:
    data = bytes.fromhex(hex_data)
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded = decryptor.update(data[16:]) + decryptor.finalize()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# ================== HOME PAGE (index.html inside main.py) ==================
@app.get("/")
async def home():
    html = """<!DOCTYPE html>
<html>
<head>
    <title>BITCHX WEB</title>
    <style>
        body { background:#000; color:#0f0; font-family:monospace; padding:20px; }
        #messages { height:500px; overflow-y:scroll; border:1px solid #0f0; padding:10px; margin:10px 0; }
        input, button { background:#111; color:#0f0; border:1px solid #0f0; padding:10px; margin:5px; }
        button { cursor:pointer; }
    </style>
</head>
<body>
    <h1>🔥 BITCHX WEB - VERCEL EDITION 🔥</h1>
    
    <div id="auth">
        <input id="user" placeholder="Username"><br>
        <input id="pass" type="password" placeholder="Password"><br><br>
        <button onclick="register()">REGISTER</button>
        <button onclick="login()">LOGIN</button>
    </div>

    <div id="chat" style="display:none;">
        <div id="messages"></div>
        <input id="msginput" placeholder="username|your message" style="width:70%">
        <button onclick="sendMessage()">SEND</button>
        <button onclick="logout()">LOGOUT</button>
    </div>

    <script>
        let ws = null;
        let myName = "";

        async function register() {
            let u = document.getElementById("user").value;
            let p = document.getElementById("pass").value;
            let res = await fetch("/register", {method:"POST", body: new URLSearchParams({username:u, password:p})});
            let data = await res.json();
            alert(data.success ? "Registered!" : data.error);
        }

        async function login() {
            let u = document.getElementById("user").value;
            let p = document.getElementById("pass").value;
            let res = await fetch("/login", {method:"POST", body: new URLSearchParams({username:u, password:p})});
            let data = await res.json();
            if (data.success) {
                myName = u;
                document.getElementById("auth").style.display = "none";
                document.getElementById("chat").style.display = "block";
                ws = new WebSocket("ws://" + location.host + "/ws/" + u);
                ws.onmessage = function(e) {
                    let [sender, receiver, enc] = e.data.split("|");
                    let div = document.createElement("div");
                    div.textContent = `[${sender}] → ${receiver}: ${enc}`;
                    document.getElementById("messages").appendChild(div);
                    document.getElementById("messages").scrollTop = 999999;
                };
            } else {
                alert(data.error);
            }
        }

        function sendMessage() {
            if (ws) {
                let text = document.getElementById("msginput").value;
                ws.send(text);
                document.getElementById("msginput").value = "";
            }
        }

        function logout() {
            if (ws) ws.close();
            location.reload();
        }
    </script>
</body>
</html>"""
    return HTMLResponse(html)

# ================== BACKEND ROUTES ==================
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    if username in users:
        return {"error": "Username already taken"}
    users[username] = {
        "pw_hash": hashlib.sha256(password.encode()).hexdigest(),
        "aes_key": os.urandom(32)
    }
    return {"success": True}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username not in users:
        return {"error": "User not found"}
    if users[username]["pw_hash"] != hashlib.sha256(password.encode()).hexdigest():
        return {"error": "Wrong password"}
    return {"success": True}

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    if username not in users:
        await websocket.close()
        return
    connected[websocket] = username
    try:
        while True:
            data = await websocket.receive_text()
            if "|" not in data: continue
            receiver, msg = data.split("|", 1)
            encrypted = encrypt(msg, users[username]["aes_key"])
            for ws in list(connected.keys()):
                try:
                    await ws.send_text(f"{username}|{receiver}|{encrypted}")
                except:
                    del connected[ws]
    except WebSocketDisconnect:
        if websocket in connected:
            del connected[websocket]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
