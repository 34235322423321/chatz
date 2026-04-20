from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os

app = FastAPI()

users = {}           # username -> {"pw_hash": str, "aes_key": bytes}
connected = {}       # websocket -> username

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

@app.get("/")
async def home():
    html = """<!DOCTYPE html>
<html>
<head>
    <title>BITCHX WEB</title>
    <style>
        body { background:#000; color:#0f0; font-family:monospace; padding:20px; margin:0; }
        h1 { color:#0f0; text-align:center; }
        #messages { height:70vh; overflow-y:scroll; border:2px solid #0f0; padding:15px; margin:10px 0; background:#111; }
        input, button { background:#111; color:#0f0; border:1px solid #0f0; padding:12px; margin:5px; font-size:16px; }
        button { cursor:pointer; }
        button:hover { background:#0f0; color:#000; }
        .msg { margin:8px 0; }
    </style>
</head>
<body>
    <h1>🔥 BITCHX WEB - LIVE ON VERCEL 🔥</h1>
    
    <div id="auth">
        <input id="user" placeholder="Username" style="width:300px"><br>
        <input id="pass" type="password" placeholder="Password" style="width:300px"><br><br>
        <button onclick="register()">REGISTER</button>
        <button onclick="login()">LOGIN</button>
    </div>

    <div id="chat" style="display:none;">
        <div id="messages"></div>
        <input id="msginput" placeholder="otheruser|your message here" style="width:70%">
        <button onclick="sendMessage()">SEND</button>
        <button onclick="logout()">LOGOUT</button>
    </div>

    <script>
        let ws = null;
        let myName = "";

        async function register() {
            let u = document.getElementById("user").value.trim();
            let p = document.getElementById("pass").value;
            if (!u || !p) return alert("Fill both fields");
            let res = await fetch("/register", {method:"POST", body: new URLSearchParams({username:u, password:p})});
            let data = await res.json();
            alert(data.success ? "Registered successfully!" : data.error || "Error");
        }

        async function login() {
            let u = document.getElementById("user").value.trim();
            let p = document.getElementById("pass").value;
            if (!u || !p) return alert("Fill both fields");
            let res = await fetch("/login", {method:"POST", body: new URLSearchParams({username:u, password:p})});
            let data = await res.json();
            if (data.success) {
                myName = u;
                document.getElementById("auth").style.display = "none";
                document.getElementById("chat").style.display = "block";
                
                ws = new WebSocket("wss://" + location.host + "/ws/" + u);   // use wss for vercel
                
                ws.onmessage = function(e) {
                    let parts = e.data.split("|");
                    if (parts.length >= 3) {
                        let sender = parts[0];
                        let receiver = parts[1];
                        let enc = parts[2];
                        let div = document.createElement("div");
                        div.className = "msg";
                        div.textContent = `[${sender}] → ${receiver}: ${enc}`;
                        document.getElementById("messages").appendChild(div);
                        document.getElementById("messages").scrollTop = 999999;
                    }
                };
                
                ws.onclose = () => console.log("WebSocket closed");
            } else {
                alert(data.error || "Login failed");
            }
        }

        function sendMessage() {
            if (!ws) return;
            let text = document.getElementById("msginput").value.trim();
            if (text && text.includes("|")) {
                ws.send(text);
                document.getElementById("msginput").value = "";
            } else {
                alert("Format: otheruser|your message");
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
            if "|" not in data:
                continue
            receiver, msg = data.split("|", 1)
            encrypted = encrypt(msg, users[username]["aes_key"])
            for ws in list(connected.keys()):
                try:
                    await ws.send_text(f"{username}|{receiver}|{encrypted}")
                except:
                    if ws in connected:
                        del connected[ws]
    except WebSocketDisconnect:
        if websocket in connected:
            del connected[websocket]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
