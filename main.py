from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel
from typing import List, Dict

import uvicorn
from cryptography.fernet import Fernet
import base64

app = FastAPI()

# in-memory message storage
messages: List[Dict] = []
users_keys: Dict[str,bytes] = {}

class Messages(BaseModel):
    sender: str
    recipient: str
    content: str

def generate_key():
    return Fernet.generate_key()

def encrypt_message(key: bytes, message:str) -> str:
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()


def decrypt_message(key: bytes, encrypted_message: str) -> str:
    f= Fernet(key)
    decrypted_message = f.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode()


@app.post("/register")
async def register_user(username: str):
    if username in users_keys:
        raise HTTPException(status_code=400, detail="Username already exists")
    key = generate_key()
    users_keys[username] = key
    return {"message":"User registered successfully", "key": key.decode()}

