from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel
from typing import List, Dict
import uvicorn
from cryptography.fernet import Fernet
import base64

app = FastAPI()

# In-memory storage for messages and user keys
messages: List[Dict] = []
user_keys: Dict[str, bytes] = {}

class Message(BaseModel):
    sender: str
    recipient: str
    content: str

def generate_key():
    return Fernet.generate_key()

def encrypt_message(key: bytes, message: str) -> str:
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(key: bytes, encrypted_message: str) -> str:
    f = Fernet(key)
    decrypted_message = f.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode()

@app.post("/register")
async def register_user(username: str):
    if username in user_keys:
        raise HTTPException(status_code=400, detail="Username already exists")
    key = generate_key()
    user_keys[username] = key
    return {"message": "User registered successfully", "key": key.decode()}

@app.post("/send")
async def send_message(message: Message):
    if message.sender not in user_keys or message.recipient not in user_keys:
        raise HTTPException(status_code=400, detail="Sender or recipient not registered")
    
    sender_key = user_keys[message.sender]
    recipient_key = user_keys[message.recipient]
    
    # Encrypt with sender's key
    encrypted_for_sender = encrypt_message(sender_key, message.content)
    
    # Encrypt with recipient's key
    encrypted_for_recipient = encrypt_message(recipient_key, message.content)
    
    messages.append({
        "sender": message.sender,
        "recipient": message.recipient,
        "content_for_sender": encrypted_for_sender,
        "content_for_recipient": encrypted_for_recipient
    })
    return {"message": "Message sent successfully"}

@app.get("/messages/{username}")
async def get_messages(username: str):
    if username not in user_keys:
        raise HTTPException(status_code=400, detail="User not registered")
    
    user_key = user_keys[username]
    user_messages = [
        msg for msg in messages 
        if msg["recipient"] == username or msg["sender"] == username
    ]
    
    decrypted_messages = []
    for msg in user_messages:
        if msg["recipient"] == username:
            encrypted_content = msg["content_for_recipient"]
        else:  # msg["sender"] == username
            encrypted_content = msg["content_for_sender"]
        
        decrypted_content = decrypt_message(user_key, encrypted_content)
        decrypted_messages.append({
            "sender": msg["sender"],
            "recipient": msg["recipient"],
            "content": decrypted_content
        })
    
    return decrypted_messages

@app.get("/raw_messages")
async def get_raw_messages():
    return messages

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)