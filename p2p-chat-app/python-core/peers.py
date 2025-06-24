# peers.py

import json
import os
import base64

DB_FILE = "known_peers.json"

def load_known_peers():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_peer_salt(peer_id: str, salt: bytes):
    db = load_known_peers()
    db[peer_id] = base64.b64encode(salt).decode()
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def get_peer_salt(peer_id: str):
    db = load_known_peers()
    if peer_id in db:
        return base64.b64decode(db[peer_id])
    return None