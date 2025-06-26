# peers.py

import json
import os
import base64
from datetime import datetime

def log(message: str):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}")

DB_FILE = "known_peers.json"

def load_known_peers():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        log("Failed to load known_peers.json. Starting with empty peer DB.")
        return {}

def save_peer_salt(peer_id: str, salt: bytes, group_id: str = None):
    db = load_known_peers()
    key = f"{group_id}:{peer_id}" if group_id else peer_id
    db[key] = {
        "peer_id": peer_id,
        "group_id": group_id,
        "salt": base64.b64encode(salt).decode(),
        "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    }
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)
    log(f"Saved salt for peer '{peer_id}' in group '{group_id}' at {db[key]['timestamp']}: {db[key]['salt']}")

def get_peer_salt(peer_id: str, group_id: str = None):
    db = load_known_peers()
    key = f"{group_id}:{peer_id}" if group_id else peer_id
    try:
        entry = db.get(key, "")
        if isinstance(entry, dict) and "salt" in entry:
            return base64.b64decode(entry["salt"])
        elif isinstance(entry, str):
            return base64.b64decode(entry)
        else:
            return None
    except base64.binascii.Error:
        log(f"Invalid salt format for peer '{key}'")
        return None