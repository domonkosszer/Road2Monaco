import json
import os
import base64
import tempfile
import threading
from datetime import datetime
from filelock import FileLock

DB_FILE = "known_peers.json"

def log(message: str):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}")

def load_known_peers():
    with FileLock(DB_FILE + ".lock", timeout=5):
        if not os.path.exists(DB_FILE):
            return {}
        try:
            with open(DB_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            backup_path = DB_FILE + ".corrupted"
            if not os.path.exists(backup_path):
                os.rename(DB_FILE, backup_path)
                log(f"Corrupted {DB_FILE} backed up to {backup_path}. Starting fresh.")
            else:
                log(f"{DB_FILE} is corrupted. Using fresh DB (backup already exists).")
            return {}

def save_known_peers(data):
    with FileLock(DB_FILE + ".lock", timeout=5):
        with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(DB_FILE), encoding="utf-8") as tmp:
            json.dump(data, tmp, indent=2)
            temp_name = tmp.name
        os.replace(temp_name, DB_FILE)  # atomic on most OSes

def save_peer_salt(peer_id: str, salt: bytes, group_id: str = None):
    db = load_known_peers()
    key = f"{group_id}:{peer_id}" if group_id else peer_id
    db[key] = {
        "peer_id": peer_id,
        "group_id": group_id,
        "salt": base64.b64encode(salt).decode(),
        "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        "last_seen": datetime.utcnow().isoformat()
    }
    save_known_peers(db)
    log(f"Saved salt for peer '{peer_id}' in group '{group_id}' at {db[key]['timestamp']}")

def update_last_seen(peer_id: str, group_id: str = None):
    db = load_known_peers()
    key = f"{group_id}:{peer_id}" if group_id else peer_id
    if key in db:
        db[key]["last_seen"] = datetime.utcnow().isoformat()
    else:
        db[key] = {
            "peer_id": peer_id,
            "group_id": group_id,
            "last_seen": datetime.utcnow().isoformat()
        }
    save_known_peers(db)

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

def load_last_seen():
    db = load_known_peers()
    result = {}
    for peer_id, data in db.items():
        if isinstance(data, dict) and "last_seen" in data:
            result[peer_id] = data["last_seen"]
    return result
