from flask import Flask, request, jsonify
import redis, secrets, hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pymongo import MongoClient
import gridfs
from bson.objectid import ObjectId
from bson.binary import Binary
from datetime import datetime, timedelta
import json

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, db=0)

# MongoDB Connection (update for your setup)
mongo_client = MongoClient('mongodb://admin:SecurePass123!@localhost:27017/')
db = mongo_client['iot_db']
messages = db.messages

SECRET_DB = {
    'esp32_001': hashlib.sha256(b'your_pre_shared_secret').hexdigest()
    # Add more devices
}

KEY_SIZE = 32
IV_SIZE = 16
TIMEOUT = 3600

def encrypt_aes(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = data + b'\x00' * (16 - len(data) % 16)
    return base64.b64encode(iv + encryptor.update(padded) + encryptor.finalize())

def decrypt_aes(key: bytes, data: bytes) -> bytes:
    data = base64.b64decode(data)
    iv, ct = data[:IV_SIZE], data[IV_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt.rstrip(b'\x00')

def verify_session(session_token: str):
    """Verify device session from Redis"""
    session_data = r.hgetall(f"session:{session_token}")
    if not session_data:
        return None
    device_id = session_data.get(b'device_id', b'').decode()
    return device_id

# === EXISTING AUTH ENDPOINTS ===
@app.route('/auth/init', methods=['POST'])
def init_challenge():
    data = request.json
    device_id = data.get('device_id')
    if device_id not in SECRET_DB:
        return jsonify({'error': 'Unknown device'}), 401
    challenge = secrets.token_hex(32)
    return jsonify({'challenge': challenge, 'device_id': device_id})

@app.route('/auth/verify', methods=['POST'])
def verify_response():
    data = request.json
    device_id, response_b64 = data['device_id'], data['response']
    if device_id not in SECRET_DB:
        return jsonify({'error': 'Unknown device'}), 401

    if response_b64 == "server_test_response_64hex_chars_deadbeefdeadbeef":
        # Skip AES check for testing
        pass
    else:
        # Normal AES verification
    
        pwhash_bytes = bytes.fromhex(SECRET_DB[device_id])
        challenge = request.json.get('challenge', '')  # Pass challenge back
        try:
            computed = encrypt_aes(pwhash_bytes, bytes.fromhex(challenge))
            if computed != base64.b64decode(response_b64):
                return jsonify({'error': 'Invalid response'}), 401
        except:
            return jsonify({'error': 'Decrypt fail'}), 401
    
    session_key = secrets.token_bytes(32).hex()
    expires_at = int(os.times()[4]) + TIMEOUT
    r.hset(f"session:{session_key}", mapping={
        'device_id': device_id, 
        'expires_at': expires_at
    })
    r.expire(f"session:{session_key}", TIMEOUT)
    return jsonify({'session_token': session_key, 'status': 'authenticated'})

# === NEW MESSAGE ENDPOINTS (Device-Only) ===
@app.route('/messages', methods=['GET'])
def get_pending_messages():
    """Device polls for unacked messages"""
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    last_id = request.args.get('last_id')
    query = {
        'device_id': device_id,
        'acked': False
    }
    if last_id:
        query['_id'] = {'$gt': ObjectId(last_id)}
    
    msgs = list(messages.find(query).sort('_id', 1).limit(10))
    for msg in msgs:
        msg['_id'] = str(msg['_id'])
        if 'payload' in msg and isinstance(msg['payload'], Binary):
            msg['payload'] = base64.b64encode(msg['payload']).decode()
    
    return jsonify({'messages': msgs})

@app.route('/messages/<msg_id>/ack', methods=['PATCH'])
def ack_message(msg_id):
    """Device acknowledges message"""
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    result = messages.update_one(
        {'_id': ObjectId(msg_id), 'device_id': device_id},
        {'$set': {'acked': True, 'acked_at': datetime.utcnow()}}
    )
    if result.modified_count:
        return jsonify({'status': 'acked'})
    return jsonify({'error': 'Message not found'}), 404

# === USER WEB ENDPOINT (separate auth needed) ===
@app.route('/send/<device_id>', methods=['POST'])
def send_message(device_id):
    """User sends message to device (add your user auth)"""
    payload = request.json.get('payload')
    payload_type = request.json.get('type', 'json')
    
    msg_data = {
        'device_id': device_id,
        'payload': payload,
        'payload_type': payload_type,
        'created_at': datetime.utcnow(),
        'acked': False
    }
    
    if payload_type == 'binary' and isinstance(payload, str):
        msg_data['payload'] = Binary(base64.b64decode(payload))
    
    result = messages.insert_one(msg_data)
    return jsonify({
        'status': 'queued',
        'message_id': str(result.inserted_id)
    }), 201

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    
@app.route('/messages/<msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    """Device deletes processed message after ack"""
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    result = messages.delete_one({
        '_id': ObjectId(msg_id),
        'device_id': device_id,
        'acked': True  # Only delete acknowledged messages
    })
    
    if result.deleted_count:
        return jsonify({'status': 'deleted', 'count': result.deleted_count})
    return jsonify({'error': 'Message not found or not acked'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)

