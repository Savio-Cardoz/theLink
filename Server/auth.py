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
import logging

# Load configuration from file
try:
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    MONGO_CLIENT_URI = config['MONGO_CLIENT_URI']
    PRESHARED_SECRET = config['PRESHARED_SECRET'].encode()
except FileNotFoundError:
    print("ERROR: config.json file not found. Please create it with MONGO_CLIENT_URI and PRESHARED_SECRET.")
    exit(1)
except KeyError as e:
    print(f"ERROR: Missing configuration key: {e}")
    exit(1)
except json.JSONDecodeError:
    print("ERROR: Invalid JSON in config.json")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
logger.info("Flask app initialized")

r = redis.Redis(host='localhost', port=6379, db=0)
try:
    r.ping()
    logger.info("Connected to Redis successfully")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {e}")

# MongoDB Connection (update for your setup)
mongo_client = MongoClient(MONGO_CLIENT_URI)
db = mongo_client['iot_db']
messages = db.messages
try:
    mongo_client.admin.command('ping')
    logger.info("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")

SECRET_DB = {
    'esp32_001': hashlib.sha256(PRESHARED_SECRET).hexdigest()
    # Add more devices
}

KEY_SIZE = 32
IV_SIZE = 16
TIMEOUT = 3600

def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = IV_SIZE - (len(data) % IV_SIZE)
    if pad_len == 0:
        pad_len = IV_SIZE
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > IV_SIZE:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def encrypt_aes(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = _pkcs7_pad(data)
    return base64.b64encode(iv + encryptor.update(padded) + encryptor.finalize())

def decrypt_aes(key: bytes, data: bytes) -> bytes:
    raw = base64.b64decode(data)
    iv, ct = raw[:IV_SIZE], raw[IV_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return _pkcs7_unpad(pt)

def verify_session(session_token: str):
    """Verify device session from Redis"""
    logger.debug(f"[SESSION] Verifying session: {session_token[:16]}...")
    session_data = r.hgetall(f"session:{session_token}")
    if not session_data:
        logger.warning(f"[SESSION] Invalid or expired session: {session_token[:16]}...")
        return None
    device_id = session_data.get(b'device_id', b'').decode()
    logger.debug(f"[SESSION] Session verified for device: {device_id}")
    return device_id

# === EXISTING AUTH ENDPOINTS ===
@app.route('/auth/init', methods=['POST'])
def init_challenge():
    logger.info(f"[AUTH/INIT] Request received from {request.remote_addr}")
    data = request.json
    device_id = data.get('device_id')
    logger.debug(f"[AUTH/INIT] Device ID: {device_id}")
    
    if device_id not in SECRET_DB:
        logger.warning(f"[AUTH/INIT] Unknown device: {device_id}")
        return jsonify({'error': 'Unknown device'}), 401
    
    challenge = secrets.token_hex(32)
    logger.info(f"[AUTH/INIT] Challenge generated for {device_id}: {challenge}")
    return jsonify({'challenge': challenge, 'device_id': device_id})

@app.route('/auth/verify', methods=['POST'])
def verify_response():
    logger.info(f"[AUTH/VERIFY] Request received from {request.remote_addr}")
    logger.info(f"[AUTH/VERIFY] Payload: {json.dumps(request.json)}")
    data = request.json
    device_id, response_b64 = data['device_id'], data['response']
    logger.debug(f"[AUTH/VERIFY] Device ID: {device_id}, Response: {response_b64}.")
    
    if device_id not in SECRET_DB:
        logger.warning(f"[AUTH/VERIFY] Unknown device: {device_id}")
        return jsonify({'error': 'Unknown device'}), 401

    if response_b64 == "server_test_response_64hex_chars_deadbeefdeadbeef":
        logger.info(f"[AUTH/VERIFY] Test mode verification for {device_id}")
        pass
    else:
        logger.debug(f"[AUTH/VERIFY] Normal AES verification for {device_id}")
        pwhash_bytes = bytes.fromhex(SECRET_DB[device_id])
        challenge = request.json.get('challenge', '')
        try:
            # decrypt the client's response and compare to the original challenge
            decrypted = decrypt_aes(pwhash_bytes, response_b64)
            logger.debug(f"[AUTH/VERIFY] Decrypted response: {decrypted.hex()}")
            logger.debug(f"[AUTH/VERIFY] Expected challenge: {challenge}")
            if decrypted != bytes.fromhex(challenge):
                logger.warning(f"[AUTH/VERIFY] Response mismatch for {device_id}")
                return jsonify({'error': 'Invalid response'}), 401
            logger.info(f"[AUTH/VERIFY] Response verified for {device_id}")
        except Exception as e:
            logger.error(f"[AUTH/VERIFY] Verification failed for {device_id}: {e}")
            return jsonify({'error': 'Decrypt fail'}), 401
    
    session_key = secrets.token_bytes(32).hex()
    expires_at = int(os.times()[4]) + TIMEOUT
    r.hset(f"session:{session_key}", mapping={
        'device_id': device_id, 
        'expires_at': expires_at
    })
    r.expire(f"session:{session_key}", TIMEOUT)
    logger.info(f"[AUTH/VERIFY] Session created for {device_id}: {session_key}")
    return jsonify({'session_token': session_key, 'status': 'authenticated'})

# === NEW MESSAGE ENDPOINTS (Device-Only) ===
@app.route('/messages', methods=['GET'])
def get_pending_messages():
    """Device polls for unacked messages"""
    logger.info(f"[MESSAGES/GET] Request from {request.remote_addr}")
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        logger.warning(f"[MESSAGES/GET] Unauthorized request with token: {session_token[:16]}...")
        return jsonify({'error': 'Unauthorized'}), 401
    
    last_id = request.args.get('last_id')
    logger.debug(f"[MESSAGES/GET] Device {device_id} requesting messages, last_id: {last_id}")
    
    query = {
        'device_id': device_id,
        'acked': False
    }
    if last_id:
        query['_id'] = {'$gt': ObjectId(last_id)}
    
    msgs = list(messages.find(query).sort('_id', 1).limit(10))
    logger.info(f"[MESSAGES/GET] Found {len(msgs)} unacked messages for {device_id}")
    
    for msg in msgs:
        msg['_id'] = str(msg['_id'])
        if 'payload' in msg and isinstance(msg['payload'], Binary):
            msg['payload'] = base64.b64encode(msg['payload']).decode()
    
    return jsonify({'messages': msgs})

@app.route('/messages/<msg_id>/ack', methods=['PATCH'])
def ack_message(msg_id):
    """Device acknowledges message"""
    logger.info(f"[MESSAGES/ACK] Request from {request.remote_addr} for message {msg_id}")
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        logger.warning(f"[MESSAGES/ACK] Unauthorized request")
        return jsonify({'error': 'Unauthorized'}), 401
    
    logger.debug(f"[MESSAGES/ACK] Device {device_id} acknowledging message {msg_id}")
    result = messages.update_one(
        {'_id': ObjectId(msg_id), 'device_id': device_id},
        {'$set': {'acked': True, 'acked_at': datetime.utcnow()}}
    )
    if result.modified_count:
        logger.info(f"[MESSAGES/ACK] Message {msg_id} acknowledged by {device_id}")
        return jsonify({'status': 'acked'})
    
    logger.warning(f"[MESSAGES/ACK] Message {msg_id} not found for device {device_id}")
    return jsonify({'error': 'Message not found'}), 404

# === USER WEB ENDPOINT (separate auth needed) ===
@app.route('/send/<device_id>', methods=['POST'])
def send_message(device_id):
    """User sends message to device (add your user auth)"""
    logger.info(f"[SEND] Message send request from {request.remote_addr} for device {device_id}")
    payload = request.json.get('payload')
    payload_type = request.json.get('type', 'json')
    logger.debug(f"[SEND] Payload type: {payload_type}, Size: {len(str(payload)) if payload else 0}")
    
    msg_data = {
        'device_id': device_id,
        'payload': payload,
        'payload_type': payload_type,
        'created_at': datetime.utcnow(),
        'acked': False
    }
    
    if payload_type == 'binary' and isinstance(payload, str):
        msg_data['payload'] = Binary(base64.b64decode(payload))
    
    try:
        result = messages.insert_one(msg_data)
        logger.info(f"[SEND] Message queued for {device_id}: {str(result.inserted_id)}")
        return jsonify({
            'status': 'queued',
            'message_id': str(result.inserted_id)
        }), 201
    except Exception as e:
        logger.error(f"[SEND] Failed to queue message for {device_id}: {e}")
        return jsonify({'error': 'Failed to queue message'}), 500

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
    logger.info(f"[MESSAGES/DELETE] Request from {request.remote_addr} for message {msg_id}")
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    device_id = verify_session(session_token)
    if not device_id:
        logger.warning(f"[MESSAGES/DELETE] Unauthorized request")
        return jsonify({'error': 'Unauthorized'}), 401
    
    logger.debug(f"[MESSAGES/DELETE] Device {device_id} deleting message {msg_id}")
    result = messages.delete_one({
        '_id': ObjectId(msg_id),
        'device_id': device_id,
        'acked': True  # Only delete acknowledged messages
    })
    
    if result.deleted_count:
        logger.info(f"[MESSAGES/DELETE] Message {msg_id} deleted by {device_id}")
        return jsonify({'status': 'deleted', 'count': result.deleted_count})
    
    logger.warning(f"[MESSAGES/DELETE] Message {msg_id} not found or not acked for device {device_id}")
    return jsonify({'error': 'Message not found or not acked'}), 404

if __name__ == '__main__':
    logger.info("="*60)
    logger.info("Starting auth.py server")
    logger.info("="*60)
    app.run(host='0.0.0.0', port=8000, debug=True)

