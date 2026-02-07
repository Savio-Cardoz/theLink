#!/usr/bin/env python3
import requests
import json
import sys
import time

BASE_URL = "http://80.225.207.106"
DEVICE_ID = "esp32_001"
USER_PAYLOADS = [
    {"cmd": "led_on"},
    {"cmd": "status_check"}, 
    {"sensor_config": {"interval": 30}}
]

def print_step(step, data=None):
    print(f"\n{'='*60}")
    print(f"📋 STEP {step}")
    print(f"{'='*60}")
    if data: print(json.dumps(data, indent=2))

def test_auth():
    print_step(1, f"Authenticate {DEVICE_ID}")
    
    resp = requests.post(f"{BASE_URL}/auth/init", json={"device_id": DEVICE_ID})
    print(f"Init: {resp.status_code}")
    challenge_data = resp.json()
    challenge_hex = challenge_data['challenge']
    
    # Test response (update server to accept)
    resp = requests.post(f"{BASE_URL}/auth/verify", json={
        "device_id": DEVICE_ID,
        "challenge": challenge_hex,
        "response": "server_test_response_64hex_chars_deadbeefdeadbeef"
    })
    
    if resp.status_code == 200:
        session_token = resp.json()['session_token']
        print(f"✅ Session: {session_token[:16]}...")
        return session_token
    print(f"❌ Auth: {resp.text}")
    return None

def test_poll_and_cleanup(session_token):
    """Poll → Ack → DELETE complete cycle"""
    print_step(2, "Poll + Ack + Delete")
    headers = {"Authorization": f"Bearer {session_token}"}
    
    # Poll unacked messages
    resp = requests.get(f"{BASE_URL}/messages", headers=headers)
    data = resp.json()
    messages = data.get('messages', [])
    
    print(f"📨 Found {len(messages)} messages")
    print(json.dumps(messages, indent=2))
    
    if not messages:
        print("✅ No pending messages - inbox clean!")
        return
    
    # Ack AND Delete each message
    deleted_count = 0
    for msg in messages:
        msg_id = msg['_id']
        
        # 1. Ack message
        ack_resp = requests.patch(f"{BASE_URL}/messages/{msg_id}/ack", headers=headers)
        print(f"  Ack {msg_id}: {ack_resp.status_code}")
        
        # 2. DELETE message (new endpoint below)
        del_resp = requests.delete(f"{BASE_URL}/messages/{msg_id}", headers=headers)
        print(f"  Delete {msg_id}: {del_resp.status_code}")
        
        if del_resp.status_code == 200:
            deleted_count += 1
    
    print(f"🗑️  Deleted {deleted_count}/{len(messages)} messages")

def test_send_message(device_id="esp32_001"):
    print_step(3, "Send Test Messages")
    for i, payload in enumerate(USER_PAYLOADS, 1):
        resp = requests.post(f"{BASE_URL}/send/{device_id}", 
                           json={"payload": payload, "type": "json"})
        result = resp.json()
        print(f"📤 Sent {i}: ID={result.get('message_id')}")

def test_full_cycle():
    print("🔄 Complete IoT Message Lifecycle")
    
    session_token = test_auth()
    if not session_token:
        return
    
    # Send messages
    test_send_message()
    time.sleep(2)
    
    # Receive + cleanup
    test_poll_and_cleanup(session_token)
    
    print("\n🎉 Inbox cleared! Ready for next cycle ✅")

if __name__ == "__main__":
    test_full_cycle()
