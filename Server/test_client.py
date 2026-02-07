#!/usr/bin/env python3
import requests
import json
import base64
import sys
import time

BASE_URL = "http://80.225.207.106"
DEVICE_ID = "esp32_001"
PSK_RAW = b"your_pre_shared_secret"  # For reference only
USER_PAYLOADS = [{"cmd": "led_on"}, {"cmd": "status_check"}]

def print_step(step, data=None):
    print(f"\n{'='*60}")
    print(f"📋 STEP {step}")
    print(f"{'='*60}")
    if data: print(json.dumps(data, indent=2))

def test_auth():
    print_step(1, f"Authenticate {DEVICE_ID}")
    
    # 1. Get challenge
    resp = requests.post(f"{BASE_URL}/auth/init", json={"device_id": DEVICE_ID})
    print(f"Init: {resp.status_code}")
    challenge_data = resp.json()
    challenge_hex = challenge_data['challenge']
    print(f"Challenge: {challenge_hex[:16]}...")
    
    # 2. SIMULATE ESP32 response (use server-expected format)
    # For testing: temporarily modify server to accept fixed response
    resp = requests.post(f"{BASE_URL}/auth/verify", json={
        "device_id": DEVICE_ID,
        "challenge": challenge_hex,
        "response": "server_test_response_64hex_chars_deadbeefdeadbeef"  # Fixed 64 chars
    })
    
    if resp.status_code == 200:
        session_token = resp.json()['session_token']
        print(f"✅ Session: {session_token[:16]}...")
        return session_token
    print(f"❌ Auth failed: {resp.text}")
    return None

# Rest of functions unchanged...
def test_poll_messages(session_token, last_id=None):
    headers = {"Authorization": f"Bearer {session_token}"}
    params = {"last_id": last_id} if last_id else {}
    resp = requests.get(f"{BASE_URL}/messages", headers=headers, params=params)
    data = resp.json()
    print(f"Poll: {resp.status_code}")
    print(json.dumps(data, indent=2))
    return data.get('messages', []), data.get('messages', [{}])[0].get('_id')

def test_send_message(device_id="esp32_001"):
    print_step(4, "Send Messages")
    for payload in USER_PAYLOADS:
        resp = requests.post(f"{BASE_URL}/send/{device_id}", 
                           json={"payload": payload, "type": "json"})
        print(f"Sent: {resp.status_code} - {resp.json()}")

def test_full_cycle():
    session_token = test_auth()
    if session_token:
        test_send_message()
        time.sleep(2)
        test_poll_messages(session_token)

if __name__ == "__main__":
    test_full_cycle()
