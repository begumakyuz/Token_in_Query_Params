import requests
import time
import subprocess
import os

# 🛡️ LIVE SECURITY DEMONSTRATION & AUDIT
# This script performs a live, practical demonstration of the L14 project's mitigations.

BASE_URL = "http://127.0.0.1:5000"
TOKEN = "secure_api_key_placeholder"

def run_demonstration():
    print("\n--- [1. VULNERABILITY DEMONSTRATION] ---")
    print("Sending Token via URL Query Parameters (GET)...")
    url = f"{BASE_URL}/vulnerable/download?token={TOKEN}"
    try:
        r = requests.get(url)
        print(f"Status Code: {r.status_code}")
        print(f"JSON Response: {r.json()}")
        print("\n\033[93m[Audit Note]: This token will now be visible in Nginx access.log files.\033[0m")
    except Exception as e:
        print(f"Failed to connect: {e}")

    print("\n--- [2. SECURITY REMEDIATION DEMONSTRATION] ---")
    print("Attempting to access /secure/download without Headers...")
    try:
        r = requests.get(f"{BASE_URL}/secure/download")
        print(f"Status Code: {r.status_code}")
        print(f"JSON Response: {r.json()}")
    except Exception as e:
        print(f"Failed to connect: {e}")

    print("\n--- [3. SUCCESSFUL BEARER AUTHENTICATION] ---")
    print("Sending Token via Authorization: Bearer Header (Encrypted Pipeline)...")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    try:
        r = requests.get(f"{BASE_URL}/secure/download", headers=headers)
        print(f"Status Code: {r.status_code}")
        print(f"JSON Response: {r.json()}")
        print(f"Security Headers Observed: { {k: v for k, v in r.headers.items() if 'X-' in k or 'Strict-' in k} }")
    except Exception as e:
        print(f"Failed to connect: {e}")

    print("\n--- [4. AUTOMATED SECURITY SUITE (PYTEST)] ---")
    print("Executing full compliance test suite...")
    subprocess.run(["pytest", "tests/test_app.py", "-v"], shell=True)

if __name__ == "__main__":
    run_demonstration()
