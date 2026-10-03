import os
import time
import requests

url = "https://integrate.api.nvidia.com/v1/models"
api_key = "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"

headers = {
    "Authorization": f"Bearer {api_key}",
    "Accept": "application/json"
}

print("Checking NVIDIA API models endpoint...")
t0 = time.time()
try:
    resp = requests.get(url, headers=headers, timeout=30)
    dur = round(time.time() - t0, 2)
    print(f"Status Code: {resp.status_code}")
    print(f"Duration: {dur}s")
    if resp.status_code == 200:
        models = [m["id"] for m in resp.json().get("data", []) if "nemotron" in m["id"].lower()]
        print(f"Nemotron models ({len(models)}): {models}")
    else:
        print(f"Error Body: {resp.text[:300]}")
except Exception as exc:
    dur = round(time.time() - t0, 2)
    print(f"Request failed after {dur}s: {exc}")
