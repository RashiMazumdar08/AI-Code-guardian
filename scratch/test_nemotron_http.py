import os
import time
import requests

url = "https://integrate.api.nvidia.com/v1/chat/completions"
api_key = "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"
model = "nvidia/nemotron-3.5-lightning-30b-a3b"

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

payload = {
    "model": model,
    "messages": [
        {"role": "user", "content": "Hi"}
    ],
    "max_tokens": 10,
    "stream": True
}

print(f"Testing streaming request for {model}...")
t0 = time.time()
try:
    resp = requests.post(url, headers=headers, json=payload, stream=True, timeout=120)
    print(f"Status Code: {resp.status_code} (took {round(time.time() - t0, 2)}s)")
    for line in resp.iter_lines():
        if line:
            print(f"Stream line: {line.decode('utf-8')[:100]}")
            break
except Exception as exc:
    dur = round(time.time() - t0, 2)
    print(f"Streaming failed after {dur}s: {exc}")
