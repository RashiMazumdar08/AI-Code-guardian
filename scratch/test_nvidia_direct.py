import time
import requests
import json
import os
from guardian.llm.config import LLMConfig

def main():
    cfg = LLMConfig.from_env()
    print("=== DIRECT HTTP TEST TO NVIDIA API ===")
    print("Base URL:", cfg.base_url)
    print("Model:", cfg.model)
    print("API Key present:", bool(cfg.api_key))

    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Return JSON: {\"status\": \"ok\"}"}
        ],
        "max_tokens": 100,
        "temperature": 0.1
    }

    t0 = time.time()
    try:
        r = requests.post(f"{cfg.base_url}/chat/completions", headers=headers, json=payload, timeout=180)
        dur = round((time.time() - t0) * 1000, 1)
        print(f"HTTP Status: {r.status_code} ({dur}ms)")
        print("Response body:")
        print(r.text[:500])
    except Exception as e:
        dur = round((time.time() - t0) * 1000, 1)
        print(f"HTTP Request Failed ({dur}ms):", type(e).__name__, "-", str(e))

if __name__ == "__main__":
    main()
