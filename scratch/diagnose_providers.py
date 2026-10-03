import sys
import os
import time
import requests

sys.path.insert(0, os.path.abspath("."))
from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm
from guardian.agents.business.agent import BusinessAgent
from guardian.agents.architecture.agent import ArchitectureAgent

def diagnose_gemini():
    print("==================================================")
    print("1. DIAGNOSING BUSINESSAGENT / GEMINI")
    print("==================================================")
    cfg = LLMConfig.from_env(agent="business")
    print(f"Provider: {cfg.provider}")
    print(f"Model: {cfg.model}")
    print(f"Base URL: {cfg.base_url}")
    print(f"API Key set?: {bool(cfg.api_key)}")

    # Make raw request to capture exact HTTP status and error body
    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "user", "content": "Respond with JSON: {\"status\": \"ok\"}"}
        ],
        "max_tokens": 100
    }
    url = f"{cfg.base_url.rstrip('/')}/chat/completions"
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        print(f"HTTP Status: {r.status_code}")
        print("Response Headers:")
        for k, v in r.headers.items():
            if "rate" in k.lower() or "retry" in k.lower() or "quota" in k.lower():
                print(f"  {k}: {v}")
        print(f"Response Body: {r.text[:500]}")
    except Exception as e:
        print(f"Exception calling Gemini: {type(e).__name__} - {e}")

def diagnose_groq():
    print("\n==================================================")
    print("2. DIAGNOSING ARCHITECTUREAGENT / GROQ")
    print("==================================================")
    cfg = LLMConfig.from_env(agent="architecture")
    print(f"Provider: {cfg.provider}")
    print(f"Model: {cfg.model}")
    print(f"Base URL: {cfg.base_url}")
    print(f"API Key set?: {bool(cfg.api_key)}")

    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "user", "content": "Respond with JSON: {\"status\": \"ok\"}"}
        ],
        "max_tokens": 100
    }
    url = f"{cfg.base_url.rstrip('/')}/chat/completions"
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        print(f"HTTP Status: {r.status_code}")
        print("Response Headers:")
        for k, v in r.headers.items():
            if "rate" in k.lower() or "retry" in k.lower() or "limit" in k.lower() or "reset" in k.lower() or "remaining" in k.lower():
                print(f"  {k}: {v}")
        print(f"Response Body: {r.text[:500]}")
    except Exception as e:
        print(f"Exception calling Groq: {type(e).__name__} - {e}")

if __name__ == "__main__":
    diagnose_gemini()
    diagnose_groq()
