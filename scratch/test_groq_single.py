import sys
import os
sys.path.insert(0, os.path.abspath("."))
import time
import json
from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm

def main():
    cfg = LLMConfig.from_env(agent="architecture")
    print(f"Provider: {cfg.provider}")
    print(f"Model: {cfg.model}")
    print(f"Base URL: {cfg.base_url}")

    llm = create_llm("nemotron", cfg)
    t0 = time.time()
    try:
        resp = llm.chat([
            {"role": "system", "content": "You are a test assistant. Reply strictly in valid JSON."},
            {"role": "user", "content": 'Return JSON {"status": "ok", "message": "groq test"}'}
        ], max_tokens=500)
        latency = (time.time() - t0) * 1000
        print("HTTP Status: 200 OK")
        print(f"Latency: {latency:.1f}ms")
        print(f"Response Model: {resp.model}")
        print(f"Parsed Content: {resp.content}")
        print(f"Tokens: prompt={resp.prompt_tokens}, completion={resp.completion_tokens}, total={resp.total_tokens}")
    except Exception as e:
        print(f"Error: {type(e).__name__} - {e}")

if __name__ == "__main__":
    main()
