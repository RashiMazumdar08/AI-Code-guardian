import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm

print("=== LLM CONFIGURATION DIAGNOSTIC ===")

# 1. Environment Variables check
env_keys = [
    "XAI_API_KEY", "GROK_API_KEY", "XAI_BASE_URL", "GROK_BASE_URL", "XAI_MODEL", "GROK_MODEL",
    "NVIDIA_API_KEY", "NVIDIA_BASE_URL", "NVIDIA_MODEL", "GROQ_API_KEY", "OPENAI_API_KEY", "LLM_PROVIDER"
]

print("\n1. Environment Variables in os.environ / .env:")
for k in env_keys:
    val = os.getenv(k)
    if val:
        masked = val[:8] + "..." if ("KEY" in k and len(val) > 8) else val
        print(f"  {k} = {masked}")
    else:
        print(f"  {k} = (NOT SET)")

# 2. LLMConfig.from_env() resolution
cfg = LLMConfig.from_env()
print("\n2. Resolved LLMConfig:")
print(f"  provider: {cfg.provider}")
print(f"  base_url: {cfg.base_url}")
print(f"  model: {cfg.model}")
masked_key = cfg.api_key[:8] + "..." if len(cfg.api_key) > 8 else cfg.api_key
print(f"  api_key: {masked_key}")

# 3. Factory Client instantiation
llm_client = create_llm(config=cfg)
print("\n3. Instantiated LLM Client:")
print(f"  class: {type(llm_client).__name__}")
print(f"  model_name: {llm_client.model_name}")

# 4. Test live call to the configured API
print("\n4. Testing Live API Request to Provider...")
try:
    resp = llm_client.chat([{"role": "user", "content": "Respond with 'OK'."}])
    print("  Status: SUCCESS")
    print(f"  Response content: {resp.content}")
    print(f"  Tokens used: {resp.total_tokens}")
except Exception as e:
    print("  Status: ERROR / FAILED")
    print(f"  Error type: {type(e).__name__}")
    print(f"  Error message: {e}")
