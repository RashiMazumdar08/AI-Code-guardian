import os
import sys

sys.path.insert(0, os.path.abspath("."))

from guardian.llm.config import LLMConfig, load_dotenv
load_dotenv()

from guardian.llm.grok import GrokLLM

print("=== TESTING XAI GROK MODELS WITH USER'S KEY ===")

xai_key = os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("NVIDIA_API_KEY")
print(f"Loaded Key prefix: {xai_key[:8] if xai_key else 'NONE'}...")

models_to_test = ["grok-2-latest", "grok-beta", "grok-2-1212", "grok-4.7"]

for m in models_to_test:
    print(f"\nTesting model: '{m}'")
    cfg = LLMConfig(
        api_key=xai_key,
        base_url="https://api.x.ai/v1",
        model=m,
        provider="grok"
    )
    grok_client = GrokLLM(cfg)
    try:
        resp = grok_client.chat([{"role": "user", "content": "Respond with 'OK'."}])
        print(f"  Result: SUCCESS! Response: {resp.content.strip()}")
    except Exception as e:
        print(f"  Result: FAILED - {e}")
