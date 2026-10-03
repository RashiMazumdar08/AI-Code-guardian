import time
from guardian.llm.config import LLMConfig
from guardian.llm.nemotron import NemotronLLM

def main():
    cfg = LLMConfig.from_env()
    print("=== CONFIG ===")
    print("Provider:", cfg.provider)
    print("Model:", cfg.model)
    print("Base URL:", cfg.base_url)

    client = NemotronLLM(cfg)

    print("\n=== TESTING DIRECT NEMOTRON CALL ===")
    t0 = time.time()
    try:
        resp = client.chat([
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": 'Respond with JSON: {"status": "ok"}'}
        ], max_tokens=50)
        dur = round((time.time() - t0) * 1000, 1)
        print(f"STATUS: SUCCESS ({dur}ms)")
        print("Model:", resp.model)
        print("Tokens:", resp.prompt_tokens, "prompt /", resp.completion_tokens, "completion /", resp.total_tokens, "total")
        print("Content:", resp.content)
    except Exception as e:
        dur = round((time.time() - t0) * 1000, 1)
        print(f"STATUS: FAILED ({dur}ms)")
        print("Error:", type(e).__name__, "-", str(e))

if __name__ == "__main__":
    main()
