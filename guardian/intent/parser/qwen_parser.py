"""
Qwen2.5-3B-Instruct Local Business-Rule Parser
===============================================
Primary natural-language business requirement parser for AI Code Guardian.
Uses local Hugging Face transformers inference to decompose natural-language
requirements into structured policy concepts (action, condition, control, evidence_terms).

Execution model:
- 100% LOCAL inference (no Gemini, Claude, OpenAI, or Groq API calls).
- Zero API keys required.
- Lazy loading & cached model instance for efficiency.
- Strictly parses requirement text into JSON schema.
- Does NOT analyze code/AST and does NOT generate compliance verdicts.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional

from guardian.intent.ingestion.document_loader import Requirement

log = logging.getLogger(__name__)

# Default model identifiers
DEFAULT_QWEN_MODEL = "Qwen/Qwen2.5-3B-Instruct"

_MODEL_LOCK = threading.Lock()
_QWEN_MODEL_CACHE: Dict[str, Any] = {}


class QwenRuleParser:
    """Local Qwen2.5-3B-Instruct parser for business requirement decomposition."""

    def __init__(
        self,
        model_name: str | None = None,
        local_path: str | None = None,
        device: str = "cpu",
        timeout: int = 30,
    ):
        self.model_name = model_name or os.getenv("LLM_RULE_PARSER_MODEL", DEFAULT_QWEN_MODEL)
        self.local_path = local_path or os.getenv("LLM_RULE_PARSER_LOCAL_PATH", "")
        self.device = device
        self.timeout = timeout
        self.tokenizer = None
        self.model = None
        self._loaded = False
        self._load_error = None

    def _ensure_model_loaded(self) -> bool:
        """Lazily load tokenizer and model for direct HF transformers local inference."""
        if self._loaded:
            return self.model is not None
        if self._load_error:
            return False

        with _MODEL_LOCK:
            if self._loaded:
                return self.model is not None

            target_path = self.local_path or self.model_name
            cache_key = f"{target_path}:{self.device}"

            if cache_key in _QWEN_MODEL_CACHE:
                cached = _QWEN_MODEL_CACHE[cache_key]
                self.tokenizer = cached["tokenizer"]
                self.model = cached["model"]
                self._loaded = True
                return True

            # Check if local weights directory exists on disk or model weights exist in HF cache
            is_local = os.path.isdir(target_path)
            if not is_local:
                try:
                    from huggingface_hub import try_to_load_from_cache
                    cached_weight = (
                        try_to_load_from_cache(target_path, "model.safetensors")
                        or try_to_load_from_cache(target_path, "model.safetensors.index.json")
                        or try_to_load_from_cache(target_path, "model-00001-of-00002.safetensors")
                    )
                    if isinstance(cached_weight, str) and os.path.exists(cached_weight):
                        is_local = True
                except Exception:
                    pass

            if not is_local and os.getenv("LLM_RULE_PARSER_ALLOW_DOWNLOAD", "false").lower() != "true":
                log.info("Local Qwen2.5-3B-Instruct model weights not found at '%s'. Using deterministic RuleParser fallback.", target_path)
                self._load_error = "Local model weights not found"
                self._loaded = True
                return False

            try:
                log.info("Loading local Qwen2.5-3B-Instruct model from '%s' on %s...", target_path, self.device)
                from transformers import AutoModelForCausalLM, AutoTokenizer
                import torch

                local_only = is_local

                tokenizer = AutoTokenizer.from_pretrained(
                    target_path,
                    trust_remote_code=True,
                    local_files_only=local_only,
                )
                
                # Configure torch dtype
                torch_dtype = torch.float32
                if self.device != "cpu" and torch.cuda.is_available():
                    torch_dtype = torch.bfloat16

                model = AutoModelForCausalLM.from_pretrained(
                    target_path,
                    dtype=torch_dtype,
                    device_map=None,
                    trust_remote_code=True,
                    local_files_only=local_only,
                    low_cpu_mem_usage=False,
                )

                if self.device == "cpu":
                    model = model.to("cpu")

                model.eval()

                self.tokenizer = tokenizer
                self.model = model
                self._loaded = True

                _QWEN_MODEL_CACHE[cache_key] = {
                    "tokenizer": tokenizer,
                    "model": model,
                }
                log.info("Successfully loaded local Qwen2.5-3B-Instruct model.")
                return True
            except Exception as exc:
                log.warning("Local Qwen2.5-3B-Instruct model load notice (%s): %s", target_path, exc)
                self._load_error = str(exc)
                self._loaded = True
                return False

    def build_prompt(self, req: Requirement) -> str:
        """Construct structured parsing prompt for Qwen."""
        system_instruction = (
            "You are a precise business requirement parser for AI Code Guardian.\n"
            "Your task is to analyze natural language business requirements and extract structured domain concepts into valid JSON.\n\n"
            "Respond ONLY with a JSON object containing these exact 4 keys:\n"
            '1. "action": target operation (e.g. "add item to cart", "transfer balance", "calculate checkout price", "cancel order")\n'
            '2. "condition": rule threshold, condition, or prerequisite (e.g. "quantity > 0", "amount <= available_balance", "before shipment", "none" if absent)\n'
            '3. "control": required control, guard check, or constraint (e.g. "inventory >= quantity", "atomic transaction lock", "server-side calculation")\n'
            '4. "evidence_terms": array of domain keywords useful for repository evidence search\n\n'
            "Rules:\n"
            "- Extract ONLY concepts present in or directly implied by the requirement text.\n"
            "- Do NOT evaluate code compliance or generate verdicts.\n"
            "- Output valid raw JSON only. Do not include extra conversational prose."
        )

        user_content = (
            f"Rule ID: {req.id}\n"
            f"Title: {req.title}\n"
            f"Requirement: {req.text}"
        )

        if hasattr(self.tokenizer, "apply_chat_template") and self.tokenizer is not None:
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content},
            ]
            try:
                return self.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )
            except Exception:
                pass

        # Generic prompt fallback
        return f"<|im_start|>system\n{system_instruction}<|im_end|>\n<|im_start|>user\n{user_content}<|im_end|>\n<|im_start|>assistant\n"

    def parse_requirement(self, req: Requirement) -> Optional[dict[str, Any]]:
        """Parse natural language requirement into structured concept dictionary.
        
        Returns None on failure/disabled model to trigger deterministic RuleParser fallback.
        """
        if not self._ensure_model_loaded():
            return None

        prompt = self.build_prompt(req)

        try:
            import torch

            inputs = self.tokenizer(prompt, return_tensors="pt")
            if self.device != "cpu" and torch.cuda.is_available():
                inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=256,
                    temperature=0.1,
                    top_p=0.9,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            generated_tokens = outputs[0][inputs["input_ids"].shape[1]:]
            raw_text = self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()

            return self.extract_structured_json(raw_text)
        except Exception as exc:
            log.warning("Qwen local inference execution notice for %s: %s", req.id, exc)
            return None

    def extract_structured_json(self, raw_text: str) -> Optional[dict[str, Any]]:
        """Clean raw LLM text and parse into validated structured dictionary."""
        if not raw_text:
            return None

        # Clean markdown wrappers if present
        text = raw_text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)

        # Locate first '{' and last '}'
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                action = str(data.get("action", "")).strip()
                condition = str(data.get("condition", "")).strip()
                control = str(data.get("control", "")).strip()
                evidence_terms = data.get("evidence_terms", [])
                if not isinstance(evidence_terms, list):
                    evidence_terms = [str(evidence_terms)]
                evidence_terms = [str(t).strip() for t in evidence_terms if str(t).strip()]

                if action or control or condition:
                    return {
                        "action": action or "generic_action",
                        "condition": condition or "none",
                        "control": control or "generic_control",
                        "evidence_terms": evidence_terms,
                    }
        except Exception as exc:
            log.debug("JSON extraction notice: %s", exc)

        return None
