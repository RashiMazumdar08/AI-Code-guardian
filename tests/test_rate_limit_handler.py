"""
Unit tests for Rate Limit Handler & 429 Quota Error Handling.
Covering all 12 test conditions specified in requirement specifications.
"""
import pytest
from unittest.mock import MagicMock, patch
from typing import Dict, Any

from guardian.llm.rate_limit_handler import (
    is_rate_limit_error,
    is_daily_quota_error,
    classify_llm_error,
    extract_token_metrics,
    sanitize_error_text,
    extract_finding_context,
    format_rate_limit_warning,
)
from guardian.llm.base import LLMRateLimitError, LLMError
from guardian.llm.nemotron import NemotronLLM
from guardian.llm.grok import GrokLLM
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest
from guardian.agents.chat.agent import InteractiveChatAgent


# 1. test_is_rate_limit_error_positive
def test_is_rate_limit_error_positive():
    assert is_rate_limit_error("HTTP 429 Too Many Requests")
    assert is_rate_limit_error("rate limit exceeded for model")
    assert is_rate_limit_error("quota exhausted: Limit 200000, Used 199401")
    assert is_rate_limit_error("TPD limit reached")
    assert is_rate_limit_error("ResourceExhausted: tokens per day exceeded")


def test_classify_llm_error():
    # 1. SKIPPED_BUDGET
    assert classify_llm_error("SKIPPED_BUDGET: Token budget reserved for scan priority reached") == "SKIPPED_BUDGET"

    # 2. PROVIDER_DAILY_QUOTA
    groq_tpd_err = "HTTP 429 rate_limit_exceeded type=tokens limit=200000 TPD used=199618 requested=1730 retry_after=9m42s"
    assert classify_llm_error(groq_tpd_err) == "PROVIDER_DAILY_QUOTA"
    assert is_daily_quota_error(groq_tpd_err)

    # 3. RATE_LIMITED (TPM)
    groq_tpm_err = "HTTP 429 rate_limit_exceeded: TPM limit reached for model openai/gpt-oss-120b"
    assert classify_llm_error(groq_tpm_err) == "RATE_LIMITED"

    # 4. PROVIDER_UNAVAILABLE
    assert classify_llm_error("HTTP 500 Internal Server Error") == "PROVIDER_UNAVAILABLE"
    assert classify_llm_error("HTTP 401 Unauthorized") == "PROVIDER_UNAVAILABLE"
    assert classify_llm_error("Connection timeout after 30s") == "PROVIDER_UNAVAILABLE"


# 2. test_is_rate_limit_error_negative
def test_is_rate_limit_error_negative():
    assert not is_rate_limit_error("HTTP 500 Internal Server Error")
    assert not is_rate_limit_error("HTTP 401 Unauthorized")
    assert not is_rate_limit_error("HTTP 404 Not Found")
    assert not is_rate_limit_error("Connection timed out after 30s")
    assert not is_rate_limit_error(None)


# 3. test_extract_token_metrics_valid
def test_extract_token_metrics_valid():
    text = "Limit 200,000, Used 199,401, Requested 843. Please try again in 1m45s."
    metrics = extract_token_metrics(text)
    assert metrics["limit"] == 200000
    assert metrics["used"] == 199401
    assert metrics["remaining"] == 599
    assert metrics["requested"] == 843


# 4. test_extract_token_metrics_missing
def test_extract_token_metrics_missing():
    text = "Rate limit reached. Try again later."
    metrics = extract_token_metrics(text)
    assert metrics["limit"] is None
    assert metrics["used"] is None
    assert metrics["remaining"] is None
    assert metrics["requested"] is None


# 5. test_sanitize_error_text_removes_keys_urls_models
def test_sanitize_error_text_removes_keys_urls_models():
    raw = (
        "Error in Groq provider with model openai/gpt-oss-120b or Nemotron. "
        "API key gsk_abc123XYZ and org org_test123. "
        "See https://console.groq.com/docs/rate-limits"
    )
    sanitized = sanitize_error_text(raw)
    assert "gsk_" not in sanitized
    assert "org_test123" not in sanitized
    assert "https://" not in sanitized
    assert "openai/gpt-oss-120b" not in sanitized
    assert "[REDACTED_KEY]" in sanitized
    assert "[AI Provider]" in sanitized


# 6. test_extract_finding_context_from_query
def test_extract_finding_context_from_query():
    query = "Tell me more about finding: Hardcoded Secret"
    title, evidence = extract_finding_context(user_query=query)
    assert title == "Hardcoded Secret"


# 7. test_extract_finding_context_from_report
def test_extract_finding_context_from_report():
    scan_report = {
        "scan": {
            "findings": [
                {
                    "rule_id": "Hardcoded Secret",
                    "file_path": "config/settings.py",
                    "line_number": 42,
                }
            ]
        }
    }
    title, evidence = extract_finding_context(
        user_query="Tell me about this finding", scan_report=scan_report
    )
    assert title == "Hardcoded Secret"
    assert "config/settings.py" in evidence
    assert "line 42" in evidence


# 8. test_format_rate_limit_warning_structure
def test_format_rate_limit_warning_structure():
    exc = LLMRateLimitError("Limit 200000, Used 199401, Requested 843")
    scan_report = {
        "findings": [
            {
                "rule_id": "Hardcoded Secret",
                "file_path": "scan_report.json",
                "line_number": 20,
            }
        ]
    }
    warning = format_rate_limit_warning(
        exc, user_query="Tell me more about finding: Hardcoded Secret", scan_report=scan_report
    )
    assert "⚠️ AI explanation temporarily unavailable" in warning
    assert "Usage: 199,401 / 200,000 tokens" in warning
    assert "Remaining: 599 tokens" in warning
    assert "Requested: ~843 tokens" in warning
    assert "Finding: Hardcoded Secret" in warning
    assert "Evidence: scan_report.json — line 20" in warning
    # Ensure sensitive provider strings are absent
    assert "Groq" not in warning
    assert "Nemotron" not in warning
    assert "gsk_" not in warning


# 9. test_nemotron_llm_rate_limit_no_retry
def test_nemotron_llm_rate_limit_no_retry():
    config = MagicMock()
    config.max_retries = 3
    llm = NemotronLLM(config=config)
    
    with patch.object(llm, "_request_once", side_effect=LLMRateLimitError("Rate limit exceeded 429")):
        with patch("time.sleep") as mock_sleep:
            with pytest.raises(LLMRateLimitError):
                llm._request_with_retry({}, stream=False)
            mock_sleep.assert_not_called()


# 10. test_grok_llm_rate_limit_no_retry
def test_grok_llm_rate_limit_no_retry():
    config = MagicMock()
    config.max_retries = 3
    llm = GrokLLM(config=config)
    
    with patch.object(llm, "_request_once", side_effect=LLMRateLimitError("Rate limit exceeded 429")):
        with patch("time.sleep") as mock_sleep:
            with pytest.raises(LLMRateLimitError):
                llm._request_with_retry({})
            mock_sleep.assert_not_called()


# 11. test_gateway_rate_limit_handling
def test_gateway_rate_limit_handling():
    llm = MagicMock()
    llm.chat.side_effect = LLMRateLimitError("Limit 200000, Used 199401")
    service = NemotronReasoningService(llm=llm, enable_cache=False)
    
    req = ReasoningRequest(task="business_intent", instruction="Analyze rule")
    result = service.reason(req)
    
    assert result.available is False
    assert "⚠️ AI explanation temporarily unavailable" in result.error
    assert "Usage: 199,401 / 200,000 tokens" in result.error


# 12. test_chat_agent_rate_limit_handling
def test_chat_agent_rate_limit_handling():
    import asyncio
    agent = InteractiveChatAgent(tool_registry=MagicMock(), event_bus=MagicMock())
    
    with patch.object(
        agent,
        "_safe_ainvoke",
        side_effect=LLMRateLimitError("Limit 200000, Used 199401, Requested 843"),
    ):
        state = {
            "messages": [{"role": "user", "type": "user", "content": "Tell me more about finding: Hardcoded Secret"}],
            "findings": [{"rule_id": "Hardcoded Secret", "file_path": "auth.py", "line_number": 15}],
        }
        res = asyncio.run(agent.run(state))
        msg_content = res["messages"][0].content
        assert "⚠️ AI explanation temporarily unavailable" in msg_content
        assert "Finding: Hardcoded Secret" in msg_content
        assert "Evidence: auth.py — line 15" in msg_content


# 13. test_ai_security_insights_api_exposure
def test_ai_security_insights_api_exposure():
    from backend.app.api.v1.agentic_scan import _STATE_KEYS, _curated_state
    assert "ai_security_insights" in _STATE_KEYS
    
    sample_state = {
        "scan_id": "test-123",
        "findings": [{"rule_id": "SEC-01", "file": "main.py"}],
        "ai_security_insights": [
            {
                "finding_id": "ai-sec-1",
                "rule_id": "AI-SEC-DESERIALIZATION",
                "source": "AI_VALIDATED",
                "engine": "grok_security_reasoning",
            }
        ],
    }
    curated = _curated_state(sample_state)
    assert "ai_security_insights" in curated
    assert curated["ai_security_insights"][0]["rule_id"] == "AI-SEC-DESERIALIZATION"
