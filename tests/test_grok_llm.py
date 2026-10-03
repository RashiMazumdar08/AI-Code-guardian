"""
Unit tests for Grok (xAI) LLM integration & optional AI reasoning across agents.
"""
import pytest
import json
from unittest.mock import MagicMock, patch

from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm, available_providers
from guardian.llm.base import BaseLLM, LLMError, LLMResponse
from guardian.llm.grok import GrokLLM
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, ReasoningResult

from guardian.agents.security.agent import SecurityAgent
from guardian.agents.business.agent import BusinessAgent
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.agents.threat_simulation.agent import ThreatSimulationAgent
from guardian.agents.validation.agent import ValidationAgent
from guardian.agents.patch.agent import PatchGenerationAgent
from guardian.agents.chat.agent import InteractiveChatAgent


class TestGrokConfigAndFactory:
    def test_grok_provider_registered(self):
        providers = available_providers()
        assert "grok" in providers
        assert "xai" in providers

    def test_grok_config_env_loading(self, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key-1234567890")
        monkeypatch.setenv("XAI_MODEL", "grok-2-custom")
        monkeypatch.setenv("LLM_ENABLED", "true")

        cfg = LLMConfig.from_env(dotenv_path="/nonexistent")
        assert cfg.provider == "grok"
        assert cfg.api_key == "xai-test-key-1234567890"
        assert cfg.model == "grok-2-custom"
        assert cfg.enabled is True
        assert cfg.is_configured is True
        assert cfg.is_agent_enabled("security") is True

    def test_llm_disabled_config(self, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key-1234567890")
        monkeypatch.setenv("LLM_ENABLED", "false")

        cfg = LLMConfig.from_env(dotenv_path="/nonexistent")
        assert cfg.enabled is False
        assert cfg.is_configured is False
        assert cfg.is_agent_enabled("security") is False

    def test_create_grok_llm_instance(self, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key-1234567890")
        cfg = LLMConfig.from_env(dotenv_path="/nonexistent")
        llm = create_llm("grok", config=cfg)
        assert isinstance(llm, BaseLLM)
        assert isinstance(llm, GrokLLM)
        assert llm.model_name == cfg.model


class TestGrokLLMClient:
    def test_grok_chat_completion_mock(self, monkeypatch):
        cfg = LLMConfig(api_key="xai-key-123", provider="grok", base_url="https://api.x.ai/v1")
        llm = GrokLLM(config=cfg)

        fake_resp = {
            "choices": [{"message": {"content": "Hello from Grok!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        monkeypatch.setattr(llm, "_request_once", lambda payload: fake_resp)

        res = llm.chat([{"role": "user", "content": "hi"}])
        assert res.content == "Hello from Grok!"
        assert res.total_tokens == 15

    def test_grok_gateway_reasoning(self, monkeypatch):
        cfg = LLMConfig(api_key="xai-key-123", provider="grok")
        gateway = ReasoningGateway(config=cfg)

        json_payload = json.dumps({
            "summary": "Semantic security gap found",
            "findings": [
                {
                    "evidence_ids": ["E1"],
                    "category": "auth_bypass",
                    "severity": "High",
                    "confidence": 0.85,
                    "reason": "Missing secondary token check",
                    "recommendation": "Add JWT verification",
                    "file": "auth.py",
                    "line": 42
                }
            ]
        })

        fake_llm_response = LLMResponse(content=json_payload, model="grok-2-latest")
        monkeypatch.setattr(gateway, "_client", lambda: MagicMock(chat=lambda msgs, **kw: fake_llm_response))

        req = ReasoningRequest(
            task="security_reasoning",
            instruction="Analyze security evidence",
            evidence_block="[E1] auth.py:42 check_token()",
        )
        res = gateway.reason(req)
        assert res.ok is True
        assert len(res.findings) == 1
        assert res.findings[0].category == "auth_bypass"


class TestAgentsWithGrokDisabledAndEnabled:
    @pytest.fixture
    def mock_state(self):
        return {
            "scan_id": "test-scan-1",
            "repository_profile": {"repo_path": ".", "primary_language": "python", "frameworks": ["FastAPI"]},
            "repository_context": {"auth_modules": ["auth.py"], "database_layers": ["models.py"]},
            "findings": [
                {
                    "finding_id": "f-1",
                    "rule_id": "SEC-001",
                    "file_path": "main.py",
                    "file": "main.py",
                    "line": 10,
                    "line_number": 10,
                    "severity": "HIGH",
                    "snippet": "db.execute(user_input)",
                    "description": "SQL injection",
                    "evidence_id": "E1",
                }
            ],
            "evidence": [{"id": "E1", "file": "main.py", "line": 10, "snippet": "db.execute(user_input)"}],
            "patches": [],
        }

    def test_security_agent_llm_disabled(self, mock_state, monkeypatch):
        monkeypatch.setenv("LLM_ENABLED", "false")
        agent = SecurityAgent()
        res = agent.run(mock_state)

        # Deterministic finding preserved
        assert len(res["findings"]) >= 1
        assert res["findings"][0]["rule_id"] == "SEC-001"
        assert "ai_security_insights" not in res

    def test_security_agent_grok_enabled(self, mock_state, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=True, findings=[
                MagicMock(
                    evidence_ids=["E1"],
                    category="SQL Injection",
                    severity="High",
                    confidence=0.88,
                    reason="Unsanitized user input reaches execute()",
                    recommendation="Use parameterized queries",
                    title="AI SQL Injection",
                    file="main.py",
                    line=10,
                )
            ])
        )

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = SecurityAgent()
            res = agent.run(mock_state)

        assert len(res["findings"]) > 1
        assert "ai_security_insights" in res

    def test_business_agent_grok_enabled(self, mock_state, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=True, findings=[
                MagicMock(
                    evidence_ids=["E1"],
                    category="fintech",
                    severity="High",
                    confidence=0.9,
                    reason="Payment processing detected",
                    recommendation="Ensure PCI-DSS compliance",
                    to_dict=lambda: {"category": "fintech", "reason": "Payment processing detected"}
                )
            ])
        )

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = BusinessAgent()
            res = agent.run(mock_state)

        assert "ai_business_insights" in res
        assert res["business_context"]["domain"] == "fintech"


    def test_patch_agent_grok_fallback_on_error(self, mock_state, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        # Simulate Grok exception / failure
        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.side_effect = LLMError("API rate limit 429")

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = PatchGenerationAgent()
            res = agent.run(mock_state)

        # Deterministic patch generation survives Grok failure cleanly
        assert len(res["patches"]) == 1
        assert "git_diff" in res

    def test_business_intent_engine_grok_rule_reasoning(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        # Mock ReasoningGateway response
        rf_mock = MagicMock()
        rf_mock.extras = {"verdict": "COMPLIANT", "policy_id": "REQ-001"}
        rf_mock.confidence = 0.88
        rf_mock.reason = "OAuth2 JWT token validation is enforced in auth_middleware.py"
        rf_mock.recommendation = "Maintain current token validation logic"
        rf_mock.file = "auth_middleware.py"
        rf_mock.function = "verify_jwt"
        rf_mock.evidence_ids = ["E1"]
        rf_mock.title = "Token Validation"

        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=True, findings=[rf_mock])
        )

        from guardian.intent.engine import BusinessIntentEngine
        from guardian.intent.parser.rule_parser import ParsedRule

        engine = BusinessIntentEngine()

        # Mock loader & parser to return 1 requirement rule that static AST considers INSUFFICIENT_EVIDENCE
        fake_rule = ParsedRule(
            rule_id="REQ-001",
            requirement_text="OAuth2 JWT tokens must be verified before resource access.",
            source_file="spec.pdf",
            line_number=1,
            action="unmatched_action_xyz",
            condition="none",
            control="unmatched_control_xyz",
            rule_type="STRUCTURED",
            title="Token Validation",
            evidence_terms=["xyz123_nonexistent_term"],
        )

        with patch.object(engine.loader, "list_documents", return_value=[{"filename": "spec.pdf"}]), \
             patch.object(engine.loader, "extract_actionable_requirements", return_value=["OAuth2 JWT tokens must be verified before resource access."]), \
             patch.object(engine.parser, "parse_all", return_value=[fake_rule]), \
             patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):

            res = engine.run(scan_findings=[])

        assert res["status"] == "SUCCESS"
        assert res["total_rules"] == 1
        assert res["matched"] == 1
        assert res["insufficient"] == 0
        assert res["findings"][0]["status"] == "COMPLIANT"
        assert "auth_middleware.py" in res["findings"][0]["evidence"]

    def test_phase1_security_agent_test_a_findings_gt_zero(self, mock_state, monkeypatch):
        """Test A: Deterministic findings > 0 -> Grok receives findings + relevant context."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        captured_req = []
        mock_svc = MagicMock()
        mock_svc.configured = True
        def mock_reason(req):
            captured_req.append(req)
            return ReasoningResult(available=True, response=MagicMock(ok=True, findings=[]))
        mock_svc.reason.side_effect = mock_reason

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = SecurityAgent()
            res = agent.run(mock_state)

        assert len(captured_req) == 1
        assert "E1" in captured_req[0].evidence_block
        assert "SQL Injection" in captured_req[0].evidence_block or "main.py" in captured_req[0].evidence_block

    def test_phase1_security_agent_test_b_zero_findings_receives_code_context(self, monkeypatch):
        """Test B: Deterministic findings = 0 -> Grok still receives relevant high-risk code context."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        state = {
            "repository_profile": {"repo_path": "."},
            "findings": [],
            "evidence": []
        }

        captured_req = []
        mock_svc = MagicMock()
        mock_svc.configured = True
        def mock_reason(req):
            captured_req.append(req)
            return ReasoningResult(available=True, response=MagicMock(ok=True, findings=[]))
        mock_svc.reason.side_effect = mock_reason

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = SecurityAgent()
            res = agent.run(state)

        assert len(captured_req) == 1
        # Check that workspace function profiles/snippets were included in evidence_block even with 0 findings
        assert "file:" in captured_req[0].evidence_block or "[E1]" in captured_req[0].evidence_block

    def test_phase1_security_agent_test_c_discovers_additional_finding_merged(self, mock_state, monkeypatch):
        """Test C: Grok discovers an additional finding -> finding is merged correctly."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        rf_mock = MagicMock()
        rf_mock.evidence_ids = ["E1"]
        rf_mock.category = "Hardcoded Secret"
        rf_mock.severity = "HIGH"
        rf_mock.confidence = 0.85
        rf_mock.reason = "Unencrypted API token stored in source"
        rf_mock.recommendation = "Use environment variables"
        rf_mock.title = "Hardcoded API Key"
        rf_mock.file = "config.py"
        rf_mock.line = 15

        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=True, findings=[rf_mock])
        )

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = SecurityAgent()
            res = agent.run(mock_state)

        # 1 deterministic finding + 1 Grok AI finding = 2 findings
        assert len(res["findings"]) == 2
        ai_f = next(f for f in res["findings"] if f.get("source") == "AI_VALIDATED")
        assert ai_f["rule_id"] == "AI-SEC-HARDCODED SECRE"
        assert ai_f["engine"] == "grok_security_reasoning"
        assert ai_f["file"] == "config.py"

    def test_phase1_security_agent_test_d_grok_unavailable_succeeds(self, mock_state, monkeypatch):
        """Test D: Grok unavailable -> deterministic scan still succeeds."""
        monkeypatch.setenv("LLM_ENABLED", "false")

        agent = SecurityAgent()
        res = agent.run(mock_state)

        assert len(res["findings"]) == 1
        assert res["findings"][0]["rule_id"] == "SEC-001"

    def test_phase1_security_agent_test_e_invalid_output_handling(self, mock_state, monkeypatch):
        """Test E: Grok returns invalid output -> invalid AI finding rejected safely."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        mock_svc = MagicMock()
        mock_svc.configured = True
        # ReasoningResult with problems / invalid schema response
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=False, findings=[], problems=["Invalid schema"])
        )

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = SecurityAgent()
            res = agent.run(mock_state)

        # Deterministic finding preserved cleanly, zero invalid findings added
        assert len(res["findings"]) == 1
        assert res["findings"][0]["rule_id"] == "SEC-001"

    def test_phase2_architecture_agent_enriched_grok_context(self, mock_state, monkeypatch):
        """Phase 2A: ArchitectureAgent passes service boundaries, API endpoints, and AST context to Grok."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        captured_req = []
        mock_svc = MagicMock()
        mock_svc.configured = True
        def mock_reason(req):
            captured_req.append(req)
            return ReasoningResult(available=True, response=MagicMock(ok=True, findings=[]))
        mock_svc.reason.side_effect = mock_reason

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = ArchitectureAgent()
            res = agent.run(mock_state)

        assert len(captured_req) == 1
        assert "Service boundaries" in captured_req[0].evidence_block
        assert "API Endpoints" in captured_req[0].evidence_block or "E1" in captured_req[0].evidence_block

    def test_phase2_threat_simulation_agent_enriched_grok_context(self, mock_state, monkeypatch):
        """Phase 2B: ThreatSimulationAgent passes attack paths, reachability, and scenario context to Grok."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        captured_req = []
        mock_svc = MagicMock()
        mock_svc.configured = True
        def mock_reason(req):
            captured_req.append(req)
            return ReasoningResult(available=True, response=MagicMock(ok=True, findings=[]))
        mock_svc.reason.side_effect = mock_reason

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = ThreatSimulationAgent()
            res = agent.run(mock_state)

        assert len(captured_req) == 1
        assert "Reachability" in captured_req[0].evidence_block or "Finding:" in captured_req[0].evidence_block

    def test_phase2_validation_agent_attaches_validation_fields(self, mock_state, monkeypatch):
        """Phase 2C: ValidationAgent attaches explicit validation_verdict and reasoning to findings."""
        monkeypatch.setenv("XAI_API_KEY", "xai-test-key")
        monkeypatch.setenv("LLM_ENABLED", "true")

        rf_mock = MagicMock()
        rf_mock.category = "SEC-001"
        rf_mock.file = "main.py"
        rf_mock.line = 10
        rf_mock.reason = "Finding is mitigated by framework input sanitization"
        rf_mock.confidence = 0.92
        rf_mock.evidence_ids = ["E1"]

        mock_svc = MagicMock()
        mock_svc.configured = True
        mock_svc.reason.return_value = ReasoningResult(
            available=True,
            response=MagicMock(ok=True, findings=[rf_mock])
        )

        with patch("guardian.reasoning.gateway.ReasoningGateway", return_value=mock_svc):
            agent = ValidationAgent()
            res = agent.run(mock_state)

        # Confirm validation fields attached to target finding without deleting it
        f_main = next(f for f in res["findings"] if f.get("file") == "main.py")
        assert f_main["validation_verdict"] == "LIKELY_FALSE_POSITIVE"
        assert f_main["validation_confidence"] == 0.92
        assert "mitigated" in f_main["validation_reasoning"]

    def test_phase3_state_reducers_merge_list_and_dict(self):
        """Phase 3: Verify state reducers merge parallel branch list and dict fields without loss or duplicates."""
        from guardian.orchestrator.state import merge_dict, merge_list

        list_a = [{"finding_id": "f1", "title": "A"}, {"finding_id": "f2", "title": "B"}]
        list_b = [{"finding_id": "f2", "title": "B_dup"}, {"finding_id": "f3", "title": "C"}]

        merged_l = merge_list(list_a, list_b)
        assert len(merged_l) == 3
        ids = [x["finding_id"] for x in merged_l]
        assert ids == ["f1", "f2", "f3"]

        dict_a = {"domain": "fintech", "criticality": "NORMAL"}
        dict_b = {"criticality": "CRITICAL", "data_classification": "CONFIDENTIAL"}

        merged_d = merge_dict(dict_a, dict_b)
        assert merged_d["domain"] == "fintech"
        assert merged_d["criticality"] == "CRITICAL"
        assert merged_d["data_classification"] == "CONFIDENTIAL"




