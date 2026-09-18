"""
AI Code Guardian v3 — Patch Generation Agent
============================================
Specialist agent generating secure remediation proposals grounded in evidence.
Never overwrites repository files on disk. Produces unified git diffs and developer explanations.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from guardian.agents.base.agent import BaseAgent
from guardian.agents.patch.models import PatchProposal
from guardian.orchestrator.state import AgentWorkflowState
from guardian.reasoning.grounding.diff import GitDiffGenerator


class PatchGenerationAgent(BaseAgent):
    """Specialist agent producing grounded remediation patch proposals and unified git diffs."""

    name: str = "patch"
    description: str = "Generates grounded patch proposals, unified git diffs, and developer explanations."

    def __init__(
        self,
        tool_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        diff_generator: Optional[GitDiffGenerator] = None
    ) -> None:
        super().__init__(tool_registry=tool_registry, event_bus=event_bus)
        self.diff_generator = diff_generator or GitDiffGenerator()

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["report_tool", "evidence_tool"]

        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        threat_ctx = state.get("threat_context", {})
        biz_ctx = state.get("business_context", {})
        policy_res = state.get("policy_results", {})

        patches: List[Dict[str, Any]] = []
        git_diffs: List[str] = []
        dev_explanations: List[str] = []

        for idx, f in enumerate(findings):
            f_id = f.get("finding_id", f"f-{idx+1}")
            rule_id = f.get("rule_id", "SEC-001")
            file_path = f.get("file_path", "app.py")
            line_no = str(f.get("line_number", 1))
            orig_snippet = f.get("snippet", "")
            ev_id = f.get("evidence_id", "")

            language = str(f.get("language") or "python").lower()

            # Generate grounded secure replacement code snippet
            suggested_replacement = self._generate_secure_snippet(rule_id, orig_snippet, language, f)

            # Compute unified git diff string (NO DISK WRITE)
            diff_str = self.diff_generator.generate_unified_diff(
                file_path=file_path,
                original_snippet=orig_snippet,
                replacement_snippet=suggested_replacement
            )
            git_diffs.append(diff_str)

            explanation = (
                f"Remediated {rule_id} in {file_path}:{line_no} by introducing secure parameterized handling. "
                f"Grounding Evidence ID: {ev_id}. Business Criticality: {biz_ctx.get('criticality', 'NORMAL')}."
            )
            dev_explanations.append(explanation)

            policy_refs = [v.get("policy_name") for v in policy_res.get("violations", []) if v.get("finding_id") == f_id]

            patch_proposal = PatchProposal(
                patch_id=f"patch-{f_id[:8] if len(f_id)>=8 else f_id}",
                finding_id=f_id,
                affected_file=file_path,
                affected_lines=line_no,
                original_snippet=orig_snippet,
                suggested_replacement=suggested_replacement,
                explanation=explanation,
                evidence_ids=[ev_id] if ev_id else [],
                confidence=0.90,
                policy_references=policy_refs,
                business_impact=biz_ctx.get("criticality", "NORMAL"),
                threat_impact="REDUCED",
                validation_status="PENDING",
                git_diff=diff_str,
            )

            patches.append(patch_proposal.to_dict())

        combined_diff = "\n".join(git_diffs)
        combined_explanation = "\n---\n".join(dev_explanations)

        new_state = dict(state)
        new_state["patches"] = patches
        new_state["git_diff"] = combined_diff
        new_state["developer_explanation"] = combined_explanation
        new_state["remediation_summary"] = {
            "total_patches_proposed": len(patches),
            "files_affected": list({p.get("affected_file") for p in patches if p.get("affected_file")}),
        }
        return new_state

    @staticmethod
    def _generate_secure_snippet(
        rule_id: str,
        orig_snippet: str,
        language: str = "python",
        finding: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generates a secure replacement snippet appropriate to the finding's
        actual language.

        Previously this always returned Python code (`import os`,
        `cursor.execute(...)`) regardless of whether the finding was in Java,
        JavaScript, TypeScript, or Rust. Suggestions are now language-aware,
        matching the same pattern used by guardian/copilot/assistant.py's
        _code_fix_for(), and fall back to the scanner's own `recommendation`
        for languages/categories without a canned pattern rather than
        guessing Python.
        """
        rule_upper = rule_id.upper()
        recommendation = (finding or {}).get("recommendation") or ""
        lang = (language or "python").lower()

        if "SEC-004" in rule_upper or "SECRET" in rule_upper:
            if lang == "python":
                return "import os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')"
            if lang == "java":
                return "// Use environment variable or Spring @Value\nString awsSecretKey = System.getenv(\"AWS_SECRET_KEY\");"
            if lang in ("javascript", "typescript"):
                return "const AWS_SECRET_KEY = process.env.AWS_SECRET_KEY || '';"
            if lang == "rust":
                return "let aws_secret_key = std::env::var(\"AWS_SECRET_KEY\").unwrap_or_default();"
            return recommendation or "Use environment variables instead of hardcoded secrets."

        if "SQL" in rule_upper or "SEC-001" in rule_upper:
            if lang == "python":
                return "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            if lang == "java":
                return "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setInt(1, userId);"
            if lang in ("javascript", "typescript"):
                return "db.query(\"SELECT * FROM users WHERE id = $1\", [userId]);"
            if lang == "rust":
                return "sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id).fetch_one(&pool).await?;"
            return recommendation or "Use parameterized queries to prevent SQL injection."

        if "COMMAND" in rule_upper or "EXEC" in rule_upper or "CWE-78" in rule_upper or "SEC-003" in rule_upper:
            if lang == "python":
                return "import subprocess\nsubprocess.run(['ping', '-c', '1', host_arg], check=True, shell=False)"
            if lang == "java":
                return "new ProcessBuilder(\"ping\", \"-c\", \"1\", hostArg).start();"
            if lang in ("javascript", "typescript"):
                return "const { execFile } = require('child_process');\nexecFile('ping', ['-c', '1', hostArg], (err, stdout) => { ... });"
            return recommendation or "Use parameterized subprocess execution without shell=True."

        if "PATH" in rule_upper or "TRAVERSAL" in rule_upper or "CWE-22" in rule_upper:
            if lang == "python":
                return "import os\nsafe_path = os.path.abspath(os.path.join(base_dir, filename))\nif not safe_path.startswith(os.path.abspath(base_dir)):\n    raise ValueError('Access denied')"
            return recommendation or "Sanitize and validate input path against base directory."

        if "IAC" in rule_upper or "SECURITY_GROUP" in rule_upper or "CIDR" in rule_upper:
            return "cidr_blocks = [\"10.0.0.0/16\"]  # Restricted internal VPC subnet"

        if "XSS" in rule_upper or "SEC-002" in rule_upper:
            if lang == "python":
                return "import html\nsafe_output = html.escape(user_input)"
            if lang == "java":
                return "String safeOutput = org.owasp.encoder.Encode.forHtml(userInput);"
            if lang in ("javascript", "typescript"):
                return "const safeOutput = escapeHtml(userInput); // or a templating engine's auto-escaping"
            if lang == "rust":
                return "let safe_output = askama_escape::escape(user_input, askama_escape::Html);"
            return recommendation or "Use context-aware output encoding before rendering untrusted input."

        if "DEP" in rule_upper or "DEPENDENCY" in rule_upper or "UNPINNED" in rule_upper:
            import re
            raw = (orig_snippet or "").strip()
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)", raw)
            pkg = m.group(1) if m and m.group(1).lower() not in ("pin", "vulnerable", "unpinned") else "dependency"

            file_lower = (finding.get("file_path") or finding.get("file") or "").lower() if finding else ""
            if "package.json" in file_lower:
                return f'"{pkg}": "^4.9.3"'
            elif "pom.xml" in file_lower:
                return f"<version>4.9.3</version>"
            else:
                return f"{pkg}>=4.9.3"

        # Direct snippet transformation for known vulnerable function calls
        orig_clean = (orig_snippet or "").strip()
        if orig_clean:
            if "pickle.loads(" in orig_clean:
                return orig_clean.replace("pickle.loads(", "json.loads(")
            if "yaml.load(" in orig_clean:
                return orig_clean.replace("yaml.load(", "yaml.safe_load(")
            if "eval(" in orig_clean:
                return orig_clean.replace("eval(", "ast.literal_eval(")
            if "exec(" in orig_clean:
                return orig_clean.replace("exec(", "safe_exec(")
            if "hashlib.md5(" in orig_clean:
                return orig_clean.replace("hashlib.md5(", "hashlib.sha256(")

        if "DESERIALIZATION" in rule_upper or "PICKLE" in rule_upper or "CWE-502" in rule_upper:
            if lang == "python":
                return "import json\ncontent = json.loads(user_input)"
            if lang == "java":
                return "// Use safe deserialization whitelist or JSON parser\nObjectMapper mapper = new ObjectMapper();"
            if lang in ("javascript", "typescript"):
                return "const content = JSON.parse(userInput);"
            return recommendation or "Replace insecure deserialization with safe JSON parsing."

        if lang == "python" and orig_clean:
            return orig_clean.replace("eval(", "safe_eval(").replace("exec(", "safe_exec(")

        return orig_clean or recommendation or f"# Review finding remediation for {rule_id}."
