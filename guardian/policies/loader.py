"""
AI Code Guardian v3 — Policy Pack Loader
========================================
Parses and validates policy definition files (YAML/JSON).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from guardian.policies.schema import PolicyPack, PolicyRule

logger = logging.getLogger(__name__)


class PolicyLoader:
    """Parses YAML and JSON policy pack files into PolicyPack data structures."""

    def load_from_file(self, file_path: Path) -> Optional[PolicyPack]:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.warning(f"Policy file not found: {file_path}")
            return None

        try:
            content = file_path.read_text(encoding="utf-8")
            if file_path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(content)
            elif file_path.suffix == ".json":
                data = json.loads(content)
            else:
                logger.warning(f"Unsupported policy file format: {file_path}")
                return None

            return self.load_from_dict(data)
        except Exception as e:
            logger.error(f"Error loading policy file '{file_path}': {e}")
            return None

    def load_from_dict(self, data: Dict[str, Any]) -> PolicyPack:
        name = data.get("name", "custom_policy_pack")
        version = str(data.get("version", "1.0.0"))
        description = data.get("description", "")

        rules_list: List[PolicyRule] = []
        for r_raw in data.get("rules", []):
            if isinstance(r_raw, dict):
                rule = PolicyRule(
                    rule_id=r_raw.get("rule_id", "POL-001"),
                    name=r_raw.get("name", "Policy Rule"),
                    severity=r_raw.get("severity", "MEDIUM").upper(),
                    category=r_raw.get("category", "general"),
                    description=r_raw.get("description", ""),
                    target=r_raw.get("target", ""),
                    condition=r_raw.get("condition", {}),
                    action=r_raw.get("action", "FLAG"),
                )
                rules_list.append(rule)

        return PolicyPack(
            name=name,
            version=version,
            description=description,
            rules=rules_list,
            metadata=data.get("metadata", {}),
        )
