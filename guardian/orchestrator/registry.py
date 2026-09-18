"""
AI Code Guardian v3 — Agent Registry
====================================
Plugin registry enabling dynamic agent registration, retrieval, and discovery
without hardcoded agent dependencies.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Type


class AgentRegistry:
    """Central registry for discovering and instantiating AI agents."""

    def __init__(self) -> None:
        self._agents: Dict[str, Any] = {}

    def register(self, name: str, agent_factory_or_cls: Any) -> None:
        """Register an agent implementation by unique name."""
        self._agents[name] = agent_factory_or_cls

    def get(self, name: str) -> Optional[Any]:
        """Retrieve an agent class or factory by name."""
        return self._agents.get(name)

    def has_agent(self, name: str) -> bool:
        """Check if an agent is registered."""
        return name in self._agents

    def list_agents(self) -> List[str]:
        """Return names of all registered agents."""
        return list(self._agents.keys())

    def unregister(self, name: str) -> None:
        """Unregister an agent by name."""
        self._agents.pop(name, None)
