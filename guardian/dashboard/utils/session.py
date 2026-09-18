"""
AI Code Guardian v3 — Session State Management
==============================================
Provides thread-safe session state accessors for active workspace, scans, chat history, and filters.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from guardian.orchestrator.state import AgentWorkflowState


class DashboardSessionManager:
    """Manages Streamlit session state object accessors."""

    @staticmethod
    def initialize_session(st: Any) -> None:
        """Ensures all session state variables exist with safe defaults."""
        if "active_repo_info" not in st.session_state:
            st.session_state["active_repo_info"] = None
        if "current_state" not in st.session_state:
            st.session_state["current_state"] = None
        if "chat_history" not in st.session_state:
            st.session_state["chat_history"] = []
        if "approved_patches" not in st.session_state:
            st.session_state["approved_patches"] = set()
        if "policy_documents" not in st.session_state:
            st.session_state["policy_documents"] = []

    @staticmethod
    def set_active_repository(st: Any, repo_info: Dict[str, Any]) -> None:
        st.session_state["active_repo_info"] = repo_info

    @staticmethod
    def get_active_repository(st: Any) -> Optional[Dict[str, Any]]:
        return st.session_state.get("active_repo_info")

    @staticmethod
    def set_current_state(st: Any, state: AgentWorkflowState) -> None:
        st.session_state["current_state"] = state

    @staticmethod
    def get_current_state(st: Any) -> Optional[AgentWorkflowState]:
        return st.session_state.get("current_state")

    @staticmethod
    def add_chat_message(st: Any, role: str, message: str, citations: Optional[List[Dict[str, Any]]] = None) -> None:
        chat = st.session_state.get("chat_history", [])
        chat.append({
            "role": role,
            "content": message,
            "citations": citations or [],
        })
        st.session_state["chat_history"] = chat

    @staticmethod
    def get_chat_history(st: Any) -> List[Dict[str, Any]]:
        return st.session_state.get("chat_history", [])

    @staticmethod
    def toggle_patch_approval(st: Any, patch_id: str) -> bool:
        approved = st.session_state.get("approved_patches", set())
        if patch_id in approved:
            approved.remove(patch_id)
            is_approved = False
        else:
            approved.add(patch_id)
            is_approved = True
        st.session_state["approved_patches"] = approved
        return is_approved

    @staticmethod
    def is_patch_approved(st: Any, patch_id: str) -> bool:
        approved = st.session_state.get("approved_patches", set())
        return patch_id in approved
