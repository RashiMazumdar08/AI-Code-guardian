"""
AI Code Guardian v3 — Interactive Assistant Page
==============================================
Real-time streaming RAG Chatbot using FastAPI Server-Sent Events (SSE).
"""
import json
import uuid
import requests
import streamlit as st
from typing import Any, Dict

from guardian.dashboard.models.dashboard_state import DashboardStateView
from backend.app.core.config import settings


class InteractiveAssistantPage:
    """Renders the real-time Interactive RAG Assistant."""

    def render(self, state_view: DashboardStateView, **kwargs: Any) -> Dict[str, Any]:
        return {"page_title": "Interactive Assistant"}

    def render_ui(self):
        st.subheader("💬 Interactive Assistant (Dynamic RAG)")
        st.caption("Real-time streaming interactions with NVIDIA Nemotron.")
        
        # Initialize thread and history
        if "assistant_thread_id" not in st.session_state:
            st.session_state.assistant_thread_id = str(uuid.uuid4())
            
        if "interactive_history" not in st.session_state:
            st.session_state.interactive_history = []
            
        # Render history
        for msg in st.session_state.interactive_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                
        # Chat Input
        if prompt := st.chat_input("Ask a question about your codebase..."):
            st.session_state.interactive_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
                
            with st.chat_message("assistant"):
                placeholder = st.empty()
                full_response = ""
                
                try:
                    # HTTP POST to streaming endpoint
                    api_url = f"http://localhost:8000{settings.API_V1_STR}/chat/stream"
                    payload = {
                        "message": prompt,
                        "thread_id": st.session_state.assistant_thread_id
                    }
                    
                    with requests.post(api_url, json=payload, stream=True) as response:
                        response.raise_for_status()
                        for line in response.iter_lines():
                            if line:
                                decoded_line = line.decode('utf-8')
                                if decoded_line.startswith("data: "):
                                    data_str = decoded_line[6:]
                                    if data_str == "[DONE]":
                                        break
                                    try:
                                        data = json.loads(data_str)
                                        if "content" in data:
                                            full_response += data["content"]
                                            placeholder.markdown(full_response + "▌")
                                        elif "error" in data:
                                            full_response += f"\n\n**Error:** {data['error']}"
                                            placeholder.markdown(full_response)
                                    except json.JSONDecodeError:
                                        pass
                                        
                    placeholder.markdown(full_response)
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code >= 500 or e.response.status_code == 429:
                        full_response = "The NVIDIA API is currently at capacity or experiencing an issue. Please wait a few seconds and try again."
                        placeholder.error(full_response)
                    else:
                        full_response = f"**Connection Error:** {str(e)}"
                        placeholder.error(full_response)
                except Exception as e:
                    full_response = f"**Connection Error:** Could not reach the streaming backend. Make sure the FastAPI server is running.\n\nError: {str(e)}"
                    placeholder.error(full_response)
                    
                st.session_state.interactive_history.append({"role": "assistant", "content": full_response})

