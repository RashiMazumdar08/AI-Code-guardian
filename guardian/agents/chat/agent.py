"""
Interactive Chat Agent
======================
Dynamically responds to user queries by interacting with the ToolRegistry
using native LangChain tool bindings via the OpenAI-compatible NVIDIA endpoint.
"""
from typing import Any, Callable, Dict, List

from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
import asyncio
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception

from guardian.llm.config import LLMConfig
from guardian.orchestrator.events import EventBus
from guardian.orchestrator.state import AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry





_nim_semaphore = asyncio.Semaphore(2)

def _is_retryable_error(exception: Exception) -> bool:
    err_str = str(exception).lower()
    return "resourceexhausted" in err_str or "limit reached" in err_str or "connection" in err_str or "timeout" in err_str or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str or "429" in err_str


class InteractiveChatAgent:
    """Conversational RAG agent interacting directly with the codebase."""
    
    def __init__(self, tool_registry: ToolRegistry, event_bus: EventBus) -> None:
        self.tool_registry = tool_registry
        self.event_bus = event_bus
        self.config = LLMConfig.from_env()
        
        # Instantiate standard LangChain client pointing to NVIDIA endpoint
        self.llm = ChatOpenAI(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            model_kwargs={"top_p": self.config.top_p}
        )
        
        self.tools = self._create_tools()
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        self.system_prompt = (
            "You are the universal AI Code Guardian assistant. Your objective is to help the user with any code or security queries.\n"
            "1. Determine if the user's question is about a specific security finding, patches, requirements, or general coding.\n"
            "2. If security or topology related, strictly use `hybrid_search` (Parallel Dual-Path RRF) or dedicated tools (`get_scan_findings`, `get_scan_patches`, `semantic_search`, `repository_graph_query`, `fetch_evidence`) to query codebase state and cite `[Evidence E1]` markers.\n"
            "3. If evidence is insufficient to answer or verify whether a requirement or vulnerability is satisfied, explicitly state 'unresolved' rather than hallucinating.\n"
            "4. If general coding, provide standard, helpful code assistant behaviors.\n"
            "You MUST NOT hallucinate answers about repository architecture; always query the tools when you need information."
        )

    def _create_tools(self) -> List[Callable]:
        """Creates LangChain-compatible @tool functions, bound to this agent instance for state access."""
        @tool
        def hybrid_search(query: str, top_k: int = 10) -> Dict[str, Any]:
            """Performs parallel dual-path vector (semantic) and Neo4j graph (structural) retrieval with Reciprocal Rank Fusion (RRF, k=60)."""
            try:
                from guardian.knowledge.retrieval.hybrid_engine import ParallelHybridEngine
                engine = ParallelHybridEngine()
                active_ev = getattr(self, "_current_state", {}).get("evidence_ids", [])
                return asyncio.run(engine.hybrid_search(query=query, top_k=top_k, active_evidence_ids=active_ev))
            except Exception as e:
                # Fallback to ToolRegistry if execution fails
                return self.tool_registry.execute("semantic_search_tool", query=query, limit=top_k)

        @tool
        def semantic_search(query: str, limit: int = 5) -> Dict[str, Any]:
            """Performs vector-based semantic search across codebase documentation and standard frameworks."""
            return self.tool_registry.execute("semantic_search_tool", query=query, limit=limit)
            
        @tool
        def repository_graph_query(node_count: int = 0, rel_count: int = 0) -> Dict[str, Any]:
            """Queries structural repository topology, call trees, and import hierarchies."""
            return self.tool_registry.execute("repository_graph_tool", node_count=node_count, rel_count=rel_count)
            
        @tool
        def fetch_evidence(evidence_ids: List[str]) -> Dict[str, Any]:
            """Manages grounding evidence objects and proof chains."""
            return self.tool_registry.execute("evidence_tool", evidence=evidence_ids)
            
        @tool
        def get_scan_findings(severity: str = "") -> str:
            """Retrieves security findings and vulnerabilities discovered in the codebase. Use severity='CRITICAL' or 'HIGH' to filter."""
            findings = getattr(self, "_current_state", {}).get("findings", [])
            if not findings:
                return "No findings are currently present in the scan state."
            
            res = []
            for f in findings:
                if severity and f.get("severity", "").upper() != severity.upper():
                    continue
                res.append({
                    "id": f.get("finding_id"),
                    "rule": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "file": f.get("file_path"),
                    "line": f.get("line_number"),
                    "description": f.get("description")
                })
            import json
            return json.dumps(res, indent=2)

        @tool
        def get_scan_patches() -> str:
            """Retrieves proposed remediation patches for discovered findings."""
            patches = getattr(self, "_current_state", {}).get("patches", [])
            if not patches:
                return "No patches are currently proposed in the scan state."
            
            res = []
            for p in patches:
                res.append({
                    "id": p.get("patch_id"),
                    "finding_id": p.get("finding_id"),
                    "file": p.get("file_path"),
                    "description": p.get("description")
                })
            import json
            return json.dumps(res, indent=2)

        return [hybrid_search, semantic_search, repository_graph_query, fetch_evidence, get_scan_findings, get_scan_patches]

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(15),
        retry=retry_if_exception(_is_retryable_error)
    )
    async def _safe_ainvoke(self, messages, config):
        async with _nim_semaphore:
            return await self.llm_with_tools.ainvoke(messages, config=config)

    async def run(self, state: AgentWorkflowState, config: Any = None) -> AgentWorkflowState:
        """Executes one turn of the chat loop."""
        self._current_state = state
        messages = state.get("messages", [])
        
        # Prepend system prompt if not present
        if not messages or not any(isinstance(m, SystemMessage) for m in messages):
            findings_count = len(state.get("findings", []))
            patches_count = len(state.get("patches", []))
            sys_prompt = self.system_prompt + f"\n\nCURRENT REPOSITORY SCAN RESULTS:\n- Total Findings: {findings_count}\n- Total Patches: {patches_count}\nUse the `get_scan_findings` and `get_scan_patches` tools to view them."
            messages = [SystemMessage(content=sys_prompt)] + messages
            
        response = await self._safe_ainvoke(messages, config)
        return {"messages": [response]}
