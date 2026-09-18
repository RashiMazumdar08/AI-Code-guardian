"""
Contextual reasoning layer
==========================
Everything between deterministic evidence and a validated finding:

    evidence selection  ->  RAG knowledge  ->  Nemotron  ->  schema
                        ->  evidence validation  ->  ValidatedFinding

`NemotronReasoningService` is the ONLY place in the platform that talks
to a language model. Engines never call it directly with source code;
they hand it selected evidence via `guardian.reasoning.context`.
"""
from guardian.reasoning.gateway import (  # noqa: F401
    NemotronReasoningService, ReasoningRequest, ReasoningResult,
)
from guardian.reasoning.knowledge import (  # noqa: F401
    KnowledgeRetriever, KnowledgeSnippet, build_default_retriever,
)
from guardian.reasoning.schemas import (  # noqa: F401
    ComplianceVerdict, MigrationUrgency, ReasoningFinding, ReasoningResponse,
    parse_business_intent_response, parse_quantum_context_response,
    parse_reasoning_response,
)
from guardian.reasoning.validation import (  # noqa: F401
    AIFindingValidator, ValidationReport, to_findings,
)

__all__ = [
    "NemotronReasoningService", "ReasoningRequest", "ReasoningResult",
    "KnowledgeRetriever", "KnowledgeSnippet", "build_default_retriever",
    "ReasoningFinding", "ReasoningResponse", "ComplianceVerdict", "MigrationUrgency",
    "parse_reasoning_response", "parse_business_intent_response",
    "parse_quantum_context_response",
    "AIFindingValidator", "ValidationReport", "to_findings",
]
