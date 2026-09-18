"""
AI Code Guardian v3 — Event Bus & Event Types
=============================================
Lightweight in-memory pub/sub event infrastructure for multi-agent coordination.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Type


@dataclass
class Event:
    """Base event class."""
    timestamp: float = field(default_factory=time.time)
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStarted(Event):
    scan_id: str = ""


@dataclass
class PlannerCompleted(Event):
    scan_id: str = ""
    agent_order: List[str] = field(default_factory=list)


@dataclass
class TaskScheduled(Event):
    agent_name: str = ""
    task_name: str = ""


@dataclass
class TaskCompleted(Event):
    agent_name: str = ""
    task_name: str = ""
    duration: float = 0.0
    # Populated by BaseAgent.run() from the same result_payload/errors it
    # already computes -- lets subscribers (e.g. the agentic-scan SSE
    # endpoint) distinguish a genuinely failed agent from a normal
    # completion without re-deriving it themselves.
    status: str = "success"
    error: str = ""


@dataclass
class WorkflowCompleted(Event):
    scan_id: str = ""
    total_findings: int = 0
    duration: float = 0.0


@dataclass
class FindingCreated(Event):
    finding_id: str = ""
    severity: str = ""
    rule_id: str = ""


@dataclass
class FindingUpdated(Event):
    finding_id: str = ""
    status: str = ""


HandlerCallable = Callable[[Event], None]


class EventBus:
    """Lightweight sync/async pub/sub event bus."""

    def __init__(self) -> None:
        self._subscribers: Dict[Type[Event], List[HandlerCallable]] = {}

    def subscribe(self, event_type: Type[Event], handler: HandlerCallable) -> None:
        """Register a handler callback for a specific event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: Type[Event], handler: HandlerCallable) -> None:
        """Remove a registered handler callback."""
        if event_type in self._subscribers and handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        """Publish an event instance to all registered handlers for its type or supertypes."""
        event_cls = type(event)
        for registered_type, handlers in self._subscribers.items():
            if isinstance(event, registered_type):
                for handler in handlers:
                    try:
                        handler(event)
                    except Exception:
                        pass
