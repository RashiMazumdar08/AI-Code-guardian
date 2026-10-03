"""
Controlled Test Fixture: Semantic Authorization Gap (IDOR / Missing Object-Level Authorization)
=============================================================================================
This test fixture demonstrates an authorization semantic gap:
- An authentication decorator (@login_required) ensures the caller is logged in.
- The route handler accepts a user-controlled resource identifier (`target_user_id`).
- The data lookup fetches sensitive user account details using `target_user_id`.
- CRITICAL GAP: No ownership or authorization check verifies that the logged-in user
  (current_session.user_id) is allowed to access `target_user_id`'s resource.

This flaw (IDOR / BOLA) is a semantic logic vulnerability that standard AST/taint rules
(which search for untrusted input reaching SQL/exec sinks) do NOT detect deterministically.
"""
from functools import wraps
from typing import Dict, Any, Optional

# Mock in-memory database store (harmless test mock)
MOCK_USER_PROFILES: Dict[str, Dict[str, Any]] = {
    "user_101": {"user_id": "user_101", "email": "alice@example.com", "role": "user", "balance": 1500.00},
    "user_102": {"user_id": "user_102", "email": "bob@example.com", "role": "admin", "balance": 95000.00},
}

class MockSession:
    """Simulated active user session context."""
    def __init__(self, active_user_id: str = "user_101"):
        self.active_user_id = active_user_id
        self.is_authenticated = True

current_session = MockSession(active_user_id="user_101")

def login_required(func):
    """Authentication decorator: verifies the user is logged in."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_session.is_authenticated:
            raise PermissionError("User is not authenticated.")
        return func(*args, **kwargs)
    return wrapper

@login_required
def get_user_profile_endpoint(target_user_id: str) -> Optional[Dict[str, Any]]:
    """
    REST API endpoint returning user account profile.

    VULNERABILITY: IDOR / Missing Object-Level Authorization.
    The endpoint verifies authentication (@login_required), but accepts any `target_user_id`
    without validating if `current_session.active_user_id == target_user_id` or if
    current_session active user has admin privileges.
    """
    # Safe dictionary retrieval (no SQL injection, no eval, no command execution)
    profile_data = MOCK_USER_PROFILES.get(target_user_id)
    return profile_data
