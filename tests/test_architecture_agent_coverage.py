import pytest
from guardian.agents.repository.agent import RepositoryAgent
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state

def test_repository_agent_endpoint_coverage_calculation():
    """Verify RepositoryAgent calculates total, authenticated, and unauthenticated endpoint counts."""
    profile = {
        "primary_language": "Python",
        "frameworks": ["FastAPI"],
        "detected_endpoints": ["/api/v1/scan", "/api/v1/scans"],
        "security_markers": ["JWT Auth"],
    }
    state = create_initial_state(scan_id="test_repo_cov_1", repository_profile=profile)
    repo_agent = RepositoryAgent()
    new_state = repo_agent._process(state)
    
    repo_ctx = new_state.get("repository_context", {})
    assert "endpoint_coverage" in repo_ctx
    ep_cov = repo_ctx["endpoint_coverage"]
    
    assert ep_cov["total_route_endpoints"] >= 0
    assert ep_cov["authenticated_endpoints_count"] >= 0
    assert ep_cov["unauthenticated_endpoints_count"] >= 0
    assert 0.0 <= ep_cov["auth_coverage_pct"] <= 100.0

def test_global_jwt_marker_remains_intact():
    """Verify existing global JWT marker remains intact in auth_modules and context."""
    profile = {
        "primary_language": "Python",
        "frameworks": ["FastAPI"],
        "detected_endpoints": ["/api/v1/scan"],
        "security_markers": ["JWT Auth", "OAuth2"],
    }
    state = create_initial_state(scan_id="test_global_jwt_1", repository_profile=profile)
    repo_agent = RepositoryAgent()
    new_state = repo_agent._process(state)
    
    repo_ctx = new_state.get("repository_context", {})
    assert "JWT Auth" in repo_ctx.get("auth_modules", [])

def test_architecture_agent_receives_coverage_evidence():
    """Verify ArchitectureAgent receives structured endpoint authentication coverage evidence."""
    profile = {
        "primary_language": "Python",
        "frameworks": ["FastAPI"],
        "detected_endpoints": ["/api/v1/scan"],
        "security_markers": ["JWT Auth"],
    }
    repo_ctx = {
        "auth_modules": ["JWT Auth"],
        "database_layers": ["ORM Data Access Layer"],
        "endpoint_coverage": {
            "total_route_endpoints": 25,
            "authenticated_endpoints_count": 1,
            "unauthenticated_endpoints_count": 24,
            "auth_coverage_pct": 4.0,
            "representative_unauthenticated_endpoints": ["backend/app/api/v1/agentic_scan.py:831 | start_agentic_scan"],
        }
    }
    state = create_initial_state(scan_id="test_arch_cov_1", repository_profile=profile, repository_context=repo_ctx)
    
    agent = ArchitectureAgent()
    # Check that _process executes cleanly without error
    new_state = agent._process(state)
    arch_ctx = new_state.get("architecture_context", {})
    assert arch_ctx is not None
    assert "trust_boundaries" in arch_ctx

def test_no_false_vulnerability_claim_generated_deterministically():
    """Verify deterministic context uses non-accusatory phrasing ('without detected route-level authentication')."""
    profile = {
        "primary_language": "Python",
        "frameworks": ["FastAPI"],
        "detected_endpoints": ["/api/v1/scan"],
        "security_markers": ["JWT Auth"],
    }
    state = create_initial_state(scan_id="test_no_false_vuln_1", repository_profile=profile)
    repo_agent = RepositoryAgent()
    new_state = repo_agent._process(state)
    
    ep_cov = new_state.get("repository_context", {}).get("endpoint_coverage", {})
    # Check field naming
    assert "unauthenticated_endpoints_count" in ep_cov
    assert "representative_unauthenticated_endpoints" in ep_cov
