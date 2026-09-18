"""Unit tests for GitHub Service URL parsing and repository fetching."""
import pytest
from pathlib import Path
from guardian.discovery.github_service import is_github_url, parse_github_url, GitHubService


def test_is_github_url_valid():
    assert is_github_url("https://github.com/pallets/flask")
    assert is_github_url("http://github.com/pallets/flask.git")
    assert is_github_url("https://github.com/pallets/flask/tree/main")
    assert is_github_url("pallets/flask")


def test_is_github_url_invalid(tmp_path: Path):
    assert not is_github_url(str(tmp_path))
    assert not is_github_url("./local_dir")
    assert not is_github_url("/absolute/path")


def test_parse_github_url():
    owner, repo, ref = parse_github_url("https://github.com/pallets/flask")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref is None

    owner2, repo2, ref2 = parse_github_url("https://github.com/pallets/flask/tree/dev")
    assert owner2 == "pallets"
    assert repo2 == "flask"
    assert ref2 == "dev"

    owner3, repo3, ref3 = parse_github_url("pallets/flask")
    assert owner3 == "pallets"
    assert repo3 == "flask"
    assert ref3 is None


def test_github_service_fetch_zipball(tmp_path: Path, monkeypatch):
    """Test zipball download fallback logic."""
    service = GitHubService(work_dir=tmp_path)
    
    # Mock git clone failure to force zipball fallback test
    def mock_git_clone(*args, **kwargs):
        return False

    monkeypatch.setattr(service, "_git_clone", mock_git_clone)

    # Mock _download_zipball to simulate successful extraction
    def mock_download_zipball(owner, repo, ref, dest_dir, token):
        (dest_dir / "README.md").write_text("# Test Repo")
        (dest_dir / "app.py").write_text("print('hello')")
        return True

    monkeypatch.setattr(service, "_download_zipball", mock_download_zipball)

    fetched_path = service.fetch_repository("pallets/flask")
    assert fetched_path.exists()
    assert (fetched_path / "README.md").exists()
