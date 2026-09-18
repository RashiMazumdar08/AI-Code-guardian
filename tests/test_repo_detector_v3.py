"""
Tests for AI Code Guardian 3.0 — Enhanced Repository Detector
"""
import tempfile
from pathlib import Path

from guardian.discovery.repo_detector import RepositoryDetector


def test_repo_detector_entrypoints_and_endpoints():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "requirements.txt").write_text("fastapi>=0.100.0\nuvicorn>=0.20.0\n")

        app_file = repo / "app.py"
        app_file.write_text('''
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/v1/users")
def get_users():
    return []

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)
''')

        detector = RepositoryDetector()
        files = [repo / "requirements.txt", app_file]
        profile = detector.detect(repo, files)

        assert profile.primary_language == "Python"
        assert "FastAPI" in profile.frameworks
        assert len(profile.entry_points) > 0
        assert len(profile.detected_endpoints) > 0
        assert "/api/v1/users" in profile.detected_endpoints
        assert "app.py" in profile.entry_points[0]
