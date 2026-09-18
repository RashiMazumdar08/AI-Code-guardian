"""
AI Code Guardian 3.0 — Repository Detection & Profiling Engine
================================================================
Answers, for ANY repository with zero prior knowledge:
    - What languages is it written in (with % distribution)?
    - Which frameworks does it use?
    - Which build systems?
    - What architecture shape (monorepo / microservices / frontend /
      backend / full-stack / cloud-native / AI-agent)?
    - What entry points, API routes, and security markers exist?

Detection is entirely manifest- and content-signature driven.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Dict, Set


EXTENSION_LANGUAGES = {
    ".java": "Java", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust",
    ".cs": "C#", ".cpp": "C++", ".cc": "C++", ".c": "C", ".h": "C/C++ Header",
    ".kt": "Kotlin", ".scala": "Scala", ".php": "PHP", ".rb": "Ruby",
    ".sql": "SQL", ".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML",
    ".xml": "XML", ".json": "JSON", ".md": "Markdown", ".sh": "Shell",
}

# manifest file -> (build_tool, primary_language_hint)
BUILD_MANIFESTS = {
    "pom.xml": ("Maven", "Java"),
    "build.gradle": ("Gradle", "Java"),
    "build.gradle.kts": ("Gradle (Kotlin DSL)", "Kotlin"),
    "requirements.txt": ("pip", "Python"),
    "pyproject.toml": ("Python (PEP 517)", "Python"),
    "setup.py": ("setuptools", "Python"),
    "Pipfile": ("pipenv", "Python"),
    "package.json": ("npm/yarn", "JavaScript"),
    "Cargo.toml": ("Cargo", "Rust"),
    "go.mod": ("Go modules", "Go"),
    "Gemfile": ("Bundler", "Ruby"),
    "composer.json": ("Composer", "PHP"),
    "*.csproj": ("MSBuild", "C#"),
    "CMakeLists.txt": ("CMake", "C++"),
    "Makefile": ("Make", None),
}

# filename or content signature -> framework
FRAMEWORK_SIGNATURES = [
    ("pom.xml", re.compile(r"spring-boot|springframework", re.I), "Spring Boot"),
    ("build.gradle", re.compile(r"spring-boot|springframework", re.I), "Spring Boot"),
    ("requirements.txt", re.compile(r"^django", re.I | re.M), "Django"),
    ("requirements.txt", re.compile(r"^flask", re.I | re.M), "Flask"),
    ("requirements.txt", re.compile(r"^fastapi", re.I | re.M), "FastAPI"),
    ("requirements.txt", re.compile(r"^streamlit", re.I | re.M), "Streamlit"),
    ("requirements.txt", re.compile(r"^langchain|^langgraph|^llama-index", re.I | re.M), "LangChain / AI Agents"),
    ("requirements.txt", re.compile(r"^torch|^tensorflow", re.I | re.M), "PyTorch / ML"),
    ("pyproject.toml", re.compile(r"langchain|langgraph|fastapi|django|flask", re.I), "Python AI/Web Framework"),
    ("package.json", re.compile(r'"react"'), "React"),
    ("package.json", re.compile(r'"vue"'), "Vue"),
    ("package.json", re.compile(r'"@angular/core"'), "Angular"),
    ("package.json", re.compile(r'"express"'), "Express"),
    ("package.json", re.compile(r'"next"'), "Next.js"),
    ("package.json", re.compile(r'"@nestjs/core"'), "NestJS"),
    ("go.mod", re.compile(r"gin-gonic|labstack/echo|go-chi"), "Go Web Framework"),
    ("Cargo.toml", re.compile(r"actix-web|axum|rocket"), "Rust Web Framework"),
]

CLOUD_NATIVE_MARKERS = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Chart.yaml",            # Helm
    ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
}
KUBE_HINT = re.compile(r"^\s*(apiVersion|kind):", re.M)
API_SPEC_NAMES = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"}

# Endpoint & Entrypoint Detection Patterns
ENTRYPOINT_PATTERNS = [
    re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']'),
    re.compile(r'public\s+static\s+void\s+main\s*\('),
    re.compile(r'fn\s+main\s*\('),
    re.compile(r'func\s+main\s*\('),
    re.compile(r'@SpringBootApplication'),
    re.compile(r'app\.listen\s*\('),
]

ENDPOINT_PATTERNS = [
    re.compile(r'@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'), # FastAPI / Flask / Express
    re.compile(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']'), # Spring Boot
    re.compile(r'(?:GET|POST|PUT|DELETE)\s+["\']([^"\']+)["\']'),
]

SECURITY_MARKER_PATTERNS = [
    ("JWT Auth", re.compile(r'jwt|bearer|jsonWebToken', re.I)),
    ("OAuth2", re.compile(r'oauth2|oidc', re.I)),
    ("CORS Policy", re.compile(r'CORSMiddleware|addCorsMappings|cors\(\)', re.I)),
    ("Encryption", re.compile(r'AES|RSA|Cipher|crypto|bcrypt', re.I)),
    ("Vault / Secrets", re.compile(r'aws_secretsmanager|hashicorp|keyvault', re.I)),
]


@dataclass
class RepositoryProfile:
    root: str
    languages: dict[str, float] = field(default_factory=dict)   # language -> % of source files
    primary_language: str = "Unknown"
    frameworks: list[str] = field(default_factory=list)
    build_tools: list[str] = field(default_factory=list)
    architecture: list[str] = field(default_factory=list)       # e.g. ["backend", "cloud-native"]
    is_monorepo: bool = False
    has_api_spec: bool = False
    manifest_files: list[str] = field(default_factory=list)
    total_files: int = 0
    entry_points: list[str] = field(default_factory=list)
    detected_endpoints: list[str] = field(default_factory=list)
    security_markers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "primary_language": self.primary_language,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "build_tools": self.build_tools,
            "architecture": self.architecture,
            "is_monorepo": self.is_monorepo,
            "has_api_spec": self.has_api_spec,
            "manifest_files": self.manifest_files,
            "total_files": self.total_files,
            "entry_points": self.entry_points,
            "detected_endpoints": self.detected_endpoints,
            "security_markers": self.security_markers,
        }


class RepositoryDetector:
    """Builds a RepositoryProfile from the discovered file list."""

    def detect(self, repo_root: Path, files: Iterable[Path]) -> RepositoryProfile:
        files = list(files)
        profile = RepositoryProfile(root=str(repo_root), total_files=len(files))

        lang_counts: Counter[str] = Counter()
        manifest_dirs: set[Path] = set()
        frameworks: set[str] = set()
        build_tools: set[str] = set()
        security_markers: set[str] = set()
        entry_points: set[str] = set()
        endpoints: set[str] = set()
        cloud_native = False

        for fp in files:
            name = fp.name
            ext = fp.suffix.lower()

            lang = EXTENSION_LANGUAGES.get(ext)
            if lang and lang not in ("YAML", "JSON", "Markdown", "XML"):
                lang_counts[lang] += 1

            if name in BUILD_MANIFESTS:
                tool, _ = BUILD_MANIFESTS[name]
                build_tools.add(tool)
                profile.manifest_files.append(str(fp))
                manifest_dirs.add(fp.parent)
            elif ext == ".csproj":
                build_tools.add("MSBuild")
                manifest_dirs.add(fp.parent)

            if name in CLOUD_NATIVE_MARKERS or "/.github/workflows/" in str(fp).replace("\\", "/"):
                cloud_native = True
            if name.lower() in API_SPEC_NAMES:
                profile.has_api_spec = True

            # Content inspection for frameworks, entry points, endpoints & security markers
            if ext in (".py", ".java", ".js", ".ts", ".tsx", ".go", ".rs", ".cs", ".json", ".toml", ".txt", ".xml", ".yaml", ".yml"):
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")[:200_000]

                    # Check framework signatures
                    for sig_file, pattern, fw in FRAMEWORK_SIGNATURES:
                        if name == sig_file and pattern.search(text):
                            frameworks.add(fw)

                    # Check entry points
                    for ep_pat in ENTRYPOINT_PATTERNS:
                        if ep_pat.search(text):
                            entry_points.add(str(fp.relative_to(repo_root) if repo_root in fp.parents or fp.parent == repo_root else fp))
                            break

                    # Check endpoints
                    for end_pat in ENDPOINT_PATTERNS:
                        matches = end_pat.findall(text)
                        for m in matches:
                            route = m if isinstance(m, str) else m[0]
                            endpoints.add(route)

                    # Check security markers
                    for sec_label, sec_pat in SECURITY_MARKER_PATTERNS:
                        if sec_pat.search(text):
                            security_markers.add(sec_label)

                except OSError:
                    pass

        total_src = sum(lang_counts.values()) or 1
        profile.languages = {
            lang: round(100.0 * n / total_src, 1)
            for lang, n in lang_counts.most_common()
        }
        if lang_counts:
            profile.primary_language = lang_counts.most_common(1)[0][0]

        profile.frameworks = sorted(frameworks)
        profile.build_tools = sorted(build_tools)
        profile.entry_points = sorted(entry_points)[:20] # Cap top 20
        profile.detected_endpoints = sorted(endpoints)[:50] # Cap top 50
        profile.security_markers = sorted(security_markers)

        # multiple build manifests in distinct directories -> monorepo signal
        profile.is_monorepo = len({d for d in manifest_dirs}) > 1

        arch: list[str] = []
        fe = {"React", "Vue", "Angular", "Next.js"}
        be = {"Spring Boot", "Django", "Flask", "FastAPI", "Express", "Go Web Framework", "Rust Web Framework", "NestJS"}
        if frameworks & fe and frameworks & be:
            arch.append("full-stack")
        elif frameworks & fe:
            arch.append("frontend")
        elif frameworks & be or profile.primary_language in {"Java", "Go", "C#", "Python", "Rust"}:
            arch.append("backend")
        if cloud_native:
            arch.append("cloud-native")
        if profile.is_monorepo:
            arch.append("monorepo")

        profile.architecture = arch or ["unclassified"]
        return profile
