"""
Dependency manifest parsers — repository-agnostic extraction of
(name, version, ecosystem) from common lockfiles/manifests.

Supported now: requirements.txt, package.json, package-lock.json,
pom.xml, go.mod.
TODO(deps-roadmap): Cargo.lock, Gemfile.lock, composer.lock, go.sum.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str        # PyPI | npm | Maven | Go
    manifest: str         # file it came from


def parse_requirements_txt(path: Path) -> list[Dependency]:
    deps = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]{1,2}=?\s*([\w.\-*]+))?', line)
        if m:
            deps.append(Dependency(m.group(1).lower(), m.group(2), "PyPI", str(path)))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            deps.append(Dependency(name, str(ver).lstrip("^~"), "npm", str(path)))
    return deps


def parse_package_lock(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for name, meta in (data.get("packages") or {}).items():
        if not name:
            continue
        short = name.split("node_modules/")[-1]
        deps.append(Dependency(short, meta.get("version"), "npm", str(path)))
    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    deps = []
    for dep in root.iterfind(f".//{q('dependencies')}/{q('dependency')}", ns):
        gid = dep.findtext(q("groupId"), default="", namespaces=ns)
        aid = dep.findtext(q("artifactId"), default="", namespaces=ns)
        ver = dep.findtext(q("version"), default=None, namespaces=ns)
        if aid:
            deps.append(Dependency(f"{gid}:{aid}".strip(":"), ver, "Maven", str(path)))
    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    deps = []
    in_block = False
    for line in path.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r'^(?:require\s+)?([\w./\-]+)\s+v([\w.\-+]+)', s) if (in_block or s.startswith("require")) else None
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "Go", str(path)))
    return deps


def parse_cargo_lock(path: Path) -> list[Dependency]:
    deps = []
    curr_name = None
    curr_ver = None
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line == "[[package]]":
            if curr_name:
                deps.append(Dependency(curr_name, curr_ver, "Cargo", str(path)))
            curr_name, curr_ver = None, None
        elif line.startswith("name = "):
            curr_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and curr_name and not curr_ver:
            curr_ver = line.split("=", 1)[1].strip().strip('"')
    if curr_name:
        deps.append(Dependency(curr_name, curr_ver, "Cargo", str(path)))
    return deps


def parse_gemfile_lock(path: Path) -> list[Dependency]:
    deps = []
    in_specs = False
    for line in path.read_text(errors="ignore").splitlines():
        if line.startswith("    specs:"):
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith("      "):
                in_specs = False
                continue
            m = re.match(r'^\s{6}([\w\-._]+)\s*\(([\w.\-+]+)\)', line)
            if m:
                deps.append(Dependency(m.group(1), m.group(2), "RubyGems", str(path)))
    return deps


def parse_composer_lock(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("packages", "packages-dev"):
        for item in data.get(section, []):
            name = item.get("name")
            ver = str(item.get("version", "")).lstrip("v")
            if name:
                deps.append(Dependency(name, ver or None, "Packagist", str(path)))
    return deps


def parse_go_sum(path: Path) -> list[Dependency]:
    deps = []
    seen = set()
    for line in path.read_text(errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            pkg, ver = parts[0], parts[1].lstrip("v").split("/")[0]
            if (pkg, ver) not in seen:
                seen.add((pkg, ver))
                deps.append(Dependency(pkg, ver, "Go", str(path)))
    return deps


def parse_yarn_lock(path: Path) -> list[Dependency]:
    deps = []
    curr_names = []
    for line in path.read_text(errors="ignore").splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            curr_names = [p.strip().strip('"\'') for p in line.rstrip(":").split(",")]
        elif line.strip().startswith("version ") and curr_names:
            ver = line.strip().split(maxsplit=1)[1].strip('"\'')
            for name_spec in curr_names:
                pkg_name = name_spec.rsplit("@", 1)[0] if "@" in name_spec[1:] else name_spec
                deps.append(Dependency(pkg_name, ver, "npm", str(path)))
            curr_names = []
    return deps


def parse_pipfile_lock(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            ver = meta.get("version", "").lstrip("=")
            deps.append(Dependency(name, ver or None, "PyPI", str(path)))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "pom.xml": parse_pom_xml,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "go.sum": parse_go_sum,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_yarn_lock,
    "poetry.lock": parse_cargo_lock,
    "Pipfile.lock": parse_pipfile_lock,
}


def parse_manifest(path: Path) -> list[Dependency]:
    parser = PARSERS.get(path.name)
    return parser(path) if parser else []

