#!/usr/bin/env python3
"""Fail-closed SEC12-03 release dependency and advisory verification."""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

try:
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version
except ImportError as err:  # pragma: no cover - exercised by invocation environment
    raise SystemExit("FAIL: the Home Assistant-provided 'packaging' module is required") from err


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "custom_components/cez_pnd/manifest.json"
SBOM_PATH = ROOT / "custom_components/cez_pnd/sbom.json"
INPUT_PATH = ROOT / "deployment/release/requirements.in"
LOCK_PATH = ROOT / "deployment/release/requirements-lock.txt"
ATTESTATION_PATH = ROOT / "deployment/release/advisory-attestation.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
ATTESTATION_SCOPE = "Known vulnerabilities returned by OSV.dev for the exact versions at checked_at"
BASELINE = {
    "home_assistant": "2026.8.3",
    "python": "3.14",
    "platform": "linux",
    "resolved_at": "2026-09-15",
}
DIRECT_ROLES = {"integration_direct", "ha_core_provided"}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UTC_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
EXPECTED_INTEGRATION_ROOTS = {"beautifulsoup4": "4.15.0", "selenium": "4.49.0"}
EXPECTED_HA_ROOTS = {"requests": "2.34.2"}
EXPECTED_APPLICATION = {
    "type": "application",
    "bom-ref": "pkg:github/igracek/HACS_CEZD_PND@1.0.2",
    "name": "HACS_CEZD_PND",
    "version": "1.0.2",
    "purl": "pkg:github/igracek/HACS_CEZD_PND@1.0.2",
}
EXPECTED_CLOSURE = {
    "attrs": "26.1.0",
    "beautifulsoup4": "4.15.0",
    "certifi": "2026.7.22",
    "charset-normalizer": "3.4.3",
    "h11": "0.16.0",
    "idna": "3.19",
    "outcome": "1.3.0.post0",
    "pysocks": "1.7.1",
    "requests": "2.34.2",
    "selenium": "4.49.0",
    "sniffio": "1.3.1",
    "sortedcontainers": "2.4.0",
    "soupsieve": "2.9.2",
    "trio": "0.34.0",
    "trio-websocket": "0.12.2",
    "typing-extensions": "4.16.0",
    "urllib3": "2.7.0",
    "websocket-client": "1.9.2",
    "wsproto": "1.3.2",
}
HA_PROVENANCE = {
    "repository": "https://github.com/home-assistant/core",
    "commit": "759e4658f40b3ccb671d418b8a0ed95224bf4561",
    "pyproject_sha256": "2618b6f740c5f55e48eeb2204661f841ea53ff9bf99edd0632879b0edf693642",
    "constraints_sha256": "94db4ee9d7731452e9479e96e72777454ccf69c0ec6a5a0742da330eaa7b7a42",
}


class VerificationError(RuntimeError):
    """Raised for any fail-closed verification error."""


def _json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as err:
        raise VerificationError(f"invalid or missing JSON artifact: {path.name}") from err
    if not isinstance(data, dict):
        raise VerificationError(f"JSON artifact is not an object: {path.name}")
    return data


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as err:
        raise VerificationError(f"cannot hash artifact: {path.name}") from err


def _properties(item: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for prop in item.get("properties", []):
        if isinstance(prop, dict) and isinstance(prop.get("name"), str) and isinstance(prop.get("value"), str):
            result[prop["name"]] = prop["value"]
    return result


def _load_components(sbom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise VerificationError("SBOM must be CycloneDX 1.5")
    metadata_props = _properties(sbom.get("metadata", {}))
    for key, value in BASELINE.items():
        if metadata_props.get(f"cez_pnd:baseline:{key}") != value:
            raise VerificationError(f"SBOM baseline drift: {key}")

    components: dict[str, dict[str, Any]] = {}
    for component in sbom.get("components", []):
        if not isinstance(component, dict):
            raise VerificationError("SBOM contains a non-object component")
        name = canonicalize_name(str(component.get("name", "")))
        version = str(component.get("version", ""))
        role = _properties(component).get("cez_pnd:dependency_role")
        hashes = component.get("hashes", [])
        sha_values = {
            str(item.get("content", "")).lower()
            for item in hashes
            if isinstance(item, dict) and str(item.get("alg", "")).upper() in {"SHA-256", "SHA_256"}
        }
        if not name or not version or role not in {
            "integration_direct", "integration_transitive", "ha_core_provided", "shared_with_ha_core"
        }:
            raise VerificationError("SBOM component is missing name, version, or dependency role")
        if len(sha_values) != 1 or not SHA256_RE.fullmatch(next(iter(sha_values))):
            raise VerificationError(f"SBOM component must have exactly one SHA-256: {name}")
        expected_ref = f"pkg:pypi/{name}@{version}"
        if component.get("bom-ref") != expected_ref or component.get("purl") != expected_ref:
            raise VerificationError(f"SBOM component has invalid purl or bom-ref: {name}")
        if name in components:
            raise VerificationError(f"duplicate SBOM component: {name}")
        component["_sha256"] = next(iter(sha_values))
        component["_role"] = role
        components[name] = component
    if not components:
        raise VerificationError("SBOM dependency closure is empty")
    return components


def _load_lock() -> dict[str, Requirement]:
    locked: dict[str, Requirement] = {}
    try:
        lines = LOCK_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise VerificationError("release lock is missing") from err
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
        except Exception as err:
            raise VerificationError("release lock contains an invalid requirement") from err
        name = canonicalize_name(requirement.name)
        if name in locked or not requirement.url:
            raise VerificationError(f"lock entry must be one unique direct artifact URL: {name}")
        parsed = urlparse(requirement.url)
        if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
            raise VerificationError(f"lock artifact is not hosted by PyPI: {name}")
        if not unquote(parsed.path).endswith(("-py3-none-any.whl", "-py2.py3-none-any.whl")):
            raise VerificationError(f"lock artifact is not a platform-independent wheel: {name}")
        if not parsed.fragment.startswith("sha256=") or not SHA256_RE.fullmatch(
            parsed.fragment.removeprefix("sha256=").lower()
        ):
            raise VerificationError(f"lock artifact lacks an exact SHA-256: {name}")
        locked[name] = requirement
    return locked


def _load_roots() -> dict[str, str]:
    roots: dict[str, str] = {}
    try:
        lines = INPUT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise VerificationError("requirements input is missing") from err
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        name = canonicalize_name(requirement.name)
        if name in roots:
            raise VerificationError(f"duplicate requirements input root: {name}")
        if len(requirement.specifier) != 1 or next(iter(requirement.specifier)).operator != "==":
            raise VerificationError(f"requirements input is not exactly pinned: {name}")
        roots[name] = next(iter(requirement.specifier)).version
    return roots


def _validate_graph(sbom: dict[str, Any], components: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    refs = {str(component["bom-ref"]): name for name, component in components.items()}
    if len(refs) != len(components):
        raise VerificationError("SBOM component bom-ref values are not unique")
    app_component = sbom.get("metadata", {}).get("component", {})
    if not isinstance(app_component, dict) or any(
        app_component.get(key) != value for key, value in EXPECTED_APPLICATION.items()
    ):
        raise VerificationError("SBOM application identity drifts from immutable baseline")
    app_ref = EXPECTED_APPLICATION["bom-ref"]
    graph: dict[str, set[str]] = {}
    dependencies = sbom.get("dependencies")
    if not isinstance(dependencies, list):
        raise VerificationError("SBOM dependency graph is not a list")
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"ref", "dependsOn"}:
            raise VerificationError("SBOM dependency graph entry is invalid")
        ref = dependency.get("ref")
        targets_list = dependency.get("dependsOn")
        if not isinstance(ref, str) or ref in graph:
            raise VerificationError("SBOM dependency graph contains a duplicate or invalid ref")
        if (
            not isinstance(targets_list, list)
            or not all(isinstance(target, str) for target in targets_list)
            or len(targets_list) != len(set(targets_list))
        ):
            raise VerificationError("SBOM dependency graph contains duplicate or invalid targets")
        if ref != app_ref and ref not in refs:
            raise VerificationError("SBOM dependency graph references an unknown component")
        targets = set(targets_list)
        if not targets.issubset(refs):
            raise VerificationError("SBOM dependency graph has an unknown dependency")
        graph[ref] = targets
    if app_ref not in graph or set(refs) - set(graph):
        raise VerificationError("SBOM dependency graph is incomplete")
    reachable: set[str] = set()
    queue = deque(graph[app_ref])
    while queue:
        ref = queue.popleft()
        if ref in reachable:
            continue
        reachable.add(ref)
        queue.extend(graph.get(ref, set()))
    if reachable != set(refs):
        raise VerificationError("SBOM contains unreachable or missing runtime components")
    return {refs[ref]: {refs[target] for target in targets} for ref, targets in graph.items() if ref in refs}


def _validate_local() -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Requirement], dict[str, set[str]]]:
    manifest = _json(MANIFEST_PATH)
    sbom = _json(SBOM_PATH)
    components = _load_components(sbom)
    locked = _load_lock()
    roots = _load_roots()
    graph = _validate_graph(sbom, components)

    if set(locked) != set(components):
        raise VerificationError("lock and SBOM dependency closures differ")
    actual_closure = {name: str(item["version"]) for name, item in components.items()}
    if actual_closure != EXPECTED_CLOSURE:
        raise VerificationError("dependency closure drifts from immutable 19-package baseline")
    expected_roots = EXPECTED_INTEGRATION_ROOTS | EXPECTED_HA_ROOTS
    if roots != expected_roots:
        raise VerificationError("requirements input drifts from immutable baseline roots")
    if {name: str(item["version"]) for name, item in components.items() if item["_role"] in DIRECT_ROLES} != expected_roots:
        raise VerificationError("requirements input and SBOM direct roots differ")
    if {name for name, item in components.items() if item["_role"] == "integration_direct"} != set(EXPECTED_INTEGRATION_ROOTS):
        raise VerificationError("SBOM integration ownership drifts from immutable baseline")
    if {name for name, item in components.items() if item["_role"] == "ha_core_provided"} != set(EXPECTED_HA_ROOTS):
        raise VerificationError("SBOM HA Core ownership drifts from immutable baseline")
    manifest_expected = sorted(f"{name}=={version}" for name, version in EXPECTED_INTEGRATION_ROOTS.items())
    if sorted(manifest.get("requirements", [])) != manifest_expected:
        raise VerificationError("manifest requirements drift from integration-owned SBOM roots")

    for name, requirement in locked.items():
        parsed = urlparse(requirement.url or "")
        sha256 = parsed.fragment.removeprefix("sha256=").lower()
        if sha256 != components[name]["_sha256"]:
            raise VerificationError(f"lock/SBOM hash drift: {name}")
        references = components[name].get("externalReferences", [])
        distribution_urls = {
            str(ref.get("url")) for ref in references if isinstance(ref, dict) and ref.get("type") == "distribution"
        }
        if requirement.url.rsplit("#", 1)[0] not in distribution_urls:
            raise VerificationError(f"lock/SBOM distribution URL drift: {name}")
    return sbom, components, locked, graph


def _fetch_json(url: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST" if body else "GET")
    try:
        with urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise VerificationError("dependency intelligence service returned a non-success status")
            data = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as err:
        raise VerificationError("dependency intelligence service unavailable or invalid") from err
    if not isinstance(data, dict):
        raise VerificationError("dependency intelligence service returned an invalid document")
    return data


def _fetch_bytes(url: str) -> bytes:
    try:
        with urlopen(Request(url), timeout=20) as response:
            if response.status != 200:
                raise VerificationError("HA provenance source returned a non-success status")
            return response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as err:
        raise VerificationError("HA provenance source unavailable") from err


def _validate_ha_provenance() -> None:
    commit = HA_PROVENANCE["commit"]
    base = f"https://raw.githubusercontent.com/home-assistant/core/{commit}"
    pyproject_data = _fetch_bytes(f"{base}/pyproject.toml")
    constraints_data = _fetch_bytes(f"{base}/homeassistant/package_constraints.txt")
    if hashlib.sha256(pyproject_data).hexdigest() != HA_PROVENANCE["pyproject_sha256"]:
        raise VerificationError("pinned HA pyproject provenance hash mismatch")
    if hashlib.sha256(constraints_data).hexdigest() != HA_PROVENANCE["constraints_sha256"]:
        raise VerificationError("pinned HA constraints provenance hash mismatch")
    try:
        project = tomllib.loads(pyproject_data.decode("utf-8"))["project"]
        constraints = constraints_data.decode("utf-8").splitlines()
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError) as err:
        raise VerificationError("pinned HA provenance content is invalid") from err
    if project.get("version") != BASELINE["home_assistant"] or project.get("requires-python") != ">=3.14.2":
        raise VerificationError("pinned HA version or Python baseline mismatch")
    if f"requests=={EXPECTED_HA_ROOTS['requests']}" not in constraints:
        raise VerificationError("HA Core-provided requests pin mismatch")


def _validate_pypi_and_closure(
    components: dict[str, dict[str, Any]], locked: dict[str, Requirement], graph: dict[str, set[str]]
) -> None:
    metadata: dict[str, dict[str, Any]] = {}
    for name, component in components.items():
        version = str(component["version"])
        document = _fetch_json(f"https://pypi.org/pypi/{name}/{version}/json")
        if set(document) < {"info", "urls"} or not isinstance(document.get("info"), dict):
            raise VerificationError(f"PyPI response lacks a valid info object: {name}")
        info = document["info"]
        if "requires_dist" not in info or (
            info["requires_dist"] is not None
            and (not isinstance(info["requires_dist"], list) or not all(isinstance(item, str) for item in info["requires_dist"]))
        ):
            raise VerificationError(f"PyPI info has invalid or missing requires_dist: {name}")
        urls = document["urls"]
        if not isinstance(urls, list):
            raise VerificationError(f"PyPI response has invalid urls: {name}")
        for item in urls:
            if not isinstance(item, dict):
                raise VerificationError(f"PyPI artifact entry is invalid: {name}")
            if not isinstance(item.get("url"), str) or not item["url"]:
                raise VerificationError(f"PyPI artifact URL is invalid: {name}")
            try:
                artifact_url = urlparse(item["url"])
                artifact_port = artifact_url.port
            except ValueError as err:
                raise VerificationError(f"PyPI artifact URL is invalid: {name}") from err
            if (
                artifact_url.scheme != "https"
                or artifact_url.hostname != "files.pythonhosted.org"
                or artifact_port not in (None, 443)
                or artifact_url.username is not None
                or artifact_url.password is not None
                or artifact_url.query
                or artifact_url.fragment
            ):
                raise VerificationError(f"PyPI artifact URL is not an allowed distribution URL: {name}")
            path_parts = artifact_url.path.split("/")
            if (
                len(path_parts) != 6
                or path_parts[:2] != ["", "packages"]
                or not re.fullmatch(r"[0-9a-f]{2}", path_parts[2])
                or not re.fullmatch(r"[0-9a-f]{2}", path_parts[3])
                or not re.fullmatch(r"[0-9a-f]{60}", path_parts[4])
                or not path_parts[5].endswith((".whl", ".tar.gz", ".zip", ".tar.bz2", ".tar.xz"))
            ):
                raise VerificationError(f"PyPI artifact URL is not an allowed distribution URL: {name}")
            digests = item.get("digests")
            if not isinstance(digests, dict) or not isinstance(digests.get("sha256"), str) or not SHA256_RE.fullmatch(digests["sha256"].lower()):
                raise VerificationError(f"PyPI artifact SHA-256 is invalid: {name}")
            if "yanked" not in item or type(item["yanked"]) is not bool:
                raise VerificationError(f"PyPI artifact yanked flag is invalid: {name}")
        lock_url = (locked[name].url or "").rsplit("#", 1)[0]
        expected_hash = component["_sha256"]
        matches = [
            item for item in urls
            if isinstance(item, dict)
            and item.get("url") == lock_url
            and item.get("digests", {}).get("sha256") == expected_hash
            and not item.get("yanked", False)
        ]
        if len(matches) != 1:
            raise VerificationError(f"locked artifact is absent, yanked, or has wrong PyPI hash: {name}")
        metadata[name] = document

    environment = default_environment()
    environment.update(
        {
            "python_version": "3.14", "python_full_version": "3.14.0", "sys_platform": "linux",
            "os_name": "posix", "platform_system": "Linux", "platform_python_implementation": "CPython",
            "implementation_name": "cpython",
        }
    )
    requested_extras: dict[str, set[str]] = {name: set() for name in components}
    calculated: dict[str, set[str]] = {name: set() for name in components}
    changed = True
    while changed:
        changed = False
        for name, document in metadata.items():
            active_extras = requested_extras[name] or {""}
            dependencies: set[str] = set()
            for raw_requirement in document["info"]["requires_dist"] or []:
                try:
                    requirement = Requirement(raw_requirement)
                except Exception as err:
                    raise VerificationError(f"PyPI has an invalid requires_dist entry: {name}") from err
                if requirement.marker and not any(
                    requirement.marker.evaluate(environment | {"extra": extra}) for extra in active_extras
                ):
                    continue
                dependency_name = canonicalize_name(requirement.name)
                if dependency_name not in components:
                    raise VerificationError(f"runtime dependency missing from lock/SBOM: {dependency_name}")
                if Version(str(components[dependency_name]["version"])) not in requirement.specifier:
                    raise VerificationError(f"locked version violates dependency constraint: {dependency_name}")
                dependencies.add(dependency_name)
                new_extras = set(requirement.extras) - requested_extras[dependency_name]
                if new_extras:
                    requested_extras[dependency_name].update(new_extras)
                    changed = True
            calculated[name] = dependencies
    if calculated != graph:
        raise VerificationError("SBOM dependency graph drifts from current PyPI metadata closure")


def _query_osv(components: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    ordered = sorted(components)
    payload = {
        "queries": [
            {"package": {"ecosystem": "PyPI", "name": name}, "version": str(components[name]["version"])}
            for name in ordered
        ]
    }
    response = _fetch_json(OSV_BATCH_URL, payload=payload)
    if set(response) != {"results"}:
        raise VerificationError("OSV top-level response schema is invalid")
    results = response.get("results")
    if not isinstance(results, list) or len(results) != len(ordered):
        raise VerificationError("OSV returned an incomplete result set")
    vulnerabilities: dict[str, list[str]] = {}
    for name, result in zip(ordered, results, strict=True):
        if not isinstance(result, dict) or result.get("next_page_token"):
            raise VerificationError("OSV result is invalid or unexpectedly paginated")
        # OSV querybatch canonically represents a clean query as an empty
        # object.  A non-empty result must be exactly a vulnerability list;
        # accepting arbitrary objects as clean would fail open on protocol
        # drift or a malformed response.
        if not result:
            continue
        if set(result) != {"vulns"} or not isinstance(result["vulns"], list):
            raise VerificationError("OSV result lacks a valid vulns list")
        ids: list[str] = []
        for item in result["vulns"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
                raise VerificationError("OSV vulnerability entry has an invalid id")
            ids.append(item["id"])
        ids = sorted(set(ids))
        if ids:
            vulnerabilities[name] = ids
    return vulnerabilities


def _expected_snapshot_packages(components: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"name": name, "version": str(components[name]["version"]), "sha256": components[name]["_sha256"]}
        for name in sorted(components)
    ]


def _validate_attestation(components: dict[str, dict[str, Any]]) -> None:
    attestation = _json(ATTESTATION_PATH)
    required_keys = {
        "schema_version", "checked_at", "database", "database_endpoint", "baseline", "home_assistant_provenance",
        "status", "scope", "valid_until", "future_safety_guarantee", "known_vulnerability_ids", "packages",
        "results", "artifacts",
    }
    if set(attestation) != required_keys or type(attestation.get("schema_version")) is not int or attestation["schema_version"] != 1:
        raise VerificationError("advisory attestation schema is invalid")
    checked_at = attestation.get("checked_at")
    if not isinstance(checked_at, str) or not UTC_TIMESTAMP_RE.fullmatch(checked_at):
        raise VerificationError("advisory attestation checked_at is not canonical UTC")
    try:
        datetime.strptime(checked_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as err:
        raise VerificationError("advisory attestation checked_at is invalid") from err
    if attestation.get("status") != "passed_at_snapshot" or attestation.get("database") != "OSV.dev":
        raise VerificationError("advisory attestation status/database is invalid")
    if attestation.get("database_endpoint") != OSV_BATCH_URL or attestation.get("scope") != ATTESTATION_SCOPE:
        raise VerificationError("advisory attestation endpoint/scope is invalid")
    if attestation.get("known_vulnerability_ids") != [] or attestation.get("valid_until", object()) is not None:
        raise VerificationError("advisory attestation must be a non-expiring historical snapshot with no recorded findings")
    if attestation.get("baseline") != BASELINE or attestation.get("future_safety_guarantee") is not False:
        raise VerificationError("advisory attestation baseline or snapshot semantics drift")
    if attestation.get("home_assistant_provenance") != HA_PROVENANCE:
        raise VerificationError("advisory attestation HA provenance drift")
    if attestation.get("packages") != _expected_snapshot_packages(components):
        raise VerificationError("advisory attestation package closure drift")
    expected_results = {name: [] for name in sorted(components)}
    if attestation.get("results") != expected_results:
        raise VerificationError("advisory attestation result set is incomplete or malformed")
    expected_artifacts = {
        "manifest_sha256": _sha256(MANIFEST_PATH), "lock_sha256": _sha256(LOCK_PATH), "sbom_sha256": _sha256(SBOM_PATH)
    }
    if attestation.get("artifacts") != expected_artifacts:
        raise VerificationError("advisory attestation artifact digest drift")


def _new_attestation(components: dict[str, dict[str, Any]], vulnerabilities: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "database": "OSV.dev",
        "database_endpoint": OSV_BATCH_URL,
        "baseline": BASELINE,
        "home_assistant_provenance": HA_PROVENANCE,
        "status": "failed_at_snapshot" if vulnerabilities else "passed_at_snapshot",
        "scope": ATTESTATION_SCOPE,
        "valid_until": None,
        "future_safety_guarantee": False,
        "known_vulnerability_ids": sorted({item for ids in vulnerabilities.values() for item in ids}),
        "results": {name: vulnerabilities.get(name, []) for name in sorted(components)},
        "packages": _expected_snapshot_packages(components),
        "artifacts": {
            "manifest_sha256": _sha256(MANIFEST_PATH), "lock_sha256": _sha256(LOCK_PATH), "sbom_sha256": _sha256(SBOM_PATH)
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Only validate committed artifact drift; no live advisory claim")
    parser.add_argument("--print-attestation", action="store_true", help="Print a fresh online attestation JSON to stdout")
    args = parser.parse_args()
    try:
        _, components, locked, graph = _validate_local()
        if not args.print_attestation:
            _validate_attestation(components)
        if args.offline:
            if args.print_attestation:
                raise VerificationError("--print-attestation requires live PyPI and OSV checks")
            print(f"PASS: offline artifact drift check ({len(components)} runtime packages); no live advisory claim")
            return 0
        _validate_ha_provenance()
        _validate_pypi_and_closure(components, locked, graph)
        vulnerabilities = _query_osv(components)
        if args.print_attestation:
            print(json.dumps(_new_attestation(components, vulnerabilities), indent=2, sort_keys=True))
        if vulnerabilities:
            raise VerificationError("OSV reports known vulnerabilities for the locked runtime closure")
        if not args.print_attestation:
            print(f"PASS: PyPI artifacts/closure and live OSV advisories checked for {len(components)} runtime packages")
        return 0
    except VerificationError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
