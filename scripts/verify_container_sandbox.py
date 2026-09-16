#!/usr/bin/env python3
"""Fail-closed attestation for the tracked container/browser sandbox baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "deployment/docker/README.md"
RUNTIME_CONFIG_PATH = ROOT / "deployment/docker/chromium-runtime.conf"
POLICY_PATH = ROOT / "deployment/docker/container-security-policy.json"
POLICY_KEYS = {"$schema", "policy", "container", "browser"}
CONTAINER_KEYS = {
    "seccomp_profile",
    "seccomp_override",
    "privileged",
    "no_new_privileges",
    "capabilities_add",
}
BROWSER_KEYS = {"user_must_be_non_root", "sandbox_disabling_flags"}
FORBIDDEN_CONTAINER_PATTERNS = (
    re.compile(r"(?i)\bseccomp\s*[:=]\s*unconfined\b"),
    re.compile(
        r"(?im)^[ \t]*[\"']?privileged[\"']?[ \t]*:[ \t]*(?:true|yes|on|1|\$\{)"
    ),
    re.compile(r"(?im)^[ \t]*[\"']?(?:cap_add|cap-add)[\"']?[ \t]*:"),
    re.compile(r"(?i)(?:^|\s)--cap-add(?:=|\s)"),
)
DISALLOWED_BROWSER_FLAGS = (
    "--no-sandbox",
    "--disable-seccomp-filter-sandbox",
    "--disable-setuid-sandbox",
)
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_RUNTIME_STATUS_BYTES = 128 * 1024
RUNTIME_STATUS_FIELDS = {
    "Name",
    "Uid",
    "NoNewPrivs",
    "CapEff",
    "CapPrm",
    "CapAmb",
    "Seccomp",
    "Seccomp_filters",
}
ALLOWED_BROWSER_PROCESS_NAMES = {"chrome", "chromium"}
EXPECTED_ARTIFACT_SHA256 = {
    "README.md": "ab7c6591b66544abbc84cf152c706b3bc633437ae637a2c73955fb4ce5685f20",
    "chromium-runtime.conf": "90d493cfbee35054ca9c1d311cd4c96205204c158cefbe11922f0ebc1a5086e1",
    "container-security-policy.json": "30b93b00ab289ca33c7337e9ccc8db9f8d18dea663ce25548621532097d43472",
}
EXPECTED_COMPOSE_BLOCK = """```yaml
  services:
    homeassistant:
      image: ghcr.io/home-assistant/home-assistant:stable
      security_opt:
        - no-new-privileges:true
      privileged: false
      # Neuvádět seccomp override: Docker použije docker-default.
  ```"""


class VerificationError(RuntimeError):
    """Raised when the tracked sandbox policy cannot be proven safe."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as err:
        raise VerificationError(f"missing or unreadable artifact: {path}") from err


def _open_no_follow(path: Path) -> int:
    """Open an absolute path without following any directory or file symlink."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise VerificationError("platform cannot enforce no-follow artifact reads")
    absolute = path.absolute()
    parts = absolute.parts
    if not parts or parts[0] != os.sep or len(parts) < 2:
        raise VerificationError(f"artifact path is not a bounded absolute file path: {path}")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    directory_fd = os.open(os.sep, directory_flags)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    except OSError as err:
        raise VerificationError(f"missing, unreadable, or linked artifact: {path}") from err
    finally:
        os.close(directory_fd)


def _read_tracked_artifact(path: Path) -> tuple[str, str]:
    """Read and hash one stable regular file without following any symlink."""
    descriptor = _open_no_follow(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT_BYTES:
            raise VerificationError(f"artifact is not a bounded regular file: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(65536, MAX_ARTIFACT_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise VerificationError(f"artifact exceeds size limit: {path}")
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise VerificationError(f"artifact changed while being attested: {path}")
        reopened = _open_no_follow(path)
        try:
            current = os.fstat(reopened)
            if not stat.S_ISREG(current.st_mode) or (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            ) != identity:
                raise VerificationError(f"artifact identity changed while being attested: {path}")
        finally:
            os.close(reopened)
    except OSError as err:
        raise VerificationError(f"artifact could not be attested safely: {path}") from err
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    try:
        return data.decode("utf-8"), hashlib.sha256(data).hexdigest()
    except UnicodeError as err:
        raise VerificationError(f"artifact is not valid UTF-8: {path}") from err


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"container security policy has duplicate key: {key}")
        result[key] = value
    return result


def _load_policy(content: str) -> dict[str, Any]:
    try:
        policy = json.loads(content, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as err:
        raise VerificationError("container security policy is not valid JSON") from err
    if not isinstance(policy, dict):
        raise VerificationError("container security policy must be a JSON object")
    container = policy.get("container")
    browser = policy.get("browser")
    if (
        set(policy) != POLICY_KEYS
        or policy.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or policy.get("policy") != "cez-pnd-container-security-v1"
        or not isinstance(container, dict)
        or not isinstance(browser, dict)
        or set(container) != CONTAINER_KEYS
        or set(browser) != BROWSER_KEYS
        or container.get("seccomp_profile") != "docker-default"
        or container.get("seccomp_override") is not False
        or container.get("privileged") is not False
        or container.get("no_new_privileges") is not True
        or container.get("capabilities_add") != []
        or browser.get("user_must_be_non_root") is not True
        or browser.get("sandbox_disabling_flags") != []
    ):
        raise VerificationError("container security policy is weaker than the required baseline")
    return policy


def attest_tracked_policy() -> dict[str, Any]:
    """Validate tracked policy and return a sanitized, reproducible attestation."""
    artifacts = {
        label: _read_tracked_artifact(path)
        for label, path in (
            ("README.md", README_PATH),
            ("chromium-runtime.conf", RUNTIME_CONFIG_PATH),
            ("container-security-policy.json", POLICY_PATH),
        )
    }
    readme = artifacts["README.md"][0]
    runtime_config = artifacts["chromium-runtime.conf"][0]
    policy = _load_policy(artifacts["container-security-policy.json"][0])

    for path, content in ((README_PATH, readme), (RUNTIME_CONFIG_PATH, runtime_config)):
        for pattern in FORBIDDEN_CONTAINER_PATTERNS:
            if pattern.search(content):
                raise VerificationError(f"forbidden container directive in {path.name}")

    active_runtime_lines = [
        line.strip()
        for line in runtime_config.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if active_runtime_lines != ['CHROMIUM_FLAGS=""']:
        raise VerificationError("Chromium runtime config must contain only one empty flags assignment")
    if any(flag in line for line in active_runtime_lines for flag in DISALLOWED_BROWSER_FLAGS):
        raise VerificationError("Chromium runtime config contains a sandbox-disabling flag")
    if readme.count(EXPECTED_COMPOSE_BLOCK) != 1:
        raise VerificationError("deployment documentation lacks the exact safe Compose baseline")

    files = {label: digest for label, (_, digest) in artifacts.items()}
    if files != EXPECTED_ARTIFACT_SHA256:
        raise VerificationError("tracked sandbox artifact content drifts from the reviewed baseline")
    return {
        "status": "pass",
        "policy": policy["policy"],
        "seccomp_profile": "docker-default",
        "privileged": False,
        "no_new_privileges": True,
        "tracked_artifacts_sha256": files,
    }


def _read_proc_status(pid: int | None) -> str:
    """Read one proc status file for a validated process target.

    The path is constructed from an integer PID rather than accepted from the
    caller.  Opening the proc file before reading it also makes the attestation
    refer to the process represented by that proc entry at open time, avoiding
    path traversal and arbitrary-file injection through a status path.
    """
    if pid is not None and (type(pid) is not int or pid <= 0):
        raise VerificationError("runtime target PID must be a positive integer")
    target_pid = os.getpid() if pid is None else int(pid)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW
    proc_fd = -1
    process_fd = -1
    try:
        proc_fd = os.open("/proc", directory_flags)
        process_fd = os.open(str(target_pid), directory_flags, dir_fd=proc_fd)
        process_identity = os.fstat(process_fd)
        descriptor = os.open("status", file_flags, dir_fd=process_fd)
    except OSError as err:
        if process_fd >= 0:
            os.close(process_fd)
        if proc_fd >= 0:
            os.close(proc_fd)
        raise VerificationError("runtime target status is missing or unreadable") from err
    try:
        stat_result = os.fstat(descriptor)
        if stat_result.st_size > MAX_RUNTIME_STATUS_BYTES:
            raise VerificationError("runtime target status exceeds the size limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(65536, MAX_RUNTIME_STATUS_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RUNTIME_STATUS_BYTES:
                raise VerificationError("runtime target status exceeds the size limit")
        replacement_fd = os.open(str(target_pid), directory_flags, dir_fd=proc_fd)
        try:
            replacement_identity = os.fstat(replacement_fd)
            if (process_identity.st_dev, process_identity.st_ino) != (
                replacement_identity.st_dev,
                replacement_identity.st_ino,
            ):
                raise VerificationError("runtime target identity changed during attestation")
        finally:
            os.close(replacement_fd)
    except OSError as err:
        raise VerificationError("runtime target status could not be read safely") from err
    finally:
        os.close(descriptor)
        os.close(process_fd)
        os.close(proc_fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeError as err:
        raise VerificationError("runtime target status is not valid UTF-8") from err


def _parse_runtime_status(content: str) -> dict[str, Any]:
    """Parse and validate the security fields from Linux ``/proc/status``."""
    if not content or len(content.encode("utf-8")) > MAX_RUNTIME_STATUS_BYTES:
        raise VerificationError("runtime target status is empty or exceeds the size limit")
    fields: dict[str, str] = {}
    seen_keys: set[str] = set()
    for line in content.splitlines():
        if not line:
            continue
        key, separator, value = line.partition(":")
        if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            raise VerificationError("runtime target status contains a malformed field")
        if key in seen_keys:
            raise VerificationError(f"runtime target status has duplicate field: {key}")
        seen_keys.add(key)
        if key in RUNTIME_STATUS_FIELDS:
            normalized = value.strip()
            if not normalized:
                raise VerificationError(f"invalid {key} value in runtime status")
            fields[key] = normalized

    missing = RUNTIME_STATUS_FIELDS - fields.keys()
    if missing:
        raise VerificationError(
            "runtime target status is missing required field(s): " + ", ".join(sorted(missing))
        )

    process_name = fields["Name"]
    if len(process_name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", process_name):
        raise VerificationError("invalid Name value in runtime status")

    uid_tokens = fields["Uid"].split()
    if len(uid_tokens) != 4 or any(
        len(token) > 20 or not re.fullmatch(r"[0-9]+", token) for token in uid_tokens
    ):
        raise VerificationError("invalid Uid value in runtime status")
    uids = [int(token) for token in uid_tokens]
    if any(uid == 0 for uid in uids):
        raise VerificationError("runtime target includes a root UID")

    if not re.fullmatch(r"[01]", fields["NoNewPrivs"]):
        raise VerificationError("invalid NoNewPrivs value in runtime status")
    no_new_privs = int(fields["NoNewPrivs"])
    if no_new_privs != 1:
        raise VerificationError("runtime target does not have NoNewPrivs=1")

    capabilities: dict[str, int] = {}
    for key in ("CapEff", "CapPrm", "CapAmb"):
        value = fields[key]
        if len(value) > 32 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            raise VerificationError(f"invalid {key} value in runtime status")
        capabilities[key] = int(value, 16)
        if capabilities[key] != 0:
            raise VerificationError(f"runtime target has non-zero {key}")

    numeric_fields: dict[str, int] = {}
    for key in ("Seccomp", "Seccomp_filters"):
        value = fields[key]
        if len(value) > 20 or not re.fullmatch(r"[0-9]+", value):
            raise VerificationError(f"invalid {key} value in runtime status")
        numeric_fields[key] = int(value)
    if numeric_fields["Seccomp"] != 2 or numeric_fields["Seccomp_filters"] < 1:
        raise VerificationError("current process does not have an active seccomp filter")

    return {
        "status": "pass",
        "process_name": process_name,
        "uids": uids,
        "no_new_privs": no_new_privs,
        "cap_eff": capabilities["CapEff"],
        "cap_prm": capabilities["CapPrm"],
        "cap_amb": capabilities["CapAmb"],
        "seccomp_mode": numeric_fields["Seccomp"],
        "seccomp_filters": numeric_fields["Seccomp_filters"],
    }


def attest_runtime_seccomp(pid: int | None = None) -> dict[str, Any]:
    """Attest a real proc target's complete least-privilege security context.

    The checker must run in the same security context as the target Chromium
    process when no PID is supplied.  ``pid`` is an explicit positive process
    ID and is converted to the bounded ``/proc/<pid>/status`` path internally;
    callers cannot inject an arbitrary filesystem path.  This verifies the
    process security context, not the identity of a Docker seccomp profile.
    """
    result = _parse_runtime_status(_read_proc_status(pid))
    if pid is None:
        result["target"] = "self"
    else:
        if result["process_name"].lower() not in ALLOWED_BROWSER_PROCESS_NAMES:
            raise VerificationError("runtime PID is not a recognized Chromium process")
        result["target_pid"] = pid
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime",
        action="store_true",
        help="also attest the target process security context (same context by default)",
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="with --runtime, attest /proc/<pid>/status for this positive PID",
    )
    args = parser.parse_args()
    if args.pid is not None and not args.runtime:
        parser.error("--pid requires --runtime")
    try:
        result = attest_tracked_policy()
        if args.runtime:
            result["runtime"] = attest_runtime_seccomp(args.pid)
    except VerificationError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
