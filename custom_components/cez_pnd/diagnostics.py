"""Diagnostics support for CEZ Distribuce PND integration."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from typing import Any, Optional

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_BROWSER_HEADLESS,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
    CONF_PASSWORD,
    CONF_SCAN_TIME,
    CONF_TARIFF_ENTITY,
    CONF_USERNAME,
    DEFAULT_DEBUG_DIR,
    DEFAULT_DEBUG_MODE,
    DEFAULT_SCAN_TIME,
    DISALLOWED_BROWSER_FLAGS,
    DOMAIN,
    mask_ean,
)

TO_REDACT = {
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_EAN,
    CONF_ELM,
    CONF_DEBUG_DIR,
    CONF_TARIFF_ENTITY,
    "access_token",
    "token",
    "api_key",
    "client_secret",
}


def _get_pkg_version(package_name: str) -> str:
    """Bezpečně vrátí verzi instalovaného balíčku bez vyvolání výjimky a bez úniku cest."""
    try:
        import importlib.metadata
        return importlib.metadata.version(package_name)
    except Exception:
        return "unavailable"


def _get_binary_version(binary_candidates: list[str]) -> str:
    """Bezpečně zjistí verzi binárky bez použití shellu a bez úniku systémových cest (CWE-532)."""
    for candidate in binary_candidates:
        # Ověření existence binárky (absolutní cesta nebo v PATH)
        if os.path.exists(candidate) or shutil.which(candidate):
            try:
                res = subprocess.run(
                    [candidate, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if res.returncode == 0 and res.stdout:
                    first_line = res.stdout.strip().splitlines()[0].strip()
                    # Extrakce čistého čísla verze (např. "128.0.6613.119" nebo "0.34.0")
                    match = re.search(r"(\d+(?:\.\d+)+)", first_line)
                    if match:
                        return match.group(1)
                    # Fallback na oříznutý bezpečný řetězec bez lomítek a cest
                    sanitized = re.sub(r"/[^\s]+", "", first_line).strip()
                    return sanitized[:64] if sanitized else "unknown"
            except Exception:
                continue
    return "not_installed"


def _attest_dependencies_and_sbom(
    installed_selenium: str,
    installed_bs4: str,
    chrome_ver: str,
    chromedriver_ver: str,
    geckodriver_ver: str,
    sbom_path: Optional[str] = None,
) -> dict[str, Any]:
    """Attest runtime dependencies and browser runtime stack against release SBOM (SEC10-06 / CWE-1104, CWE-1357)."""
    if sbom_path is None:
        sbom_path = os.path.join(os.path.dirname(__file__), "sbom.json")

    sbom_present = os.path.isfile(sbom_path)
    sbom_sha256 = "unavailable"
    sbom_data: dict[str, Any] = {}

    if sbom_present:
        try:
            with open(sbom_path, "rb") as f:
                content = f.read()
                sbom_sha256 = hashlib.sha256(content).hexdigest()
                sbom_data = json.loads(content.decode("utf-8"))
        except Exception:
            sbom_present = False

    components_map: dict[str, dict[str, Any]] = {}
    if sbom_data and "components" in sbom_data:
        for comp in sbom_data["components"]:
            if isinstance(comp, dict) and "name" in comp:
                components_map[comp["name"]] = comp

    def _parse_version_tuple(v_str: str) -> tuple[int, ...]:
        clean = re.sub(r"[^\d.]", "", v_str.split()[0] if v_str else "")
        parts = [int(p) for p in clean.split(".") if p.isdigit()]
        return tuple(parts) if parts else (0,)

    dep_attestation: dict[str, Any] = {}
    vulnerable_detected = False
    drift_detected = False

    for pkg_name, installed_v in [("selenium", installed_selenium), ("beautifulsoup4", installed_bs4)]:
        comp = components_map.get(pkg_name, {})
        baseline_v = comp.get("version", "unknown")
        advisory_min = comp.get("advisory_min_version", "unknown")
        max_exclusive = comp.get("max_version_exclusive", "unknown")

        installed_tuple = _parse_version_tuple(installed_v)
        advisory_tuple = _parse_version_tuple(advisory_min)
        max_tuple = _parse_version_tuple(max_exclusive)

        advisory_compliant = True
        bounds_compliant = True

        if installed_v in ("not_installed", "unknown"):
            advisory_compliant = False
            bounds_compliant = False
        else:
            if advisory_tuple != (0,) and installed_tuple < advisory_tuple:
                advisory_compliant = False
                vulnerable_detected = True
            if max_tuple != (0,) and installed_tuple >= max_tuple:
                bounds_compliant = False
                drift_detected = True
            if baseline_v != "unknown" and installed_v != baseline_v:
                drift_detected = True

        dep_attestation[pkg_name] = {
            "installed_version": installed_v,
            "attested_baseline": baseline_v,
            "advisory_min_version": advisory_min,
            "advisory_compliant": advisory_compliant,
            "bounds_compliant": bounds_compliant,
            "status": "compliant" if (advisory_compliant and bounds_compliant) else (
                "vulnerable" if not advisory_compliant else "out_of_bounds"
            ),
        }

    browser_matrix = sbom_data.get("browser_runtime_matrix", {})
    chrome_tuple = _parse_version_tuple(chrome_ver)
    c_driver_tuple = _parse_version_tuple(chromedriver_ver)

    chrome_major = chrome_tuple[0] if chrome_tuple else 0
    driver_major = c_driver_tuple[0] if c_driver_tuple else 0

    browser_compat_status = "not_installed"
    driver_match = True

    if chrome_ver != "not_installed" or chromedriver_ver != "not_installed":
        if chrome_ver != "not_installed" and chromedriver_ver != "not_installed":
            if chrome_major > 0 and driver_major > 0 and chrome_major != driver_major:
                driver_match = False
                browser_compat_status = "major_version_mismatch"
            elif chrome_major >= 114:
                browser_compat_status = "compatible"
            else:
                browser_compat_status = "unsupported_version"
        elif chrome_ver != "not_installed":
            browser_compat_status = "browser_only" if chrome_major >= 114 else "unsupported_version"
        else:
            browser_compat_status = "driver_only"
    elif geckodriver_ver != "not_installed":
        browser_compat_status = "geckodriver_available"

    browser_attestation = {
        "active_browser_version": chrome_ver,
        "active_driver_version": chromedriver_ver,
        "geckodriver_version": geckodriver_ver,
        "major_version_aligned": driver_match,
        "compatibility_status": browser_compat_status,
        "matrix_enforced": bool(browser_matrix),
    }

    if not sbom_present:
        overall_status = "missing_sbom"
    elif vulnerable_detected:
        overall_status = "vulnerable_dependency_detected"
    elif not driver_match:
        overall_status = "browser_stack_mismatch"
    elif drift_detected:
        overall_status = "drift_detected"
    else:
        overall_status = "attested"

    return {
        "sbom_present": sbom_present,
        "sbom_format": sbom_data.get("bomFormat", "unknown"),
        "sbom_spec_version": sbom_data.get("specVersion", "unknown"),
        "sbom_sha256": sbom_sha256,
        "attestation_status": overall_status,
        "dependency_attestation": dep_attestation,
        "browser_stack_attestation": browser_attestation,
    }


def _collect_fs_diagnostics(
    debug_dir: str, headless: bool
) -> dict[str, Any]:
    """Synchronní pomocná funkce pro bezpečný sběr diagnostických dat o souborech a prostředí v executoru."""
    has_chrome = os.path.exists("/usr/bin/google-chrome") or os.path.exists("/usr/bin/chromium")
    has_chromedriver = os.path.exists("/usr/bin/chromedriver") or os.path.exists("/usr/local/bin/chromedriver")
    has_geckodriver = os.path.exists("/usr/bin/geckodriver") or os.path.exists("/usr/local/bin/geckodriver")

    chrome_ver = _get_binary_version(["/usr/bin/google-chrome", "/usr/bin/chromium", "google-chrome", "chromium"])
    chromedriver_ver = _get_binary_version(["/usr/bin/chromedriver", "/usr/local/bin/chromedriver", "chromedriver"])
    geckodriver_ver = _get_binary_version(["/usr/bin/geckodriver", "/usr/local/bin/geckodriver", "geckodriver"])

    active_driver = "Chrome" if (has_chrome or has_chromedriver) else ("Firefox" if has_geckodriver else "none")

    debug_artifacts_count = 0
    if os.path.isdir(debug_dir):
        try:
            debug_artifacts_count = len([f for f in os.listdir(debug_dir) if f.startswith("cez_pnd_debug_")])
        except Exception:
            pass

    # Atestace bezpečnostní konfigurace prohlížeče a sandboxu (SEC10-03 / CWE-693 / CWE-250)
    disallowed_found = False
    detected_disallowed = []
    for env_var in ("CHROMIUM_FLAGS", "CHROME_FLAGS", "EXTRA_CHROMIUM_FLAGS"):
        val = os.environ.get(env_var, "")
        for flag in DISALLOWED_BROWSER_FLAGS:
            if flag in val and flag not in detected_disallowed:
                disallowed_found = True
                detected_disallowed.append(flag)

    for cfg_path in ("/etc/chromium/docker.conf", "/etc/chromium/default", "/etc/chromium-browser/default"):
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for flag in DISALLOWED_BROWSER_FLAGS:
                        if flag in content and flag not in detected_disallowed:
                            disallowed_found = True
                            detected_disallowed.append(flag)
            except Exception:
                pass

    selenium_ver = _get_pkg_version("selenium")
    bs4_ver = _get_pkg_version("beautifulsoup4")

    # Reprodukovatelná atestace závislostí a browser stacku podle SBOM (SEC10-06 / CWE-1104, CWE-1357)
    sbom_attestation = _attest_dependencies_and_sbom(
        installed_selenium=selenium_ver,
        installed_bs4=bs4_ver,
        chrome_ver=chrome_ver,
        chromedriver_ver=chromedriver_ver,
        geckodriver_ver=geckodriver_ver,
    )

    return {
        "has_chrome_binary": has_chrome,
        "has_chromedriver_binary": has_chromedriver,
        "has_geckodriver_binary": has_geckodriver,
        "chrome_version": chrome_ver,
        "chromedriver_version": chromedriver_ver,
        "geckodriver_version": geckodriver_ver,
        "active_driver": active_driver,
        "headless": headless,
        "debug_artifacts_count": debug_artifacts_count,
        "selenium_version": selenium_ver,
        "beautifulsoup4_version": bs4_ver,
        "python_version": platform.python_version(),
        "seccomp_filter_sandbox_enforced": not disallowed_found,
        "disallowed_flags_detected": detected_disallowed,
        "effective_sandbox_mode": "enforced_least_privilege" if not disallowed_found else "degraded_insecure",
        "sbom_present": sbom_attestation["sbom_present"],
        "sbom_attestation_status": sbom_attestation["attestation_status"],
        "sbom_sha256": sbom_attestation["sbom_sha256"],
        "dependency_attestation": sbom_attestation["dependency_attestation"],
        "browser_stack_attestation": sbom_attestation["browser_stack_attestation"],
        "sbom_attestation": sbom_attestation,
    }


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry with strict redaction of sensitive paths and usage."""
    coordinator = None
    if DOMAIN in hass.data and entry.entry_id in hass.data[DOMAIN]:
        coordinator = hass.data[DOMAIN][entry.entry_id]
    if coordinator is None:
        coordinator = getattr(entry, "runtime_data", None)

    debug_dir = (
        entry.options.get(CONF_DEBUG_DIR, entry.data.get(CONF_DEBUG_DIR, DEFAULT_DEBUG_DIR))
        if hasattr(entry, "options")
        else DEFAULT_DEBUG_DIR
    )

    headless = entry.data.get(CONF_BROWSER_HEADLESS, True) if hasattr(entry, "data") else True

    # Přesun diskových operací výhradně do executoru
    if hasattr(hass, "async_add_executor_job") and callable(hass.async_add_executor_job):
        job_res = hass.async_add_executor_job(
            _collect_fs_diagnostics, debug_dir, headless
        )
        if asyncio.iscoroutine(job_res) or isinstance(job_res, asyncio.Future) or hasattr(job_res, "__await__"):
            scraper_env = await job_res
        else:
            scraper_env = job_res if isinstance(job_res, dict) else _collect_fs_diagnostics(debug_dir, headless)
    else:
        scraper_env = _collect_fs_diagnostics(debug_dir, headless)

    tariff_entity = (
        entry.options.get(CONF_TARIFF_ENTITY, entry.data.get(CONF_TARIFF_ENTITY))
        if hasattr(entry, "options")
        else entry.data.get(CONF_TARIFF_ENTITY)
    )

    state = (
        hass.states.get(tariff_entity)
        if (tariff_entity and hasattr(hass, "states") and hass.states)
        else None
    )

    history_changes_count = 0
    fallback_used = False
    if coordinator and hasattr(coordinator, "tariff_evaluator"):
        history_changes_count = getattr(coordinator.tariff_evaluator, "last_history_state_changes_count", 0)
        fallback_used = getattr(coordinator.tariff_evaluator, "last_fallback_used", False)

    # Redakce identifikátoru tarifní entity (C-06 / SEC04-04)
    tariff_status: dict[str, Any] = {
        "is_configured": bool(tariff_entity),
        "entity_exists": state is not None,
        "current_state": state.state if state else None,
        "history_state_changes_count": history_changes_count,
        "fallback_used": fallback_used,
    }

    last_sync_time_str = None
    if coordinator and getattr(coordinator, "last_sync_time", None):
        last_sync_time_str = coordinator.last_sync_time.isoformat()

    coord_diag: dict[str, Any] = {
        "is_running": coordinator.is_running if coordinator else False,
        "last_sync_time": last_sync_time_str,
        "last_sync_duration_seconds": (
            coordinator.last_sync_result.duration_seconds
            if (coordinator and coordinator.last_sync_result)
            else 0.0
        ),
        "last_sync_status": (
            coordinator.last_sync_result.status
            if (coordinator and coordinator.last_sync_result)
            else None
        ),
        "last_error_code": (
            coordinator.last_sync_result.error_code
            if (coordinator and coordinator.last_sync_result)
            else None
        ),
        "last_error": (
            coordinator.last_sync_result.error_message
            if (coordinator and coordinator.last_sync_result)
            else None
        ),
        "scan_time": getattr(coordinator, "scan_time_str", DEFAULT_SCAN_TIME) if coordinator else DEFAULT_SCAN_TIME,
        "has_schedule": getattr(coordinator, "_unsub_schedule", None) is not None if coordinator else False,
    }

    # Redakce detailní spotřeby domácnosti v kWh (SEC04-04)
    last_sync_metrics: dict[str, Any] = {}
    if coordinator and coordinator.last_sync_result:
        res = coordinator.last_sync_result
        if res.daily_summary:
            last_sync_metrics["summary_date"] = (
                res.daily_summary.date.strftime("%Y-%m-%d")
                if res.daily_summary.date
                else None
            )
            last_sync_metrics["app_version"] = res.daily_summary.app_version
        total_inv = len(res.intervals)
        valid_inv = sum(1 for i in res.intervals if i.is_valid)
        last_sync_metrics["total_intervals"] = total_inv
        last_sync_metrics["valid_intervals"] = valid_inv
        last_sync_metrics["invalid_intervals"] = total_inv - valid_inv

    ha_version = getattr(hass.config, "version", "unknown") if hasattr(hass, "config") else "unknown"
    ha_tz = getattr(hass.config, "time_zone", "Europe/Prague") if hasattr(hass, "config") else "Europe/Prague"

    raw_title = getattr(entry, "title", f"ČEZ PND ({entry.entry_id})")
    masked_title = re.sub(r"\b\d{18}\b", lambda m: mask_ean(m.group(0)), str(raw_title))

    entry_data = {
        "entry_id": entry.entry_id,
        "version": getattr(entry, "version", 1),
        "domain": getattr(entry, "domain", DOMAIN),
        "title": masked_title,
        "data": async_redact_data(dict(getattr(entry, "data", {})), TO_REDACT),
        "options": async_redact_data(dict(getattr(entry, "options", {})), TO_REDACT),
    }

    payload = {
        "home_assistant": {
            "version": ha_version,
            "os_version": platform.system(),
            "timezone": str(ha_tz),
        },
        "integration": entry_data,
        "entry": entry_data,
        "coordinator": coord_diag,
        "last_sync_metrics": last_sync_metrics,
        "tariff_evaluation": tariff_status,
        "scraper_environment": scraper_env,
    }

    return payload
