"""Direct HTTP client for CEZ Distribuce PND portal (browserless mode)."""
import codecs
from datetime import datetime, timedelta
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Mapping
from typing import Any, Dict, Final, List, Optional, Protocol, Tuple, Union
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup
from urllib3.util import Timeout as Urllib3Timeout

from .client import (
    PndAccountLockedError,
    PndAuthError,
    PndCaptchaError,
    PndElmNotFoundError,
    PndElmUnavailableError,
    PndInsecureBrowserError,
    PndMaintenanceError,
    PndParseError,
    PndPortalError,
    PndScraperError,
    PndTimeoutError,
)
from .const import (
    ALLOWED_HOSTNAMES_BY_STATE,
    APP_PATH_PREFIX,
    AUTH_HOST_PATH_CONTRACTS,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_DEBUG_DIR,
    DEFAULT_DEBUG_MODE,
    IDP_ALLOWED_HOSTNAMES,
    MAX_CSV_RESPONSE_SIZE,
    ORIGIN_STATE_APP,
    ORIGIN_STATE_AUTH,
    ORIGIN_STATE_CREDENTIALS,
    ORIGIN_STATE_IDP,
    ORIGIN_STATE_PREAUTH,
    PREAUTH_ALLOWED_HOSTNAMES,
    URL_PND_LOGIN,
)
from .fd_security import SealedReport
from .url_security import matches_segment_prefix, normalize_url_path

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT: Final[Tuple[int, int]] = (10, 30)
MAX_REDIRECTS: Final = 8
CSV_STREAM_CHUNK_SIZE: Final = 64 * 1024
MAX_AUTH_RESPONSE_SIZE: Final = 512 * 1024
MAX_DASHBOARD_RESPONSE_SIZE: Final = 256 * 1024
MAX_METERS_RESPONSE_SIZE: Final = 256 * 1024
MAX_DASHBOARD_ITEMS: Final = 256
HTTP_STREAM_CHUNK_SIZE: Final = 64 * 1024
MAX_CONTENT_LENGTH_DIGITS: Final = 20
METER_ELM_FIELDS: Final = ("elm", "electrometerId", "id")
METER_EAN_FIELD: Final = "ean"
METER_METADATA_FIELDS: Final = ("meters", "devices", "electrometers")
DASHBOARD_ELM_FIELDS: Final = ("electrometerId", "elm")
ELM_CONTRACT_CANONICAL: Final = "canonical"
ELM_CONTRACT_ALIAS_ELM: Final = "alias_elm"
ELM_CONTRACT_MIXED: Final = "mixed"
ELM_CONTRACT_ABSENT: Final = "absent"
ELM_CONTRACT_VALUES: Final = frozenset({
    ELM_CONTRACT_CANONICAL,
    ELM_CONTRACT_ALIAS_ELM,
    ELM_CONTRACT_MIXED,
    ELM_CONTRACT_ABSENT,
})
# ``requests`` does not enforce urllib3's ``total`` timeout while a streamed
# body is consumed.  Keep each blocking socket read bounded so the cooperative
# deadline check between chunks cannot stall indefinitely.  Half a second was
# too short for normal PND redirects and report generation in production; five
# seconds stays inside the coordinator's 175 s / 180 s deadline margin.
STREAM_READ_TIMEOUT_SLICE: Final = 5.0
REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
CSV_CONTENT_TYPES: Final = frozenset(
    {
        "application/csv",
        "application/octet-stream",
        "application/vnd.ms-excel",
        "text/csv",
        "text/plain",
    }
)
OPTIONAL_REPORT_HTTP_STATUSES: Final = frozenset({204, 404, 410})
DEFAULT_USER_AGENT: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Endpoint constants based on network capture analysis
URL_DASHBOARD_DATA: Final = "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view/data"
URL_EXPORT: Final = "https://pnd.cezdistribuce.cz/cezpnd2/external/data/export"

# Assembly IDs for CSV export reports:
# -1001: 01 Profil spotřeby (15-min range consumption)
# -1002: 02 Profil výroby (15-min range production)
# -1021: 17 Denní spotřeba (daily consumption)
# -1022: 18 Denní výroba (daily production)
ASSEMBLY_RANGE_CONSUMPTION: Final = "-1001"
ASSEMBLY_RANGE_PRODUCTION: Final = "-1002"
ASSEMBLY_DAILY_CONSUMPTION: Final = "-1021"
ASSEMBLY_DAILY_PRODUCTION: Final = "-1022"

EXPORT_SELECTOR_BOTH: Final = "device_set_and_elm"
EXPORT_SELECTOR_DEVICE_SET: Final = "device_set_only"
EXPORT_SELECTOR_ELM: Final = "elm_only"
EXPORT_SELECTOR_VALUES: Final = (
    EXPORT_SELECTOR_BOTH,
    EXPORT_SELECTOR_DEVICE_SET,
    EXPORT_SELECTOR_ELM,
)


def _normalize_dashboard_payload(payload: Any) -> Dict[str, Any]:
    """Normalize the current dashboard list response without trusting it.

    The legacy dashboard response is intentionally returned unchanged so its
    existing validation/selection behavior remains intact.  The current
    response is a bounded list of window records; only the scalar fields used
    by the HTTP client are accepted and copied into a minimal supported
    metadata shape.
    """
    if isinstance(payload, dict):
        return payload
    if not isinstance(payload, list):
        raise PndParseError("Dashboard metadata has an invalid shape (ERR_PORTAL)")
    if not payload or len(payload) > MAX_DASHBOARD_ITEMS:
        raise PndParseError("Dashboard metadata has an invalid list size (ERR_PORTAL)")

    device_sets: set[int] = set()
    electrometers: List[Dict[str, Any]] = []
    elm_contracts: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise PndParseError("Dashboard metadata contains a non-object record (ERR_PORTAL)")

        if "idDeviceSet" not in item:
            raise PndParseError("Dashboard metadata contains a missing device set (ERR_PORTAL)")
        device_set = item["idDeviceSet"]
        if device_set is not None:
            if isinstance(device_set, bool) or not isinstance(device_set, int):
                raise PndParseError("Dashboard metadata contains an invalid device set (ERR_PORTAL)")
            if device_set <= 0:
                raise PndParseError("Dashboard metadata contains an invalid device set (ERR_PORTAL)")
            device_sets.add(device_set)

        present_elm_fields = [
            field for field in DASHBOARD_ELM_FIELDS
            if field in item and item[field] is not None
        ]
        normalized_elms: set[str] = set()
        for field in present_elm_fields:
            raw_elm = item[field]
            if isinstance(raw_elm, bool) or not isinstance(raw_elm, str):
                raise PndParseError("Dashboard metadata contains an invalid identifier (ERR_PORTAL)")
            normalized_elm = str(raw_elm).strip()
            if not normalized_elm:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", normalized_elm):
                raise PndParseError("Dashboard metadata contains an invalid identifier (ERR_PORTAL)")
            normalized_elms.add(normalized_elm)
            elm_contracts.add({
                "electrometerId": ELM_CONTRACT_CANONICAL,
                "elm": ELM_CONTRACT_ALIAS_ELM,
            }[field])
        if len(normalized_elms) > 1:
            raise PndParseError("Dashboard metadata contains conflicting ELM identifiers (ERR_PORTAL)")
        if normalized_elms:
            meter = {"electrometerId": next(iter(normalized_elms))}
            if device_set is not None:
                meter["idDeviceSet"] = device_set
            normalized_eans: set[str] = set()
            if item.get(METER_EAN_FIELD) not in (None, ""):
                raw_ean = item[METER_EAN_FIELD]
                if isinstance(raw_ean, bool) or not isinstance(raw_ean, (str, int)):
                    raise PndParseError("Dashboard metadata contains an invalid EAN (ERR_PORTAL)")
                normalized_eans.add(str(raw_ean).strip())
            if normalized_eans:
                meter["ean"] = next(iter(normalized_eans))
            if meter not in electrometers:
                electrometers.append(meter)

    if not device_sets:
        raise PndParseError("Dashboard metadata contains a missing or conflicting device set (ERR_PORTAL)")

    if not elm_contracts:
        elm_contract = ELM_CONTRACT_ABSENT
    elif len(elm_contracts) == 1:
        elm_contract = next(iter(elm_contracts))
    else:
        elm_contract = ELM_CONTRACT_MIXED
    result = {
        "electrometers": electrometers,
        "elmMetadataStatus": elm_contract,
    }
    if len(device_sets) == 1:
        result["idDeviceSet"] = next(iter(device_sets))
    else:
        result["requiresMeterDeviceSet"] = True
    return result


class _BoundedResponseText(str):
    """String response carrying immutable-per-read diagnostic metadata."""

    pnd_metadata: Dict[str, Any]

    def __new__(cls, value: str, metadata: Dict[str, Any]) -> "_BoundedResponseText":
        instance = super().__new__(cls, value)
        instance.pnd_metadata = dict(metadata)
        return instance


class PndClientProtocol(Protocol):
    """Protocol defining the interface for PND clients (HTTP and Browser)."""

    app_version: Optional[str]

    def test_login(
        self,
        temp_dir: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Test login credentials and configured ELM."""
        ...
    def download_yesterday_data(
        self,
        download_dir: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, Union[str, SealedReport]]:
        """Download yesterday's consumption and production data."""
        ...

    def download_custom_range(
        self,
        download_dir: str,
        date_range: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, Union[str, SealedReport]]:
        """Download custom range consumption and production data."""
        ...


class PndReportUnavailableError(PndPortalError):
    """An optional report is explicitly unavailable for this account."""


class PndHttpClient:
    """Direct HTTP client for CEZ Distribuce PND portal (browserless mode)."""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize PndHttpClient with configuration dictionary."""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        self.username = str(config.get(CONF_USERNAME, config.get("username", ""))).strip()
        self.password = str(config.get(CONF_PASSWORD, config.get("password", "")))
        self.elm = str(config.get(CONF_ELM, config.get("elm", ""))).strip()
        self.ean = str(config.get(CONF_EAN, config.get("ean", ""))).strip()
        self.debug_mode = config.get(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE)
        self.debug_dir = config.get(CONF_DEBUG_DIR, DEFAULT_DEBUG_DIR)
        self.app_version: Optional[str] = "PND 2.0"
        self.last_debug_artifacts: List[str] = []

    @staticmethod
    def _safe_mime_type(content_type: Any) -> str:
        """Return a conservative media type without exposing header content."""
        if not isinstance(content_type, str):
            return "unknown"
        media_type = content_type.split(";", 1)[0].strip().lower()
        if re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
            return media_type
        return "unknown"

    def _safe_endpoint_label(self, url: Any) -> str:
        """Build an allowlisted host/path label, omitting query and fragment."""
        allowed_hosts = {
            hostname
            for hostnames in ALLOWED_HOSTNAMES_BY_STATE.values()
            for hostname in hostnames
        }
        try:
            parsed = urlsplit(str(url))
            hostname = (parsed.hostname or "").lower()
            if (
                parsed.scheme.lower() != "https"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port not in (None, 443)
                or hostname not in allowed_hosts
            ):
                return "unknown"
            normalized_path = normalize_url_path(parsed.path or "/")
            allowed_prefixes = AUTH_HOST_PATH_CONTRACTS.get(hostname, ())
            if not any(
                matches_segment_prefix(normalized_path, prefix)
                for prefix in allowed_prefixes
            ):
                return "unknown"
            return f"{hostname}{normalized_path}"
        except (TypeError, ValueError):
            return "unknown"

    def _debug_http_event(self, stage: str, method: str, endpoint_url: Any,
                          status: Any = "unknown", redirect_index: Any = "unknown",
                          **fields: Any) -> None:
        """Emit safe, bounded diagnostics only when explicitly debug-enabled."""
        if not bool(self.debug_mode):
            return
        safe_method = method.upper() if isinstance(method, str) else "UNKNOWN"
        if safe_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            safe_method = "UNKNOWN"
        safe_status = status if isinstance(status, int) and 100 <= status <= 599 else "unknown"
        safe_index = redirect_index if isinstance(redirect_index, int) and redirect_index >= 0 else "unknown"
        safe_fields = {"stage": stage, "method": safe_method,
                       "endpoint": self._safe_endpoint_label(endpoint_url),
                       "status": safe_status, "redirect_index": safe_index}
        for name, value in fields.items():
            if name in {"mime", "shape", "report_kind", "exception_type"}:
                safe_fields[name] = value if isinstance(value, str) else "unknown"
            elif name == "elm_contract":
                safe_fields[name] = value if value in ELM_CONTRACT_VALUES else "unknown"
            elif name in {
                "bytes", "body_bytes", "body_characters", "item_count",
                "declared_bytes", "records_with_elm", "records_with_device_set",
            }:
                safe_fields[name] = value if isinstance(value, int) and value >= 0 else "unknown"
        details = " ".join(f"{key}={value}" for key, value in safe_fields.items())
        _LOGGER.warning("HTTP debug %s", details)

    def _debug_operation_phase(self, phase: str) -> None:
        """Log an allowlisted high-level phase without identifiers or payloads."""
        allowed_phases = {
            "yesterday_login",
            "yesterday_metadata",
            "yesterday_meter",
            "yesterday_range_consumption",
            "yesterday_range_production",
            "yesterday_daily_consumption",
            "yesterday_daily_production",
            "custom_login",
            "custom_metadata",
            "custom_meter",
            "custom_range_consumption",
            "custom_range_production",
            "complete",
        }
        if not bool(self.debug_mode):
            return
        safe_phase = phase if phase in allowed_phases else "unknown"
        _LOGGER.warning("HTTP debug stage=operation_phase phase=%s", safe_phase)

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive data in strings for logging and debugging."""
        if not text:
            return ""
        masked = str(text)
        if self.password:
            masked = masked.replace(self.password, "********")
        if self.username:
            masked = masked.replace(self.username, "********")
        if self.ean:
            masked = masked.replace(self.ean, "******************")
        if self.elm:
            masked = masked.replace(self.elm, "********")

        masked = re.sub(r"\b\d{18}\b", "******************", masked)
        masked = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]+", "Bearer ********", masked)
        masked = re.sub(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", "********", masked)
        masked = re.sub(
            r"(?i)\b(access_token|sessionid|jsessionid|session_id|client_secret|token|password|passwd|pwd|secret|auth|session|key)\s*([:=]|\s+)\s*([^\s\"'<>&;,]+)",
            r"\1\2********",
            masked,
        )
        return masked

    @staticmethod
    def _matches_segment_prefix(path: str, prefix: str) -> bool:
        """Return whether path equals a prefix or starts at its next segment."""
        return matches_segment_prefix(path, prefix)

    def _verify_origin(self, url: str, state: str) -> None:
        """Validate HTTPS origin and state-specific path contract (CWE-346)."""
        allowed_hosts = ALLOWED_HOSTNAMES_BY_STATE.get(state)
        if allowed_hosts is None:
            raise PndAuthError("Invalid navigation state (ERR_AUTH)")

        try:
            parsed = urlsplit(str(url))
            hostname = (parsed.hostname or "").lower()
            if (
                parsed.scheme.lower() != "https"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port not in (None, 443)
                or hostname not in allowed_hosts
            ):
                raise ValueError("origin mismatch")

            raw_path = parsed.path or "/"
            normalized_path = normalize_url_path(raw_path)

            if state == ORIGIN_STATE_APP:
                prefixes = (APP_PATH_PREFIX,)
            else:
                prefixes = AUTH_HOST_PATH_CONTRACTS.get(hostname, ())
            if not prefixes or not any(
                matches_segment_prefix(normalized_path, prefix)
                for prefix in prefixes
            ):
                raise ValueError("path contract mismatch")
        except (TypeError, ValueError):
            _LOGGER.error(
                "Rejected URL outside navigation contract for state '%s'",
                state,
            )
            raise PndAuthError("Insecure redirect or URL detected (ERR_AUTH)") from None

    @staticmethod
    def _response_url(response: requests.Response, requested_url: str) -> str:
        """Return a concrete response URL, tolerating minimal test doubles."""
        response_url = getattr(response, "url", None)
        return response_url if isinstance(response_url, str) and response_url else requested_url

    @staticmethod
    def _validate_download_directory(download_dir: str) -> Tuple[int, int]:
        """Require a real, owner-controlled directory and return its identity."""
        try:
            directory_stat = os.lstat(download_dir)
        except OSError as err:
            raise PndPortalError("Report directory is unavailable (ERR_PORTAL)") from err
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_ISLNK(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or stat.S_IMODE(directory_stat.st_mode) & 0o022
        ):
            raise PndPortalError("Report directory is not owner-controlled (ERR_PORTAL)")
        return directory_stat.st_dev, directory_stat.st_ino

    @classmethod
    def _open_download_directory(cls, download_dir: str) -> Tuple[int, Tuple[int, int]]:
        """Open a verified directory descriptor immune to later path swaps."""
        identity = cls._validate_download_directory(download_dir)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(download_dir, flags)
        except OSError as err:
            raise PndPortalError("Report directory cannot be opened safely (ERR_PORTAL)") from err
        descriptor_stat = os.fstat(directory_fd)
        if (
            (descriptor_stat.st_dev, descriptor_stat.st_ino) != identity
            or not stat.S_ISDIR(descriptor_stat.st_mode)
            or descriptor_stat.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor_stat.st_mode) & 0o022
        ):
            os.close(directory_fd)
            raise PndPortalError("Report directory changed during validation (ERR_PORTAL)")
        return directory_fd, identity

    def _request_with_safe_redirects(
        self,
        session: requests.Session,
        method: str,
        url: str,
        state: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        *,
        credential_request: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        """Follow a bounded, prevalidated redirect chain without credential replay."""
        current_method = method.upper()
        current_url = url
        request_kwargs = dict(kwargs)

        for redirect_count in range(MAX_REDIRECTS + 1):
            self._verify_origin(current_url, state)
            request_kwargs["allow_redirects"] = False
            response = self._safe_request(session, current_method, current_url,
                                          stop_event, deadline, **request_kwargs)
            try:
                response_url = self._response_url(response, current_url)
                self._verify_origin(response_url, state)
            except Exception:
                response.close()
                raise
            status = response.status_code
            try:
                setattr(response, "_pnd_redirect_index", redirect_count)
                setattr(response, "_pnd_request_method", current_method)
            except Exception:
                pass
            self._debug_http_event(
                "response", current_method, response_url, status, redirect_count,
            )
            if status not in REDIRECT_STATUSES:
                return response
            if redirect_count >= MAX_REDIRECTS:
                response.close()
                raise PndAuthError("Too many authentication redirects (ERR_AUTH)")

            location = response.headers.get("Location")
            if not location:
                response.close()
                raise PndAuthError("Authentication redirect omitted Location (ERR_AUTH)")
            next_url = urljoin(current_url, location)
            response.close()
            self._verify_origin(next_url, state)

            if credential_request and status in (307, 308):
                raise PndAuthError("Unsafe credential-preserving redirect rejected (ERR_AUTH)")

            # RFC-compatible POST redirect handling without retaining the body.
            if current_method == "POST" and status in (301, 302, 303):
                current_method = "GET"
                request_kwargs.pop("data", None)
                request_kwargs.pop("json", None)
                headers = dict(request_kwargs.get("headers", {}))
                headers.pop("Content-Type", None)
                request_kwargs["headers"] = headers
                credential_request = False
            request_kwargs.pop("params", None)
            current_url = next_url

        raise PndAuthError("Too many authentication redirects (ERR_AUTH)")

    def _check_deadline_and_stop(
        self,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Check if operation has been cancelled or deadline exceeded."""
        if stop_event is not None and stop_event.is_set():
            raise PndTimeoutError("Operation cancelled by stop_event")
        if deadline is not None and time.monotonic() >= deadline:
            raise PndTimeoutError("Operation deadline exceeded")

    def _check_html_errors(self, html_text: str) -> None:
        """Check HTML response body for portal errors, CAPTCHA, lock, or maintenance."""
        text_lower = html_text.lower()
        if "recaptcha" in text_lower or "g-recaptcha" in text_lower or "captcha challenge" in text_lower:
            raise PndCaptchaError("CAPTCHA challenge detected on ČEZ portal (ERR_CAPTCHA)")
        if "zablokován" in text_lower or "účet je uzamčen" in text_lower or "account locked" in text_lower:
            raise PndAccountLockedError("Account is locked by ČEZ portal (ERR_LOCKED)")
        if "neplatné uživatelské jméno" in text_lower or "chybné jméno" in text_lower or "invalid credentials" in text_lower or "bad credentials" in text_lower:
            raise PndAuthError("Invalid username or password (ERR_AUTH)")
        if "odstávka" in text_lower or "probíhá údržba" in text_lower or "under maintenance" in text_lower:
            raise PndMaintenanceError("ČEZ PND portal is under maintenance (ERR_MAINTENANCE)")

    @staticmethod
    def _response_header(response: requests.Response, name: str) -> str:
        """Read one response header from real responses and small test doubles."""
        headers = getattr(response, "headers", None)
        if not isinstance(headers, Mapping):
            return ""
        for header_name, value in headers.items():
            if isinstance(header_name, str) and header_name.lower() == name.lower():
                if not isinstance(value, str):
                    raise PndPortalError(f"Malformed response header: {name} (ERR_PORTAL)")
                return value.strip()
        return ""

    def _read_bounded_response(
        self,
        response: requests.Response,
        max_bytes: int,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> str:
        """Stream and strictly decode one bounded, non-CSV response.

        Callers request ``stream=True`` so headers are available before body
        consumption. ``requests`` yields decompressed bytes from
        ``iter_content``; counting those bytes limits expansion rather than
        trusting a compressed Content-Length. This method owns the response
        and closes it on every success and failure path.
        """
        response_status = getattr(response, "status_code", "unknown")
        response_status = response_status if isinstance(response_status, int) else "unknown"
        response_url = self._response_url(response, "")
        response_method = getattr(response, "_pnd_request_method", "GET")
        redirect_index = getattr(response, "_pnd_redirect_index", "unknown")
        response_mime = "unknown"
        total = 0
        try:
            response_mime = self._safe_mime_type(
                self._response_header(response, "Content-Type")
            )
            if max_bytes <= 0:
                raise PndPortalError("Invalid response size limit (ERR_PORTAL)")
            content_length = self._response_header(response, "Content-Length")
            if content_length:
                if not re.fullmatch(r"[0-9]+", content_length):
                    raise PndPortalError("Invalid response Content-Length (ERR_PORTAL)")
                if len(content_length) > MAX_CONTENT_LENGTH_DIGITS:
                    raise PndPortalError("Response exceeds size limit (ERR_PORTAL)")
                normalized_length = content_length.lstrip("0") or "0"
                limit_text = str(max_bytes)
                if len(normalized_length) > len(limit_text) or (
                    len(normalized_length) == len(limit_text)
                    and normalized_length > limit_text
                ):
                    raise PndPortalError("Response exceeds size limit (ERR_PORTAL)")

            content_type = self._response_header(response, "Content-Type")
            encoding = getattr(response, "encoding", None)
            if not isinstance(encoding, str) or not encoding.strip():
                charset_match = re.search(
                    r"(?i)(?:^|;)\s*charset\s*=\s*([^;\s]+)", content_type
                )
                encoding = charset_match.group(1).strip("\"'") if charset_match else "utf-8"
            try:
                decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
            except (LookupError, TypeError) as err:
                raise PndPortalError("Unsupported response encoding (ERR_PORTAL)") from err

            text_parts: list[str] = []
            self._check_deadline_and_stop(stop_event, deadline)
            for chunk in response.iter_content(
                chunk_size=HTTP_STREAM_CHUNK_SIZE,
                decode_unicode=False,
            ):
                self._check_deadline_and_stop(stop_event, deadline)
                if not chunk:
                    continue
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise PndPortalError("Malformed response body chunk (ERR_PORTAL)")
                chunk_bytes = bytes(chunk)
                total += len(chunk_bytes)
                if total > max_bytes:
                    raise PndPortalError("Response exceeds size limit (ERR_PORTAL)")
                try:
                    text_parts.append(decoder.decode(chunk_bytes, final=False))
                except UnicodeError as err:
                    raise PndPortalError("Malformed response encoding (ERR_PORTAL)") from err
            try:
                text_parts.append(decoder.decode(b"", final=True))
            except UnicodeError as err:
                raise PndPortalError("Malformed response encoding (ERR_PORTAL)") from err
            self._check_deadline_and_stop(stop_event, deadline)
            response_text = _BoundedResponseText(
                "".join(text_parts),
                {
                    "status": response_status,
                    "mime": response_mime,
                    "decoded_bytes": total,
                    "body_characters": sum(len(part) for part in text_parts),
                },
            )
            self._debug_http_event("read", response_method, response_url,
                                   response_status, redirect_index,
                                   mime=response_mime, bytes=total)
            return response_text
        except requests.exceptions.Timeout as err:
            self._debug_http_event(
                "read_timeout", response_method, response_url, response_status,
                redirect_index, mime=response_mime, bytes=total,
                exception_type=type(err).__name__,
            )
            raise PndTimeoutError("HTTP response read timeout (ERR_TIMEOUT)") from err
        except requests.exceptions.ConnectionError as err:
            if "read timed out" in str(err).lower() or any(
                type(item).__name__ == "ReadTimeoutError" for item in err.args
            ):
                self._debug_http_event(
                    "read_timeout", response_method, response_url, response_status,
                    redirect_index, mime=response_mime, bytes=total,
                    exception_type=type(err).__name__,
                )
                raise PndTimeoutError("HTTP response read timeout (ERR_TIMEOUT)") from err
            raise PndPortalError("HTTP response connection failed (ERR_PORTAL)") from err
        except requests.exceptions.RequestException as err:
            raise PndPortalError("HTTP response read failed (ERR_PORTAL)") from err
        finally:
            try:
                response.close()
            except Exception:
                pass

    def _safe_request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute HTTP request with timeout, stop event check, and exception mapping."""
        self._check_deadline_and_stop(stop_event, deadline)
        requested_timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PndTimeoutError("Operation deadline exceeded")
            if isinstance(requested_timeout, tuple):
                connect_requested, read_requested = requested_timeout
            else:
                connect_requested = read_requested = requested_timeout
            # A requests ``(connect, read)`` tuple applies both values
            # independently, so capping each to ``remaining`` permits one
            # request to consume almost twice the remaining operation budget.
            # urllib3's total timeout accounts for elapsed connect time; the
            # explicit split also bounds both phases when an adapter/test
            # double only observes the phase values.
            connect_limit = remaining * 0.4
            read_limit = remaining - connect_limit
            if kwargs.get("stream"):
                read_limit = min(read_limit, STREAM_READ_TIMEOUT_SLICE)
            connect_timeout = (
                connect_limit
                if connect_requested is None
                else min(float(connect_requested), connect_limit)
            )
            read_timeout = (
                read_limit
                if read_requested is None
                else min(float(read_requested), read_limit)
            )
            requested_timeout = Urllib3Timeout(
                total=remaining,
                connect=connect_timeout,
                read=read_timeout,
            )
        kwargs["timeout"] = requested_timeout

        try:
            resp = session.request(method, url, **kwargs)
            try:
                self._check_deadline_and_stop(stop_event, deadline)
            except Exception:
                resp.close()
                raise
            return resp
        except requests.exceptions.Timeout as err:
            self._debug_http_event("timeout", method, url,
                                   exception_type=type(err).__name__)
            raise PndTimeoutError("HTTP request timeout (ERR_TIMEOUT)") from err
        except requests.exceptions.RequestException as err:
            raise PndPortalError(f"HTTP request error: {self._mask_sensitive(str(err))} (ERR_PORTAL)") from err

    def _login(
        self,
        session: requests.Session,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Authenticate via ČEZ SSO (MEPAS / DIP CAS) OIDC flow using HTTP requests."""
        # Step 1: Initial GET to PND dashboard landing (triggers OIDC redirects to CAS login)
        resp = self._request_with_safe_redirects(
            session,
            "GET",
            URL_PND_LOGIN,
            ORIGIN_STATE_PREAUTH,
            stop_event,
            deadline,
            stream=True,
        )
        response_text = self._read_bounded_response(
            resp,
            MAX_AUTH_RESPONSE_SIZE,
            stop_event,
            deadline,
        )
        response_url = self._response_url(resp, URL_PND_LOGIN)
        self._verify_origin(response_url, ORIGIN_STATE_PREAUTH)
        self._check_html_errors(response_text)

        # Step 2: Parse CAS login form HTML
        soup = BeautifulSoup(response_text, "html.parser")
        form = soup.find("form", id="fm1") or soup.find("form")

        if not form:
            if "cezpnd2" in response_url and (
                "dashboard" in response_url or "view" in response_url
            ):
                return
            raise PndAuthError("Could not locate CAS authentication form (ERR_AUTH)")

        action_url = urljoin(response_url, form.get("action") or response_url)
        self._verify_origin(action_url, ORIGIN_STATE_CREDENTIALS)

        form_data: Dict[str, str] = {}
        for input_elem in form.find_all("input"):
            name = input_elem.get("name")
            value = input_elem.get("value", "")
            if name:
                form_data[name] = value

        form_data["username"] = self.username
        form_data["password"] = self.password
        form_data.setdefault("_eventId", "submit")
        form_data.setdefault("submit", "PŘIHLÁSIT SE")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": response_url,
        }

        # Step 3: POST credentials to CAS
        post_resp = self._request_with_safe_redirects(
            session,
            "POST",
            action_url,
            ORIGIN_STATE_PREAUTH,
            stop_event,
            deadline,
            credential_request=True,
            data=form_data,
            headers=headers,
            stream=True,
        )

        post_text = self._read_bounded_response(
            post_resp,
            MAX_AUTH_RESPONSE_SIZE,
            stop_event,
            deadline,
        )
        self._check_html_errors(post_text)
        if "neplatné" in post_text.lower() or "chybné" in post_text.lower():
            raise PndAuthError("Invalid credentials provided to ČEZ SSO (ERR_AUTH)")
        self._verify_origin(
            self._response_url(post_resp, action_url), ORIGIN_STATE_APP
        )

    def _fetch_dashboard_metadata(
        self,
        session: requests.Session,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch dashboard configuration JSON (idDeviceSet, electrometers list, user metadata)."""
        try:
            resp = self._request_with_safe_redirects(
                session,
                "GET",
                URL_DASHBOARD_DATA,
                ORIGIN_STATE_APP,
                stop_event,
                deadline,
                stream=True,
            )
            response_status = resp.status_code
            response_url = self._response_url(resp, URL_DASHBOARD_DATA)
            response_text = self._read_bounded_response(
                resp,
                MAX_DASHBOARD_RESPONSE_SIZE,
                stop_event,
                deadline,
            )
            read_metadata = dict(getattr(response_text, "pnd_metadata", {}))
            content_type = str(read_metadata.get("mime", "unknown"))
            if response_status == 200 and "application/json" in content_type:
                try:
                    data = json.loads(response_text)
                except (TypeError, ValueError) as err:
                    self._debug_http_event("dashboard_parse", "GET", response_url,
                        response_status, mime=content_type,
                        body_bytes=read_metadata.get("decoded_bytes"),
                        body_characters=read_metadata.get("body_characters"), shape="other")
                    raise PndParseError("Dashboard metadata is invalid (ERR_PORTAL)") from err
                shape = "object" if isinstance(data, dict) else "list" if isinstance(data, list) else "other"
                telemetry_fields: Dict[str, Any] = {
                    "body_bytes": read_metadata.get("decoded_bytes"),
                    "body_characters": read_metadata.get("body_characters"),
                    "shape": shape,
                }
                if isinstance(data, list):
                    telemetry_fields["item_count"] = len(data)
                self._debug_http_event(
                    "dashboard_parse", "GET", response_url,
                    response_status, mime=content_type, **telemetry_fields
                )
                normalized = _normalize_dashboard_payload(data)
                if isinstance(data, list):
                    contract_fields = {
                        "elm_contract": normalized.get("elmMetadataStatus"),
                        "records_with_elm": len(normalized.get("electrometers", [])),
                        "records_with_device_set": sum(
                            1 for item in data
                            if isinstance(item, dict) and item.get("idDeviceSet") is not None
                        ),
                    }
                    self._debug_http_event(
                        "dashboard_contract", "GET", response_url,
                        response_status, **contract_fields
                    )
                return normalized
        except (PndAuthError, PndTimeoutError, PndPortalError, PndParseError):
            raise
        except Exception:
            return {}
        return {}

    @staticmethod
    def _parse_meter_records(data: list[Any]) -> Tuple[List[str], List[str]]:
        """Validate meter records and return normalized ELM and EAN values."""
        def normalize_identifier(value: Any) -> str:
            if value is None:
                return ""
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise PndParseError("Meter response contains an invalid identifier (ERR_PORTAL)")
            return str(value).strip()

        elm_list: List[str] = []
        ean_list: List[str] = []
        for item in data:
            if not isinstance(item, dict):
                raise PndParseError("Meter response contains a non-object record (ERR_PORTAL)")
            normalized_fields = {
                field: normalize_identifier(item[field])
                for field in (*METER_ELM_FIELDS, METER_EAN_FIELD)
                if field in item
            }
            elms = {
                normalized_fields[field]
                for field in METER_ELM_FIELDS
                if normalized_fields.get(field)
            }
            if len(elms) > 1:
                raise PndParseError("Meter response contains conflicting identifiers (ERR_PORTAL)")
            elm = next(iter(elms), "")
            ean = normalized_fields.get(METER_EAN_FIELD, "")
            if not elm and not ean:
                raise PndParseError("Meter response record has no identifier (ERR_PORTAL)")
            if elm:
                elm_list.append(elm)
            if ean:
                ean_list.append(ean)
        return elm_list, ean_list

    @staticmethod
    def _metadata_meter_records(metadata: Dict[str, Any]) -> Optional[List[Any]]:
        """Validate the metadata container contract before selecting records."""
        present_fields = [field for field in METER_METADATA_FIELDS if field in metadata]
        if not present_fields:
            return None
        for field in present_fields:
            if not isinstance(metadata[field], list):
                raise PndParseError(
                    f"Metadata field {field} must be a list (ERR_PORTAL)"
                )
        if len(present_fields) > 1:
            raise PndParseError(
                "Metadata contains conflicting meter list fields (ERR_PORTAL)"
            )
        return metadata[present_fields[0]]

    def _validate_selected_meter(self, records: List[Any], metadata: Optional[Dict[str, Any]]) -> List[str]:
        """Validate a single meter and retain its export device set.

        Some dashboard windows expose only ELM; validate EAN whenever the
        selected meter provides it, never use another meter's EAN as a match.
        """
        available_elms, _ = self._parse_meter_records(records)
        available_elms = list(dict.fromkeys(available_elms))
        if self.elm and not available_elms:
            raise PndElmUnavailableError(
                "PND account does not provide an ELM identifier (ERR_ELM_UNAVAILABLE)"
            )
        matches = []
        for record in records:
            elms, eans = self._parse_meter_records([record])
            if self.elm:
                matches_identifier = self.elm in elms
            else:
                matches_identifier = self.ean in eans
            if matches_identifier:
                if self.ean and eans and self.ean not in eans:
                    raise PndElmNotFoundError("Configured ELM does not belong to EAN (ERR_ELM_NOT_FOUND)")
                matches.append(record)
        if not matches:
            raise PndElmNotFoundError("Configured meter not found in account (ERR_ELM_NOT_FOUND)")
        selected_elms = {elm for record in matches for elm in self._parse_meter_records([record])[0]}
        if len(selected_elms) > 1:
            raise PndParseError("Configured meter selection is ambiguous (ERR_PORTAL)")
        device_sets = set()
        for record in matches:
            value = record.get("idDeviceSet")
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise PndParseError("Selected meter has an invalid device set (ERR_PORTAL)")
                device_sets.add(value)
        if len(device_sets) > 1:
            raise PndParseError("Selected meter belongs to multiple device sets (ERR_PORTAL)")
        if metadata is not None:
            if device_sets:
                metadata["idDeviceSet"] = next(iter(device_sets))
            elif metadata.get("requiresMeterDeviceSet") or (
                any("idDeviceSet" in record for record in records) and not metadata.get("idDeviceSet")
            ):
                raise PndParseError("Selected meter has no device set (ERR_PORTAL)")
        if not self.elm and selected_elms:
            self.elm = next(iter(selected_elms))
        return available_elms

    def _select_elm(
        self,
        session: requests.Session,
        metadata: Optional[Dict[str, Any]] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> List[str]:
        """Verify/select ELM meter identifier in PND account and return available ELMs."""
        available_elms: List[str] = []
        if not self.elm and not self.ean:
            return available_elms

        # 1. Check dashboard metadata if provided.  A present empty list is
        # an explicit request to use the API fallback; malformed containers or
        # conflicting supported fields never silently fall through.
        if metadata is not None:
            if not isinstance(metadata, dict):
                raise PndParseError("Dashboard metadata must be an object (ERR_PORTAL)")
            meters = self._metadata_meter_records(metadata)
            if meters:
                return self._validate_selected_meter(meters, metadata)

        # 2. Check meters API endpoint fallback
        meters_url = "https://pnd.cezdistribuce.cz/cezpnd2/api/v1/consumption/meters"
        try:
            resp = self._request_with_safe_redirects(
                session,
                "GET",
                meters_url,
                ORIGIN_STATE_APP,
                stop_event,
                deadline,
                stream=True,
            )
            response_status = resp.status_code
            response_url = self._response_url(resp, meters_url)
            response_text = self._read_bounded_response(
                resp,
                MAX_METERS_RESPONSE_SIZE,
                stop_event,
                deadline,
            )
            read_metadata = dict(getattr(response_text, "pnd_metadata", {}))
            content_type = str(read_metadata.get("mime", "unknown"))
            if response_status == 200 and "application/json" in content_type:
                try:
                    data = json.loads(response_text)
                except (TypeError, ValueError) as err:
                    self._debug_http_event("meters_parse", "GET", response_url,
                        response_status, mime=content_type,
                        body_bytes=read_metadata.get("decoded_bytes"),
                        body_characters=read_metadata.get("body_characters"), shape="other")
                    raise PndParseError("Meter response is invalid (ERR_PORTAL)") from err
                shape = "object" if isinstance(data, dict) else "list" if isinstance(data, list) else "other"
                self._debug_http_event("meters_parse", "GET", response_url,
                    response_status, mime=content_type,
                    body_bytes=read_metadata.get("decoded_bytes"),
                    body_characters=read_metadata.get("body_characters"), shape=shape)
                if isinstance(data, list) and len(data) > 0:
                    return self._validate_selected_meter(data, metadata)
                raise PndParseError("Meter response has an invalid shape (ERR_PORTAL)")
        except (PndElmNotFoundError, PndElmUnavailableError):
            raise
        except (PndAuthError, PndTimeoutError, PndPortalError, PndParseError):
            raise
        except Exception as err:
            raise PndPortalError("Meter selection could not be verified (ERR_PORTAL)") from err

        raise PndPortalError("Meter selection could not be verified (ERR_PORTAL)")

    def _format_date_param(self, date_str: str) -> str:
        """Format date string to DD.MM.YYYY 00:00 as required by export API endpoint."""
        clean = date_str.strip()
        if not clean:
            return ""
        if " " in clean:
            return clean
        if re.match(r"^\d{4}-\d{2}-\d{2}$", clean):
            try:
                dt = datetime.strptime(clean, "%Y-%m-%d")
                return f"{dt.strftime('%d.%m.%Y')} 00:00"
            except ValueError:
                pass
        if re.match(r"^\d{2}\.\d{2}\.\d{4}$", clean):
            return f"{clean} 00:00"
        return f"{clean} 00:00"

    def _fetch_csv_report(
        self,
        session: requests.Session,
        download_dir: str,
        filename: str,
        assembly_id: str,
        id_device_set: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        selector_mode: Optional[str] = None,
    ) -> str:
        """Download and atomically store a bounded, validated CSV response."""
        strict_selector = selector_mode is not None
        if selector_mode is None:
            selector_mode = (
                EXPORT_SELECTOR_BOTH if id_device_set and self.elm
                else EXPORT_SELECTOR_DEVICE_SET if id_device_set
                else EXPORT_SELECTOR_ELM
            )
        if selector_mode not in EXPORT_SELECTOR_VALUES:
            raise PndPortalError("Invalid export selector mode (ERR_PORTAL)")
        if os.path.basename(filename) != filename:
            raise PndPortalError("Invalid report filename (ERR_PORTAL)")
        os.makedirs(download_dir, mode=0o700, exist_ok=True)
        target_path = os.path.join(download_dir, filename)

        params: Dict[str, Any] = {
            "format": "csv",
            "idAssembly": assembly_id,
        }
        if selector_mode in (EXPORT_SELECTOR_BOTH, EXPORT_SELECTOR_DEVICE_SET) and id_device_set:
            params["idDeviceSet"] = id_device_set
        if date_from:
            params["intervalFrom"] = self._format_date_param(date_from)
        if date_to:
            params["intervalTo"] = self._format_date_param(date_to)
        if selector_mode in (EXPORT_SELECTOR_BOTH, EXPORT_SELECTOR_ELM) and self.elm:
            params["electrometerId"] = self.elm
        if strict_selector and selector_mode == EXPORT_SELECTOR_BOTH and not (id_device_set and self.elm):
            raise PndPortalError("Combined export selector is incomplete (ERR_PORTAL)")
        if strict_selector and selector_mode == EXPORT_SELECTOR_DEVICE_SET and not id_device_set:
            raise PndPortalError("Device-set export selector is incomplete (ERR_PORTAL)")
        if strict_selector and selector_mode == EXPORT_SELECTOR_ELM and not self.elm:
            raise PndPortalError("ELM export selector is incomplete (ERR_PORTAL)")

        headers = {
            "Referer": URL_PND_LOGIN,
        }

        directory_fd: Optional[int] = None
        directory_identity: Optional[Tuple[int, int]] = None
        temp_name: Optional[str] = None
        resp: Optional[requests.Response] = None
        total = 0
        report_kind = {
            "range-consumption.csv": "range_consumption",
            "range-production.csv": "range_production",
            "daily-consumption.csv": "daily_consumption",
            "daily-production.csv": "daily_production",
        }.get(filename, "unknown")
        try:
            directory_fd, directory_identity = self._open_download_directory(download_dir)
            resp = self._request_with_safe_redirects(
                session,
                "GET",
                URL_EXPORT,
                ORIGIN_STATE_APP,
                stop_event,
                deadline,
                params=params,
                headers=headers,
                stream=True,
            )
            if resp.status_code in OPTIONAL_REPORT_HTTP_STATUSES:
                raise PndReportUnavailableError(
                    f"Report is unavailable (HTTP {resp.status_code}) (ERR_PORTAL)"
                )
            if resp.status_code != 200:
                raise PndPortalError(
                    f"Report download returned HTTP {resp.status_code} (ERR_PORTAL)"
                )

            content_type = self._safe_mime_type(
                self._response_header(resp, "Content-Type")
            )
            declared_length = self._response_header(resp, "Content-Length")
            declared_bytes: Union[int, str] = "unknown"
            if declared_length and re.fullmatch(r"[0-9]+", declared_length):
                try:
                    declared_bytes = int(declared_length)
                except ValueError:
                    declared_bytes = "unknown"
            self._debug_http_event("csv_response", "GET", URL_EXPORT, resp.status_code,
                getattr(resp, "_pnd_redirect_index", "unknown"), mime=content_type,
                report_kind=report_kind, declared_bytes=declared_bytes, bytes=0)
            if content_type != "unknown" and content_type not in CSV_CONTENT_TYPES:
                raise PndPortalError("Report response is not CSV (ERR_PORTAL)")
            content_length = declared_length
            if content_length:
                try:
                    if int(content_length) > MAX_CSV_RESPONSE_SIZE:
                        raise PndPortalError("Report response exceeds size limit (ERR_PORTAL)")
                except ValueError as err:
                    raise PndPortalError("Invalid report Content-Length (ERR_PORTAL)") from err

            temp_name = f".{filename}.{secrets.token_hex(12)}.part"
            fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.fchmod(fd, 0o600)
                report_file = os.fdopen(fd, "wb")
            except Exception:
                os.close(fd)
                raise
            prefix = bytearray()
            with report_file:
                for chunk in resp.iter_content(chunk_size=CSV_STREAM_CHUNK_SIZE):
                    self._check_deadline_and_stop(stop_event, deadline)
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_CSV_RESPONSE_SIZE:
                        raise PndPortalError("Report response exceeds size limit (ERR_PORTAL)")
                    if len(prefix) < 4096:
                        prefix.extend(chunk[: 4096 - len(prefix)])
                    report_file.write(chunk)
                report_file.flush()
                os.fsync(report_file.fileno())

            self._debug_http_event("csv_read", "GET", URL_EXPORT, resp.status_code,
                getattr(resp, "_pnd_redirect_index", "unknown"), mime=content_type,
                report_kind=report_kind, declared_bytes=declared_bytes, bytes=total)

            if total == 0:
                raise PndPortalError("Report response is empty (ERR_PORTAL)")
            signature = bytes(prefix).lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
            if signature.startswith((b"<!doctype html", b"<html", b"<?xml")):
                raise PndPortalError("Report response contains markup, not CSV (ERR_PORTAL)")
            first_line = signature.splitlines()[0] if signature else b""
            if b";" not in first_line and b"," not in first_line:
                raise PndPortalError("Report response lacks a CSV delimiter (ERR_PORTAL)")

            if self._validate_download_directory(download_dir) != directory_identity:
                raise PndPortalError("Report directory changed during download (ERR_PORTAL)")
            os.replace(
                temp_name,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temp_name = None
            if self._validate_download_directory(download_dir) != directory_identity:
                os.unlink(filename, dir_fd=directory_fd)
                raise PndPortalError("Report directory changed during publication (ERR_PORTAL)")
            return target_path
        except requests.exceptions.Timeout as err:
            self._debug_http_event(
                "csv_timeout", "GET", URL_EXPORT,
                getattr(resp, "status_code", "unknown"),
                getattr(resp, "_pnd_redirect_index", "unknown"),
                report_kind=report_kind, bytes=total,
                exception_type=type(err).__name__,
            )
            raise PndTimeoutError("HTTP response read timeout (ERR_TIMEOUT)") from err
        except requests.exceptions.ConnectionError as err:
            # requests wraps urllib3 ReadTimeoutError in ConnectionError while
            # iterating a streamed response instead of raising Timeout.
            if "read timed out" in str(err).lower() or any(
                type(item).__name__ == "ReadTimeoutError" for item in err.args
            ):
                self._debug_http_event(
                    "csv_timeout", "GET", URL_EXPORT,
                    getattr(resp, "status_code", "unknown"),
                    getattr(resp, "_pnd_redirect_index", "unknown"),
                    report_kind=report_kind, bytes=total,
                    exception_type=type(err).__name__,
                )
                raise PndTimeoutError("HTTP response read timeout (ERR_TIMEOUT)") from err
            raise PndPortalError("Report download connection failed (ERR_PORTAL)") from err
        except (PndAuthError, PndPortalError, PndTimeoutError):
            raise
        except Exception as err:
            raise PndPortalError(
                f"Report download failed: {type(err).__name__} (ERR_PORTAL)"
            ) from err
        finally:
            if resp is not None:
                resp.close()
            if temp_name is not None and directory_fd is not None:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            if directory_fd is not None:
                os.close(directory_fd)

    def _export_selector_plan(
        self,
        session: requests.Session,
        metadata: Dict[str, Any],
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> Tuple[Optional[str], List[str], str]:
        """Return a fail-closed, ordered selector plan and its identity basis."""
        id_device_set = str(metadata.get("idDeviceSet", "")) if metadata.get("idDeviceSet") else None
        if metadata.get("elmMetadataStatus") == ELM_CONTRACT_ABSENT:
            if not id_device_set or metadata.get("requiresMeterDeviceSet"):
                raise PndElmUnavailableError(
                    "PND does not expose ELM and the device set is ambiguous (ERR_ELM_UNAVAILABLE)"
                )
            _LOGGER.warning(
                "PND identity check result=elm_unavailable basis=single_device_set; "
                "skipping unsupported meter lookup and using device-set-only export"
            )
            return id_device_set, [EXPORT_SELECTOR_DEVICE_SET], "single_device_set"
        try:
            self._select_elm(session, metadata, stop_event, deadline)
        except PndElmUnavailableError:
            if not id_device_set or metadata.get("requiresMeterDeviceSet"):
                raise
            _LOGGER.warning(
                "PND identity check result=elm_unavailable basis=single_device_set; "
                "using restricted device-set-only fallback"
            )
            return id_device_set, [EXPORT_SELECTOR_DEVICE_SET], "single_device_set"

        id_device_set = str(metadata.get("idDeviceSet", "")) if metadata.get("idDeviceSet") else None
        plan: List[str] = []
        if id_device_set and self.elm:
            plan.append(EXPORT_SELECTOR_BOTH)
        if id_device_set:
            plan.append(EXPORT_SELECTOR_DEVICE_SET)
        if self.elm:
            plan.append(EXPORT_SELECTOR_ELM)
        if not plan:
            if not self.ean and not self.elm:
                # Compatibility for isolated low-level tests; real config
                # entries always carry an EAN and are rejected fail-closed.
                return None, [EXPORT_SELECTOR_ELM], "test_only_unconfigured"
            raise PndElmUnavailableError("No verified export selector is available (ERR_ELM_UNAVAILABLE)")
        return id_device_set, plan, "verified_meter"

    @staticmethod
    def _scenario_reason(err: Exception) -> str:
        """Map an export error to a bounded, identifier-free reason code."""
        if isinstance(err, PndTimeoutError):
            return "timeout"
        if isinstance(err, PndReportUnavailableError):
            return "report_unavailable"
        if isinstance(err, PndAuthError):
            return "authentication"
        if isinstance(err, PndPortalError):
            return "portal_response"
        return "unexpected"

    def _fetch_csv_with_fallback(
        self,
        session: requests.Session,
        download_dir: str,
        filename: str,
        assembly_id: str,
        selector_plan: List[str],
        id_device_set: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> Tuple[str, str]:
        """Try verified selectors in order and return path plus selected mode."""
        last_error: Optional[Exception] = None
        for selector_mode in selector_plan:
            try:
                path = self._fetch_csv_report(
                    session, download_dir, filename, assembly_id,
                    id_device_set=id_device_set, date_from=date_from, date_to=date_to,
                    stop_event=stop_event, deadline=deadline, selector_mode=selector_mode,
                )
                _LOGGER.info("PND export scenario succeeded scenario=%s", selector_mode)
                return path, selector_mode
            except (PndReportUnavailableError, PndPortalError, PndTimeoutError) as err:
                last_error = err
                _LOGGER.warning(
                    "PND export scenario failed scenario=%s reason=%s",
                    selector_mode,
                    self._scenario_reason(err),
                )
        if last_error is not None:
            raise last_error
        raise PndPortalError("No export scenario was attempted (ERR_PORTAL)")

    def test_export_scenarios(
        self,
        download_dir: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Probe eligible export selectors without importing data into HA."""
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        results: Dict[str, str] = {mode: "not_eligible" for mode in EXPORT_SELECTOR_VALUES}
        try:
            self._login(session, stop_event, deadline)
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            id_device_set, plan, identity_basis = self._export_selector_plan(
                session, metadata, stop_event, deadline
            )
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%d.%m.%Y")
            today = datetime.now().strftime("%d.%m.%Y")
            for selector_mode in plan:
                try:
                    self._fetch_csv_report(
                        session, download_dir,
                        f"test-{selector_mode}.csv", ASSEMBLY_RANGE_CONSUMPTION,
                        id_device_set=id_device_set, date_from=yesterday, date_to=today,
                        stop_event=stop_event, deadline=deadline, selector_mode=selector_mode,
                    )
                    results[selector_mode] = "success"
                except (PndReportUnavailableError, PndPortalError, PndTimeoutError) as err:
                    results[selector_mode] = self._scenario_reason(err)
            return {"identity_basis": identity_basis, "scenarios": results}
        finally:
            session.close()

    def test_login(
        self,
        temp_dir: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Test HTTP login credentials and configured ELM."""
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        try:
            self._login(session, stop_event, deadline)
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            available_elms = self._select_elm(session, metadata, stop_event, deadline) or []
            return True, self.app_version or "PND 2.0", available_elms
        finally:
            session.close()

    def download_yesterday_data(
        self,
        download_dir: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Download yesterday's 15-minute interval and daily summary CSV reports via HTTP."""
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        try:
            self._debug_operation_phase("yesterday_login")
            self._login(session, stop_event, deadline)
            self._debug_operation_phase("yesterday_metadata")
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            self._debug_operation_phase("yesterday_meter")
            id_device_set, selector_plan, _identity_basis = self._export_selector_plan(
                session, metadata, stop_event, deadline
            )
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%d.%m.%Y")
            today = datetime.now().strftime("%d.%m.%Y")

            # 1. Download 15-min interval range consumption (+A) - idAssembly -1001
            self._debug_operation_phase("yesterday_range_consumption")
            range_cons, selected_scenario = self._fetch_csv_with_fallback(
                session, download_dir, "range-consumption.csv", ASSEMBLY_RANGE_CONSUMPTION,
                selector_plan=selector_plan, id_device_set=id_device_set,
                date_from=yesterday, date_to=today,
                stop_event=stop_event, deadline=deadline
            )

            # 2. Download 15-min interval range production (-A) - idAssembly -1002
            try:
                self._debug_operation_phase("yesterday_range_production")
                range_prod = self._fetch_csv_report(
                    session, download_dir, "range-production.csv", ASSEMBLY_RANGE_PRODUCTION,
                    id_device_set=id_device_set, date_from=yesterday, date_to=today,
                    stop_event=stop_event, deadline=deadline, selector_mode=selected_scenario
                )
            except PndReportUnavailableError:
                range_prod = ""

            # 3. Download Daily Consumption (+A) - idAssembly -1021
            self._debug_operation_phase("yesterday_daily_consumption")
            daily_cons = self._fetch_csv_report(
                session, download_dir, "daily-consumption.csv", ASSEMBLY_DAILY_CONSUMPTION,
                id_device_set=id_device_set, date_from=yesterday, date_to=yesterday,
                stop_event=stop_event, deadline=deadline, selector_mode=selected_scenario
            )

            # 4. Download Daily Production (-A) - idAssembly -1022
            try:
                self._debug_operation_phase("yesterday_daily_production")
                daily_prod = self._fetch_csv_report(
                    session, download_dir, "daily-production.csv", ASSEMBLY_DAILY_PRODUCTION,
                    id_device_set=id_device_set, date_from=yesterday, date_to=yesterday,
                    stop_event=stop_event, deadline=deadline, selector_mode=selected_scenario
                )
            except PndReportUnavailableError:
                daily_prod = ""

            # Validate mandatory consumption report
            if not os.path.exists(range_cons):
                raise PndPortalError("Mandatory report download failed: range-consumption.csv (ERR_PORTAL)")

            self._debug_operation_phase("complete")
            return {
                "daily_consumption": daily_cons,
                "daily_production": daily_prod,
                "range_consumption": range_cons,
                "range_production": range_prod,
            }
        except Exception as err:
            _LOGGER.error("Error during HTTP PND data download: %s", type(err).__name__)
            raise
        finally:
            session.close()

    def download_custom_range(
        self,
        download_dir: str,
        date_range: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Download custom date range 15-minute interval reports via HTTP."""
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        try:
            self._debug_operation_phase("custom_login")
            self._login(session, stop_event, deadline)
            self._debug_operation_phase("custom_metadata")
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            self._debug_operation_phase("custom_meter")
            id_device_set, selector_plan, _identity_basis = self._export_selector_plan(
                session, metadata, stop_event, deadline
            )
            dates = date_range.split(" - ")
            date_from = dates[0].strip() if len(dates) > 0 else ""
            date_to_raw = dates[1].strip() if len(dates) > 1 else date_from

            date_to = date_to_raw
            if date_to_raw:
                parsed_dt = None
                for fmt in ("%d.%m.%Y", "%Y-%m-%d"):
                    try:
                        parsed_dt = datetime.strptime(date_to_raw, fmt)
                        break
                    except ValueError:
                        pass
                if parsed_dt:
                    date_to = (parsed_dt + timedelta(days=1)).strftime("%d.%m.%Y")

            self._debug_operation_phase("custom_range_consumption")
            range_cons, selected_scenario = self._fetch_csv_with_fallback(
                session, download_dir, "range-consumption.csv", ASSEMBLY_RANGE_CONSUMPTION,
                selector_plan=selector_plan, id_device_set=id_device_set,
                date_from=date_from, date_to=date_to,
                stop_event=stop_event, deadline=deadline
            )

            self._debug_operation_phase("custom_range_production")
            range_prod = self._fetch_csv_report(
                session, download_dir, "range-production.csv", ASSEMBLY_RANGE_PRODUCTION,
                id_device_set=id_device_set, date_from=date_from, date_to=date_to,
                stop_event=stop_event, deadline=deadline, selector_mode=selected_scenario
            )

            if not os.path.exists(range_cons):
                raise PndPortalError("Mandatory range consumption report download failed (ERR_PORTAL)")

            self._debug_operation_phase("complete")
            return {
                "range_consumption": range_cons,
                "range_production": range_prod,
            }
        except Exception as err:
            _LOGGER.error("Error during custom range HTTP PND download: %s", type(err).__name__)
            raise
        finally:
            session.close()

    download_historical_data = download_custom_range
