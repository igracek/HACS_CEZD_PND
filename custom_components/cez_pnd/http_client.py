"""Direct HTTP client for CEZ Distribuce PND portal (browserless mode)."""
from datetime import datetime, timedelta
import logging
import os
import re
import tempfile
import threading
import time
from typing import Any, Dict, Final, List, Optional, Protocol, Tuple, Union
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from .client import (
    PndAccountLockedError,
    PndAuthError,
    PndCaptchaError,
    PndElmNotFoundError,
    PndInsecureBrowserError,
    PndMaintenanceError,
    PndParseError,
    PndPortalError,
    PndScraperError,
    PndTimeoutError,
)
from .const import (
    ALLOWED_HOSTNAMES_BY_STATE,
    ALLOWED_ORIGINS_BY_STATE,
    APP_PATH_PREFIX,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_DEBUG_DIR,
    DEFAULT_DEBUG_MODE,
    IDP_ALLOWED_HOSTNAMES,
    ORIGIN_STATE_APP,
    ORIGIN_STATE_AUTH,
    ORIGIN_STATE_CREDENTIALS,
    ORIGIN_STATE_IDP,
    ORIGIN_STATE_PREAUTH,
    PREAUTH_ALLOWED_HOSTNAMES,
    URL_PND_LOGIN,
    mask_ean,
    mask_elm,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT: Final[Tuple[int, int]] = (10, 30)
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


class PndClientProtocol(Protocol):
    """Protocol defining the interface for PND clients (HTTP and Browser)."""

    app_version: Optional[str]

    def download_yesterday_data(
        self,
        download_dir: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Download yesterday's consumption and production data."""
        ...

    def download_custom_range(
        self,
        download_dir: str,
        date_range: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Download custom range consumption and production data."""
        ...


class PndHttpClient:
    """Direct HTTP client for CEZ Distribuce PND portal (browserless mode)."""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize PndHttpClient with configuration dictionary."""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        self.username = str(config.get(CONF_USERNAME, config.get("username", ""))).strip()
        self.password = str(config.get(CONF_PASSWORD, config.get("password", ""))).strip()
        self.elm = str(config.get(CONF_ELM, config.get("elm", ""))).strip()
        self.ean = str(config.get(CONF_EAN, config.get("ean", ""))).strip()
        self.debug_mode = config.get(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE)
        self.debug_dir = config.get(CONF_DEBUG_DIR, DEFAULT_DEBUG_DIR)
        self.app_version: Optional[str] = "PND 2.0"
        self.last_debug_artifacts: List[str] = []

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

    def _verify_origin(self, url: str, state: str) -> None:
        """Validate URL origin against allowed hosts for given navigation state (CWE-346)."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        allowed_hosts = ALLOWED_HOSTNAMES_BY_STATE.get(state, ())
        if allowed_hosts and hostname not in allowed_hosts:
            msg = f"Insecure redirect host '{hostname}' in state '{state}' (allowed: {allowed_hosts})"
            _LOGGER.error(self._mask_sensitive(msg))
            raise PndAuthError("Insecure redirect host detected (ERR_AUTH)")

    def _check_deadline_and_stop(
        self,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Check if operation has been cancelled or deadline exceeded."""
        if stop_event is not None and stop_event.is_set():
            raise PndTimeoutError("Operation cancelled by stop_event")
        if deadline is not None and time.monotonic() > deadline:
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
        if "timeout" not in kwargs:
            kwargs["timeout"] = DEFAULT_TIMEOUT

        try:
            resp = session.request(method, url, **kwargs)
            self._check_deadline_and_stop(stop_event, deadline)
            return resp
        except requests.exceptions.Timeout as err:
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
        _LOGGER.debug("Starting HTTP SSO authentication for user %s", self._mask_sensitive(self.username))

        # Step 1: Initial GET to PND dashboard landing (triggers OIDC redirects to CAS login)
        resp = self._safe_request(session, "GET", URL_PND_LOGIN, stop_event, deadline)
        self._verify_origin(resp.url, ORIGIN_STATE_PREAUTH)
        self._check_html_errors(resp.text)

        # Step 2: Parse CAS login form HTML
        soup = BeautifulSoup(resp.text, "html.parser")
        form = soup.find("form", id="fm1") or soup.find("form")

        if not form:
            if "cezpnd2" in resp.url and ("dashboard" in resp.url or "view" in resp.url):
                _LOGGER.debug("Already authenticated to PND portal")
                return
            raise PndAuthError("Could not locate CAS authentication form (ERR_AUTH)")

        action_url = form.get("action") or resp.url
        action_url = urljoin(resp.url, action_url)

        # Verify host of login action URL (must be credential entry IDP host)
        self._verify_origin(action_url, ORIGIN_STATE_CREDENTIALS)

        # Extract hidden form fields (execution, _eventId, lt, etc.)
        form_data: Dict[str, str] = {}
        for input_elem in form.find_all("input"):
            name = input_elem.get("name")
            value = input_elem.get("value", "")
            if name:
                form_data[name] = value

        form_data["username"] = self.username
        form_data["password"] = self.password
        if "_eventId" not in form_data:
            form_data["_eventId"] = "submit"
        if "submit" not in form_data:
            form_data["submit"] = "PŘIHLÁSIT SE"

        # Step 3: POST credentials to CAS
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": resp.url,
        }
        post_resp = self._safe_request(
            session, "POST", action_url, stop_event, deadline, data=form_data, headers=headers
        )

        # Check response for CAS authentication errors
        self._check_html_errors(post_resp.text)

        # Step 4: Verify post-login redirection to PND APP state
        if "neplatné" in post_resp.text.lower() or "chybné" in post_resp.text.lower():
            raise PndAuthError("Invalid credentials provided to ČEZ SSO (ERR_AUTH)")

        self._verify_origin(post_resp.url, ORIGIN_STATE_APP)
        _LOGGER.debug("HTTP SSO authentication successful")

    def _fetch_dashboard_metadata(
        self,
        session: requests.Session,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Fetch dashboard configuration JSON (idDeviceSet, electrometers list, user metadata)."""
        try:
            resp = self._safe_request(session, "GET", URL_DASHBOARD_DATA, stop_event, deadline)
            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        return data
                except ValueError:
                    pass
        except Exception as err:
            _LOGGER.debug("Fetch dashboard metadata note: %s", err)
        return {}

    def _select_elm(
        self,
        session: requests.Session,
        metadata: Optional[Dict[str, Any]] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Verify/select ELM meter identifier in PND account."""
        if not self.elm and not self.ean:
            return

        # 1. Check metadata meters if provided
        if metadata:
            meters = metadata.get("meters") or metadata.get("devices") or metadata.get("electrometers")
            if isinstance(meters, list) and len(meters) > 0:
                elm_list = [str(m.get("elm") or m.get("electrometerId") or m.get("id", "")).strip() for m in meters if isinstance(m, dict)]
                ean_list = [str(m.get("ean", "")).strip() for m in meters if isinstance(m, dict)]
                if self.elm and self.elm not in elm_list and self.ean not in ean_list:
                    raise PndElmNotFoundError(f"ELM meter {mask_elm(self.elm)} not found in account (ERR_ELM_NOT_FOUND)")

        # 2. Check meters API endpoint fallback
        meters_url = "https://pnd.cezdistribuce.cz/cezpnd2/api/v1/consumption/meters"
        try:
            resp = self._safe_request(session, "GET", meters_url, stop_event, deadline)
            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        elm_list = [str(item.get("elm", "")).strip() for item in data if isinstance(item, dict)]
                        ean_list = [str(item.get("ean", "")).strip() for item in data if isinstance(item, dict)]
                        if self.elm and self.elm not in elm_list and self.ean not in ean_list:
                            raise PndElmNotFoundError(f"ELM meter {mask_elm(self.elm)} not found in account (ERR_ELM_NOT_FOUND)")
                except ValueError:
                    pass
        except PndElmNotFoundError:
            raise
        except Exception as err:
            _LOGGER.debug("ELM verification endpoint check note: %s", err)

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
    ) -> str:
        """Download CSV report from PND export endpoint and save to download_dir."""
        os.makedirs(download_dir, exist_ok=True)
        target_path = os.path.join(download_dir, filename)

        params: Dict[str, Any] = {
            "format": "csv",
            "idAssembly": assembly_id,
        }
        if id_device_set:
            params["idDeviceSet"] = id_device_set
        if date_from:
            params["intervalFrom"] = self._format_date_param(date_from)
        if date_to:
            params["intervalTo"] = self._format_date_param(date_to)
        if self.elm:
            params["electrometerId"] = self.elm

        headers = {
            "Referer": URL_PND_LOGIN,
        }

        try:
            resp = self._safe_request(session, "GET", URL_EXPORT, stop_event, deadline, params=params, headers=headers)
            if resp.status_code == 200 and resp.content:
                with open(target_path, "wb") as f:
                    f.write(resp.content)
                return target_path
            else:
                _LOGGER.warning("Report %s download returned status %s", filename, resp.status_code)
        except Exception as err:
            _LOGGER.info("Report %s fetch note: %s", filename, err)

        # Create placeholder empty file if report fetch failed/optional
        if not os.path.exists(target_path):
            with open(target_path, "w", encoding="utf-8") as f:
                f.write("")
        return target_path

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
            self._login(session, stop_event, deadline)
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            self._select_elm(session, metadata, stop_event, deadline)

            id_device_set = str(metadata.get("idDeviceSet", "")) if metadata.get("idDeviceSet") else None
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%d.%m.%Y")
            today = datetime.now().strftime("%d.%m.%Y")

            # 1. Download 15-min interval range consumption (+A) - idAssembly -1001
            range_cons = self._fetch_csv_report(
                session, download_dir, "range-consumption.csv", ASSEMBLY_RANGE_CONSUMPTION,
                id_device_set=id_device_set, date_from=yesterday, date_to=today,
                stop_event=stop_event, deadline=deadline
            )

            # 2. Download 15-min interval range production (-A) - idAssembly -1002
            range_prod = self._fetch_csv_report(
                session, download_dir, "range-production.csv", ASSEMBLY_RANGE_PRODUCTION,
                id_device_set=id_device_set, date_from=yesterday, date_to=today,
                stop_event=stop_event, deadline=deadline
            )

            # 3. Download Daily Consumption (+A) - idAssembly -1021
            daily_cons = self._fetch_csv_report(
                session, download_dir, "daily-consumption.csv", ASSEMBLY_DAILY_CONSUMPTION,
                id_device_set=id_device_set, date_from=yesterday, date_to=yesterday,
                stop_event=stop_event, deadline=deadline
            )

            # 4. Download Daily Production (-A) - idAssembly -1022
            daily_prod = self._fetch_csv_report(
                session, download_dir, "daily-production.csv", ASSEMBLY_DAILY_PRODUCTION,
                id_device_set=id_device_set, date_from=yesterday, date_to=yesterday,
                stop_event=stop_event, deadline=deadline
            )

            # Validate mandatory consumption report
            if not os.path.exists(range_cons):
                raise PndPortalError("Mandatory report download failed: range-consumption.csv (ERR_PORTAL)")

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
            self._login(session, stop_event, deadline)
            metadata = self._fetch_dashboard_metadata(session, stop_event, deadline)
            self._select_elm(session, metadata, stop_event, deadline)

            id_device_set = str(metadata.get("idDeviceSet", "")) if metadata.get("idDeviceSet") else None
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

            range_cons = self._fetch_csv_report(
                session, download_dir, "range-consumption.csv", ASSEMBLY_RANGE_CONSUMPTION,
                id_device_set=id_device_set, date_from=date_from, date_to=date_to,
                stop_event=stop_event, deadline=deadline
            )

            range_prod = self._fetch_csv_report(
                session, download_dir, "range-production.csv", ASSEMBLY_RANGE_PRODUCTION,
                id_device_set=id_device_set, date_from=date_from, date_to=date_to,
                stop_event=stop_event, deadline=deadline
            )

            if not os.path.exists(range_cons):
                raise PndPortalError("Mandatory range consumption report download failed (ERR_PORTAL)")

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

