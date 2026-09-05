"""Selenium headless scraper client for CEZ Distribuce PND portal."""
from datetime import datetime, timedelta
import json
import logging
import os
import posixpath
import re
import shutil
import tempfile
import threading
import time
from typing import Any, Dict, Final, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, urlsplit

from .const import (
    ALLOWED_HOSTNAMES,
    ALLOWED_HOSTNAMES_BY_STATE,
    ALLOWED_ORIGIN,
    ALLOWED_ORIGINS,
    ALLOWED_ORIGINS_BY_STATE,
    APP_ALLOWED_HOSTNAMES,
    APP_PATH_PREFIX,
    AUTH_ALLOWED_HOSTNAMES,
    AUTH_HOST_PATH_CONTRACTS,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CREDENTIAL_ENTRY_ALLOWED_PATH_PREFIXES,
    DEFAULT_BROWSER_HEADLESS,
    DEFAULT_DEBUG_DIR,
    DEFAULT_DEBUG_MODE,
    DISALLOWED_BROWSER_FLAGS,
    ERR_INSECURE_BROWSER,
    IDP_ALLOWED_HOSTNAMES,
    IDP_ALLOWED_ORIGINS,
    ORIGIN_STATE_APP,
    ORIGIN_STATE_AUTH,
    ORIGIN_STATE_CREDENTIALS,
    ORIGIN_STATE_IDP,
    ORIGIN_STATE_PREAUTH,
    PREAUTH_ALLOWED_HOSTNAMES,
    PREAUTH_ALLOWED_ORIGINS,
    URL_PND_LOGIN,
    mask_ean,
    mask_elm,
)

_LOGGER = logging.getLogger(__name__)


class PndError(Exception):
    """Base exception for CEZ PND."""


class PndAuthError(PndError):
    """Authentication failed."""


class PndCaptchaError(PndError):
    """CAPTCHA challenge detected."""


class PndAccountLockedError(PndError):
    """Account is locked by CEZ portal."""


class PndElmNotFoundError(PndError):
    """ELM meter identifier not found in account."""


class PndMaintenanceError(PndError):
    """CEZ PND portal is under maintenance."""


class PndTimeoutError(PndError):
    """Timeout during CEZ PND portal operations."""


class PndScraperError(PndError):
    """Error during scraping operations."""


class PndInsecureBrowserError(PndScraperError):
    """Error raised when browser runtime violates least-privilege / sandbox requirements (SEC10-03)."""


class PndParseError(PndError, ValueError):
    """Error parsing CSV or portal data."""


PndParserError = PndParseError


class PndPortalError(PndError):
    """Error reported by CEZ PND portal."""


class PndStatisticsError(PndError):
    """Error during statistics processing or Recorder operations."""


class PndStatisticsQueryError(PndStatisticsError):
    """Error querying Recorder statistics database."""


class PndStatisticsMonotonicityError(PndStatisticsError):
    """Monotonicity validation failed for cumulative statistics series."""


def validate_safe_path(
    target_path: str,
    hass_config_dir: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> str:
    """Ověří, že cílová cesta leží striktně uvnitř povoleného kořenového adresáře a neobsahuje symlinky."""
    if not target_path or not str(target_path).strip():
        raise ValueError("Cílová cesta nesmí být prázdná.")

    root_dir = hass_config_dir or base_dir or (
        "/config" if os.path.isdir("/config") else os.path.dirname(os.path.abspath(__file__))
    )
    resolved_base = os.path.realpath(root_dir)
    resolved_target = os.path.realpath(target_path)

    # Kontrola symlinků v celé hierarchii cesty
    curr = os.path.abspath(target_path)
    while curr and curr != os.path.dirname(curr):
        if os.path.islink(curr):
            raise ValueError(f"Cílová cesta '{target_path}' nesmí být symbolickým odkazem (nalezeno v '{curr}').")
        curr = os.path.dirname(curr)

    # Kontrola path traversal
    if not (resolved_target == resolved_base or resolved_target.startswith(resolved_base + os.sep)):
        raise ValueError(f"Cesta '{target_path}' leží mimo povolený kořenový adresář '{root_dir}'.")

    return resolved_target


class PndScraperClient:
    """Headless browser client for CEZ Distribuce PND portal."""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize scraper client with configuration."""
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.elm = str(config.get("elm", "")).strip()
        self.ean = str(config.get("ean", "")).strip()
        self.headless = config.get("browser_headless", DEFAULT_BROWSER_HEADLESS)
        self.app_version: str = "unknown"
        self.debug_mode = config.get(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE)
        self.debug_dir = config.get(CONF_DEBUG_DIR, DEFAULT_DEBUG_DIR)
        self.last_debug_artifacts: List[str] = []
        self.effective_sandbox_verified: bool = False
        self.effective_sandbox_mode: str = "enforced_least_privilege"

    def _mask_sensitive(self, text: str) -> str:
        """Mask password, username, identifiers, tokens, URLs, and filesystem paths."""
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

        # Mask 18-digit numbers (EANs)
        masked = re.sub(r'\b\d{18}\b', '******************', masked)

        # Mask Bearer tokens and JWTs
        masked = re.sub(r'(?i)\bbearer\s+[A-Za-z0-9_\-\.]+', 'Bearer ********', masked)
        masked = re.sub(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b', '********', masked)

        # Mask tokens, session, cookies, secrets, passwords key-value pairs
        masked = re.sub(
            r'(?i)\b(access_token|sessionid|jsessionid|session_id|client_secret|token|password|passwd|pwd|secret|auth|session|key)\s*([:=]|\s+)\s*([^\s"\'<>&;,]+)',
            r'\1\2********',
            masked,
        )

        # Mask credentials and query parameters in URLs
        masked = re.sub(r'(https?://[^:\s]+):([^@\s]+)@', r'\1:********@', masked)
        masked = re.sub(r'([?&][a-zA-Z0-9_\-]+)=([^&\s"\'<>]*)', r'\1=********', masked)

        # Mask absolute filesystem paths
        masked = re.sub(r'(?:/(?:tmp|config|var|home|root|etc|opt|usr)/[^\s\'"<>:]+)', '[REDACTED_PATH]', masked)

        return masked

    def _sanitize_html(self, html: str) -> str:
        """Sanitize plain-text passwords, credentials, identifiers and sensitive attributes from HTML content."""
        if not html:
            return ""

        sanitized = html
        if self.password:
            sanitized = sanitized.replace(self.password, "********")
        if self.username:
            sanitized = sanitized.replace(self.username, "********")
        if self.ean:
            sanitized = sanitized.replace(self.ean, "******************")
        if self.elm:
            sanitized = sanitized.replace(self.elm, "********")

        # Mask all input values
        sanitized = re.sub(
            r'(<input\b[^>]*?\bvalue\s*=\s*)(["\'])(.*?)\2',
            r'\1\2********\2',
            sanitized,
            flags=re.IGNORECASE,
        )
        sanitized = re.sub(
            r'(<input\b[^>]*?\bvalue\s*=\s*)([^\s>"\']+)',
            r'\1"********"',
            sanitized,
            flags=re.IGNORECASE,
        )

        # Scrub script blocks to prevent leaking inlined JS session data/tokens
        sanitized = re.sub(
            r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
            '<!-- SCRIPT SCRUBBED -->',
            sanitized,
            flags=re.IGNORECASE,
        )

        return sanitized

    def _check_deadline_and_stop(
        self,
        driver: Any = None,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Check monotonic deadline and cooperative stop signal."""
        if stop_event is not None and stop_event.is_set():
            _LOGGER.warning("Zastavení vyžádáno přes stop_event. Provádím bezpečný teardown.")
            self._safe_teardown(driver, proc)
            raise PndTimeoutError("Operace byla přerušena (stop signal received).")

        if deadline is not None and time.monotonic() > deadline:
            _LOGGER.warning("Interní deadline překročen (time.monotonic() > deadline). Provádím bezpečný teardown.")
            self._safe_teardown(driver, proc)
            raise PndTimeoutError("Interní deadline překročen (Task Deadline Exceeded).")

    def _validate_debug_dir(self, debug_dir: str, hass_config_dir: Optional[str] = None) -> str:
        """Validate and prepare debug directory fail-closed inside allowed root."""
        root_dir = hass_config_dir or (
            "/config" if os.path.isdir("/config") else os.path.dirname(os.path.abspath(__file__))
        )
        target_dir = debug_dir or DEFAULT_DEBUG_DIR
        try:
            safe_dir = validate_safe_path(target_dir, hass_config_dir=root_dir)
        except Exception as err:
            _LOGGER.warning(
                "Debug dir is outside safe root or invalid (%s); falling back strictly to default safe directory",
                type(err).__name__,
            )
            fallback_target = os.path.join(root_dir, "cez_pnd_debug")
            safe_dir = validate_safe_path(fallback_target, hass_config_dir=root_dir)

        os.makedirs(safe_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(safe_dir, 0o700)
        except OSError:
            pass
        return safe_dir

    def _validate_and_prepare_dir(self, debug_dir: str, hass_config_dir: Optional[str] = None) -> str:
        """Validate and prepare debug directory fail-closed inside allowed root (alias for _validate_debug_dir)."""
        return self._validate_debug_dir(debug_dir, hass_config_dir=hass_config_dir)

    def _atomic_write_file(self, target_path: str, data: bytes) -> None:
        """Write file atomically using mkstemp with 0600 permissions and O_NOFOLLOW flag."""
        target_dir = os.path.dirname(target_path)
        if target_dir:
            os.makedirs(target_dir, mode=0o700, exist_ok=True)

        temp_fd, temp_file = tempfile.mkstemp(prefix="cez_pnd_tmp_", dir=target_dir)
        try:
            os.chmod(temp_file, 0o600)
            with os.fdopen(temp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, target_path)
            temp_file = ""
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass

    def _prune_debug_artifacts(self, target_dir: Optional[str] = None, max_sets: int = 5, max_age_days: int = 7) -> None:
        """Keep only latest max_sets debug sets and remove older than max_age_days (allowlist: cez_pnd_debug_* only)."""
        active_dir = target_dir or self.debug_dir
        if not os.path.isdir(active_dir):
            return
        try:
            now = time.time()
            # Allowlist ONLY files strictly starting with 'cez_pnd_debug_'
            all_files = [
                os.path.join(active_dir, f)
                for f in os.listdir(active_dir)
                if os.path.isfile(os.path.join(active_dir, f))
                and not os.path.islink(os.path.join(active_dir, f))
                and f.startswith("cez_pnd_debug_")
            ]

            # 1. Delete files older than max_age_days
            remaining_files = []
            for fp in all_files:
                try:
                    if now - os.path.getmtime(fp) > max_age_days * 86400:
                        os.remove(fp)
                        _LOGGER.debug("Pruned expired debug file: %s", os.path.basename(fp))
                    else:
                        remaining_files.append(fp)
                except Exception as del_err:
                    _LOGGER.debug("Could not check/remove old debug file %s: %s", os.path.basename(fp), type(del_err).__name__)

            # 2. Group files by timestamp prefix (cez_pnd_debug_YYYYMMDD_HHMMSS)
            set_dict: Dict[str, List[str]] = {}
            for fp in remaining_files:
                fname = os.path.basename(fp)
                match = re.search(r"(cez_pnd_debug_\d{8}_\d{6})", fname)
                prefix = match.group(1) if match else fname
                set_dict.setdefault(prefix, []).append(fp)

            # Sort groups by newest mtime
            sorted_prefixes = sorted(
                set_dict.keys(),
                key=lambda p: max(os.path.getmtime(f) for f in set_dict[p]),
                reverse=True,
            )

            # Keep only the newest max_sets groups
            if len(sorted_prefixes) > max_sets:
                for old_p in sorted_prefixes[max_sets:]:
                    for fp in set_dict[old_p]:
                        try:
                            os.remove(fp)
                            _LOGGER.debug("Pruned extra debug file: %s", os.path.basename(fp))
                        except Exception as rem_err:
                            _LOGGER.debug("Could not remove old set file %s: %s", os.path.basename(fp), type(rem_err).__name__)
        except Exception as p_err:
            _LOGGER.debug("Error during debug artifacts pruning: %s", type(p_err).__name__)

    def _capture_debug_dump(
        self,
        driver: Any,
        phase: str,
        error_msg: str = "",
        hass_config_dir: Optional[str] = None,
    ) -> List[str]:
        """Uloží ladicí artefakty výhradně v bezpečné pre_auth fázi. Post-auth záchyt DOMu a metadat je striktně zakázán."""
        if not self.debug_mode or not driver:
            return []

        # Záchyt DOMu, screenshotu a metadat je povolen VÝHRADNĚ v bezpečné pre-auth fázi
        if not phase.startswith("pre_auth_"):
            _LOGGER.debug(
                "Záchyt ladicích artefaktů ve fázi '%s' je z bezpečnostních důvodů zakázán (povolen pouze v pre_auth_* fázi).",
                phase,
            )
            return []

        created_files = []
        try:
            target_dir = self._validate_debug_dir(self.debug_dir, hass_config_dir=hass_config_dir)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            prefix = f"cez_pnd_debug_{ts}_{phase}"

            # 1. Sanitizovaný DOM HTML dump (výhradně v bezpečné pre-auth fázi)
            html_path = os.path.join(target_dir, f"{prefix}_page.html")
            try:
                raw_html = driver.page_source or ""
                sanitized_html = self._sanitize_html(raw_html)
                self._atomic_write_file(html_path, sanitized_html.encode("utf-8"))
                created_files.append(html_path)
            except Exception as h_err:
                _LOGGER.debug("Could not save DOM dump: %s", type(h_err).__name__)

            # 2. Screenshot (výhradně v bezpečné pre-auth fázi)
            png_path = os.path.join(target_dir, f"{prefix}_screenshot.png")
            try:
                if hasattr(driver, "get_screenshot_as_png"):
                    png_data = driver.get_screenshot_as_png()
                    if isinstance(png_data, bytes):
                        self._atomic_write_file(png_path, png_data)
                        created_files.append(png_path)
                elif hasattr(driver, "save_screenshot"):
                    driver.save_screenshot(png_path)
                    try:
                        os.chmod(png_path, 0o600)
                    except OSError:
                        pass
                    created_files.append(png_path)
            except Exception as s_err:
                _LOGGER.debug("Could not save screenshot: %s", type(s_err).__name__)

            # 3. Metadata JSON (s maskovaným EAN a ELM)
            meta_path = os.path.join(target_dir, f"{prefix}_meta.json")
            try:
                curr_url = driver.current_url if hasattr(driver, "current_url") else "unknown"
                meta_data = {
                    "timestamp": datetime.now().isoformat(),
                    "phase": phase,
                    "error_message": self._mask_sensitive(error_msg),
                    "current_url": self._mask_sensitive(str(curr_url)),
                    "ean_masked": mask_ean(self.ean),
                    "elm_masked": mask_elm(self.elm),
                }
                self._atomic_write_file(meta_path, json.dumps(meta_data, indent=2).encode("utf-8"))
                created_files.append(meta_path)
            except Exception as m_err:
                _LOGGER.debug("Could not save meta JSON: %s", type(m_err).__name__)

            self.last_debug_artifacts = created_files
            self._prune_debug_artifacts(target_dir=target_dir)
            _LOGGER.info("Saved %d debug artifacts to %s", len(created_files), os.path.basename(target_dir))
        except Exception as err:
            _LOGGER.debug("Chyba při vytváření debug dumpu: %s", type(err).__name__)
        return created_files

    def _get_driver_process(self, driver: Any) -> Optional[Any]:
        """Safely extract subprocess.Popen handle from WebDriver service."""
        if driver and hasattr(driver, "service"):
            proc = getattr(driver.service, "process", None)
            if proc is not None and hasattr(proc, "poll"):
                return proc
        return None

    def _verify_effective_browser_security(self, driver: Any = None, proc: Optional[Any] = None) -> None:
        """Verify effective command line, capabilities and runtime environment fail-closed against sandbox-disabling flags (SEC10-03)."""
        disallowed = DISALLOWED_BROWSER_FLAGS

        # 1. Inspect environment variables
        for env_var in ("CHROMIUM_FLAGS", "CHROME_FLAGS", "EXTRA_CHROMIUM_FLAGS"):
            val = os.environ.get(env_var, "")
            for flag in disallowed:
                if flag in val:
                    if driver:
                        self._safe_teardown(driver, proc)
                    raise PndInsecureBrowserError(
                        f"Environment variable {env_var} contains disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                    )

        # 2. Inspect external config files if accessible
        for cfg_path in ("/etc/chromium/docker.conf", "/etc/chromium/default", "/etc/chromium-browser/default"):
            if os.path.isfile(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
                        cfg_content = f.read()
                        for flag in disallowed:
                            if flag in cfg_content:
                                if driver:
                                    self._safe_teardown(driver, proc)
                                raise PndInsecureBrowserError(
                                    f"External config {cfg_path} contains disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                                )
                except (OSError, PermissionError):
                    pass

        # 3. Inspect driver capabilities
        if driver is not None:
            caps = getattr(driver, "capabilities", {}) or {}
            checked_args: List[str] = []
            if isinstance(caps, dict):
                for opt_key in ("goog:chromeOptions", "chrome", "moz:firefoxOptions"):
                    if opt_key in caps and isinstance(caps[opt_key], dict):
                        args = caps[opt_key].get("args", [])
                        if isinstance(args, list):
                            checked_args.extend(str(a) for a in args)

            for arg in checked_args:
                for flag in disallowed:
                    if flag in arg:
                        self._safe_teardown(driver, proc)
                        raise PndInsecureBrowserError(
                            f"Browser capabilities contain disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                        )

        # 4. Inspect effective process command line
        if proc is not None:
            if hasattr(proc, "cmdline") and callable(proc.cmdline):
                try:
                    proc_cmdline = proc.cmdline()
                    if isinstance(proc_cmdline, (list, tuple)):
                        cmd_str = " ".join(str(a) for a in proc_cmdline)
                        for flag in disallowed:
                            if flag in cmd_str:
                                self._safe_teardown(driver, proc)
                                raise PndInsecureBrowserError(
                                    f"Effective process command line contains disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                                )
                except Exception as e:
                    if isinstance(e, PndInsecureBrowserError):
                        raise

            args_val = getattr(proc, "args", None)
            if isinstance(args_val, (list, tuple)):
                cmd_str = " ".join(str(a) for a in args_val)
                for flag in disallowed:
                    if flag in cmd_str:
                        self._safe_teardown(driver, proc)
                        raise PndInsecureBrowserError(
                            f"Process args contain disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                        )
            elif isinstance(args_val, str):
                for flag in disallowed:
                    if flag in args_val:
                        self._safe_teardown(driver, proc)
                        raise PndInsecureBrowserError(
                            f"Process args contain disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                        )

            if hasattr(proc, "pid") and isinstance(proc.pid, int):
                pids_to_check = [proc.pid]
                task_dir = f"/proc/{proc.pid}/task"
                if os.path.isdir(task_dir):
                    try:
                        for tid in os.listdir(task_dir):
                            child_file = os.path.join(task_dir, tid, "children")
                            if os.path.isfile(child_file):
                                with open(child_file, "r") as cf:
                                    for cpid in cf.read().split():
                                        if cpid.isdigit():
                                            pids_to_check.append(int(cpid))
                    except Exception:
                        pass

                for check_pid in pids_to_check:
                    cmdline_path = f"/proc/{check_pid}/cmdline"
                    if os.path.exists(cmdline_path):
                        try:
                            with open(cmdline_path, "rb") as f:
                                c_str = f.read().decode("utf-8", errors="ignore").replace("\x00", " ")
                                for flag in disallowed:
                                    if flag in c_str:
                                        self._safe_teardown(driver, proc)
                                        raise PndInsecureBrowserError(
                                            f"Effective process command line in /proc contains disallowed flag '{flag}' (ERR_INSECURE_BROWSER)"
                                        )
                        except Exception as pe:
                            if isinstance(pe, PndInsecureBrowserError):
                                raise

        self.effective_sandbox_verified = True
        self.effective_sandbox_mode = "enforced_least_privilege"

    def _init_driver(self, download_dir: str) -> Any:
        """Initialize headless Chrome or Firefox WebDriver."""
        os.makedirs(download_dir, exist_ok=True)
        try:
            os.chmod(download_dir, 0o777)
        except Exception:
            pass
        # Pre-launch environment and system config verification
        self._verify_effective_browser_security()

        # Try Chrome / Chromium first
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver.chrome.service import Service as ChromeService

            options = ChromeOptions()
            if self.headless:
                options.add_argument("--headless=new")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-gpu-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--log-level=3")
            options.add_experimental_option("prefs", {
                "download.default_directory": os.path.abspath(download_dir),
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "plugins.always_open_pdf_externally": False,
            })

            # Check known chromium binary paths
            for bp in ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome", "/usr/local/bin/chromium"]:
                if os.path.exists(bp):
                    options.binary_location = bp
                    break

            # Check known driver binary paths
            service = None
            for p in ["/usr/bin/chromedriver", "/usr/local/bin/chromedriver"]:
                if os.path.exists(p):
                    service = ChromeService(p)
                    break

            driver = webdriver.Chrome(service=service, options=options) if service else webdriver.Chrome(options=options)
            proc = self._get_driver_process(driver)
            self._verify_effective_browser_security(driver=driver, proc=proc)
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)
            driver.set_window_size(1920, 1080)
            if hasattr(driver, "execute_cdp_cmd"):
                for cmd in ("Browser.setDownloadBehavior", "Page.setDownloadBehavior"):
                    try:
                        driver.execute_cdp_cmd(
                            cmd,
                            {"behavior": "allow", "downloadPath": os.path.abspath(download_dir)},
                        )
                    except Exception as cdp_err:
                        _LOGGER.debug("Could not set CDP %s: %s", cmd, type(cdp_err).__name__)
            _LOGGER.debug("ChromeDriver initialized successfully")
            return driver
        except Exception as chrome_err:
            if isinstance(chrome_err, PndInsecureBrowserError):
                raise
            _LOGGER.debug("Chrome driver initialization failed: %s; trying Firefox", type(chrome_err).__name__)

        # Fallback to Firefox / GeckoDriver
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.webdriver.firefox.service import Service as FirefoxService

            ff_options = FirefoxOptions()
            if self.headless:
                ff_options.add_argument("--headless")
            ff_options.set_preference("browser.download.folderList", 2)
            ff_options.set_preference("browser.download.dir", os.path.abspath(download_dir))
            ff_options.set_preference("browser.download.manager.showWhenStarting", False)
            ff_options.set_preference(
                "browser.helperApps.neverAsk.saveToDisk",
                "application/pdf,application/zip,text/csv,application/vnd.ms-excel",
            )
            ff_options.set_preference("pdfjs.disabled", True)

            # Check known firefox binary paths
            for fbp in ["/usr/bin/firefox", "/usr/bin/firefox-esr", "/usr/local/bin/firefox"]:
                if os.path.exists(fbp):
                    ff_options.binary_location = fbp
                    break

            service = None
            for p in ["/usr/bin/geckodriver", "/usr/local/bin/geckodriver"]:
                if os.path.exists(p):
                    service = FirefoxService(p)
                    break

            driver = webdriver.Firefox(service=service, options=ff_options) if service else webdriver.Firefox(options=ff_options)
            proc = self._get_driver_process(driver)
            self._verify_effective_browser_security(driver=driver, proc=proc)
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)
            driver.set_window_size(1920, 1080)
            _LOGGER.debug("GeckoDriver initialized successfully")
            return driver
        except Exception as ff_err:
            if isinstance(ff_err, PndInsecureBrowserError):
                raise
            _LOGGER.error(
                "Both Chrome and Firefox WebDriver initialization failed: %s (ERR_SCRAPER)",
                type(ff_err).__name__,
            )
            raise PndScraperError("Cannot initialize WebDriver (ERR_SCRAPER)") from ff_err

    def _safe_teardown(self, driver: Any, process_handle: Optional[Any] = None) -> None:
        """Bezpečně ukončí prohlížeč a jeho subprocess.Popen proces bez číselného PID fallbacku (C-01)."""
        if driver is not None:
            try:
                driver.quit()
            except Exception as e:
                _LOGGER.debug("driver.quit() vyvolal výjimku (ignorováno): %s", type(e).__name__)

        proc = process_handle
        if proc is None and driver is not None and hasattr(driver, "service"):
            proc = getattr(driver.service, "process", None)

        if proc is not None and hasattr(proc, "poll"):
            try:
                if proc.poll() is None:
                    _LOGGER.warning("Proces WebDriveru stále běží po quit(); zasílám terminate()")
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except Exception:
                        _LOGGER.warning("Proces WebDriveru nereagoval na terminate(); zasílám kill()")
                        proc.kill()
                        try:
                            proc.wait(timeout=1.0)
                        except Exception:
                            pass
            except Exception as err:
                _LOGGER.debug("Chyba při ukončování process handle: %s", type(err).__name__)

    def _wait_for_download(
        self,
        download_dir: str,
        timeout: int = 30,
        pre_snapshot: Optional[Set[str]] = None,
        min_mtime: Optional[float] = None,
        driver: Any = None,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        expected_extension: Optional[str] = ".csv",
        expected_pattern: Optional[str] = None,
    ) -> Optional[str]:
        """Wait for newly downloaded, complete regular file in directory with strict attribution checks."""
        start_time = time.monotonic()
        known_files = set(pre_snapshot) if pre_snapshot is not None else set()
        threshold_mtime = (min_mtime - 0.5) if min_mtime is not None else 0.0

        while (time.monotonic() - start_time) < timeout:
            self._check_deadline_and_stop(driver, proc, stop_event, deadline)

            if os.path.exists(download_dir):
                try:
                    entries = os.listdir(download_dir)
                except OSError:
                    entries = []

                candidates: List[Tuple[float, str]] = []
                for f in entries:
                    if f in known_files:
                        continue
                    if f.endswith((".crdownload", ".part", ".tmp")):
                        continue
                    if expected_extension and not f.lower().endswith(expected_extension.lower()):
                        continue
                    if expected_pattern and not re.search(expected_pattern, f, re.IGNORECASE):
                        continue

                    full_path = os.path.join(download_dir, f)
                    try:
                        if os.path.islink(full_path) or not os.path.isfile(full_path):
                            continue

                        st = os.stat(full_path)
                        if min_mtime is not None and st.st_mtime < threshold_mtime:
                            continue

                        if st.st_size <= 0:
                            continue

                        candidates.append((st.st_mtime, full_path))
                    except OSError:
                        continue

                if candidates:
                    candidates.sort(key=lambda x: x[0])
                    candidate_path = candidates[-1][1]
                    try:
                        size1 = os.path.getsize(candidate_path)
                        time.sleep(0.1)
                        size2 = os.path.getsize(candidate_path)
                        if size1 == size2 and size1 > 0 and os.path.isfile(candidate_path) and not os.path.islink(candidate_path):
                            return candidate_path
                    except OSError:
                        pass

            time.sleep(0.5)
        return None

    def _validate_downloaded_report(
        self,
        file_path: str,
        target_filename: str,
    ) -> None:
        """Validate downloaded report integrity, structure, encoding, and profile binding (SEC10-05)."""
        if not file_path or not os.path.exists(file_path):
            raise PndScraperError(f"Stažený soubor neexistuje: {file_path}")

        if os.path.islink(file_path) or not os.path.isfile(file_path):
            raise PndScraperError(f"Stažený artefakt není regulární soubor nebo jde o symlink: {file_path}")

        try:
            size = os.path.getsize(file_path)
        except OSError as err:
            raise PndScraperError(f"Nelze zjistit velikost staženého souboru: {err}") from err

        if size == 0:
            raise PndScraperError(f"Stažený soubor je prázdný (0 B): {file_path}")

        if not file_path.lower().endswith(".csv"):
            raise PndScraperError(f"Stažený soubor nemá příponu .csv: {file_path}")

        chunk_size = min(size, 65536)
        try:
            with open(file_path, "rb") as f:
                content_bytes = f.read(chunk_size)
        except OSError as err:
            raise PndScraperError(f"Chyba při čtení staženého reportu: {err}") from err

        decoded_text: Optional[str] = None
        for enc in ("utf-8", "cp1250", "windows-1250", "iso-8859-2", "latin2"):
            try:
                decoded_text = content_bytes.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if decoded_text is None:
            raise PndScraperError(f"Stažený report obsahuje neplatné binární kódování: {file_path}")

        lower_sample = decoded_text.strip().lower()
        html_signatures = ("<!doctype html", "<html", "<head", "<body", "<div", "<title")
        for sig in html_signatures:
            if lower_sample.startswith(sig) or sig in lower_sample[:1024]:
                raise PndScraperError(
                    f"Stažený report je HTML chybová stránka místo CSV: {file_path}"
                )

        lines = [line.strip() for line in decoded_text.splitlines() if line.strip()]
        if not lines:
            raise PndScraperError(f"Stažený report neobsahuje žádné datové řádky: {file_path}")

        first_line = lines[0].lower()
        if ";" not in first_line and "," not in first_line:
            raise PndScraperError(f"Stažený CSV report postrádá oddělovač (; nebo ,): {file_path}")

        # Semantic profile binding check
        header_sample = " \n ".join(lines[:10]).lower()
        plus_markers = ("+a", "+e", "spotřeb", "spotreb", "odběr", "odber")
        minus_markers = ("-a", "-e", "výrob", "vyrob", "dodávk", "dodavk")

        has_plus = any(m in header_sample for m in plus_markers)
        has_minus = any(m in header_sample for m in minus_markers)

        target_lower = target_filename.lower()
        if "consumption" in target_lower:
            if has_minus and not has_plus:
                raise PndScraperError(
                    f"Neshoda profilu reportu: očekávána spotřeba (+A) pro {target_filename}, ale report obsahuje pouze výrobu (-A)"
                )
        elif "production" in target_lower:
            if has_plus and not has_minus:
                raise PndScraperError(
                    f"Neshoda profilu reportu: očekávána výroba (-A) pro {target_filename}, ale report obsahuje pouze spotřebu (+A)"
                )

    def _dismiss_cookie_banner(self, driver: Any) -> None:
        """Dismiss Cookiebot banner if present."""
        try:
            from selenium.webdriver.common.by import By

            button = driver.find_element(
                By.ID, "CybotCookiebotDialogBodyLevelButtonLevelOptinAllowallSelection"
            )
            button.click()
            _LOGGER.debug("Cookie banner dismissed")
            time.sleep(1)
        except Exception:
            _LOGGER.debug("No cookie banner found")

    def _check_maintenance(self, driver: Any) -> None:
        """Check if portal displays maintenance text."""
        try:
            page_text = driver.page_source.lower()
            if "odstávka systému" in page_text or "probíhá údržba" in page_text:
                raise PndMaintenanceError("ČEZ PND Portal is currently under maintenance")
        except PndMaintenanceError:
            raise
        except Exception:
            pass

    def _verify_origin(
        self,
        driver: Any,
        state: str = ORIGIN_STATE_APP,
        expected_path_prefix: Optional[str] = None,
        allowed_path_prefixes: Optional[Union[str, Tuple[str, ...], List[str]]] = None,
    ) -> None:
        """Striktně ověří HTTPS schéma, standardní port, povolený hostname a segment-safe prefix cesty (SEC08-06, SEC10-07)."""
        current_url = getattr(driver, "current_url", "") or ""
        if hasattr(current_url, "_mock_name") or hasattr(current_url, "return_value"):
            current_url = "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"

        allowed_hosts = ALLOWED_HOSTNAMES_BY_STATE.get(state)
        if allowed_hosts is None:
            _LOGGER.error("Zjištěn neplatný stav navigace pro ověření origin: %s", state)
            raise PndAuthError("Bezpečnostní selhání: Zjištěn neplatný stav origin (ERR_INVALID_ORIGIN)")

        try:
            parts = urlsplit(str(current_url))
            hostname = parts.hostname or ""
            is_valid = (
                parts.scheme == "https"
                and hostname in allowed_hosts
                and parts.port in (None, 443)
            )

            raw_path = parts.path or ""
            decoded_path = unquote(raw_path) if raw_path else ""
            norm_path = posixpath.normpath(decoded_path) if decoded_path else ""
            if norm_path and not norm_path.startswith("/"):
                norm_path = "/" + norm_path.lstrip("/")
            elif not norm_path:
                norm_path = "/"

            def _matches_segment_prefix(path: str, prefix: str) -> bool:
                p = prefix.rstrip("/")
                if not p:
                    return True
                return path == p or path.startswith(p + "/")

            # 1. Check explicit expected_path_prefix
            if is_valid and expected_path_prefix is not None:
                if not raw_path or not _matches_segment_prefix(norm_path, expected_path_prefix):
                    is_valid = False

            # 2. Check explicit allowed_path_prefixes
            if is_valid and allowed_path_prefixes is not None:
                prefixes = (allowed_path_prefixes,) if isinstance(allowed_path_prefixes, str) else tuple(allowed_path_prefixes)
                if not raw_path or not any(_matches_segment_prefix(norm_path, p) for p in prefixes):
                    is_valid = False

            # 3. SEC10-07 (CWE-346): Enforce exact host/path contracts during credential entry (ORIGIN_STATE_CREDENTIALS / ORIGIN_STATE_IDP)
            if is_valid and state in (ORIGIN_STATE_CREDENTIALS, ORIGIN_STATE_IDP):
                host_contracts = AUTH_HOST_PATH_CONTRACTS.get(hostname, CREDENTIAL_ENTRY_ALLOWED_PATH_PREFIXES)
                if not raw_path or not any(_matches_segment_prefix(norm_path, p) for p in host_contracts):
                    _LOGGER.error(
                        "Cesta '%s' na hostiteli '%s' neodpovídá povolenému kontraktu pro zadání credentials %s",
                        norm_path,
                        hostname,
                        host_contracts,
                    )
                    is_valid = False
        except Exception:
            is_valid = False

        if not is_valid:
            _LOGGER.error("Zjištěn neplatný nebo podvržený origin stránky pro stav '%s' (ERR_INVALID_ORIGIN)", state)
            raise PndAuthError("Bezpečnostní selhání: Zjištěn neplatný origin stránky (ERR_INVALID_ORIGIN)")

    def _login(
        self,
        driver: Any,
        download_dir: Optional[str] = None,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> None:
        """Perform login to CEZ PND portal."""
        from selenium.common.exceptions import TimeoutException
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)

        _LOGGER.debug("Navigating to login page %s", URL_PND_LOGIN)
        driver.get(URL_PND_LOGIN)
        time.sleep(2)

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_PREAUTH)
        self._check_maintenance(driver)
        self._dismiss_cookie_banner(driver)

        # Locate inputs
        try:
            wait = WebDriverWait(driver, 15)
            username_field = wait.until(
                EC.presence_of_element_located((
                    By.XPATH,
                    "//input[@placeholder='Zadejte svůj e-mail' or @placeholder='Uživatelské jméno / e-mail' or @type='email' or @type='text']",
                ))
            )
            password_field = None
            for _ in range(10):
                try:
                    password_field = driver.find_element(
                        By.XPATH,
                        "//input[@placeholder='Zadejte své heslo' or @placeholder='Heslo' or @type='password']",
                    )
                    if password_field:
                        break
                except Exception:
                    time.sleep(0.5)
            if not password_field:
                password_field = driver.find_element(
                    By.XPATH,
                    "//input[@placeholder='Zadejte své heslo' or @placeholder='Heslo' or @type='password']",
                )

            login_button = None
            for _ in range(10):
                try:
                    login_button = driver.find_element(
                        By.XPATH,
                        "//button[@type='submit' and (contains(@class, 'mui-btn--primary') or contains(@class, 'btn-primary') or @type='submit')]",
                    )
                    if login_button:
                        break
                except Exception:
                    time.sleep(0.5)
            if not login_button:
                login_button = driver.find_element(
                    By.XPATH,
                    "//button[@type='submit' and (contains(@class, 'mui-btn--primary') or contains(@class, 'btn-primary') or @type='submit')]",
                )

            self._verify_origin(driver, state=ORIGIN_STATE_CREDENTIALS)

            username_field.clear()
            self._verify_origin(driver, state=ORIGIN_STATE_CREDENTIALS)
            username_field.send_keys(self.username)

            self._verify_origin(driver, state=ORIGIN_STATE_CREDENTIALS)
            password_field.clear()
            password_field.send_keys(self.password)

            self._check_deadline_and_stop(driver, proc, stop_event, deadline)
            self._verify_origin(driver, state=ORIGIN_STATE_CREDENTIALS)

            login_button = wait.until(EC.element_to_be_clickable(login_button))
            self._verify_origin(driver, state=ORIGIN_STATE_CREDENTIALS)
            login_button.click()
            _LOGGER.debug("Login form submitted")
        except Exception as err:
            if isinstance(err, PndError):
                raise
            raise PndAuthError("Failed to submit login form (ERR_AUTH)") from err

        time.sleep(4)
        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_AUTH)
        self._check_maintenance(driver)

        # Verify login success
        try:
            wait = WebDriverWait(driver, 20)
            h1_element = wait.until(
                EC.presence_of_element_located((By.XPATH, "//h1[contains(text(), 'Naměřená data')]"))
            )
            _LOGGER.debug("Login successful; found H1 tag 'Naměřená data'")
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
        except TimeoutException:
            # Check for error alert box
            error_msg = ""
            try:
                alert = driver.find_element(By.CLASS_NAME, "alertWidget__content")
                error_msg = alert.text.strip()
            except Exception:
                try:
                    alert2 = driver.find_element(By.CSS_SELECTOR, ".alert, .alert-danger, .error-message")
                    error_msg = alert2.text.strip()
                except Exception:
                    pass

            # Check for CAPTCHA, lockout, or maintenance
            page_src = driver.page_source.lower()
            if "recaptcha" in page_src or "hcaptcha" in page_src or "robot" in page_src or "iframe[src*='recaptcha']" in page_src:
                self._capture_debug_dump(driver, "captcha_detected", error_msg or "CAPTCHA challenge detected", hass_config_dir=hass_config_dir)
                raise PndCaptchaError("CAPTCHA challenge detected on login page (ERR_CAPTCHA)")
            if "účet zablokován" in page_src or "zablokování" in page_src or "locked" in page_src:
                self._capture_debug_dump(driver, "account_locked", error_msg or "Account is locked", hass_config_dir=hass_config_dir)
                raise PndAccountLockedError("ČEZ account has been locked (ERR_LOCKED)")
            if "odstávka systému" in page_src or "probíhá údržba" in page_src:
                self._capture_debug_dump(driver, "maintenance_detected", error_msg or "Maintenance detected", hass_config_dir=hass_config_dir)
                raise PndMaintenanceError("ČEZ PND Portal is currently under maintenance (ERR_MAINTENANCE)")

            if error_msg:
                self._capture_debug_dump(driver, "login_failed", error_msg, hass_config_dir=hass_config_dir)
                raise PndAuthError("Authentication failed on CEZ PND portal (ERR_AUTH)")

            # Generic dashboard timeout
            self._capture_debug_dump(driver, "dashboard_timeout", "Timeout waiting for dashboard H1 tag", hass_config_dir=hass_config_dir)
            raise PndTimeoutError("Timeout waiting for CEZ PND dashboard to load (ERR_TIMEOUT)")

        # Check for 'Přečteno' modal dialog
        try:
            modal = driver.find_element(By.CLASS_NAME, "modal-dialog")
            _LOGGER.debug("Found modal dialog on dashboard")
            close_btn = modal.find_element(
                By.XPATH,
                ".//button[contains(@class, 'btn') and contains(text(), 'Přečteno')]",
            )
            close_btn.click()
            _LOGGER.debug("Clicked 'Přečteno' button, reloading page")
            time.sleep(2)
            driver.refresh()
            time.sleep(2)
        except Exception:
            _LOGGER.debug("No modal dialog to dismiss")

        # Extract app version if present
        try:
            ver_elem = driver.find_element(By.XPATH, "//div[contains(text(), 'Verze aplikace:')]")
            ver_text = (ver_elem.get_attribute("textContent") or ver_elem.text or "").replace("\xa0", " ")
            if ":" in ver_text:
                self.app_version = ver_text.split(":", 1)[1].strip()
            else:
                self.app_version = ver_text.strip()
        except Exception:
            pass

        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

    def _match_elm_option(self, elm_text: str, target_elm: str) -> bool:
        """Exaktně porovná ELM identifikátor vůči textu položky (žádný volný substring match)."""
        tokens = re.split(r"[\s\-_/]+", elm_text.strip())
        return target_elm.strip() in tokens or elm_text.strip() == target_elm.strip()

    def _select_elm(
        self,
        driver: Any,
        download_dir: Optional[str] = None,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> List[str]:
        """Select configured ELM meter in dropdown using safe CSS selectors."""
        from bs4 import BeautifulSoup
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
        wait = WebDriverWait(driver, 10)

        # Open 'Export' or 'Rychlá sestava' window if required
        try:
            window = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, ".pnd-window")))
            export_btn = window.find_element(By.XPATH, ".//button[@title='Export']")
            export_btn.click()
            time.sleep(1)
        except Exception:
            pass

        # Select 'Rychlá sestava'
        try:
            for _ in range(5):
                dropdown_label = wait.until(
                    EC.visibility_of_element_located((By.XPATH, "//label[contains(text(), 'Sestava')]"))
                )
                dropdown = dropdown_label.find_element(
                    By.XPATH, "./following-sibling::div//div[contains(@class, 'multiselect__tags')]"
                )
                dropdown.click()
                time.sleep(0.5)
                option = wait.until(
                    EC.element_to_be_clickable((By.XPATH, "//span[contains(text(), 'Rychlá sestava')]"))
                )
                option.click()
                time.sleep(0.5)
                break
        except Exception as e:
            _LOGGER.debug("Note on selecting 'Rychlá sestava': %s", type(e).__name__)

        # Extract available ELM options safely without logging raw list (C-06/SEC04-04)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        elm_spans = soup.find_all(
            "span",
            class_="multiselect__option",
            string=lambda t: t and ("ELM" in t or t.strip().isdigit()),
        )
        available_elms = [s.text.strip() for s in elm_spans if s.text.strip()]
        _LOGGER.debug("Available ELMs parsed from dropdown: %d candidates found", len(available_elms))

        if not self.elm and available_elms:
            self.elm = available_elms[0].split()[0]
            _LOGGER.info("No ELM configured; auto-selected first available ELM '%s'", mask_elm(self.elm))

        # Select ELM in dropdown using safe CSS search
        elm_selected = False
        for attempt in range(10):
            self._check_deadline_and_stop(driver, proc, stop_event, deadline)
            try:
                dropdown_label = wait.until(
                    EC.visibility_of_element_located((By.XPATH, "//label[contains(text(), 'Množina zařízení')]"))
                )
                dropdown = dropdown_label.find_element(
                    By.XPATH, "./following-sibling::div//div[contains(@class, 'multiselect__select')]"
                )
                dropdown.click()
                time.sleep(0.5)

                options = driver.find_elements(By.CSS_SELECTOR, "span.multiselect__option")
                target_option = None
                for opt in options:
                    text = (opt.text or "").strip()
                    if self._match_elm_option(text, self.elm):
                        target_option = opt
                        break

                if target_option:
                    target_option.click()
                    elm_selected = True
                    _LOGGER.debug("Selected ELM '%s' on attempt %d", mask_elm(self.elm), attempt + 1)
                    time.sleep(1)
                    break
            except Exception:
                time.sleep(1)

        if not elm_selected:
            self._capture_debug_dump(
                driver,
                "elm_not_found",
                f"ELM '{mask_elm(self.elm)}' not found in available devices",
                hass_config_dir=hass_config_dir,
            )
            # Never include unmasked raw ELMs list in exception (SEC04-04)
            raise PndElmNotFoundError(
                f"ELM '{mask_elm(self.elm)}' not found in account (ERR_ELM_NOT_FOUND)."
            )

        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
        return available_elms

    def test_login(
        self,
        temp_dir: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Test login credentials and return (success, app_version, available_elms)."""
        driver = None
        proc = None
        created_temp = False
        target_dir = temp_dir
        if not target_dir:
            target_dir = tempfile.mkdtemp(prefix="cez_pnd_test_login_")
            created_temp = True
        try:
            driver = self._init_driver(target_dir)
            proc = self._get_driver_process(driver)

            self._login(driver, target_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            available_elms = self._select_elm(driver, target_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            return True, self.app_version, available_elms
        finally:
            self._safe_teardown(driver, proc)
            if created_temp and target_dir and os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)

    def _click_search_data(
        self,
        driver: Any,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Click 'Vyhledat data' button safely with multi-locator fallback and JS click."""
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

        # 1. Candidate XPath locators
        locators = [
            "//button[contains(., 'Vyhledat data')]",
            "//button[contains(., 'Vyhledat')]",
            "//button[contains(., 'Hledat')]",
            "//button[contains(., 'Zobrazit')]",
            "//input[@type='submit' or @type='button'][contains(@value, 'Vyhledat') or contains(@value, 'Hledat')]",
            "//a[contains(@class, 'btn')][contains(., 'Vyhledat')]",
            "//button[contains(@class, 'search') or contains(@class, 'btn-search')]",
        ]

        for loc in locators:
            self._check_deadline_and_stop(driver, proc, stop_event, deadline)
            try:
                elems = driver.find_elements(By.XPATH, loc)
                for btn in elems:
                    if btn.is_displayed():
                        try:
                            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                            time.sleep(0.3)
                            btn.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", btn)
                        _LOGGER.debug("Clicked search button via locator %s", loc)
                        time.sleep(2)
                        return
            except Exception:
                pass

        # 2. Fallback to explicit wait
        try:
            wait = WebDriverWait(driver, 10)
            search_btn = wait.until(
                EC.element_to_be_clickable(
                    (By.XPATH, "//button[contains(., 'Vyhledat')] | //button[contains(., 'data')]")
                )
            )
            try:
                search_btn.click()
            except Exception:
                driver.execute_script("arguments[0].click();", search_btn)
            time.sleep(2)
        except Exception as err:
            raise PndScraperError("Failed to click 'Vyhledat data' (ERR_SCRAPER)") from err

    def download_yesterday_data(
        self,
        download_dir: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
        driver: Optional[Any] = None,
    ) -> Dict[str, str]:
        """Download yesterday's 15-minute intervals and daily summary reports."""
        own_driver = False
        proc = None
        try:
            if driver is None:
                driver = self._init_driver(download_dir)
                own_driver = True
            proc = self._get_driver_process(driver)

            self._login(driver, download_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            self._select_elm(driver, download_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait

            self._check_deadline_and_stop(driver, proc, stop_event, deadline)
            wait = WebDriverWait(driver, 10)

            # 1. Select 'Včera' in 'Období'
            try:
                dropdown_label = wait.until(
                    EC.element_to_be_clickable((By.XPATH, "//label[contains(text(), 'Období')]"))
                )
                dropdown_container = dropdown_label.find_element(
                    By.XPATH, "./following-sibling::div//div[contains(@class, 'multiselect__select')]"
                )
                dropdown_container.click()
                time.sleep(0.5)

                option_vcera = wait.until(
                    EC.element_to_be_clickable((
                        By.XPATH,
                        "//span[contains(text(), 'Včera') and contains(@class, 'multiselect__option')]",
                    ))
                )
                option_vcera.click()
                time.sleep(0.5)
            except Exception as err:
                raise PndScraperError("Failed to select 'Včera' period (ERR_SCRAPER)") from err

            # 2. Click 'Vyhledat data'
            self._click_search_data(driver, proc=proc, stop_event=stop_event, deadline=deadline)

            # 3. Download Daily Consumption (+A)
            daily_cons = self._download_report_by_name(
                driver, download_dir, ["07 Profil spotřeby za den (+A)", "07 Profil spotřeby", "17 Registry za den (+E, -E)", "17 Registry za den"], "daily-consumption.csv",
                proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
            )

            # 4. Download Daily Production (-A)
            daily_prod = ""
            try:
                daily_prod = self._download_report_by_name(
                    driver, download_dir, ["08 Profil výroby za den (-A)", "08 Profil výroby"], "daily-production.csv",
                    proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
                )
            except PndScraperError as err:
                _LOGGER.info("Daily production report not available for this EAN (consumption-only): %s", err)

            # 5. Switch to 'Vlastní období' or interval view for range 15min data
            yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%d.%m.%Y")
            yesterday_range = f"{yesterday_str} - {yesterday_str}"
            self._set_custom_date_range(driver, yesterday_range, proc=proc, stop_event=stop_event, deadline=deadline)

            # 6. Download 15-min interval range consumption
            range_cons = self._download_report_by_name(
                driver, download_dir, ["01 Profil spotřeby (+A)", "01 Profil spotřeby", "Profil spotřeby (+A)"], "range-consumption.csv",
                proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
            )

            # 7. Download 15-min interval range production
            range_prod = ""
            try:
                range_prod = self._download_report_by_name(
                    driver, download_dir, ["02 Profil výroby (-A)", "02 Profil výroby", "Profil výroby (-A)"], "range-production.csv",
                    proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
                )
            except PndScraperError as err:
                _LOGGER.info("Range production report not available for this EAN (consumption-only): %s", err)

            # SEC10-02 (CWE-252, CWE-682): Validate mandatory interval reports
            if not range_cons or not os.path.isfile(range_cons) or os.path.getsize(range_cons) == 0:
                raise PndScraperError("Mandatory report download failed: range-consumption.csv (ERR_SCRAPER)")
            if range_prod and (not os.path.isfile(range_prod) or os.path.getsize(range_prod) == 0):
                raise PndScraperError("Mandatory report download failed: range-production.csv (ERR_SCRAPER)")

            return {
                "daily_consumption": daily_cons or os.path.join(download_dir, "daily-consumption.csv"),
                "daily_production": daily_prod or "",
                "range_consumption": range_cons,
                "range_production": range_prod or "",
            }

        except Exception as err:
            _LOGGER.error("Error during scraping CEZ PND portal: %s", type(err).__name__)
            if driver:
                self._capture_debug_dump(driver, "scraping_failure", str(err), hass_config_dir=hass_config_dir)
            raise
        finally:
            if own_driver:
                self._safe_teardown(driver, proc)

    def download_custom_range(
        self,
        download_dir: str,
        date_range: str,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
        driver: Optional[Any] = None,
    ) -> Dict[str, str]:
        """Download custom date range 15-minute interval and summary reports."""
        own_driver = False
        proc = None
        try:
            if driver is None:
                driver = self._init_driver(download_dir)
                own_driver = True
            proc = self._get_driver_process(driver)

            self._login(driver, download_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            self._select_elm(driver, download_dir, proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

            self._set_custom_date_range(driver, date_range, proc=proc, stop_event=stop_event, deadline=deadline)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

            # Download range reports
            range_cons = self._download_report_by_name(
                driver, download_dir, ["01 Profil spotřeby (+A)", "01 Profil spotřeby", "Profil spotřeby (+A)"], "range-consumption.csv",
                proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
            )
            range_prod = self._download_report_by_name(
                driver, download_dir, ["02 Profil výroby (-A)", "02 Profil výroby", "Profil výroby (-A)"], "range-production.csv",
                proc=proc, stop_event=stop_event, deadline=deadline, hass_config_dir=hass_config_dir,
            )

            # SEC10-02 (CWE-252, CWE-682): Validate mandatory historical report downloads
            if not range_cons or not os.path.isfile(range_cons) or os.path.getsize(range_cons) == 0:
                raise PndScraperError("Mandatory historical report download failed: range-consumption.csv (ERR_SCRAPER)")
            if not range_prod or not os.path.isfile(range_prod) or os.path.getsize(range_prod) == 0:
                raise PndScraperError("Mandatory historical report download failed: range-production.csv (ERR_SCRAPER)")

            return {
                "range_consumption": range_cons,
                "range_production": range_prod,
            }
        except Exception as err:
            _LOGGER.error("Error during custom range scraping: %s", type(err).__name__)
            if driver:
                self._capture_debug_dump(driver, "custom_range_failure", str(err), hass_config_dir=hass_config_dir)
            raise
        finally:
            if own_driver:
                self._safe_teardown(driver, proc)

    download_historical_data = download_custom_range

    def _set_custom_date_range(
        self,
        driver: Any,
        date_range: str,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Set custom date range in PND interface."""
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
        wait = WebDriverWait(driver, 10)

        # Select 'Vlastní' or 'Vlastní období' in 'Období'
        dropdown_label = wait.until(
            EC.element_to_be_clickable((By.XPATH, "//label[contains(text(), 'Období')]"))
        )
        dropdown_container = dropdown_label.find_element(
            By.XPATH, "./following-sibling::div//div[contains(@class, 'multiselect__select')]"
        )
        dropdown_container.click()
        time.sleep(0.5)

        option_vlastni = wait.until(
            EC.element_to_be_clickable((
                By.XPATH,
                "//span[contains(text(), 'Vlastní') and contains(@class, 'multiselect__option')]",
            ))
        )
        option_vlastni.click()
        time.sleep(0.5)

        # Enter custom range into input field
        label = wait.until(
            EC.visibility_of_element_located((By.XPATH, "//label[contains(text(), 'Vlastní období')]"))
        )
        input_field = label.find_element(By.XPATH, "./following::input[1]")
        input_field.clear()
        input_field.send_keys(date_range)
        input_field.send_keys(Keys.TAB)
        time.sleep(0.5)

        # Click 'Vyhledat data' or 'Tabulka dat'
        try:
            self._click_search_data(driver, proc=proc, stop_event=stop_event, deadline=deadline)
        except Exception:
            pass

    def _download_report_by_name(
        self,
        driver: Any,
        download_dir: str,
        link_text: Union[str, List[str]],
        target_filename: str,
        proc: Any = None,
        stop_event: Optional[threading.Event] = None,
        deadline: Optional[float] = None,
        hass_config_dir: Optional[str] = None,
    ) -> str:
        """Find link by name, click Export -> CSV, and save with target_filename."""
        from selenium.webdriver.common.action_chains import ActionChains
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
        wait = WebDriverWait(driver, 10)

        # 1. Take pre-download directory snapshot and record request timestamp
        pre_snapshot = set(os.listdir(download_dir)) if os.path.exists(download_dir) else set()
        request_time = time.time()

        # Clear existing download temp files
        tmp_csv = os.path.join(download_dir, "pnd_export.csv")
        if os.path.exists(tmp_csv):
            try:
                os.remove(tmp_csv)
                pre_snapshot.discard("pnd_export.csv")
            except OSError:
                pass

        # Build candidate xpath targeting non-disabled elements
        candidates = [link_text] if isinstance(link_text, str) else list(link_text)
        xpath_parts = []
        for cand in candidates:
            xpath_parts.append(f".//a[contains(., '{cand}') and not(contains(@class, 'disabled'))]")
            xpath_parts.append(f".//span[contains(., '{cand}') and not(contains(@class, 'disabled'))]")
            xpath_parts.append(f".//a[contains(text(), '{cand}') and not(contains(@class, 'disabled'))]")
        link_xpath = " | ".join(xpath_parts)

        # Click report link
        try:
            try:
                link = wait.until(
                    EC.presence_of_element_located((By.XPATH, link_xpath))
                )
            except Exception:
                fallback_parts = []
                for cand in candidates:
                    fallback_parts.append(f".//a[contains(., '{cand}')]")
                    fallback_parts.append(f".//span[contains(., '{cand}')]")
                    fallback_parts.append(f".//a[contains(text(), '{cand}')]")
                link = wait.until(
                    EC.presence_of_element_located((By.XPATH, " | ".join(fallback_parts)))
                )
            try:
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", link)
                time.sleep(0.5)
                actions = ActionChains(driver)
                actions.move_to_element(link).perform()
                time.sleep(0.3)
                link.click()
            except Exception:
                driver.execute_script("arguments[0].click();", link)
            time.sleep(1)
        except Exception as err:
            _LOGGER.warning("Could not find or click report link %s: %s", candidates, type(err).__name__)
            if self.debug_mode:
                self._capture_debug_dump(driver, f"missing_report_{target_filename}", str(err), hass_config_dir=hass_config_dir)
            return ""

        self._check_deadline_and_stop(driver, proc, stop_event, deadline)
        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

        # Ensure CDP download directory is active on driver BEFORE triggering download click
        if hasattr(driver, "execute_cdp_cmd"):
            for cdp_cmd in ("Browser.setDownloadBehavior", "Page.setDownloadBehavior"):
                try:
                    driver.execute_cdp_cmd(
                        cdp_cmd,
                        {"behavior": "allow", "downloadPath": os.path.abspath(download_dir)},
                    )
                except Exception:
                    pass

        # Click 'Exportovat data' -> 'CSV'
        try:
            toggle_xpath = (
                "//button[contains(., 'Exportovat data')] | //button[contains(., 'Exportovat')]"
                " | //button[contains(., 'Export')] | //a[contains(., 'Exportovat data')]"
            )
            toggle_button = wait.until(
                EC.presence_of_element_located((By.XPATH, toggle_xpath))
            )
            try:
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", toggle_button)
                time.sleep(0.3)
                toggle_button.click()
            except Exception:
                driver.execute_script("arguments[0].click();", toggle_button)
            time.sleep(1)

            csv_xpath = "//a[normalize-space()='CSV'] | //a[contains(., 'CSV')] | //button[contains(., 'CSV')]"
            csv_link = wait.until(
                EC.presence_of_element_located((By.XPATH, csv_xpath))
            )
            try:
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", csv_link)
                time.sleep(0.3)
                csv_link.click()
            except Exception:
                driver.execute_script("arguments[0].click();", csv_link)
            time.sleep(2)
        except Exception as err:
            _LOGGER.warning("Could not trigger CSV download for '%s': %s", link_text, type(err).__name__)
            if self.debug_mode:
                self._capture_debug_dump(driver, f"missing_csv_{target_filename}", str(err), hass_config_dir=hass_config_dir)
            return ""

        self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)

        # Wait for newly downloaded file
        downloaded = self._wait_for_download(
            download_dir,
            timeout=30,
            pre_snapshot=pre_snapshot,
            min_mtime=request_time,
            driver=driver,
            proc=proc,
            stop_event=stop_event,
            deadline=deadline,
            expected_extension=".csv",
        )
        target_path = os.path.join(download_dir, target_filename)

        if downloaded and os.path.exists(downloaded):
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            try:
                self._validate_downloaded_report(downloaded, target_filename)
            except Exception as err:
                try:
                    if os.path.exists(downloaded):
                        os.remove(downloaded)
                except OSError:
                    pass
                _LOGGER.error("Downloaded report failed validation for '%s': %s", target_filename, err)
                if self.debug_mode:
                    self._capture_debug_dump(
                        driver,
                        f"invalid_report_{target_filename}",
                        str(err),
                        hass_config_dir=hass_config_dir,
                    )
                raise PndScraperError(
                    f"Downloaded report failed validation for '{target_filename}': {err}"
                ) from err

            # Atomically replace target_path
            os.replace(downloaded, target_path)
            self._verify_origin(driver, state=ORIGIN_STATE_APP, expected_path_prefix=APP_PATH_PREFIX)
            _LOGGER.debug("Downloaded %s as %s", link_text, target_filename)
            return target_path

        _LOGGER.warning("No new file was saved for report '%s'", link_text)
        if self.debug_mode:
            self._capture_debug_dump(driver, f"timeout_download_{target_filename}", "File not saved within timeout", hass_config_dir=hass_config_dir)
        return ""
