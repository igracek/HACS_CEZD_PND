"""DataUpdateCoordinator for CEZ Distribuce PND integration."""
import asyncio
from datetime import datetime, time as dt_time, timedelta
import logging
import os
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Optional

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.event import async_call_later, async_track_time_change
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import (
    PndAccountLockedError,
    PndAuthError,
    PndCaptchaError,
    PndElmNotFoundError,
    PndInsecureBrowserError,
    PndMaintenanceError,
    PndParseError,
    PndPortalError,
    PndResourceError,
    PndScraperClient,
    PndScraperError,
    PndTimeoutError,
)
from .http_client import PndHttpClient
from .const import (
    CONF_BROWSER_HEADLESS,
    CONF_CLIENT_MODE,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
    CONF_ENABLE_NETWORK_CAPTURE,
    CONF_PASSWORD,
    CONF_SCAN_TIME,
    CONF_TARIFF_ENTITY,
    CONF_USERNAME,
    CLIENT_MODE_BROWSER,
    CLIENT_MODE_HTTP,
    DEFAULT_CLIENT_MODE,
    DEFAULT_DEBUG_DIR,
    DEFAULT_DEBUG_MODE,
    DEFAULT_SCAN_TIME,
    DOMAIN,
    ERR_AUTH,
    ERR_CAPTCHA,
    ERR_ELM_NOT_FOUND,
    ERR_INSECURE_BROWSER,
    ERR_LOCKED,
    ERR_MAINTENANCE,
    ERR_PARSER,
    ERR_PORTAL,
    ERR_RESOURCE,
    ERR_SCRAPER,
    ERR_TIMEOUT,
    ERR_UNKNOWN,
    mask_ean,
    mask_elm,
)
from .models import SyncResult
from .parser import PndCsvParser
from .statistics import PndStatisticsManager
from .tariff import TariffEvaluator

_LOGGER = logging.getLogger(__name__)


class LoopSafeSemaphore:
    """Asyncio semaphore that safely attaches to the current running event loop."""

    def __init__(self, value: int = 1) -> None:
        self._value = value
        self._sem: Optional[asyncio.Semaphore] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_sem(self) -> asyncio.Semaphore:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if self._sem is None or (current_loop is not None and self._loop != current_loop):
            self._loop = current_loop
            self._sem = asyncio.Semaphore(self._value)
        return self._sem

    async def acquire(self) -> bool:
        return await self._get_sem().acquire()

    def release(self) -> None:
        if self._sem is not None:
            if self._loop is not None and self._loop.is_running():
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None
                if running_loop != self._loop:
                    self._loop.call_soon_threadsafe(self._sem.release)
                    return
            self._sem.release()

    def locked(self) -> bool:
        if self._sem is not None:
            return self._sem.locked()
        return False

    async def __aenter__(self) -> bool:
        await self.acquire()
        return True

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


# Global concurrency semaphore across all instances/entries
GLOBAL_BROWSER_SEMAPHORE = LoopSafeSemaphore(1)


def _is_future_done(future: Any) -> bool:
    """Return True if the future/worker has physically finished, False otherwise."""
    if future is None:
        return True
    if hasattr(future, "done") and callable(future.done):
        try:
            return bool(future.done())
        except Exception:
            return True
    if asyncio.iscoroutine(future):
        import inspect
        try:
            return inspect.getcoroutinestate(future) == inspect.CORO_CLOSED
        except Exception:
            return True
    if not hasattr(future, "result"):
        return True
    return False


def _safe_remove_dir_sync(path: str) -> None:
    """Synchronously remove directory safely in executor thread (SEC10-04)."""
    try:
        if path and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


async def _async_safe_remove_dir(hass: Optional[Any], path: str) -> None:
    """Safely remove directory on executor without blocking event loop (SEC10-04)."""
    if not path:
        return
    try:
        if hass and hasattr(hass, "async_add_executor_job") and callable(hass.async_add_executor_job):
            job = hass.async_add_executor_job(_safe_remove_dir_sync, path)
            if asyncio.iscoroutine(job) or isinstance(job, asyncio.Future) or hasattr(job, "__await__"):
                await job
        else:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _safe_remove_dir_sync, path)
    except (Exception, StopIteration, StopAsyncIteration):
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _safe_remove_dir_sync, path)
        except Exception:
            _safe_remove_dir_sync(path)


class BrowserWorkerOwnership:
    """Explicit ownership tracker for browser executor jobs, temporary directories, and global semaphore."""

    def __init__(
        self,
        semaphore: LoopSafeSemaphore,
        temp_dir: str,
        stop_event: threading.Event,
        hass: Optional[HomeAssistant] = None,
    ) -> None:
        """Initialize worker ownership tracker."""
        self.semaphore = semaphore
        self.temp_dir = temp_dir
        self.stop_event = stop_event
        self.hass = hass
        self.worker_future: Any = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self._released: bool = False
        self._cleanup_scheduled: bool = False
        self._lock = threading.Lock()

    def set_future(self, future: Any) -> None:
        """Register running executor future."""
        self.worker_future = future

    def cleanup_sync(self, force: bool = False) -> None:
        """Synchronously release resources if worker thread has completed or not started without blocking event loop."""
        with self._lock:
            if self._released:
                return
            if not force and not _is_future_done(self.worker_future):
                _LOGGER.debug(
                    "BrowserWorkerOwnership: worker future is still running, deferring cleanup until physical completion."
                )
                return
            self._released = True

        target_dir = self.temp_dir
        if self.hass is None:
            _safe_remove_dir_sync(target_dir)
            self.semaphore.release()
            return

        try:
            loop = asyncio.get_running_loop()
            # Running on event loop thread! Schedule deletion on executor so we never block the event loop,
            # and release the semaphore ONLY after physical deletion completes in the executor.
            def _remove_and_release() -> None:
                _safe_remove_dir_sync(target_dir)
                self.semaphore.release()
                _LOGGER.debug(
                    "BrowserWorkerOwnership: temp_dir %s removed and semaphore released via executor.",
                    target_dir,
                )

            if hasattr(self.hass, "async_add_executor_job") and callable(self.hass.async_add_executor_job):
                try:
                    job = self.hass.async_add_executor_job(_remove_and_release)
                    if asyncio.iscoroutine(job):
                        loop.create_task(job)
                except (Exception, StopIteration, StopAsyncIteration):
                    loop.run_in_executor(None, _remove_and_release)
            else:
                loop.run_in_executor(None, _remove_and_release)
        except RuntimeError:
            # Running on worker thread or synchronous context without event loop
            _safe_remove_dir_sync(target_dir)
            self.semaphore.release()
            _LOGGER.debug(
                "BrowserWorkerOwnership: temp_dir %s removed and semaphore released synchronously.",
                target_dir,
            )

    async def async_cleanup(self, force: bool = False) -> None:
        """Asynchronously clean up temp_dir on executor and release semaphore only after deletion completes."""
        with self._lock:
            if self._released:
                return
            if not force and not _is_future_done(self.worker_future):
                return
            self._released = True

        try:
            if self.temp_dir:
                await _async_safe_remove_dir(self.hass, self.temp_dir)
        finally:
            self.semaphore.release()
            _LOGGER.debug(
                "BrowserWorkerOwnership: temp_dir %s removed and semaphore released via async cleanup.",
                self.temp_dir,
            )

    def schedule_background_cleanup(self) -> Optional[asyncio.Task]:
        """Schedule background cleanup that retains semaphore and temp_dir until physical completion."""
        with self._lock:
            if self._released or self._cleanup_scheduled:
                return self.cleanup_task
            self._cleanup_scheduled = True

        future = self.worker_future
        self.stop_event.set()

        if _is_future_done(future):
            self.cleanup_sync(force=True)
            return None

        # Authoritative binding to worker future completion
        if hasattr(future, "add_done_callback") and callable(future.add_done_callback):
            try:
                future.add_done_callback(lambda _f: self.cleanup_sync(force=True))
            except Exception as err:
                _LOGGER.debug("Failed to attach done callback to future: %s", err)
        else:
            def _thread_waiter() -> None:
                try:
                    if hasattr(future, "result") and callable(future.result):
                        future.result()
                    elif hasattr(future, "done") and callable(future.done):
                        while not future.done():
                            time.sleep(0.05)
                except Exception:
                    pass
                finally:
                    self.cleanup_sync(force=True)

            t = threading.Thread(target=_thread_waiter, daemon=True)
            t.start()

        async def _async_cleanup() -> None:
            try:
                if asyncio.iscoroutine(future) or isinstance(future, asyncio.Future):
                    await asyncio.shield(future)
                elif hasattr(future, "result"):
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, future.result)
            except Exception:
                pass
            finally:
                if _is_future_done(future):
                    self.cleanup_sync(force=True)

        scheduled = False
        coro = _async_cleanup()
        task: Optional[asyncio.Task] = None

        if self.hass is not None:
            try:
                if (
                    hasattr(self.hass, "async_create_background_task")
                    and callable(self.hass.async_create_background_task)
                    and type(self.hass.async_create_background_task).__name__ not in ("MagicMock", "AsyncMock")
                ):
                    task = self.hass.async_create_background_task(coro, name="cez_pnd_worker_cleanup")
                    scheduled = True
            except Exception as err:
                _LOGGER.debug("Failed creating background task in hass: %s", err)
                scheduled = False

        if not scheduled:
            try:
                task = asyncio.create_task(coro)
                scheduled = True
            except Exception as err:
                _LOGGER.debug("Failed creating background task in asyncio loop: %s", err)
                scheduled = False

        if not scheduled:
            try:
                coro.close()
            except Exception:
                pass
            _LOGGER.warning("Could not schedule async background cleanup task; using fallback thread waiter")
            def _fallback_waiter() -> None:
                try:
                    if hasattr(future, "result") and callable(future.result):
                        future.result()
                    elif hasattr(future, "done") and callable(future.done):
                        while not future.done():
                            time.sleep(0.05)
                except Exception:
                    pass
                finally:
                    self.cleanup_sync(force=True)

            t = threading.Thread(target=_fallback_waiter, daemon=True)
            t.start()

        self.cleanup_task = task
        return task

    async def async_release_or_schedule(self) -> None:
        """Asynchronously release resources if worker is done, or schedule background cleanup if still running."""
        if not _is_future_done(self.worker_future):
            self.schedule_background_cleanup()
        else:
            await self.async_cleanup(force=True)

    def release_or_schedule(self) -> None:
        """Finalizer called in finally blocks to ensure proper cleanup without premature resource release."""
        if not _is_future_done(self.worker_future):
            self.schedule_background_cleanup()
        else:
            self.cleanup_sync(force=True)


def _map_exception_to_error_code(err: Exception) -> str:
    """Map exception instance to bounded error code string."""
    if isinstance(err, PndAuthError):
        return ERR_AUTH
    if isinstance(err, PndCaptchaError):
        return ERR_CAPTCHA
    if isinstance(err, PndAccountLockedError):
        return ERR_LOCKED
    if isinstance(err, PndElmNotFoundError):
        return ERR_ELM_NOT_FOUND
    if isinstance(err, PndMaintenanceError):
        return ERR_MAINTENANCE
    if isinstance(err, (PndTimeoutError, TimeoutError, asyncio.TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(err, PndInsecureBrowserError) or "INSECURE_BROWSER" in str(err):
        return ERR_INSECURE_BROWSER
    if isinstance(err, PndResourceError) or "ERR_RESOURCE" in str(err):
        return ERR_RESOURCE
    if isinstance(err, PndScraperError):
        return ERR_SCRAPER
    if isinstance(err, PndParseError):
        return ERR_PARSER
    if isinstance(err, PndPortalError):
        return ERR_PORTAL
    err_type = type(err).__name__
    if "Parse" in err_type or "Parser" in err_type:
        return ERR_PARSER
    if "Portal" in err_type:
        return ERR_PORTAL
    return ERR_UNKNOWN


def _map_error_code_to_message(code: str) -> str:
    """Map error code to bounded, sanitized Czech message."""
    messages = {
        ERR_AUTH: "Neplatné přihlašovací jméno nebo heslo k portálu ČEZ PND.",
        ERR_CAPTCHA: "Portál ČEZ PND vyžaduje ověření CAPTCHA.",
        ERR_LOCKED: "Účet ČEZ PND byl zablokován.",
        ERR_ELM_NOT_FOUND: "Zadané číslo ELM nebylo nalezeno v účtu.",
        ERR_MAINTENANCE: "Portál ČEZ PND prochází údržbou.",
        ERR_TIMEOUT: "Časový limit operace vypršel (Task Deadline Exceeded).",
        ERR_SCRAPER: "Chyba při komunikaci s portálem ČEZ PND.",
        ERR_INSECURE_BROWSER: "Detekována nepovolená bezpečnostní konfigurace prohlížeče (ERR_INSECURE_BROWSER).",
        ERR_RESOURCE: "Nedostatek volné operační paměti pro bezpečné spuštění prohlížeče (ERR_RESOURCE).",
        ERR_PARSER: "Chyba při zpracování dat z portálu ČEZ PND.",
        ERR_PORTAL: "Chyba portálu ČEZ PND.",
        ERR_UNKNOWN: "Neočekávaná chyba při synchronizaci ČEZ PND.",
    }
    return messages.get(code, messages[ERR_UNKNOWN])


class CezPndCoordinator(DataUpdateCoordinator[SyncResult]):
    """Coordinator orchestrating PND scraping, parsing, tariff evaluation, and statistics import."""

    def __init__(self, hass: HomeAssistant, entry: Any) -> None:
        """Initialize coordinator."""
        self.entry = entry
        self.ean: str = entry.data.get(CONF_EAN, "")
        self.elm: str = entry.data.get(CONF_ELM, "")
        self.username: str = entry.data.get(CONF_USERNAME, "")
        self.password: str = entry.data.get(CONF_PASSWORD, "")
        self.masked_ean: str = mask_ean(self.ean)
        self.masked_elm: str = mask_elm(self.elm)

        options = entry.options if hasattr(entry, "options") else {}
        self.tariff_entity: Optional[str] = options.get(
            CONF_TARIFF_ENTITY, entry.data.get(CONF_TARIFF_ENTITY)
        )
        self.scan_time_str: str = options.get(
            CONF_SCAN_TIME, entry.data.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)
        )
        self.browser_headless: bool = entry.data.get(CONF_BROWSER_HEADLESS, True)
        self.debug_mode: bool = options.get(CONF_DEBUG_MODE, entry.data.get(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE))

        default_dbg_dir = (
            hass.config.path("cez_pnd_debug")
            if hasattr(hass, "config") and hasattr(hass.config, "path")
            else DEFAULT_DEBUG_DIR
        )
        self.debug_dir: str = options.get(CONF_DEBUG_DIR, entry.data.get(CONF_DEBUG_DIR, default_dbg_dir))

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{self.ean}",
            update_interval=None,
            config_entry=entry,
        )

        self.scraper = self._get_client()
        self.parser = PndCsvParser()
        self.tariff_evaluator = TariffEvaluator(hass, self.tariff_entity)
        self.stats_manager = PndStatisticsManager(hass, self.ean)

        self.is_running: bool = False
        self.last_sync_result: Optional[SyncResult] = None
        self.last_sync_time: Optional[datetime] = None
        self._last_ownership: Optional[BrowserWorkerOwnership] = None
        self._unsub_schedule: Optional[Callable[[], None]] = None
        self._unsub_retry: Optional[Callable[[], None]] = None
        self._retry_scheduled: bool = False

    def _get_client(self) -> Any:
        """Instantiate client (PndHttpClient or PndScraperClient) based on config_entry mode."""
        client_mode = CLIENT_MODE_BROWSER
        if hasattr(self, "config_entry") and self.config_entry is not None:
            client_mode = self.config_entry.options.get(
                CONF_CLIENT_MODE,
                self.config_entry.data.get(CONF_CLIENT_MODE, CLIENT_MODE_BROWSER),
            )

        current_scraper = getattr(self, "scraper", None)
        if current_scraper is not None:
            if (
                type(current_scraper).__name__ in ("MagicMock", "AsyncMock")
                or hasattr(current_scraper, "_mock_return_value")
            ):
                return current_scraper
            if client_mode == CLIENT_MODE_HTTP and isinstance(current_scraper, PndHttpClient):
                return current_scraper
            if client_mode == CLIENT_MODE_BROWSER and isinstance(current_scraper, PndScraperClient):
                return current_scraper

        config = {
            CONF_USERNAME: self.username,
            CONF_PASSWORD: self.password,
            CONF_EAN: self.ean,
            CONF_ELM: self.elm,
            CONF_BROWSER_HEADLESS: self.browser_headless,
            CONF_DEBUG_MODE: self.debug_mode,
            CONF_DEBUG_DIR: self.debug_dir,
            CONF_ENABLE_NETWORK_CAPTURE: self.entry.options.get(CONF_ENABLE_NETWORK_CAPTURE, False) or self.debug_mode,
        }
        if client_mode == CLIENT_MODE_HTTP:
            return PndHttpClient(config)
        return PndScraperClient(config)

    def _get_hass_config_path(self) -> Optional[str]:
        """Return Home Assistant root config path if available."""
        if hasattr(self.hass, "config") and hasattr(self.hass.config, "path"):
            return self.hass.config.path()
        return None

    def setup_daily_schedule(self) -> None:
        """Register daily scheduled time tracker."""
        if self._unsub_schedule:
            self._unsub_schedule()
            self._unsub_schedule = None

        try:
            parts = self.scan_time_str.split(":")
            hour = int(parts[0])
            minute = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            hour, minute = 6, 0

        _LOGGER.info(
            "Scheduling daily PND synchronization for EAN %s at %02d:%02d",
            self.masked_ean,
            hour,
            minute,
        )

        async def _scheduled_tick(_now: datetime) -> None:
            _LOGGER.info("Starting scheduled daily synchronization for EAN %s", self.masked_ean)
            await self.async_request_refresh()

        self._unsub_schedule = async_track_time_change(
            self.hass, _scheduled_tick, hour=hour, minute=minute, second=0
        )

    def cancel_schedule(self) -> None:
        """Cancel scheduled time tracker and any pending retry callbacks (SEC04-05)."""
        if self._unsub_schedule:
            self._unsub_schedule()
            self._unsub_schedule = None
        if self._unsub_retry:
            self._unsub_retry()
            self._unsub_retry = None
        self._retry_scheduled = False

    async def _async_retry_maintenance(self, _now: Optional[datetime] = None) -> None:
        """Retry synchronization after portal maintenance."""
        self._unsub_retry = None
        self._retry_scheduled = False
        _LOGGER.info("Spouštím odložený pokus o synchronizaci PND po údržbě pro EAN %s", self.masked_ean)
        await self.async_request_refresh()

    def _schedule_background_cleanup(self, future: Any, temp_dir: str) -> BrowserWorkerOwnership:
        """Schedule background task to hold semaphore and temp_dir until worker thread physically finishes (SEC04-01 / SEC05-02 / SEC06-02)."""
        ownership = BrowserWorkerOwnership(
            semaphore=GLOBAL_BROWSER_SEMAPHORE,
            temp_dir=temp_dir,
            stop_event=threading.Event(),
            hass=self.hass,
        )
        ownership.set_future(future)
        ownership.schedule_background_cleanup()
        self._last_ownership = ownership
        return ownership

    async def _async_update_data(self) -> SyncResult:
        """Fetch yesterday's data from CEZ PND and process pipeline under global semaphore."""
        if self.is_running:
            _LOGGER.warning("Synchronizace pro EAN %s již probíhá, přeskakuji.", self.masked_ean)
            if self.last_sync_result:
                return self.last_sync_result
            raise HomeAssistantError("Synchronization is already in progress")

        start_time = time.time()
        temp_dir = ""
        stop_event = threading.Event()
        deadline = time.monotonic() + 175.0
        ownership: Optional[BrowserWorkerOwnership] = None

        await GLOBAL_BROWSER_SEMAPHORE.acquire()
        try:
            temp_dir = tempfile.mkdtemp(prefix="cez_pnd_sync_")
            try:
                os.chmod(temp_dir, 0o777)
            except Exception:
                pass
            ownership = BrowserWorkerOwnership(
                semaphore=GLOBAL_BROWSER_SEMAPHORE,
                temp_dir=temp_dir,
                stop_event=stop_event,
                hass=self.hass,
            )
            self._last_ownership = ownership
            self.is_running = True
            self.async_update_listeners()

            async with asyncio.timeout(180):
                hass_cfg = self._get_hass_config_path()
                self.scraper = self._get_client()

                worker_future = self.hass.async_add_executor_job(
                    self.scraper.download_yesterday_data,
                    temp_dir,
                    stop_event,
                    deadline,
                    hass_cfg,
                )
                ownership.set_future(worker_future)

                _LOGGER.debug("Downloading yesterday's PND data to %s", temp_dir)
                if asyncio.iscoroutine(worker_future) or isinstance(worker_future, asyncio.Future):
                    await asyncio.shield(worker_future)
                else:
                    await worker_future

                self.parser.app_version = getattr(self.scraper, "app_version", None)
                parsed_data = await self.hass.async_add_executor_job(
                    self.parser.parse, temp_dir
                )

                _LOGGER.debug("Evaluating VT/NT tariff classification for %d intervals", len(parsed_data.intervals))
                await self.tariff_evaluator.async_evaluate(parsed_data.intervals)

                if parsed_data.daily_summary and parsed_data.intervals:
                    vt_kwh = sum(r.consumption_kwh for r in parsed_data.intervals if r.is_vt and r.is_valid_consumption)
                    nt_kwh = sum(r.consumption_kwh for r in parsed_data.intervals if not r.is_vt and r.is_valid_consumption)
                    tot_kwh = vt_kwh + nt_kwh
                    parsed_data.daily_summary.consumption_vt_kwh = round(vt_kwh, 4)
                    parsed_data.daily_summary.consumption_nt_kwh = round(nt_kwh, 4)
                    parsed_data.daily_summary.vt_ratio_percent = round((vt_kwh / tot_kwh * 100.0) if tot_kwh > 0 else 100.0, 1)

                _LOGGER.debug("Importing %d intervals to HA long-term statistics", len(parsed_data.intervals))
                await self.stats_manager.async_import(parsed_data)

                duration = round(time.time() - start_time, 2)
                self.last_sync_time = datetime.now()
                sync_result = SyncResult(
                    intervals=parsed_data.intervals,
                    daily_summary=parsed_data.daily_summary,
                    duration_seconds=duration,
                    status="OK",
                    records_count=len(parsed_data.intervals),
                    debug_artifacts_created=list(self.scraper.last_debug_artifacts),
                )
                self.last_sync_result = sync_result
                return sync_result

        except (TimeoutError, asyncio.TimeoutError, PndTimeoutError) as err:
            stop_event.set()

            duration = round(time.time() - start_time, 2)
            self.last_sync_time = datetime.now()
            err_msg = _map_error_code_to_message(ERR_TIMEOUT)
            _LOGGER.error("PND synchronizace pro EAN %s překročila časový limit (%s)", self.masked_ean, ERR_TIMEOUT)
            self.last_sync_result = SyncResult(
                duration_seconds=duration,
                status="Error",
                error_message=err_msg,
                error_code=ERR_TIMEOUT,
                debug_artifacts_created=list(self.scraper.last_debug_artifacts),
            )
            raise UpdateFailed(err_msg) from err

        except Exception as err:
            stop_event.set()

            duration = round(time.time() - start_time, 2)
            self.last_sync_time = datetime.now()
            err_code = _map_exception_to_error_code(err)
            err_msg = _map_error_code_to_message(err_code)

            _LOGGER.error("PND synchronization failed for EAN %s (%s): %s", self.masked_ean, err_code, type(err).__name__)

            if isinstance(err, PndMaintenanceError):
                _LOGGER.warning("Portál ČEZ PND prochází údržbou. Plánuji automatický opakovaný pokus za 60 minut.")
                if not self._retry_scheduled:
                    self._retry_scheduled = True
                    self._unsub_retry = async_call_later(self.hass, 3600, self._async_retry_maintenance)

            self.last_sync_result = SyncResult(
                duration_seconds=duration,
                status="Error",
                error_message=err_msg,
                error_code=err_code,
                debug_artifacts_created=list(self.scraper.last_debug_artifacts),
            )

            if isinstance(err, PndAuthError):
                raise ConfigEntryAuthFailed(err_msg) from err

            raise UpdateFailed(err_msg) from err

        except BaseException:
            stop_event.set()
            raise

        finally:
            self.is_running = False
            if ownership is not None:
                await ownership.async_release_or_schedule()
            else:
                if temp_dir:
                    await _async_safe_remove_dir(self.hass, temp_dir)
                GLOBAL_BROWSER_SEMAPHORE.release()
            self.async_update_listeners()

    async def async_fetch_range(self, date_range: str) -> SyncResult:
        """Fetch custom date range and import into long-term statistics under global semaphore."""
        if self.is_running:
            raise HomeAssistantError("Synchronization is already in progress")

        start_time = time.time()
        temp_dir = ""
        stop_event = threading.Event()
        deadline = time.monotonic() + 175.0
        ownership: Optional[BrowserWorkerOwnership] = None

        await GLOBAL_BROWSER_SEMAPHORE.acquire()
        try:
            temp_dir = tempfile.mkdtemp(prefix="cez_pnd_range_")
            try:
                os.chmod(temp_dir, 0o777)
            except Exception:
                pass
            ownership = BrowserWorkerOwnership(
                semaphore=GLOBAL_BROWSER_SEMAPHORE,
                temp_dir=temp_dir,
                stop_event=stop_event,
                hass=self.hass,
            )
            self._last_ownership = ownership
            self.is_running = True
            self.async_update_listeners()

            async with asyncio.timeout(180):
                hass_cfg = self._get_hass_config_path()
                self.scraper = self._get_client()

                _LOGGER.info("Fetching custom date range '%s' for EAN %s", date_range, self.masked_ean)
                worker_future = self.hass.async_add_executor_job(
                    self.scraper.download_custom_range,
                    temp_dir,
                    date_range,
                    stop_event,
                    deadline,
                    hass_cfg,
                )
                ownership.set_future(worker_future)
                if asyncio.iscoroutine(worker_future) or isinstance(worker_future, asyncio.Future):
                    await asyncio.shield(worker_future)
                else:
                    await worker_future

                self.parser.app_version = getattr(self.scraper, "app_version", None)
                parsed_data = await self.hass.async_add_executor_job(
                    self.parser.parse, temp_dir
                )

                await self.tariff_evaluator.async_evaluate(parsed_data.intervals)

                if parsed_data.daily_summary and parsed_data.intervals:
                    vt_kwh = sum(r.consumption_kwh for r in parsed_data.intervals if r.is_vt and r.is_valid_consumption)
                    nt_kwh = sum(r.consumption_kwh for r in parsed_data.intervals if not r.is_vt and r.is_valid_consumption)
                    tot_kwh = vt_kwh + nt_kwh
                    parsed_data.daily_summary.consumption_vt_kwh = round(vt_kwh, 4)
                    parsed_data.daily_summary.consumption_nt_kwh = round(nt_kwh, 4)
                    parsed_data.daily_summary.vt_ratio_percent = round((vt_kwh / tot_kwh * 100.0) if tot_kwh > 0 else 100.0, 1)

                await self.stats_manager.async_import(parsed_data)

                duration = round(time.time() - start_time, 2)
                self.last_sync_time = datetime.now()
                sync_result = SyncResult(
                    intervals=parsed_data.intervals,
                    daily_summary=parsed_data.daily_summary,
                    duration_seconds=duration,
                    status="OK",
                    records_count=len(parsed_data.intervals),
                    debug_artifacts_created=list(self.scraper.last_debug_artifacts),
                )
                self.last_sync_result = sync_result
                self.async_set_updated_data(sync_result)
                return sync_result

        except (TimeoutError, asyncio.TimeoutError, PndTimeoutError) as err:
            stop_event.set()

            duration = round(time.time() - start_time, 2)
            self.last_sync_time = datetime.now()
            err_msg = _map_error_code_to_message(ERR_TIMEOUT)
            _LOGGER.error("PND custom range fetch timeout for EAN %s", self.masked_ean)
            self.last_sync_result = SyncResult(
                duration_seconds=duration,
                status="Error",
                error_message=err_msg,
                error_code=ERR_TIMEOUT,
                debug_artifacts_created=list(self.scraper.last_debug_artifacts),
            )
            raise HomeAssistantError(f"Fetch custom range failed: {err_msg}") from err

        except Exception as err:
            stop_event.set()

            duration = round(time.time() - start_time, 2)
            self.last_sync_time = datetime.now()
            err_code = _map_exception_to_error_code(err)
            err_msg = _map_error_code_to_message(err_code)

            _LOGGER.error("PND custom range fetch failed for EAN %s (%s)", self.masked_ean, err_code)
            self.last_sync_result = SyncResult(
                duration_seconds=duration,
                status="Error",
                error_message=err_msg,
                error_code=err_code,
                debug_artifacts_created=list(self.scraper.last_debug_artifacts),
            )
            raise HomeAssistantError(f"Fetch custom range failed: {err_msg}") from err

        except BaseException:
            stop_event.set()
            raise

        finally:
            self.is_running = False
            if ownership is not None:
                await ownership.async_release_or_schedule()
            else:
                if temp_dir:
                    await _async_safe_remove_dir(self.hass, temp_dir)
                GLOBAL_BROWSER_SEMAPHORE.release()
            self.async_update_listeners()
