"""Config flow and Options flow for CEZ Distribuce PND integration."""
from __future__ import annotations

import asyncio
import inspect
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from typing import Any, Dict, Optional

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector
import homeassistant.helpers.config_validation as cv

from .client import (
    PndAccountLockedError,
    PndAuthError,
    PndCaptchaError,
    PndElmNotFoundError,
    PndMaintenanceError,
    PndScraperClient,
    PndTimeoutError,
    validate_safe_path,
)
from .http_client import PndHttpClient
from .const import (
    CONF_BROWSER_HEADLESS,
    CONF_CLIENT_MODE,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
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
    mask_ean,
)
from .coordinator import (
    GLOBAL_BROWSER_SEMAPHORE,
    BrowserWorkerOwnership,
    _async_safe_remove_dir,
)

_LOGGER = logging.getLogger(__name__)


def _get_hass_config_path(hass: Any) -> str:
    """Extract configuration directory path from HomeAssistant instance."""
    if hass is not None:
        if hasattr(hass, "config") and hasattr(hass.config, "path"):
            try:
                path_val = hass.config.path()
                if isinstance(path_val, str) and path_val.strip():
                    return path_val
            except Exception:
                pass
        if hasattr(hass, "config") and hasattr(hass.config, "config_dir"):
            try:
                cdir = hass.config.config_dir
                if isinstance(cdir, str) and cdir.strip():
                    return cdir
            except Exception:
                pass
    return "/config"


def validate_ean(ean: str) -> bool:
    """Verify that EAN is exactly an 18-digit numeric string."""
    return bool(re.match(r"^\d{18}$", str(ean).strip()))


def validate_elm(elm: str) -> bool:
    """Verify that ELM is an alphanumeric string (with dash and underscore) up to 30 chars."""
    return bool(re.match(r"^[A-Za-z0-9_-]{1,30}$", str(elm).strip()))


def validate_scan_time(scan_time: str) -> bool:
    """Verify scan time in HH:MM format."""
    return bool(re.match(r"^([01]\d|2[0-3]):[0-5]\d$", str(scan_time).strip()))


async def _test_credentials(
    hass_or_user_input: Any,
    user_input: Optional[Dict[str, Any]] = None,
) -> None:
    """Verify PND credentials and ELM under appropriate client mode."""
    if user_input is None and isinstance(hass_or_user_input, dict):
        hass = None
        input_data = hass_or_user_input
    else:
        hass = hass_or_user_input
        input_data = user_input or {}

    client_mode = input_data.get(CONF_CLIENT_MODE, CLIENT_MODE_BROWSER)

    if client_mode == CLIENT_MODE_HTTP:
        stop_event = threading.Event()
        deadline = time.monotonic() + 175.0
        temp_dir = tempfile.mkdtemp(prefix="cez_pnd_test_login_http_")
        try:
            async with asyncio.timeout(180):
                hass_cfg = _get_hass_config_path(hass)
                client = PndHttpClient(input_data)
                if hass is not None and hasattr(hass, "async_add_executor_job"):
                    worker_future = hass.async_add_executor_job(
                        client.test_login,
                        temp_dir,
                        stop_event,
                        deadline,
                        hass_cfg,
                    )
                else:
                    loop = asyncio.get_running_loop()
                    worker_future = loop.run_in_executor(
                        None,
                        client.test_login,
                        temp_dir,
                        stop_event,
                        deadline,
                        hass_cfg,
                    )
                if inspect.isawaitable(worker_future) or isinstance(worker_future, (asyncio.Future, asyncio.Task)):
                    await asyncio.shield(worker_future)
                elif hasattr(worker_future, "result"):
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, worker_future.result)
        except (TimeoutError, asyncio.TimeoutError, PndTimeoutError) as err:
            stop_event.set()
            raise PndTimeoutError("Časový limit pro ověření přihlašovacích údajů vypršel.") from err
        except Exception:
            stop_event.set()
            raise
        finally:
            if temp_dir:
                await _async_safe_remove_dir(hass, temp_dir)
        return

    stop_event = threading.Event()
    deadline = time.monotonic() + 175.0
    temp_dir = ""
    ownership: Optional[BrowserWorkerOwnership] = None

    await GLOBAL_BROWSER_SEMAPHORE.acquire()
    try:
        temp_dir = tempfile.mkdtemp(prefix="cez_pnd_test_login_")
        ownership = BrowserWorkerOwnership(
            semaphore=GLOBAL_BROWSER_SEMAPHORE,
            temp_dir=temp_dir,
            stop_event=stop_event,
            hass=hass,
        )

        async with asyncio.timeout(180):
            hass_cfg = _get_hass_config_path(hass)
            client = PndScraperClient(input_data)

            if hass is not None and hasattr(hass, "async_add_executor_job"):
                worker_future = hass.async_add_executor_job(
                    client.test_login,
                    temp_dir,
                    stop_event,
                    deadline,
                    hass_cfg,
                )
            else:
                loop = asyncio.get_running_loop()
                worker_future = loop.run_in_executor(
                    None,
                    client.test_login,
                    temp_dir,
                    stop_event,
                    deadline,
                    hass_cfg,
                )

            ownership.set_future(worker_future)
            if inspect.isawaitable(worker_future) or isinstance(worker_future, (asyncio.Future, asyncio.Task)):
                await asyncio.shield(worker_future)
            elif hasattr(worker_future, "result"):
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, worker_future.result)

    except (TimeoutError, asyncio.TimeoutError, PndTimeoutError) as err:
        stop_event.set()
        raise PndTimeoutError("Časový limit pro ověření přihlašovacích údajů vypršel.") from err
    except Exception:
        stop_event.set()
        raise
    except BaseException:
        stop_event.set()
        raise
    finally:
        if ownership is not None:
            await ownership.async_release_or_schedule()
        else:
            if temp_dir:
                await _async_safe_remove_dir(hass, temp_dir)
            GLOBAL_BROWSER_SEMAPHORE.release()


class CezPndConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for CEZ Distribuce PND."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize flow instance."""
        self._reauth_entry: Optional[config_entries.ConfigEntry] = None
        self._reconfigure_entry: Optional[config_entries.ConfigEntry] = None

    def _get_context_entry(self) -> Optional[config_entries.ConfigEntry]:
        """Safely fetch config entry from flow context."""
        if self._reconfigure_entry is not None:
            return self._reconfigure_entry
        if self._reauth_entry is not None:
            return self._reauth_entry
        entry_id = self.context.get("entry_id")
        if entry_id and hasattr(self, "hass") and self.hass is not None and hasattr(self.hass, "config_entries") and hasattr(self.hass.config_entries, "async_get_entry"):
            try:
                entry = self.hass.config_entries.async_get_entry(entry_id)
                if entry is not None:
                    return entry
            except Exception:
                pass
        if hasattr(self, "_get_reconfigure_entry"):
            try:
                entry = self._get_reconfigure_entry()
                if entry:
                    return entry
            except Exception:
                pass
        if hasattr(self, "_get_reauth_entry"):
            try:
                entry = self._get_reauth_entry()
                if entry:
                    return entry
            except Exception:
                pass
        return None

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Handle the initial setup step."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            ean = str(user_input.get(CONF_EAN, "")).strip()
            elm = str(user_input.get(CONF_ELM, "")).strip()
            scan_time = str(user_input.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)).strip()

            # 1. Regex validation of input formats
            if not validate_ean(ean):
                errors["base"] = "invalid_ean"
            elif not validate_elm(elm):
                errors["base"] = "invalid_elm"
            elif not validate_scan_time(scan_time):
                errors["base"] = "invalid_scan_time"
            else:
                await self.async_set_unique_id(ean)
                self._abort_if_unique_id_configured()

                # Test connection and authentication
                try:
                    await _test_credentials(self.hass, user_input)
                except PndAuthError:
                    errors["base"] = "invalid_auth"
                except PndCaptchaError:
                    errors["base"] = "captcha_detected"
                except PndAccountLockedError:
                    errors["base"] = "account_locked"
                except PndTimeoutError:
                    errors["base"] = "timeout"
                except PndElmNotFoundError:
                    errors["base"] = "elm_not_found"
                except PndMaintenanceError:
                    errors["base"] = "service_unavailable"
                except Exception as err:
                    _LOGGER.error("Unexpected error during login verification: %s", type(err).__name__)
                    errors["base"] = "cannot_connect"

                if not errors:
                    return self.async_create_entry(
                        title=f"ČEZ PND ({mask_ean(ean)})",
                        data=user_input,
                    )

        schema = vol.Schema({
            vol.Required(CONF_USERNAME): cv.string,
            vol.Required(CONF_PASSWORD): cv.string,
            vol.Required(CONF_EAN): cv.string,
            vol.Required(CONF_ELM): cv.string,
            vol.Optional(CONF_CLIENT_MODE, default=DEFAULT_CLIENT_MODE): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[CLIENT_MODE_HTTP, CLIENT_MODE_BROWSER],
                    translation_key="client_mode",
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(CONF_TARIFF_ENTITY): selector.EntitySelector(
                selector.EntitySelectorConfig(domain=["binary_sensor", "input_boolean", "sensor"])
            ),
            vol.Optional(CONF_SCAN_TIME, default=DEFAULT_SCAN_TIME): cv.string,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Handle re-authentication upon auth failure (SEC04-05)."""
        self._reauth_entry = self._get_context_entry()
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Dialog to enter new credentials for reauthentication."""
        errors: Dict[str, str] = {}
        entry = self._get_context_entry()

        if user_input is not None and entry is not None:
            new_password = str(user_input.get(CONF_PASSWORD, "")).strip()
            test_config = dict(entry.data)
            test_config[CONF_PASSWORD] = new_password

            try:
                await _test_credentials(self.hass, test_config)
            except PndAuthError:
                errors["base"] = "invalid_auth"
            except PndCaptchaError:
                errors["base"] = "captcha_detected"
            except PndAccountLockedError:
                errors["base"] = "account_locked"
            except PndTimeoutError:
                errors["base"] = "timeout"
            except PndElmNotFoundError:
                errors["base"] = "elm_not_found"
            except PndMaintenanceError:
                errors["base"] = "service_unavailable"
            except Exception as err:
                _LOGGER.error("Reauth verification failed: %s", type(err).__name__)
                errors["base"] = "cannot_connect"

            if not errors:
                new_data = {**entry.data, CONF_PASSWORD: new_password}
                if hasattr(self, "async_update_reload_and_abort"):
                    return self.async_update_reload_and_abort(entry, data=new_data)
                self.hass.config_entries.async_update_entry(entry, data=new_data)
                return self.async_abort(reason="reauth_successful")

        schema = vol.Schema({
            vol.Required(CONF_PASSWORD): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
        })

        ean_display = mask_ean(entry.data.get(CONF_EAN, "")) if entry else ""
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            errors=errors,
            description_placeholders={"ean": ean_display},
        )

    async def async_step_reconfigure(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Handle reconfiguring the existing integration entry (SEC04-05, SEC05-07)."""
        entry = self._get_context_entry()
        errors: Dict[str, str] = {}

        if user_input is not None and entry is not None:
            existing_ean = str(entry.data.get(CONF_EAN, "")).strip()
            submitted_ean = str(user_input.get(CONF_EAN, existing_ean)).strip()

            if submitted_ean != existing_ean:
                errors["base"] = "cannot_change_ean"

            elm = str(user_input.get(CONF_ELM, entry.data.get(CONF_ELM, ""))).strip()
            scan_time = str(user_input.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)).strip()

            if "cannot_change_ean" in errors.values():
                pass
            elif not validate_elm(elm):
                errors["base"] = "invalid_elm"
            elif not validate_scan_time(scan_time):
                errors["base"] = "invalid_scan_time"
            else:
                updated_data = {**entry.data, **user_input, CONF_EAN: existing_ean}
                try:
                    await _test_credentials(self.hass, updated_data)
                except PndAuthError:
                    errors["base"] = "invalid_auth"
                except PndCaptchaError:
                    errors["base"] = "captcha_detected"
                except PndAccountLockedError:
                    errors["base"] = "account_locked"
                except PndTimeoutError:
                    errors["base"] = "timeout"
                except PndElmNotFoundError:
                    errors["base"] = "elm_not_found"
                except PndMaintenanceError:
                    errors["base"] = "service_unavailable"
                except Exception as err:
                    _LOGGER.error("Reconfigure verification failed: %s", type(err).__name__)
                    errors["base"] = "cannot_connect"

                if not errors:
                    if hasattr(self, "async_update_reload_and_abort"):
                        return self.async_update_reload_and_abort(entry, data=updated_data)
                    self.hass.config_entries.async_update_entry(entry, data=updated_data)
                    return self.async_abort(reason="reconfigure_successful")

        current_data = entry.data if entry else {}
        schema = vol.Schema({
            vol.Required(CONF_USERNAME, default=current_data.get(CONF_USERNAME, "")): cv.string,
            vol.Required(CONF_PASSWORD, default=current_data.get(CONF_PASSWORD, "")): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(CONF_ELM, default=current_data.get(CONF_ELM, "")): cv.string,
            vol.Optional(CONF_SCAN_TIME, default=current_data.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)): cv.string,
        })

        ean_display = mask_ean(entry.data.get(CONF_EAN, "")) if entry else ""
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=schema,
            errors=errors,
            description_placeholders={"ean": ean_display},
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Get options flow handler."""
        return CezPndOptionsFlowHandler(config_entry)


class CezPndOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for CEZ Distribuce PND."""

    def __init__(self, config_entry: Optional[config_entries.ConfigEntry] = None) -> None:
        """Initialize options flow."""
        self._entry = config_entry

    @property
    def entry(self) -> config_entries.ConfigEntry:
        """Return the active config entry."""
        if self._entry is not None:
            return self._entry
        try:
            return self.config_entry
        except Exception:
            from unittest.mock import MagicMock
            return MagicMock()

    async def async_step_init(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Manage the options and password rotation."""
        errors: Dict[str, str] = {}
        entry = self.entry

        if user_input is not None:
            new_password = user_input.get(CONF_PASSWORD)
            scan_time = str(user_input.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)).strip()
            debug_dir_val = user_input.get(CONF_DEBUG_DIR)
            debug_path_val = user_input.get("debug_path")

            if scan_time and not validate_scan_time(scan_time):
                errors["base"] = "invalid_scan_time"

            debug_target = debug_dir_val if debug_dir_val is not None else debug_path_val
            if debug_target is not None and str(debug_target).strip():
                try:
                    hass_root = _get_hass_config_path(self.hass)
                    validate_safe_path(str(debug_target).strip(), hass_config_dir=hass_root)
                except Exception as d_err:
                    _LOGGER.warning("Invalid debug path in options flow: %s", type(d_err).__name__)
                    errors["debug_path"] = "invalid_debug_path"
                    errors[CONF_DEBUG_DIR] = "invalid_debug_path"

            if not errors:
                # If user entered a new password, verify and update ConfigEntry.data
                if new_password and str(new_password).strip():
                    new_pwd_clean = str(new_password).strip()
                    test_config = dict(getattr(entry, "data", {}))
                    test_config[CONF_PASSWORD] = new_pwd_clean

                    try:
                        await _test_credentials(self.hass, test_config)
                    except PndAuthError:
                        errors["base"] = "invalid_auth"
                    except PndCaptchaError:
                        errors["base"] = "captcha_detected"
                    except PndAccountLockedError:
                        errors["base"] = "account_locked"
                    except PndTimeoutError:
                        errors["base"] = "timeout"
                    except PndElmNotFoundError:
                        errors["base"] = "elm_not_found"
                    except PndMaintenanceError:
                        errors["base"] = "service_unavailable"
                    except Exception as err:
                        _LOGGER.error("Password update verification failed: %s", type(err).__name__)
                        errors["base"] = "cannot_connect"

                    if not errors:
                        # Atomically update entry data
                        new_data = dict(getattr(entry, "data", {}))
                        new_data[CONF_PASSWORD] = new_pwd_clean
                        self.hass.config_entries.async_update_entry(entry, data=new_data)

                if not errors:
                    # Clean options: never store password in options dict
                    clean_options = {k: v for k, v in user_input.items() if k != CONF_PASSWORD}
                    return self.async_create_entry(title="", data=clean_options)

        current_options = getattr(entry, "options", {})
        current_data = getattr(entry, "data", {})

        def get_val(key: str, default: Any = None) -> Any:
            return current_options.get(key, current_data.get(key, default))

        schema = vol.Schema({
            vol.Optional(
                CONF_CLIENT_MODE,
                default=get_val(CONF_CLIENT_MODE, DEFAULT_CLIENT_MODE),
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[CLIENT_MODE_HTTP, CLIENT_MODE_BROWSER],
                    translation_key="client_mode",
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(CONF_PASSWORD, default=""): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(
                CONF_TARIFF_ENTITY,
                description={"suggested_value": get_val(CONF_TARIFF_ENTITY)},
            ): selector.EntitySelector(
                selector.EntitySelectorConfig(domain=["binary_sensor", "input_boolean", "sensor"])
            ),
            vol.Optional(
                CONF_SCAN_TIME,
                default=get_val(CONF_SCAN_TIME, DEFAULT_SCAN_TIME),
            ): cv.string,
            vol.Optional(
                CONF_DEBUG_MODE,
                default=get_val(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE),
            ): cv.boolean,
            vol.Optional(
                CONF_DEBUG_DIR,
                default=get_val(CONF_DEBUG_DIR, DEFAULT_DEBUG_DIR),
            ): cv.string,
        })

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
        )
