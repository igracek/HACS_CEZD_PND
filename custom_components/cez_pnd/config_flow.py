"""Config flow and Options flow for CEZ Distribuce PND integration."""
from __future__ import annotations

import asyncio
from datetime import datetime
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
    PndElmUnavailableError,
    PndExportIdentityMismatchError,
    PndIdentityUnverifiedError,
    PndMaintenanceError,
    PndScraperClient,
    PndTimeoutError,
    validate_safe_path,
)
from .http_client import PndHttpClient
from .const import (
    CONF_BILLING_START_DATE,
    CONF_BROWSER_HEADLESS,
    CONF_CLIENT_MODE,
    CONF_COST_TRACKING,
    CONF_DEBUG_DIR,
    CONF_DEBUG_MODE,
    CONF_EAN,
    CONF_ELM,
    CONF_UNVERIFIED_IDENTITY_CONFIRMED,
    CONF_PASSWORD,
    CONF_PRICE_CURRENCY,
    CONF_PRICE_NT,
    CONF_PRICE_SCHEDULE,
    CONF_PRICE_SINGLE,
    CONF_PRICE_VALID_FROM,
    CONF_PRICE_VT,
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
from .pricing import (
    PriceCurrencyMismatchError,
    PriceScheduleError,
    merge_price_period,
    migrate_single_tariff_schedule,
    single_tariff_price,
)

_LOGGER = logging.getLogger(__name__)

MAX_CREDENTIAL_LENGTH = 256


class _ConditionalNumberSelector(selector.NumberSelector):
    """Expose HA 2026.8+ ha-form visibility in a config-flow field."""

    def __init__(self, config: Any, visible: Dict[str, Any]) -> None:
        super().__init__(config)
        self._visible = visible

    def serialize(self) -> Dict[str, Any]:
        return {**super().serialize(), "visible": self._visible}


class _ConditionalDateSelector(selector.DateSelector):
    """Date selector with the same conditional visibility contract."""

    def __init__(self, config: Any, visible: Dict[str, Any]) -> None:
        super().__init__(config)
        self._visible = visible

    def serialize(self) -> Dict[str, Any]:
        return {**super().serialize(), "visible": self._visible}


def credentials_within_length_limit(user_input: Dict[str, Any]) -> bool:
    """Return whether submitted credentials are within the accepted size limit."""
    return all(
        len(str(user_input.get(key, ""))) <= MAX_CREDENTIAL_LENGTH
        for key in (CONF_USERNAME, CONF_PASSWORD)
        if key in user_input
    )


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


def _entry_client_config(
    entry: config_entries.ConfigEntry,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build validation config with options taking precedence over entry data."""
    config = dict(getattr(entry, "data", {}) or {})
    config.update(dict(getattr(entry, "options", {}) or {}))
    if overrides:
        config.update(overrides)
    return config


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

    client_mode = input_data.get(CONF_CLIENT_MODE, DEFAULT_CLIENT_MODE)

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

            worker_future = ownership.set_future(worker_future)
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
        self._pending_identity_confirmation: Optional[Dict[str, Any]] = None

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
            if not credentials_within_length_limit(user_input):
                errors["base"] = "credentials_too_long"
            elif not validate_ean(ean):
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
                except PndIdentityUnverifiedError:
                    self._pending_identity_confirmation = dict(user_input)
                    return await self.async_step_identity_warning()
                except PndExportIdentityMismatchError:
                    errors["base"] = "identity_mismatch"
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
                except PndElmUnavailableError:
                    errors["base"] = "elm_unavailable"
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
            vol.Required(CONF_USERNAME): vol.All(cv.string, vol.Length(max=MAX_CREDENTIAL_LENGTH)),
            vol.Required(CONF_PASSWORD): vol.All(cv.string, vol.Length(max=MAX_CREDENTIAL_LENGTH)),
            vol.Required(CONF_EAN): cv.string,
            vol.Required(CONF_ELM): cv.string,
            vol.Optional(CONF_CLIENT_MODE, default=DEFAULT_CLIENT_MODE): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[CLIENT_MODE_HTTP, CLIENT_MODE_BROWSER],
                    translation_key="client_mode",
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(
                CONF_DEBUG_MODE,
                default=(user_input or {}).get(CONF_DEBUG_MODE, DEFAULT_DEBUG_MODE),
            ): cv.boolean,
            vol.Optional(CONF_TARIFF_ENTITY): selector.EntitySelector(
                selector.EntitySelectorConfig(domain=["binary_sensor", "input_boolean", "sensor"])
            ),
            vol.Optional(CONF_BILLING_START_DATE): selector.DateSelector(
                selector.DateSelectorConfig()
            ),
            vol.Optional(CONF_SCAN_TIME, default=DEFAULT_SCAN_TIME): cv.string,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_identity_warning(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Require an explicit decision when the export has no EAN binding."""
        pending = self._pending_identity_confirmation
        if pending is None:
            return self.async_abort(reason="identity_confirmation_expired")
        errors: Dict[str, str] = {}
        if user_input is not None:
            if user_input.get("confirm_unverified_identity") is not True:
                errors["base"] = "confirmation_required"
            else:
                confirmed = {
                    **pending,
                    CONF_UNVERIFIED_IDENTITY_CONFIRMED: True,
                }
                try:
                    await _test_credentials(self.hass, confirmed)
                except PndExportIdentityMismatchError:
                    errors["base"] = "identity_mismatch"
                except PndAuthError:
                    errors["base"] = "invalid_auth"
                except PndTimeoutError:
                    errors["base"] = "timeout"
                except PndElmUnavailableError:
                    errors["base"] = "elm_unavailable"
                except Exception as err:
                    _LOGGER.error("Identity confirmation failed: %s", type(err).__name__)
                    errors["base"] = "cannot_connect"
                if not errors:
                    self._pending_identity_confirmation = None
                    return self.async_create_entry(
                        title=f"ČEZ PND ({mask_ean(pending[CONF_EAN])})",
                        data=confirmed,
                    )
        return self.async_show_form(
            step_id="identity_warning",
            data_schema=vol.Schema({
                vol.Required("confirm_unverified_identity", default=False): cv.boolean,
            }),
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
            new_password = str(user_input.get(CONF_PASSWORD, ""))
            test_config = _entry_client_config(
                entry,
                {CONF_PASSWORD: new_password},
            )

            if not credentials_within_length_limit(user_input):
                errors["base"] = "credentials_too_long"
            else:
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
                except PndElmUnavailableError:
                    errors["base"] = "elm_unavailable"
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

            if not credentials_within_length_limit(user_input):
                errors["base"] = "credentials_too_long"
            elif submitted_ean != existing_ean:
                errors["base"] = "cannot_change_ean"

            effective_config = _entry_client_config(entry)
            elm = str(user_input.get(CONF_ELM, effective_config.get(CONF_ELM, ""))).strip()
            scan_time = str(user_input.get(CONF_SCAN_TIME, effective_config.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME))).strip()

            if errors:
                pass
            elif not validate_elm(elm):
                errors["base"] = "invalid_elm"
            elif not validate_scan_time(scan_time):
                errors["base"] = "invalid_scan_time"
            else:
                updates = {
                    **user_input,
                    CONF_EAN: existing_ean,
                    CONF_ELM: elm,
                    CONF_SCAN_TIME: scan_time,
                    CONF_CLIENT_MODE: effective_config.get(CONF_CLIENT_MODE, DEFAULT_CLIENT_MODE),
                }
                updated_data = {**entry.data, **updates}
                # Remove stale options for edited fields so reload uses exactly
                # the values which passed credential validation.
                updated_options = {key: value for key, value in entry.options.items() if key not in updates}
                test_config = {**effective_config, **updates}
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
                except PndElmUnavailableError:
                    errors["base"] = "elm_unavailable"
                except PndMaintenanceError:
                    errors["base"] = "service_unavailable"
                except Exception as err:
                    _LOGGER.error("Reconfigure verification failed: %s", type(err).__name__)
                    errors["base"] = "cannot_connect"

                if not errors:
                    if hasattr(self, "async_update_reload_and_abort"):
                        return self.async_update_reload_and_abort(entry, data=updated_data, options=updated_options)
                    self.hass.config_entries.async_update_entry(entry, data=updated_data, options=updated_options)
                    return self.async_abort(reason="reconfigure_successful")

        current_data = _entry_client_config(entry) if entry else {}
        schema = vol.Schema({
            vol.Required(CONF_USERNAME, default=current_data.get(CONF_USERNAME, "")): vol.All(cv.string, vol.Length(max=MAX_CREDENTIAL_LENGTH)),
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
        self._pending_options: Dict[str, Any] = {}

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
        current_options = getattr(entry, "options", {})
        current_data = getattr(entry, "data", {})

        def get_val(key: str, default: Any = None) -> Any:
            return current_options.get(key, current_data.get(key, default))

        if user_input is not None:
            new_password = user_input.get(CONF_PASSWORD)
            scan_time = str(user_input.get(CONF_SCAN_TIME, DEFAULT_SCAN_TIME)).strip()
            debug_dir_val = user_input.get(CONF_DEBUG_DIR)
            debug_path_val = user_input.get("debug_path")

            if not credentials_within_length_limit(user_input):
                errors["base"] = "credentials_too_long"
            elif scan_time and not validate_scan_time(scan_time):
                errors["base"] = "invalid_scan_time"

            billing_start_val = user_input.get(CONF_BILLING_START_DATE)
            if billing_start_val and str(billing_start_val).strip():
                b_str = str(billing_start_val).strip()
                parsed_b = False
                for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d"):
                    try:
                        datetime.strptime(b_str, fmt)
                        parsed_b = True
                        break
                    except ValueError:
                        continue
                if not parsed_b:
                    errors[CONF_BILLING_START_DATE] = "invalid_billing_start_date"

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
                    new_pwd_clean = str(new_password)
                    test_config = _entry_client_config(
                        entry,
                        {**user_input, CONF_PASSWORD: new_pwd_clean},
                    )

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
                    except PndElmUnavailableError:
                        errors["base"] = "elm_unavailable"
                    except PndMaintenanceError:
                        errors["base"] = "service_unavailable"
                    except Exception as err:
                        _LOGGER.error("Password update verification failed: %s", type(err).__name__)
                        errors["base"] = "cannot_connect"

                if not errors:
                    self._pending_options = dict(user_input)
                    # An absent optional selector means "remove HDO", including
                    # when an older entry still has a tariff entity in data.
                    self._pending_options.setdefault(CONF_TARIFF_ENTITY, "")
                    if user_input.get(CONF_COST_TRACKING, False):
                        return await self.async_step_costs(user_input)
                    return self._save_options()

        schema = self._options_schema(get_val)

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
        )

    def _save_options(self, schedule: Optional[list[dict[str, Any]]] = None) -> FlowResult:
        """Commit options and any verified password only after the complete flow."""
        entry = self.entry
        clean_options = {k: v for k, v in self._pending_options.items() if k != CONF_PASSWORD}
        if not clean_options.get(CONF_COST_TRACKING, False):
            for key in (CONF_PRICE_SINGLE, CONF_PRICE_VT, CONF_PRICE_NT, CONF_PRICE_VALID_FROM):
                clean_options.pop(key, None)
        current_options = getattr(entry, "options", {})
        if schedule is not None:
            clean_options[CONF_PRICE_SCHEDULE] = schedule
            clean_options[CONF_PRICE_CURRENCY] = str(self.hass.config.currency).upper()
        elif CONF_PRICE_SCHEDULE in current_options:
            clean_options[CONF_PRICE_SCHEDULE] = current_options[CONF_PRICE_SCHEDULE]
            if CONF_PRICE_CURRENCY in current_options:
                clean_options[CONF_PRICE_CURRENCY] = current_options[CONF_PRICE_CURRENCY]
        password = self._pending_options.get(CONF_PASSWORD)
        if password and str(password).strip():
            self.hass.config_entries.async_update_entry(
                entry, data={**getattr(entry, "data", {}), CONF_PASSWORD: str(password)}
            )
        return self.async_create_entry(title="", data=clean_options)

    async def async_step_costs(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Show one price without HDO, or VT/NT prices with HDO."""
        current_options = getattr(self.entry, "options", {})
        has_hdo = bool(self._pending_options.get(CONF_TARIFF_ENTITY))
        previous_hdo = bool(
            current_options.get(
                CONF_TARIFF_ENTITY,
                getattr(self.entry, "data", {}).get(CONF_TARIFF_ENTITY),
            )
        )
        existing = list(current_options.get(CONF_PRICE_SCHEDULE, []))
        migrated, conflicts = migrate_single_tariff_schedule(existing) if not has_hdo else (existing, [])
        errors: Dict[str, str] = {}
        if user_input is not None:
            try:
                if has_hdo:
                    vt, nt = user_input.get(CONF_PRICE_VT), user_input.get(CONF_PRICE_NT)
                else:
                    vt = nt = user_input.get(CONF_PRICE_SINGLE)
                schedule = merge_price_period(
                    migrated,
                    valid_from=user_input.get(CONF_PRICE_VALID_FROM),
                    price_vt=vt,
                    price_nt=nt,
                    currency=str(self.hass.config.currency).upper(),
                )
                self._pending_options[CONF_PRICE_VALID_FROM] = user_input[CONF_PRICE_VALID_FROM]
                if has_hdo:
                    self._pending_options[CONF_PRICE_VT] = vt
                    self._pending_options[CONF_PRICE_NT] = nt
                    self._pending_options.pop(CONF_PRICE_SINGLE, None)
                else:
                    self._pending_options[CONF_PRICE_SINGLE] = vt
                    self._pending_options.pop(CONF_PRICE_VT, None)
                    self._pending_options.pop(CONF_PRICE_NT, None)
                return self._save_options(schedule)
            except PriceCurrencyMismatchError:
                errors["base"] = "price_currency_mismatch"
            except (PriceScheduleError, KeyError):
                errors["base"] = "invalid_price_settings"

        return self.async_show_form(
            step_id="costs",
            data_schema=self._cost_schema(
                has_hdo,
                lambda key: self._price_value(
                    current_options,
                    key,
                    prefer_vt_for_single=previous_hdo and not has_hdo,
                ),
            ),
            errors=errors,
            description_placeholders={"conflict_dates": ", ".join(conflicts) or "—"},
        )

    @staticmethod
    def _price_value(
        current_options: Dict[str, Any],
        key: str,
        *,
        prefer_vt_for_single: bool = False,
    ) -> Any:
        """Find a price; only an explicit HDO removal may suggest the VT price."""
        if key == CONF_PRICE_SINGLE and prefer_vt_for_single:
            schedule = current_options.get(CONF_PRICE_SCHEDULE, [])
            if schedule:
                latest = max(schedule, key=lambda period: str(period.get("valid_from", "")))
                return latest.get(CONF_PRICE_VT)
            return current_options.get(CONF_PRICE_VT)
        if key in current_options:
            return current_options[key]
        schedule = current_options.get(CONF_PRICE_SCHEDULE, [])
        if not schedule:
            return None
        latest = max(schedule, key=lambda period: str(period.get("valid_from", "")))
        if key == CONF_PRICE_VALID_FROM:
            return latest.get("valid_from")
        if key == CONF_PRICE_SINGLE:
            return single_tariff_price(latest.get("price_vt"), latest.get("price_nt"))
        return latest.get(key)

    def _options_schema(self, get_val: Any) -> vol.Schema:
        """Build one reactive options form for cost tracking and HDO mode."""
        fields: Dict[Any, Any] = {
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
                CONF_BILLING_START_DATE,
                description={"suggested_value": get_val(CONF_BILLING_START_DATE)},
            ): selector.DateSelector(selector.DateSelectorConfig()),
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
            vol.Optional(
                CONF_COST_TRACKING,
                default=get_val(CONF_COST_TRACKING, False),
            ): cv.boolean,
        }
        current_options = getattr(self.entry, "options", {})
        previous_hdo = bool(get_val(CONF_TARIFF_ENTITY))
        fields.update(
            self._cost_schema(
                False,
                lambda key: self._price_value(
                    current_options, key, prefer_vt_for_single=previous_hdo
                ),
                conditional=True,
            ).schema
        )
        return vol.Schema(fields)

    def _cost_schema(
        self, has_hdo: bool, get_val: Any, *, conditional: bool = False
    ) -> vol.Schema:
        """Build the price form appropriate to the selected tariff source."""
        currency = str(getattr(getattr(self.hass, "config", None), "currency", "CZK"))
        price_config = selector.NumberSelectorConfig(
            min=0, max=10000, step="any",
            mode=selector.NumberSelectorMode.BOX,
            unit_of_measurement=f"{currency.upper()}/kWh",
        )
        fields: Dict[Any, Any] = {}
        if conditional:
            tracking = {"field": CONF_COST_TRACKING, "value": True}
            hdo_present = {"field": CONF_TARIFF_ENTITY, "operator": "exists"}
            hdo_absent = {"field": CONF_TARIFF_ENTITY, "operator": "not_exists"}
            for key, condition in (
                (CONF_PRICE_SINGLE, hdo_absent),
                (CONF_PRICE_VT, hdo_present),
                (CONF_PRICE_NT, hdo_present),
            ):
                fields[vol.Optional(
                    key, description={"suggested_value": get_val(key)}
                )] = _ConditionalNumberSelector(
                    price_config,
                    {"condition": "and", "conditions": [tracking, condition]},
                )
            fields[vol.Optional(
                CONF_PRICE_VALID_FROM,
                description={"suggested_value": get_val(CONF_PRICE_VALID_FROM)},
            )] = _ConditionalDateSelector(
                selector.DateSelectorConfig(), tracking
            )
            return vol.Schema(fields)

        price_selector = selector.NumberSelector(price_config)
        if has_hdo:
            fields[vol.Optional(
                CONF_PRICE_VT, description={"suggested_value": get_val(CONF_PRICE_VT)}
            )] = price_selector
            fields[vol.Optional(
                CONF_PRICE_NT, description={"suggested_value": get_val(CONF_PRICE_NT)}
            )] = price_selector
        else:
            fields[vol.Optional(
                CONF_PRICE_SINGLE, description={"suggested_value": get_val(CONF_PRICE_SINGLE)}
            )] = price_selector
        fields[vol.Optional(
            CONF_PRICE_VALID_FROM,
            description={"suggested_value": get_val(CONF_PRICE_VALID_FROM)},
        )] = selector.DateSelector(selector.DateSelectorConfig())
        return vol.Schema(fields)
