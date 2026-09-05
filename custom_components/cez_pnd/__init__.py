"""The CEZ Distribuce PND integration."""
from __future__ import annotations

import asyncio
from enum import Enum, auto
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PLATFORMS
from .coordinator import CezPndCoordinator
from .services import async_setup_services, async_unload_services

_LOGGER = logging.getLogger(__name__)

type CezPndConfigEntry = ConfigEntry[CezPndCoordinator]


class SetupStage(Enum):
    """Lifecycle stages of config entry setup for precise rollback tracking (SEC10-R02)."""

    COORDINATOR_REGISTERED = auto()
    SCHEDULE_CONFIGURED = auto()
    PLATFORMS_FORWARDED = auto()
    SERVICES_REGISTERED = auto()


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up the CEZ Distribuce PND component."""
    await async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up CEZ Distribuce PND from a config entry (HA 2026.8+ lifecycle)."""
    coordinator = CezPndCoordinator(hass, entry)
    entry.runtime_data = coordinator

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    schedule_configured = False
    platforms_forwarded = False

    try:
        # První inicializační refresh - vyvolá ConfigEntryAuthFailed při selhání autentizace (SEC04-05, SEC05-07)
        await coordinator.async_config_entry_first_refresh()

        coordinator.setup_daily_schedule()
        schedule_configured = True

        platforms_forwarded = True
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

        await async_setup_services(hass)

        entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    except (Exception, BaseException):
        # SEC10-R02: Unwind acquired resources strictly in reverse order of acquisition.
        # 1. Unload services if no active entries remain.
        try:
            await async_unload_services(hass)
        except Exception as svc_err:
            _LOGGER.debug("Error during rollback unloading services: %s", svc_err)

        # 2. Only unload platforms if platform forwarding was initiated/attempted.
        # If first refresh failed, platforms were never forwarded; calling async_unload_platforms
        # causes secondary errors ("Config entry was never loaded!").
        if platforms_forwarded:
            if hasattr(hass, "config_entries") and hasattr(hass.config_entries, "async_unload_platforms"):
                try:
                    res = hass.config_entries.async_unload_platforms(entry, PLATFORMS)
                    if asyncio.iscoroutine(res) or hasattr(res, "__await__"):
                        await res
                except Exception as unload_err:
                    _LOGGER.debug("Error during rollback unloading platforms: %s", unload_err)

        # 3. Cancel schedule if it was configured.
        if schedule_configured:
            coordinator.cancel_schedule()

        # 4. Remove coordinator registration and clear runtime_data.
        if DOMAIN in hass.data and entry.entry_id in hass.data[DOMAIN]:
            hass.data[DOMAIN].pop(entry.entry_id, None)
            if not hass.data[DOMAIN]:
                hass.data.pop(DOMAIN, None)
        if hasattr(entry, "runtime_data"):
            entry.runtime_data = None

        raise

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        coordinator: CezPndCoordinator = (
            getattr(entry, "runtime_data", None)
            or hass.data.get(DOMAIN, {}).get(entry.entry_id)
        )
        if coordinator is not None:
            coordinator.cancel_schedule()

        if DOMAIN in hass.data and entry.entry_id in hass.data[DOMAIN]:
            hass.data[DOMAIN].pop(entry.entry_id, None)
            if not hass.data[DOMAIN]:
                hass.data.pop(DOMAIN, None)

        await async_unload_services(hass)

        if hasattr(entry, "runtime_data"):
            entry.runtime_data = None

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
