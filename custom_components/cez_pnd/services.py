"""Services for CEZ Distribuce PND integration."""
from __future__ import annotations

from datetime import datetime
import logging
import re
from typing import Any, Dict

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
import homeassistant.helpers.config_validation as cv

from .const import (
    ATTR_DATE_RANGE,
    ATTR_EAN,
    DOMAIN,
    SERVICE_FETCH_DATA,
)
from .coordinator import CezPndCoordinator

_LOGGER = logging.getLogger(__name__)

FETCH_DATA_SCHEMA = vol.Schema({
    vol.Optional(ATTR_EAN): cv.string,
    vol.Optional(ATTR_DATE_RANGE): cv.string,
})


def validate_ean(ean: str) -> None:
    """Validate that EAN contains exactly 18 digits."""
    if not ean or not str(ean).strip() or not re.match(r"^\d{18}$", str(ean).strip()):
        raise ServiceValidationError(f"Neplatný formát EAN kódu '{ean}' (musí obsahovat přesně 18 číslic).")


def validate_date_range(date_range_str: str) -> None:
    """Validate date range string format and ensure <= 60 days."""
    if not date_range_str or not str(date_range_str).strip():
        raise ServiceValidationError("Parametr 'date_range' nesmí být prázdný.")

    match = re.match(r"^(\d{2}\.\d{2}\.\d{4})\s*-\s*(\d{2}\.\d{2}\.\d{4})$", date_range_str.strip())
    if not match:
        raise ServiceValidationError(
            f"Neplatný formát období '{date_range_str}'. Očekává se formát 'DD.MM.YYYY - DD.MM.YYYY'."
        )

    d1_str, d2_str = match.group(1), match.group(2)
    try:
        d1 = datetime.strptime(d1_str, "%d.%m.%Y")
        d2 = datetime.strptime(d2_str, "%d.%m.%Y")
    except ValueError as err:
        raise ServiceValidationError(f"Neplatné datum v období '{date_range_str}': {err}") from err

    if d1 > d2:
        raise ServiceValidationError(f"Počáteční datum {d1_str} nesmí být po koncovém datu {d2_str}.")

    days_diff = (d2 - d1).days
    if days_diff > 60:
        raise ServiceValidationError(
            f"Rozsah období nesmí překročit 60 dní (zadáno {days_diff} dní)."
        )


def _get_coordinator(hass: HomeAssistant, call: ServiceCall) -> CezPndCoordinator:
    """Find coordinator for a service call by EAN or pick the only configured one."""
    coords: list[CezPndCoordinator] = []
    if DOMAIN in hass.data:
        coords.extend([c for c in hass.data[DOMAIN].values() if isinstance(c, CezPndCoordinator)])

    if hasattr(hass, "config_entries"):
        for entry in hass.config_entries.async_entries(DOMAIN):
            coord = getattr(entry, "runtime_data", None)
            if isinstance(coord, CezPndCoordinator) and coord not in coords:
                coords.append(coord)

    if not coords:
        raise HomeAssistantError("No CEZ PND integrations configured")

    target_ean = call.data.get(ATTR_EAN)
    if target_ean:
        validate_ean(target_ean)
        for coord in coords:
            if coord.ean == target_ean:
                return coord
        raise HomeAssistantError(f"No CEZ PND integration found for EAN '{target_ean}'")

    if len(coords) == 1:
        return coords[0]

    raise HomeAssistantError(
        "Multiple CEZ PND integrations exist; please specify 'ean' parameter in service call"
    )


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register integration services."""

    async def handle_fetch_data(call: ServiceCall) -> None:
        """Handle fetch_data service."""
        target_ean = call.data.get(ATTR_EAN)
        if target_ean:
            validate_ean(target_ean)
        coordinator = _get_coordinator(hass, call)
        date_range = call.data.get(ATTR_DATE_RANGE)

        if date_range:
            validate_date_range(date_range)
            _LOGGER.info("Executing manual fetch_data for EAN %s with custom range '%s'", coordinator.masked_ean, date_range)
            await coordinator.async_fetch_range(date_range)
        else:
            _LOGGER.info("Executing manual refresh of yesterday's data for EAN %s", coordinator.masked_ean)
            await coordinator.async_request_refresh()

    if not hass.services.has_service(DOMAIN, SERVICE_FETCH_DATA):
        hass.services.async_register(
            DOMAIN,
            SERVICE_FETCH_DATA,
            handle_fetch_data,
            schema=FETCH_DATA_SCHEMA,
        )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unregister integration services if no entries remain."""
    has_active_entries = False
    if DOMAIN in hass.data and hass.data[DOMAIN]:
        has_active_entries = True
    elif hasattr(hass, "config_entries"):
        for entry in hass.config_entries.async_entries(DOMAIN):
            if getattr(entry, "runtime_data", None) is not None:
                has_active_entries = True
                break

    if not has_active_entries:
        if hass.services.has_service(DOMAIN, SERVICE_FETCH_DATA):
            hass.services.async_remove(DOMAIN, SERVICE_FETCH_DATA)
