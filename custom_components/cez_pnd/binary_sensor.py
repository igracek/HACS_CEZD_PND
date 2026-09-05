"""Binary sensor platform for CEZ Distribuce PND."""
from __future__ import annotations

from typing import Any, Dict, Optional

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, mask_ean
from .coordinator import CezPndCoordinator
from .models import SyncResult

PND_BINARY_SENSOR_DESCRIPTIONS: tuple[BinarySensorEntityDescription, ...] = (
    BinarySensorEntityDescription(
        key="running",
        name="Synchronizace PND běží",
        device_class=BinarySensorDeviceClass.RUNNING,
    ),
    BinarySensorEntityDescription(
        key="status",
        name="Stav připojení ČEZ PND",
        device_class=BinarySensorDeviceClass.PROBLEM,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up CEZ PND binary sensor entities from a config entry."""
    coordinator: CezPndCoordinator = (
        getattr(entry, "runtime_data", None)
        or hass.data[DOMAIN][entry.entry_id]
    )

    entities = [
        CezPndBinarySensor(coordinator, entry, description)
        for description in PND_BINARY_SENSOR_DESCRIPTIONS
    ]
    async_add_entities(entities)


class CezPndBinarySensor(CoordinatorEntity[CezPndCoordinator], BinarySensorEntity):
    """Representation of a CEZ PND binary sensor."""

    def __init__(
        self,
        coordinator: CezPndCoordinator,
        entry: ConfigEntry,
        description: BinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._ean = coordinator.ean
        self._attr_unique_id = f"{coordinator.ean}_{description.key}"
        self._attr_has_entity_name = True

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._ean)},
            name=f"ČEZ Elektroměr ({mask_ean(self._ean)})",
            manufacturer="ČEZ Distribuce, a. s.",
            model="Portál Naměřených Dat (PND)",
            configuration_url="https://pnd.cezdistribuce.cz",
        )

    @property
    def is_on(self) -> Optional[bool]:
        """Return true if the binary sensor is on."""
        key = self.entity_description.key

        if key == "running":
            return self.coordinator.is_running

        if key == "status":
            # Problem class: on means problem/error
            res: Optional[SyncResult] = self.coordinator.last_sync_result
            if res is None:
                return False
            return res.status != "OK"

        return False

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Return binary sensor extra state attributes."""
        res: Optional[SyncResult] = self.coordinator.last_sync_result
        attrs: Dict[str, Any] = {}

        if self.entity_description.key == "status" and res is not None:
            attrs["status"] = res.status
            if res.error_message:
                attrs["error_message"] = res.error_message
            if res.error_code:
                attrs["error_code"] = res.error_code
            attrs["last_duration_seconds"] = res.duration_seconds
            attrs["records_count"] = res.records_count

        return attrs
