"""Sensor platform for CEZ Distribuce PND."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, mask_ean
from .coordinator import CezPndCoordinator
from .models import SyncResult

PND_SENSOR_DESCRIPTIONS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="yesterday_consumption",
        name="Včerejší spotřeba",
        native_unit_of_measurement="kWh",
        device_class=SensorDeviceClass.ENERGY,
    ),
    SensorEntityDescription(
        key="yesterday_production",
        name="Včerejší výroba",
        native_unit_of_measurement="kWh",
        device_class=SensorDeviceClass.ENERGY,
    ),
    SensorEntityDescription(
        key="interval_consumption",
        name="Intervalová spotřeba",
        native_unit_of_measurement="kWh",
        device_class=SensorDeviceClass.ENERGY,
    ),
    SensorEntityDescription(
        key="interval_production",
        name="Intervalová výroba",
        native_unit_of_measurement="kWh",
        device_class=SensorDeviceClass.ENERGY,
    ),
    SensorEntityDescription(
        key="production_ratio",
        name="Pokrytí spotřeby výrobou",
        native_unit_of_measurement="%",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:percent",
    ),
    SensorEntityDescription(
        key="app_version",
        name="Verze PND aplikace",
        icon="mdi:check-decagram",
    ),
    SensorEntityDescription(
        key="sync_duration",
        name="Doba běhu synchronizace",
        native_unit_of_measurement="s",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up CEZ PND sensor entities from a config entry."""
    coordinator: CezPndCoordinator = (
        getattr(entry, "runtime_data", None)
        or hass.data[DOMAIN][entry.entry_id]
    )

    entities = [
        CezPndSensor(coordinator, entry, description)
        for description in PND_SENSOR_DESCRIPTIONS
    ]
    async_add_entities(entities)


class CezPndSensor(CoordinatorEntity[CezPndCoordinator], SensorEntity):
    """Representation of a CEZ PND sensor entity."""

    def __init__(
        self,
        coordinator: CezPndCoordinator,
        entry: ConfigEntry,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
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
    def native_value(self) -> Any:
        """Return native sensor value."""
        res: Optional[SyncResult] = self.coordinator.last_sync_result
        if not res:
            return None

        key = self.entity_description.key

        if key == "yesterday_consumption":
            if res.daily_summary:
                return res.daily_summary.total_consumption_kwh
            if res.intervals:
                return round(sum(r.consumption_kwh for r in res.intervals), 4)
            return None

        if key == "yesterday_production":
            if res.daily_summary:
                return res.daily_summary.total_production_kwh
            if res.intervals:
                return round(sum(r.production_kwh for r in res.intervals), 4)
            return None

        if key == "interval_consumption":
            if res.intervals:
                return round(sum(r.consumption_kwh for r in res.intervals), 4)
            return None

        if key == "interval_production":
            if res.intervals:
                return round(sum(r.production_kwh for r in res.intervals), 4)
            return None

        if key == "production_ratio":
            cons = 0.0
            prod = 0.0
            if res.daily_summary:
                cons = res.daily_summary.total_consumption_kwh
                prod = res.daily_summary.total_production_kwh
            elif res.intervals:
                cons = sum(r.consumption_kwh for r in res.intervals)
                prod = sum(r.production_kwh for r in res.intervals)

            if cons > 0:
                ratio = round((prod / cons) * 100.0, 2)
                return min(ratio, 100.0)
            return 0.0

        if key == "app_version":
            if res.daily_summary and res.daily_summary.app_version != "unknown":
                return res.daily_summary.app_version
            return self.coordinator.scraper.app_version or "unknown"

        if key == "sync_duration":
            return res.duration_seconds

        return None

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Return additional state attributes."""
        res: Optional[SyncResult] = self.coordinator.last_sync_result
        if not res:
            return {}

        key = self.entity_description.key
        attrs: Dict[str, Any] = {}

        if key in ("yesterday_consumption", "yesterday_production"):
            if res.daily_summary and res.daily_summary.date:
                attrs["date"] = res.daily_summary.date.strftime("%Y-%m-%d")

        if key == "production_ratio":
            cons = 0.0
            prod = 0.0
            if res.daily_summary:
                cons = res.daily_summary.total_consumption_kwh
                prod = res.daily_summary.total_production_kwh
            elif res.intervals:
                cons = sum(r.consumption_kwh for r in res.intervals)
                prod = sum(r.production_kwh for r in res.intervals)

            if cons > 0:
                full_ratio = round((prod / cons) * 100.0, 2)
                attrs["full_ratio"] = full_ratio
                attrs["floor_ratio"] = max(round(full_ratio - 100.0, 2), 0.0)
            else:
                attrs["full_ratio"] = 0.0
                attrs["floor_ratio"] = 0.0

        return attrs
