"""Tariff evaluator for splitting CEZ PND intervals into VT and NT."""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from .models import IntervalRecord

_LOGGER = logging.getLogger(__name__)

VT_STATES = {"on", "true", "1", "vt", "high"}
NT_STATES = {"off", "false", "0", "nt", "low"}


class TariffEvaluator:
    """Evaluates High (VT) and Low (NT) tariffs for 15-minute interval records."""

    def __init__(self, hass: Any, tariff_entity: Optional[str]) -> None:
        """Initialize tariff evaluator."""
        self.hass = hass
        self.tariff_entity = tariff_entity.strip() if tariff_entity else None
        self.last_history_state_changes_count: int = 0
        self.last_fallback_used: bool = False
        self.last_vt_ratio_percent: float = 100.0
        self.last_vt_kwh: float = 0.0
        self.last_nt_kwh: float = 0.0

    async def async_evaluate(self, intervals: List[IntervalRecord]) -> None:
        """Evaluate and assign is_vt flag to each interval record."""
        if not intervals:
            return

        # Check entity in HA State Machine
        if self.tariff_entity and hasattr(self.hass, "states") and self.hass.states:
            state = self.hass.states.get(self.tariff_entity)
            if state is None:
                _LOGGER.info("VT/NT entita '%s' nebyla nalezena ve stavovém registru Home Assistantu", self.tariff_entity)
            else:
                _LOGGER.debug("VT/NT entita '%s' nalezena v HA ve stavu '%s'", self.tariff_entity, state.state)

        if not self.tariff_entity:
            _LOGGER.debug("No tariff entity configured; assigning all intervals to VT (High Tariff)")
            for record in intervals:
                record.is_vt = True
            total_kwh = sum(r.consumption_kwh for r in intervals)
            self.last_vt_kwh = round(total_kwh, 4)
            self.last_nt_kwh = 0.0
            self.last_vt_ratio_percent = 100.0
            self.last_fallback_used = False
            self.last_history_state_changes_count = 0
            return

        try:
            # Query history from recorder
            min_start = min(r.start_time for r in intervals)
            max_end = max(r.end_time for r in intervals)

            # Ensure UTC / timezone handling if needed
            state_history = await self._async_get_entity_history(min_start, max_end)
            if not state_history:
                _LOGGER.info(
                    "VT/NT entita '%s' nemá v Recorderu žádnou historii pro cílové období (%s -> %s); aplikován bezpečný fallback (100 %% alokováno do VT).",
                    self.tariff_entity,
                    min_start,
                    max_end,
                )
                self.last_fallback_used = True
                self.last_history_state_changes_count = 0
                for record in intervals:
                    record.is_vt = True
                total_kwh = sum(r.consumption_kwh for r in intervals)
                self.last_vt_kwh = round(total_kwh, 4)
                self.last_nt_kwh = 0.0
                self.last_vt_ratio_percent = 100.0
                return

            # Classify intervals based on states
            self._classify_intervals(intervals, state_history)

            # Compute diagnostic metrics
            total_kwh = sum(r.consumption_kwh for r in intervals)
            vt_kwh = sum(r.consumption_kwh for r in intervals if r.is_vt)
            nt_kwh = sum(r.consumption_kwh for r in intervals if not r.is_vt)
            vt_ratio = (vt_kwh / total_kwh * 100.0) if total_kwh > 0 else 100.0

            self.last_vt_kwh = round(vt_kwh, 4)
            self.last_nt_kwh = round(nt_kwh, 4)
            self.last_vt_ratio_percent = round(vt_ratio, 1)
            self.last_history_state_changes_count = len(state_history)
            self.last_fallback_used = False

            _LOGGER.debug(
                "VT/NT evaluace pro entitu '%s' dokončena: %d intervalů, historie: %d stavových změn (%s -> %s). "
                "Výsledek: VT = %.4f kWh (%.1f %%), NT = %.4f kWh (%.1f %%)",
                self.tariff_entity,
                len(intervals),
                len(state_history),
                min_start,
                max_end,
                vt_kwh,
                vt_ratio,
                nt_kwh,
                100.0 - vt_ratio,
            )

        except Exception as err:
            _LOGGER.warning(
                "Error evaluating VT/NT tariff history for %s: %s; falling back to VT",
                self.tariff_entity,
                err,
            )
            self.last_fallback_used = True
            for record in intervals:
                record.is_vt = True

    async def _async_get_entity_history(
        self, start_time: datetime, end_time: datetime
    ) -> List[Any]:
        """Fetch state changes from Home Assistant recorder history."""
        try:
            from homeassistant.components.recorder import get_instance, history

            def _get_history():
                return history.state_changes_during_period(
                    self.hass,
                    start_time=start_time,
                    end_time=end_time,
                    entity_id=self.tariff_entity,
                    include_start_time_state=True,
                    no_attributes=True,
                )

            instance = get_instance(self.hass)
            history_data = await instance.async_add_executor_job(_get_history)
            if history_data and self.tariff_entity in history_data:
                return history_data[self.tariff_entity]
        except (ImportError, AttributeError) as err:
            _LOGGER.debug("Recorder history module not available or mocked: %s", err)
            # Check if hass.data or mock has history helper
            if hasattr(self.hass, "async_get_history"):
                return await self.hass.async_get_history(self.tariff_entity, start_time, end_time)
        return []

    def _classify_intervals(
        self, intervals: List[IntervalRecord], states: List[Any]
    ) -> None:
        """Classify each interval into VT or NT based on state timestamps."""
        # Convert state timestamps to comparable objects
        parsed_states = []
        for s in states:
            state_val = str(getattr(s, "state", s)).lower()
            last_updated = getattr(s, "last_updated", None)
            if last_updated is None:
                last_updated = getattr(s, "last_changed", None)

            # If last_updated is timezone-aware and intervals are naive, normalize
            if isinstance(last_updated, datetime) and last_updated.tzinfo is not None:
                last_updated = last_updated.astimezone().replace(tzinfo=None)

            parsed_states.append((last_updated, state_val))

        parsed_states.sort(key=lambda x: x[0] if x[0] else datetime.min)

        for record in intervals:
            st = record.start_time
            et = record.end_time
            interval_duration = (et - st).total_seconds()
            if interval_duration <= 0:
                record.is_vt = True
                continue

            # Determine initial state at start_time
            current_state = "unknown"
            for state_time, state_val in parsed_states:
                if state_time is None or state_time <= st:
                    current_state = state_val
                else:
                    break

            # Calculate time spent in each state within [st, et]
            cursor = st
            vt_seconds = 0.0
            nt_seconds = 0.0

            for state_time, state_val in parsed_states:
                if state_time is None or state_time <= st:
                    continue
                if state_time >= et:
                    break

                # Segment from cursor to state_time
                segment_len = (state_time - cursor).total_seconds()
                if current_state in VT_STATES:
                    vt_seconds += segment_len
                elif current_state in NT_STATES:
                    nt_seconds += segment_len
                else:
                    # Default unknown to VT
                    vt_seconds += segment_len

                cursor = state_time
                current_state = state_val

            # Remaining segment from cursor to et
            segment_len = (et - cursor).total_seconds()
            if current_state in VT_STATES:
                vt_seconds += segment_len
            elif current_state in NT_STATES:
                nt_seconds += segment_len
            else:
                vt_seconds += segment_len

            # Classify: majority rule (or fallback to VT)
            record.is_vt = (vt_seconds >= nt_seconds)
