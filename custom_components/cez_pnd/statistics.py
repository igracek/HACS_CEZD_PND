"""Statistics manager for importing CEZ PND data into Home Assistant Recorder."""
import asyncio
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional

from homeassistant.components.recorder.models import (
    StatisticData,
    StatisticMetaData,
    StatisticMeanType,
)
try:
    from homeassistant.const import UnitOfEnergy
    UOM_KWH = UnitOfEnergy.KILO_WATT_HOUR
except (ImportError, AttributeError):
    UOM_KWH = "kWh"

from .client import (
    PndStatisticsError,
    PndStatisticsMonotonicityError,
    PndStatisticsQueryError,
)
from .const import (
    DOMAIN,
    STATISTIC_CONSUMPTION,
    STATISTIC_CONSUMPTION_VT,
    STATISTIC_CONSUMPTION_NT,
    STATISTIC_PREFIX,
    STATISTIC_PRODUCTION,
    mask_ean,
)
from .models import IntervalRecord, ParsedPndData

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "PndStatisticsManager",
    "PndStatisticsError",
    "PndStatisticsQueryError",
    "PndStatisticsMonotonicityError",
]

REQUIRED_INTERVALS_PER_HOUR = 4


def _normalize_datetime(dt_val: Any) -> datetime:
    """Normalize datetime or timestamp to UTC-aware datetime."""
    if isinstance(dt_val, (int, float)):
        return datetime.fromtimestamp(dt_val, tz=timezone.utc)
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            try:
                import homeassistant.util.dt as dt_util
                return dt_util.as_utc(dt_val)
            except Exception:
                return dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)
    raise ValueError(f"Invalid datetime value: {dt_val!r}")


class PndStatisticsManager:
    """Manages long-term external statistics for CEZ PND in HA Recorder."""

    def __init__(self, hass: Any, ean: str) -> None:
        """Initialize statistics manager for a given EAN."""
        self.hass = hass
        self.ean = ean

    def _get_statistic_id(self, stat_type: str) -> str:
        """Return the formatted statistic ID."""
        return f"{STATISTIC_PREFIX}:{self.ean}_{stat_type}"

    async def _async_get_baseline_sum(self, statistic_id: str, before_time: datetime) -> float:
        """Fetch cumulative sum from Recorder immediately preceding before_time without 30-day or year 2000 limit."""
        norm_before = _normalize_datetime(before_time) if before_time else None
        try:
            from homeassistant.components.recorder import get_instance
            from homeassistant.components.recorder.statistics import statistics_during_period

            instance = get_instance(self.hass)
            start_search = datetime(1970, 1, 1, tzinfo=timezone.utc)
            end_search = norm_before - timedelta(microseconds=1) if norm_before else None
            stats = await instance.async_add_executor_job(
                statistics_during_period,
                self.hass,
                start_search,
                end_search,
                {statistic_id},
                "hour",
                None,
                {"sum"},
            )
            if stats and statistic_id in stats and stats[statistic_id]:
                last_entry = stats[statistic_id][-1]
                entry_sum = last_entry.get("sum") if isinstance(last_entry, dict) else getattr(last_entry, "sum", None)
                if entry_sum is not None:
                    return float(entry_sum)
            return 0.0
        except ImportError as err:
            _LOGGER.debug(
                "Recorder module not available for baseline query %s before %s: %s",
                statistic_id,
                norm_before,
                err,
            )
            return 0.0
        except Exception as err:
            _LOGGER.error(
                "Chyba při dotazu na baseline statistiky pro %s: %s",
                statistic_id,
                type(err).__name__,
            )
            raise PndStatisticsQueryError(
                f"Chyba při dotazu na baseline statistiky pro {statistic_id}: {type(err).__name__}"
            ) from err

    async def _async_get_existing_statistics(
        self, statistic_id: str, start_time: datetime, end_time: Optional[datetime] = None
    ) -> List[Any]:
        """Fetch existing statistics for given period from Recorder fail-closed."""
        norm_start = _normalize_datetime(start_time)
        norm_end = _normalize_datetime(end_time) if end_time is not None else None
        try:
            from homeassistant.components.recorder import get_instance
            from homeassistant.components.recorder.statistics import statistics_during_period

            instance = get_instance(self.hass)
            stats = await instance.async_add_executor_job(
                statistics_during_period,
                self.hass,
                norm_start,
                norm_end,
                {statistic_id},
                "hour",
                None,
                {"sum", "state"},
            )
            if stats and statistic_id in stats and stats[statistic_id]:
                return list(stats[statistic_id])
            return []
        except ImportError as err:
            _LOGGER.debug(
                "Recorder module not available for existing statistics query %s: %s",
                statistic_id,
                err,
            )
            return []
        except Exception as err:
            _LOGGER.error(
                "Chyba při dotazu na existující statistiky pro %s: %s",
                statistic_id,
                type(err).__name__,
            )
            raise PndStatisticsQueryError(
                f"Chyba při dotazu na existující statistiky pro {statistic_id}: {type(err).__name__}"
            ) from err

    async def async_import(self, parsed_data: ParsedPndData) -> None:
        """Import all parsed interval records into HA Recorder statistics."""
        if not parsed_data.intervals:
            _LOGGER.debug("No interval records to import into statistics for EAN %s", mask_ean(self.ean))
            return

        intervals = sorted(parsed_data.intervals, key=lambda r: r.start_time)
        masked = mask_ean(self.ean)

        # Definitions of the 4 statistic streams
        stat_configs = [
            (
                STATISTIC_CONSUMPTION,
                f"ČEZ PND Celková spotřeba ({masked})",
                lambda r: r.consumption_kwh,
                lambda r: r.is_valid_consumption,
            ),
            (
                STATISTIC_CONSUMPTION_VT,
                f"ČEZ PND Spotřeba VT ({masked})",
                lambda r: r.consumption_kwh if r.is_vt else 0.0,
                lambda r: r.is_valid_consumption,
            ),
            (
                STATISTIC_CONSUMPTION_NT,
                f"ČEZ PND Spotřeba NT ({masked})",
                lambda r: r.consumption_kwh if not r.is_vt else 0.0,
                lambda r: r.is_valid_consumption,
            ),
            (
                STATISTIC_PRODUCTION,
                f"ČEZ PND Výroba / Dodávka ({masked})",
                lambda r: r.production_kwh,
                lambda r: r.is_valid_production,
            ),
        ]

        for stat_key, stat_name, delta_fn, validity_fn in stat_configs:
            stat_id = self._get_statistic_id(stat_key)
            await self._async_import_single_statistic(
                stat_id, stat_name, intervals, delta_fn, validity_fn=validity_fn
            )

    async def _async_import_single_statistic(
        self,
        statistic_id: str,
        name: str,
        intervals: List[IntervalRecord],
        delta_fn: Any,
        validity_fn: Optional[Any] = None,
    ) -> None:
        """Import single statistic stream with deterministic hourly aggregation, baseline sum, merge, and backfill shift."""
        if not intervals:
            return

        # 1. Deterministic aggregation of valid 15-minute intervals into 1-hour UTC buckets
        hourly_deltas: Dict[datetime, float] = {}
        hourly_interval_counts: Dict[datetime, int] = {}
        for record in intervals:
            # Skip invalid intervals for this specific statistic stream
            if validity_fn is not None and not validity_fn(record):
                _LOGGER.debug(
                    "Skipping invalid interval %s for statistic %s",
                    record.start_time,
                    statistic_id,
                )
                continue

            r_dt = _normalize_datetime(record.start_time)
            hour_dt = r_dt.replace(minute=0, second=0, microsecond=0)
            delta = float(delta_fn(record))
            hourly_deltas[hour_dt] = round(hourly_deltas.get(hour_dt, 0.0) + delta, 6)
            hourly_interval_counts[hour_dt] = hourly_interval_counts.get(hour_dt, 0) + 1

        # Completeness policy: omit hours with != 4 valid intervals
        incomplete_hours = [
            h for h, count in hourly_interval_counts.items()
            if count != REQUIRED_INTERVALS_PER_HOUR
        ]
        for h in incomplete_hours:
            _LOGGER.warning(
                "Omitting incomplete hour %s for statistic %s: "
                "got %d valid intervals, required %d",
                h.isoformat(), statistic_id,
                hourly_interval_counts[h], REQUIRED_INTERVALS_PER_HOUR,
            )
            del hourly_deltas[h]

        if not hourly_deltas:
            return

        sorted_batch_hours = sorted(hourly_deltas.keys())
        min_start_dt = sorted_batch_hours[0]
        max_start_dt = sorted_batch_hours[-1]

        # 2. Fetch existing statistics in the batch window [min_start_dt, max_start_dt]
        prev_batch_stats = await self._async_get_existing_statistics(statistic_id, min_start_dt, max_start_dt)

        # 3. Fetch baseline sum strictly preceding this batch window
        base_sum = await self._async_get_baseline_sum(statistic_id, min_start_dt)

        # 4. Build lookup maps for new records and existing points in the window, deriving state if missing
        sorted_existing = []
        for point in prev_batch_stats:
            p_start = point.get("start") if isinstance(point, dict) else getattr(point, "start", None)
            if p_start is None:
                continue
            p_dt = _normalize_datetime(p_start).replace(minute=0, second=0, microsecond=0)
            p_state = point.get("state") if isinstance(point, dict) else getattr(point, "state", None)
            p_sum = point.get("sum") if isinstance(point, dict) else getattr(point, "sum", None)
            sorted_existing.append((p_dt, p_state, p_sum))

        sorted_existing.sort(key=lambda x: x[0])

        existing_deltas: Dict[datetime, float] = {}
        prev_sum_map: Dict[datetime, float] = {}
        running_prev_sum = base_sum

        for p_dt, p_state, p_sum in sorted_existing:
            if p_sum is not None:
                p_sum_f = float(p_sum)
                prev_sum_map[p_dt] = p_sum_f
                if p_state is not None:
                    existing_deltas[p_dt] = float(p_state)
                else:
                    # Derive state from sum delta: sum - running_prev_sum
                    derived_state = max(0.0, p_sum_f - running_prev_sum)
                    existing_deltas[p_dt] = round(derived_state, 6)
                running_prev_sum = p_sum_f
            elif p_state is not None:
                p_state_f = float(p_state)
                existing_deltas[p_dt] = p_state_f
                running_prev_sum += p_state_f
                prev_sum_map[p_dt] = running_prev_sum

        # All distinct hourly timestamps in window in chronological order
        all_timestamps = sorted(set(hourly_deltas.keys()) | set(existing_deltas.keys()))

        stats_payload: List[Dict[str, Any]] = []
        current_sum = base_sum

        for dt in all_timestamps:
            # New batch data takes precedence over existing data for identical hourly timestamp
            if dt in hourly_deltas:
                state_val = hourly_deltas[dt]
            else:
                state_val = existing_deltas[dt]

            current_sum += state_val
            stats_payload.append({
                "start": dt,
                "state": round(state_val, 4),
                "sum": round(current_sum, 4),
            })

        batch_final_sum = current_sum
        batch_delta = current_sum - base_sum

        # 5. Determine delta shift for subsequent points (T > max_start_dt)
        if prev_batch_stats:
            last_prev_entry = prev_batch_stats[-1]
            prev_sum = last_prev_entry.get("sum") if isinstance(last_prev_entry, dict) else getattr(last_prev_entry, "sum", None)
            delta_shift = round(batch_final_sum - (float(prev_sum) if prev_sum is not None else base_sum), 4)
        else:
            delta_shift = round(batch_delta, 4)

        # 6. Fetch subsequent points and shift their sums if delta_shift != 0
        effective_max_dt = all_timestamps[-1] if all_timestamps else max_start_dt
        shifted_subsequent_objects: List[StatisticData] = []
        if abs(delta_shift) > 1e-6:
            subsequent_stats = await self._async_get_existing_statistics(
                statistic_id, effective_max_dt + timedelta(seconds=1), None
            )
            for point in subsequent_stats:
                p_start = point.get("start") if isinstance(point, dict) else getattr(point, "start", None)
                p_state = point.get("state") if isinstance(point, dict) else getattr(point, "state", None)
                p_sum = point.get("sum") if isinstance(point, dict) else getattr(point, "sum", None)
                if p_start is not None and p_sum is not None:
                    p_dt = _normalize_datetime(p_start).replace(minute=0, second=0, microsecond=0)
                    shifted_subsequent_objects.append(
                        StatisticData(
                            start=p_dt,
                            state=p_state,
                            sum=round(float(p_sum) + delta_shift, 4),
                        )
                    )

        statistic_data_objects = [
            StatisticData(
                start=p["start"],
                state=p["state"],
                sum=p["sum"],
            )
            for p in stats_payload
        ]
        statistic_data_objects.extend(shifted_subsequent_objects)

        # 7. Monotonicity and non-negative delta validation
        prev_valid_sum = base_sum
        for obj in statistic_data_objects:
            obj_sum = obj.get("sum") if isinstance(obj, dict) else getattr(obj, "sum", None)
            obj_state = obj.get("state") if isinstance(obj, dict) else getattr(obj, "state", None)
            obj_start = obj.get("start") if isinstance(obj, dict) else getattr(obj, "start", None)

            if obj_state is not None and float(obj_state) < -1e-6:
                raise PndStatisticsMonotonicityError(
                    f"Neplatná záporná hodnota delta ({obj_state}) pro statistiku {statistic_id} v čase {obj_start}"
                )

            if obj_sum is not None:
                obj_sum_f = float(obj_sum)
                if obj_sum_f < prev_valid_sum - 1e-6:
                    raise PndStatisticsMonotonicityError(
                        f"Porušení monotónnosti pro statistiku {statistic_id} v čase {obj_start}: sum {obj_sum_f} < prev_sum {prev_valid_sum}"
                    )
                prev_valid_sum = obj_sum_f

        # 8. Import into HA Recorder via async_add_external_statistics
        try:
            from homeassistant.components.recorder.statistics import async_add_external_statistics

            metadata = StatisticMetaData(
                has_sum=True,
                mean_type=StatisticMeanType.NONE,
                name=name,
                source=DOMAIN,
                statistic_id=statistic_id,
                unit_class="energy",
                unit_of_measurement=UOM_KWH,
            )

            async_add_external_statistics(self.hass, metadata, statistic_data_objects)
            min_t = stats_payload[0]["start"] if stats_payload else None
            max_t = stats_payload[-1]["start"] if stats_payload else None
            min_str = min_t.strftime("%Y-%m-%d %H:%M") if hasattr(min_t, "strftime") else str(min_t)
            max_str = max_t.strftime("%Y-%m-%d %H:%M") if hasattr(max_t, "strftime") else str(max_t)

            _LOGGER.info(
                "Statistiky %s: importováno %d bodů (%d v dávce, %d posunutých následných), okno %s -> %s, delta: %.4f kWh, base_sum: %.4f kWh -> nová suma: %.4f kWh (posun: %.4f kWh).",
                statistic_id,
                len(statistic_data_objects),
                len(stats_payload),
                len(shifted_subsequent_objects),
                min_str,
                max_str,
                batch_delta,
                base_sum,
                batch_final_sum,
                delta_shift,
            )

        except (ImportError, AttributeError) as err:
            _LOGGER.debug(
                "HA recorder async_add_external_statistics not loaded (mocked/test mode): %s", err
            )
            if hasattr(self.hass, "async_add_external_statistics") and callable(self.hass.async_add_external_statistics):
                res = self.hass.async_add_external_statistics(statistic_id, stats_payload)
                if asyncio.iscoroutine(res):
                    await res
            elif hasattr(self.hass, "async_import_statistics") and callable(self.hass.async_import_statistics):
                res = self.hass.async_import_statistics(statistic_id, stats_payload)
                if asyncio.iscoroutine(res):
                    await res
        except Exception as err:
            _LOGGER.error(
                "Chyba při volání async_add_external_statistics pro %s: %s",
                statistic_id,
                type(err).__name__,
            )
            raise PndStatisticsError(f"Chyba při importu statistik pro {statistic_id}: {type(err).__name__}") from err
