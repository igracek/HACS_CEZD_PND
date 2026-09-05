"""Data models for CEZ Distribuce PND integration."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class IntervalRecord:
    """Represents a single 15-minute measurement interval."""

    start_time: datetime
    end_time: datetime
    consumption_kwh: float  # Value from profile +A
    production_kwh: float = 0.0  # Value from profile -A
    is_vt: bool = True  # True = High Tariff (VT), False = Low Tariff (NT)
    is_valid: bool = True
    is_valid_consumption: bool = True
    is_valid_production: bool = True

    def __post_init__(self) -> None:
        """Enforce combined validity invariant: False if any stream is invalid."""
        if not self.is_valid_consumption or not self.is_valid_production:
            self.is_valid = False


@dataclass
class DailySummary:
    """Represents aggregated daily summary."""

    date: datetime
    total_consumption_kwh: float
    total_production_kwh: float = 0.0
    consumption_vt_kwh: float = 0.0
    consumption_nt_kwh: float = 0.0
    vt_ratio_percent: float = 100.0
    app_version: str = "unknown"


@dataclass
class ParsedPndData:
    """Container for parsed CSV data."""

    intervals: List[IntervalRecord] = field(default_factory=list)
    daily_summary: Optional[DailySummary] = None
    detected_encoding: str = "unknown"
    total_rows: int = 0
    invalid_rows_count: int = 0
    duplicate_rows_count: int = 0


@dataclass
class SyncResult:
    """Result of a complete synchronization run."""

    intervals: List[IntervalRecord] = field(default_factory=list)
    daily_summary: Optional[DailySummary] = None
    duration_seconds: float = 0.0
    status: str = "OK"
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    records_count: int = 0
    debug_artifacts_created: List[str] = field(default_factory=list)
