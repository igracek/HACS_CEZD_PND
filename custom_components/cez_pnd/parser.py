"""CSV parser for CEZ Distribuce PND measurement reports."""
import csv
from datetime import datetime, timedelta
from enum import Enum
import logging
import math
import os
import stat
from typing import Any, Dict, Final, Iterator, List, Optional, Set, Tuple, Union

from .client import PndParseError, PndParserError
from .fd_security import (
    SealedReport,
    SnapshotError,
    bounded_sealed_snapshot,
    close_sealed_reports,
    verify_sealed_fd,
)
from .models import DailySummary, IntervalRecord, ParsedPndData

_LOGGER = logging.getLogger(__name__)

MAX_CSV_FILE_SIZE: Final = 5 * 1024 * 1024  # 5 MB
MAX_CSV_ROWS: Final = 10000
MAX_CSV_COLS: Final = 50
MAX_CELL_LENGTH: Final = 128

ALLOWED_CSV_FILES: Final[Set[str]] = {
    "range-consumption.csv",
    "range_consumption.csv",
    "range_consumption_sample.csv",
    "range_consumption_with_na.csv",
    "range-production.csv",
    "range_production.csv",
    "range_production_sample.csv",
    "range_production_with_na.csv",
    "daily-consumption.csv",
    "daily_consumption.csv",
    "daily_consumption_sample.csv",
    "daily_consumption_with_na.csv",
    "daily-production.csv",
    "daily_production.csv",
    "daily_production_sample.csv",
    "daily_registers_with_na.csv",
    "pnd_export.csv",
    "pnd_export_1.csv",
    "pnd_export_1_.csv",
}


PLUS_PROFILE_KEYWORDS: Final[Tuple[str, ...]] = ("+a", "+e", "spotřeb", "spotreb", "odběr", "odber")
MINUS_PROFILE_KEYWORDS: Final[Tuple[str, ...]] = ("-a", "-e", "výrob", "vyrob", "dodávk", "dodavk")
DATE_HEADER_KEYWORDS: Final[Tuple[str, ...]] = ("datum", "date", "cas", "čas")
STATUS_HEADER_KEYWORDS: Final[Tuple[str, ...]] = ("status", "stav", "valid", "validita")


class StatusSemantic(str, Enum):
    """Semantic classification of measurement interval/daily status."""

    VALID = "valid"
    PLACEHOLDER = "placeholder"
    INVALID = "invalid"
    UNKNOWN = "unknown"


REPORT_TYPE_INTERVAL_CONSUMPTION: Final = "interval_consumption"
REPORT_TYPE_INTERVAL_PRODUCTION: Final = "interval_production"
REPORT_TYPE_DAILY_CONSUMPTION: Final = "daily_consumption"
REPORT_TYPE_DAILY_PRODUCTION: Final = "daily_production"
REPORT_TYPE_DAILY_REGISTERS: Final = "daily_registers"

SUPPORTED_REPORT_TYPES: Final[Tuple[str, ...]] = (
    REPORT_TYPE_INTERVAL_CONSUMPTION,
    REPORT_TYPE_INTERVAL_PRODUCTION,
    REPORT_TYPE_DAILY_CONSUMPTION,
    REPORT_TYPE_DAILY_PRODUCTION,
    REPORT_TYPE_DAILY_REGISTERS,
)

VALID_STATUSES: Final[Set[str]] = {
    "platna",
    "platná",
    "platna data",
    "platná data",
    "naměřená data ok",
    "namerena data ok",
    "ok",
    "valid",
    "platné",
    "platne",
}

PLACEHOLDER_STATUSES: Final[Set[str]] = {
    "neznámá hodnota",
    "neznama hodnota",
    "neznámá",
    "neznama",
    "neznámé",
    "nezname",
    "nedostupná data",
    "nedostupna data",
    "nedostupná",
    "nedostupna",
    "unknown",
    "unavailable",
    "n/a",
    "na",
    "n.a.",
    "n / a",
}

INVALID_STATUSES: Final[Set[str]] = {
    "neplatná data",
    "neplatna data",
    "neplatná",
    "neplatna",
    "neplatné",
    "neplatne",
    "invalid",
    "chyba",
    "chyba měření",
    "chyba mereni",
}

POWER_OUTAGE_INTERVAL_STATUSES: Final[Set[str]] = {
    # PND status code 16: the portal reports a measured interval during a
    # voltage outage.  Keep the interval for continuity, but mark it invalid
    # so Recorder statistics do not treat the value as a reliable reading.
    "naměřená data, výpadek napětí",
    "namerena data, vypadek napeti",
}

VALID_ESTIMATE_INTERVAL_STATUSES: Final[Set[str]] = {
    # PND status code 2 is explicitly documented as a valid estimate.
    "platný odhad",
    "platny odhad",
}

UNDEFINED_INTERVAL_STATUSES: Final[Set[str]] = {
    # PND status code 64 carries no trustworthy validity semantics.  Treat it
    # like an unavailable value so one row cannot discard the whole profile.
    "nedefinovaný status",
    "nedefinovany status",
}

# Explicit per-report semantic mapping contract
REPORT_STATUS_SEMANTICS: Final[Dict[str, Dict[str, StatusSemantic]]] = {
    report_type: {
        **{s: StatusSemantic.VALID for s in VALID_STATUSES},
        **{s: StatusSemantic.PLACEHOLDER for s in PLACEHOLDER_STATUSES},
        **{s: StatusSemantic.INVALID for s in INVALID_STATUSES},
        **(
            {s: StatusSemantic.INVALID for s in POWER_OUTAGE_INTERVAL_STATUSES}
            if report_type
            in (REPORT_TYPE_INTERVAL_CONSUMPTION, REPORT_TYPE_INTERVAL_PRODUCTION)
            else {}
        ),
        **(
            {s: StatusSemantic.VALID for s in VALID_ESTIMATE_INTERVAL_STATUSES}
            if report_type
            in (REPORT_TYPE_INTERVAL_CONSUMPTION, REPORT_TYPE_INTERVAL_PRODUCTION)
            else {}
        ),
        **(
            {s: StatusSemantic.PLACEHOLDER for s in UNDEFINED_INTERVAL_STATUSES}
            if report_type
            in (REPORT_TYPE_INTERVAL_CONSUMPTION, REPORT_TYPE_INTERVAL_PRODUCTION)
            else {}
        ),
    }
    for report_type in SUPPORTED_REPORT_TYPES
}


def resolve_status_semantic(
    raw_status: Optional[str],
    report_type: Optional[str] = None,
) -> StatusSemantic:
    """Resolve portal status string to its verified semantic category.

    Fail-closed: returns StatusSemantic.UNKNOWN for any unverified status.
    Empty status string is treated as VALID for backward compatibility with
    simple exports lacking a status column.
    """
    if raw_status is None:
        return StatusSemantic.UNKNOWN
    cleaned = raw_status.strip().lower()
    if not cleaned:
        return StatusSemantic.VALID

    if report_type:
        report_semantics = REPORT_STATUS_SEMANTICS.get(report_type)
        if report_semantics is not None:
            return report_semantics.get(cleaned, StatusSemantic.UNKNOWN)

    if cleaned in VALID_STATUSES:
        return StatusSemantic.VALID
    if cleaned in PLACEHOLDER_STATUSES:
        return StatusSemantic.PLACEHOLDER
    if cleaned in INVALID_STATUSES:
        return StatusSemantic.INVALID

    return StatusSemantic.UNKNOWN



def parse_cez_datetime(date_str: Any) -> Tuple[datetime, datetime]:
    """Parse CEZ timestamp string into (start_time, end_time).

    Handles 15-minute intervals and the 24:00:00 midnight edge case.
    Example:
      '01.09.2026 00:15:00' -> (2026-09-01 00:00:00, 2026-09-01 00:15:00)
      '01.09.2026 24:00:00' -> (2026-09-01 23:45:00, 2026-09-02 00:00:00)
    """
    if date_str is None or not isinstance(date_str, str):
        raise PndParseError(f"Neplatný formát data a času: '{date_str}'")
    date_str_clean = date_str.strip()
    if not date_str_clean:
        raise PndParseError("Prázdný řetězec data a času")

    try:
        if " " in date_str_clean:
            d_part, t_part = date_str_clean.split(" ", 1)
            day, month, year = [int(x) for x in d_part.split(".")]
            if t_part in ("24:00:00", "24:00"):
                base_date = datetime(year, month, day) + timedelta(days=1)
                end_time = datetime(base_date.year, base_date.month, base_date.day, 0, 0, 0)
            else:
                time_parts = [int(x) for x in t_part.split(":")]
                hour = time_parts[0]
                minute = time_parts[1] if len(time_parts) > 1 else 0
                second = time_parts[2] if len(time_parts) > 2 else 0
                end_time = datetime(year, month, day, hour, minute, second)
        else:
            # Date only (e.g. daily summary)
            day, month, year = [int(x) for x in date_str_clean.split(".")]
            end_time = datetime(year, month, day, 0, 0, 0)
            return end_time, end_time

        start_time = end_time - timedelta(minutes=15)
        return start_time, end_time
    except Exception as err:
        raise PndParseError(f"Chyba při parsování data a času '{date_str_clean}': {err}") from err


def parse_float_value(val: Any) -> float:
    """Parse float from string replacing comma with dot and validating bounds."""
    if val is None:
        _LOGGER.warning("Could not parse numeric value in CSV: value is None")
        raise PndParseError("Chybějící nebo neplatná číselná hodnota v CSV (hodnota je None).")
    val_clean = str(val).strip().replace(" ", "").replace(",", ".")
    if not val_clean or val_clean == "-":
        _LOGGER.warning("Could not parse numeric value in CSV: empty or placeholder value")
        raise PndParseError("Chybějící nebo neplatná číselná hodnota v CSV (prázdná hodnota nebo pomlčka).")
    try:
        parsed = float(val_clean)
    except (ValueError, TypeError) as err:
        _LOGGER.warning("Could not parse numeric value in CSV")
        raise PndParseError("Nelze naparsovat číselnou hodnotu v CSV.") from err

    if not math.isfinite(parsed) or parsed < 0.0 or parsed > 100000.0:
        _LOGGER.warning("Parsed numeric value in CSV is non-finite or out of bounds [0, 100000]")
        raise PndParseError("Numerická hodnota v CSV je neplatná, nekonečná nebo mimo meze [0, 100000].")

    return parsed


class PndCsvParser:
    """Parser for CEZ PND 15-minute interval and daily summary CSV files with streaming and hard limits."""

    def __init__(self, app_version: str = "unknown") -> None:
        """Initialize parser."""
        self.app_version = app_version
        self.detected_encoding = "unknown"
        self.invalid_rows_count = 0
        self.duplicate_rows_count = 0
        self.total_rows_parsed = 0

    def _stream_csv_rows(self, file_path: Union[str, SealedReport]) -> Iterator[List[str]]:
        """Stream CSV rows generator with file size and hard limits without materializing full file."""
        basename = os.path.basename(
            file_path.logical_name if isinstance(file_path, SealedReport) else file_path
        )
        descriptor = -1
        snapshot_descriptor = -1
        snapshot_owner: Optional[SealedReport] = None
        if isinstance(file_path, SealedReport):
            if file_path.size <= 0:
                raise PndParseError(f"Soubor CSV '{basename}' je prázdný.")
            if file_path.size > MAX_CSV_FILE_SIZE:
                raise PndParseError(
                    f"Soubor CSV '{basename}' překročil maximální limit 5 MB."
                )
            try:
                snapshot_descriptor = file_path.duplicate_for_read()
                size = file_path.size
            except SnapshotError as err:
                raise PndParseError("Sealed CSV report nelze bezpečně ověřit.") from err
        else:
            size = 0
            path_stat = None
            try:
                path_stat = os.lstat(file_path)
            except FileNotFoundError:
                _LOGGER.debug("File does not exist: %s", basename)
                return
            except OSError as err:
                raise PndParseError("CSV soubor nelze bezpečně otevřít.") from err

            if not stat.S_ISREG(path_stat.st_mode) or not hasattr(os, "O_NOFOLLOW"):
                raise PndParseError(f"CSV soubor '{basename}' není bezpečný regulární soubor.")
            try:
                descriptor = os.open(file_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
                file_stat = os.fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise PndParseError(f"CSV soubor '{basename}' není bezpečný regulární soubor.")
                if (file_stat.st_dev, file_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                    raise PndParseError("CSV soubor se během otevírání změnil.")
                if file_stat.st_size > MAX_CSV_FILE_SIZE:
                    _LOGGER.error("Soubor CSV %s překročil maximální povolenou velikost 5 MB (%d bajtů)", basename, file_stat.st_size)
                    raise PndParseError(f"Soubor CSV '{basename}' překročil maximální limit 5 MB.")
                try:
                    snapshot_owner = bounded_sealed_snapshot(
                        descriptor, MAX_CSV_FILE_SIZE, "cez-pnd-csv", logical_name=basename
                    )
                    snapshot_descriptor = snapshot_owner.fd
                    size = snapshot_owner.size
                except SnapshotError as err:
                    if "exceeds" in str(err):
                        raise PndParseError(f"Soubor CSV '{basename}' překročil maximální limit 5 MB.") from err
                    raise PndParseError("CSV soubor se během bezpečného snapshotu změnil.") from err
            except PndParseError:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise
            except OSError as err:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise PndParseError("CSV soubor nelze bezpečně otevřít.") from err

        encodings = ["utf-8-sig", "utf-8", "cp1250", "iso-8859-2"]
        try:
            for enc in encodings:
                try:
                    os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
                    with os.fdopen(os.dup(snapshot_descriptor), "r", encoding=enc, newline="") as f:
                        # Detect delimiter safely
                        sample = f.read(2048)
                        f.seek(0)
                        delimiter = ";" if ";" in sample else ","
                        reader = csv.reader(f, delimiter=delimiter)

                        row_count = 0
                        for row in reader:
                            if not row or not any(cell.strip() for cell in row):
                                continue
                            row_count += 1
                            if row_count > MAX_CSV_ROWS:
                                _LOGGER.error(
                                    "Dosažen maximální limit %d řádků v CSV souboru %s.",
                                    MAX_CSV_ROWS,
                                    basename,
                                )
                                raise PndParseError(
                                    f"CSV soubor '{basename}' překročil maximální limit {MAX_CSV_ROWS} řádků."
                                )

                            if len(row) > MAX_CSV_COLS:
                                _LOGGER.error(
                                    "Řádek %d má %d sloupců (limit %d) v CSV souboru %s.",
                                    row_count,
                                    len(row),
                                    MAX_CSV_COLS,
                                    basename,
                                )
                                raise PndParseError(
                                    f"Řádek {row_count} má {len(row)} sloupců, což překračuje limit {MAX_CSV_COLS} v souboru '{basename}'."
                                )

                            if any(len(cell) > MAX_CELL_LENGTH for cell in row):
                                self.invalid_rows_count += 1
                                _LOGGER.error(
                                    "Řádek %d v %s obsahuje buňku delší než %d znaků.",
                                    row_count,
                                    basename,
                                    MAX_CELL_LENGTH,
                                )
                                raise PndParseError(
                                    f"Řádek {row_count} v souboru '{basename}' obsahuje buňku delší než limit {MAX_CELL_LENGTH} znaků."
                                )

                            yield row

                        try:
                            final_stat = os.fstat(snapshot_descriptor)
                        except OSError as err:
                            raise PndParseError("CSV soubor nelze bezpečně číst.") from err
                        if final_stat.st_size != size:
                            raise PndParseError("CSV soubor se během čtení změnil.")
                        if final_stat.st_size > MAX_CSV_FILE_SIZE:
                            raise PndParseError(f"Soubor CSV '{basename}' překročil maximální limit 5 MB.")
                        self.detected_encoding = enc
                        return
                except UnicodeDecodeError as err:
                    _LOGGER.debug("Failed streaming %s with encoding %s: %s", basename, enc, err)
                    continue
                except OSError as err:
                    raise PndParseError("CSV soubor nelze bezpečně číst.") from err

            _LOGGER.error("Failed to decode CSV file %s with all known encodings", basename)
            raise PndParseError(f"Soubor CSV '{basename}' se nepodařilo dekódovat v žádném z podporovaných kódování.")
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if snapshot_owner is not None:
                snapshot_owner.close()
            elif snapshot_descriptor >= 0 and snapshot_descriptor != descriptor:
                try:
                    os.close(snapshot_descriptor)
                except OSError:
                    pass

    def _read_csv_file(self, file_path: Union[str, SealedReport]) -> List[List[str]]:
        """Compatibility wrapper returning list of rows from _stream_csv_rows."""
        return list(self._stream_csv_rows(file_path))

    def _resolve_column_indices_and_scale(
        self,
        header_row: List[str],
        basename: str,
        expected_profile: Optional[str] = None,
    ) -> Tuple[int, int, Optional[int], float]:
        """Validate header row, determine date, value, status column indices, and unit scale factor.

        Returns: (date_col_idx, value_col_idx, status_col_idx, unit_scale)
        Raises: PndParseError if header is invalid, profile mismatch/ambiguous, or unit unsupported/missing.
        """
        if len(header_row) < 2:
            self.invalid_rows_count += 1
            _LOGGER.error("Řádek v %s má méně než 2 sloupce (%d)", basename, len(header_row))
            raise PndParseError(f"Řádek v {basename} má méně než 2 sloupce.")

        header_cols = [c.strip().lower() for c in header_row]

        # 1. Detect date column
        date_col_idx: Optional[int] = None
        for idx, col in enumerate(header_cols):
            if any(k in col for k in DATE_HEADER_KEYWORDS):
                date_col_idx = idx
                break

        if date_col_idx is None:
            self.invalid_rows_count += 1
            _LOGGER.error("Soubor %s neobsahuje platný řádek s hlavičkou", basename)
            raise PndParseError(f"Soubor '{basename}' neobsahuje platný řádek s hlavičkou.")

        # 2. Detect status column
        status_col_idx: Optional[int] = None
        for idx, col in enumerate(header_cols):
            if idx != date_col_idx and any(k in col for k in STATUS_HEADER_KEYWORDS):
                status_col_idx = idx
                break

        # 3. Identify candidate measurement columns
        candidates = [
            idx for idx in range(len(header_cols))
            if idx != date_col_idx and idx != status_col_idx
        ]
        if not candidates:
            self.invalid_rows_count += 1
            _LOGGER.error("Soubor %s neobsahuje žádný sloupec pro naměřené hodnoty", basename)
            raise PndParseError(f"Soubor '{basename}' neobsahuje žádný sloupec pro naměřené hodnoty.")

        # 4. Categorize candidate columns by profile keywords
        matching_plus = [
            idx for idx in candidates
            if any(k in header_cols[idx] for k in PLUS_PROFILE_KEYWORDS)
        ]
        matching_minus = [
            idx for idx in candidates
            if any(k in header_cols[idx] for k in MINUS_PROFILE_KEYWORDS)
        ]

        # 5. Validate profile against expected_profile
        if expected_profile == "+A":
            if not matching_plus:
                self.invalid_rows_count += 1
                if matching_minus:
                    _LOGGER.error(
                        "Soubor %s obsahuje profil výroby namísto očekávaného profilu spotřeby (+A)",
                        basename,
                    )
                    raise PndParseError(
                        f"Soubor '{basename}' obsahuje profil výroby namísto očekávaného profilu spotřeby (+A)."
                    )
                _LOGGER.error("Soubor %s neobsahuje prokázaný profil spotřeby (+A)", basename)
                raise PndParseError(
                    f"Soubor '{basename}' neobsahuje prokázaný profil spotřeby (+A)."
                )
            if len(matching_plus) > 1:
                self.invalid_rows_count += 1
                _LOGGER.error("Soubor %s obsahuje vícečetné/ambivalentní sloupce spotřeby (+A)", basename)
                raise PndParseError(
                    f"Soubor '{basename}' obsahuje vícečetné/ambivalentní sloupce spotřeby (+A)."
                )
            value_col_idx = matching_plus[0]

        elif expected_profile == "-A":
            if not matching_minus:
                self.invalid_rows_count += 1
                if matching_plus:
                    _LOGGER.error(
                        "Soubor %s obsahuje profil spotřeby namísto očekávaného profilu výroby (-A)",
                        basename,
                    )
                    raise PndParseError(
                        f"Soubor '{basename}' obsahuje profil spotřeby namísto očekávaného profilu výroby (-A)."
                    )
                _LOGGER.error("Soubor %s neobsahuje prokázaný profil výroby (-A)", basename)
                raise PndParseError(
                    f"Soubor '{basename}' neobsahuje prokázaný profil výroby (-A)."
                )
            if len(matching_minus) > 1:
                self.invalid_rows_count += 1
                _LOGGER.error("Soubor %s obsahuje vícečetné/ambivalentní sloupce výroby (-A)", basename)
                raise PndParseError(
                    f"Soubor '{basename}' obsahuje vícečetné/ambivalentní sloupce výroby (-A)."
                )
            value_col_idx = matching_minus[0]

        elif expected_profile is None:
            if len(candidates) == 1:
                value_col_idx = candidates[0]
            elif len(matching_plus) == 1 and len(matching_minus) == 0:
                value_col_idx = matching_plus[0]
            elif len(matching_minus) == 1 and len(matching_plus) == 0:
                value_col_idx = matching_minus[0]
            else:
                self.invalid_rows_count += 1
                _LOGGER.error(
                    "Soubor %s obsahuje nejednoznačné sloupce měření bez specifikovaného profilu",
                    basename,
                )
                raise PndParseError(
                    f"Soubor '{basename}' obsahuje nejednoznačné sloupce měření bez specifikovaného profilu."
                )
        else:
            self.invalid_rows_count += 1
            _LOGGER.error("Neznámý očekávaný profil '%s' pro soubor %s", expected_profile, basename)
            raise PndParseError(f"Neznámý očekávaný profil '{expected_profile}'.")

        # 6. Validate unit of the selected value column
        raw_val_header = header_row[value_col_idx].strip()
        val_header_lower = header_cols[value_col_idx]

        if "kwh" in val_header_lower:
            unit_scale = 1.0
        elif (
            "[kw]" in val_header_lower
            or "(kw)" in val_header_lower
            or "/kw" in val_header_lower
            or " kw" in val_header_lower
            or val_header_lower.endswith("kw")
        ):
            unit_scale = 0.25
        else:
            self.invalid_rows_count += 1
            _LOGGER.error(
                "Soubor %s obsahuje neznámou nebo nepodporovanou jednotku v hlavičce '%s'",
                basename,
                raw_val_header,
            )
            raise PndParseError(
                f"Soubor '{basename}' obsahuje neznámou nebo nepodporovanou jednotku v hlavičce '{raw_val_header}'."
            )

        return date_col_idx, value_col_idx, status_col_idx, unit_scale

    def _parse_interval_file(
        self,
        file_path: Union[str, SealedReport],
        expected_profile: Optional[str] = None,
    ) -> Dict[datetime, Tuple[datetime, float, bool]]:
        """Parse 15-minute interval CSV file.

        Returns a dictionary mapping start_time -> (end_time, value_kwh, is_valid).
        """
        basename = os.path.basename(
            file_path.logical_name if isinstance(file_path, SealedReport) else file_path
        )
        results: Dict[datetime, Tuple[datetime, float, bool]] = {}
        row_stream = self._stream_csv_rows(file_path)

        date_col_idx = 0
        value_col_idx = 1
        status_col_idx: Optional[int] = None
        unit_scale = 1.0
        first_row = True

        for row in row_stream:
            self.total_rows_parsed += 1

            # Header detection and validation on first row
            if first_row:
                first_row = False
                date_col_idx, value_col_idx, status_col_idx, unit_scale = (
                    self._resolve_column_indices_and_scale(
                        row, basename, expected_profile=expected_profile
                    )
                )
                continue

            req_cols = max(date_col_idx, value_col_idx) + 1
            if len(row) < req_cols:
                self.invalid_rows_count += 1
                _LOGGER.error(
                    "Řádek v %s má méně než %d sloupců (%d)",
                    basename,
                    req_cols,
                    len(row),
                )
                if req_cols == 2:
                    raise PndParseError(f"Řádek v {basename} má méně než 2 sloupce.")
                raise PndParseError(f"Řádek v {basename} má méně než {req_cols} sloupců.")

            date_str = row[date_col_idx].strip()
            val_str = row[value_col_idx].strip()
            raw_status = (
                row[status_col_idx].strip()
                if (status_col_idx is not None and len(row) > status_col_idx)
                else ""
            )

            report_type = (
                REPORT_TYPE_INTERVAL_PRODUCTION
                if expected_profile == "-A"
                else REPORT_TYPE_INTERVAL_CONSUMPTION
            )
            semantic = resolve_status_semantic(raw_status, report_type=report_type)

            # Skip placeholder intervals that have not been measured yet (e.g. future days in monthly range, N/A)
            if semantic == StatusSemantic.PLACEHOLDER:
                _LOGGER.debug(
                    "Interval %s v %s má stav neměřené hodnoty '%s', přeskočeno",
                    date_str,
                    basename,
                    raw_status,
                )
                continue

            if semantic == StatusSemantic.VALID:
                is_valid = True
            elif semantic == StatusSemantic.INVALID:
                is_valid = False
                self.invalid_rows_count += 1
                _LOGGER.debug(
                    "Interval %s v %s má neplatný stav: '%s'",
                    date_str,
                    basename,
                    raw_status,
                )
            else:
                self.invalid_rows_count += 1
                _LOGGER.error(
                    "Interval %s v %s obsahuje neznámý stav validity '%s' (FAIL-CLOSED)",
                    date_str,
                    basename,
                    raw_status,
                )
                raise PndParseError(f"Neznámý nebo nepodporovaný stav validity '{raw_status}' v souboru '{basename}'.")

            start_time, end_time = parse_cez_datetime(date_str)
            raw_val = parse_float_value(val_str)
            value_kwh = round(raw_val * unit_scale, 6)

            if start_time in results:
                prev_end_time, prev_val_kwh, prev_valid = results[start_time]
                if prev_end_time != end_time or abs(prev_val_kwh - value_kwh) > 1e-6 or prev_valid != is_valid:
                    self.invalid_rows_count += 1
                    _LOGGER.error(
                        "Detekován konfliktní duplicitní interval v %s",
                        basename,
                    )
                    raise PndParseError(f"Konfliktní duplicitní interval v souboru '{basename}'.")
                self.duplicate_rows_count += 1
                _LOGGER.debug(
                    "Duplicitní identický interval v %s přeskočen",
                    basename,
                )
                continue

            results[start_time] = (end_time, value_kwh, is_valid)

        return results

    def _parse_daily_file(
        self,
        file_path: Union[str, SealedReport],
        expected_profile: Optional[str] = None,
    ) -> Optional[Tuple[datetime, float]]:
        """Parse daily summary CSV file returning (date, total_kwh)."""
        basename = os.path.basename(
            file_path.logical_name if isinstance(file_path, SealedReport) else file_path
        )
        row_stream = self._stream_csv_rows(file_path)
        last_valid_result: Optional[Tuple[datetime, float]] = None
        daily_accum: Dict[Any, Tuple[datetime, float]] = {}

        date_col_idx = 0
        value_col_idx = 1
        status_col_idx: Optional[int] = None
        unit_scale = 1.0
        first_row = True

        for row in row_stream:
            self.total_rows_parsed += 1

            if first_row:
                first_row = False
                date_col_idx, value_col_idx, status_col_idx, unit_scale = (
                    self._resolve_column_indices_and_scale(
                        row, basename, expected_profile=expected_profile
                    )
                )
                continue

            req_cols = max(date_col_idx, value_col_idx) + 1
            if len(row) < req_cols:
                self.invalid_rows_count += 1
                _LOGGER.error(
                    "Řádek v %s má méně než %d sloupců (%d)",
                    basename,
                    req_cols,
                    len(row),
                )
                if req_cols == 2:
                    raise PndParseError(f"Řádek v {basename} má méně než 2 sloupce.")
                raise PndParseError(
                    f"Řádek v {basename} má méně než {req_cols} sloupců."
                )

            actual_status_idx = status_col_idx
            if actual_status_idx is None and len(row) > max(date_col_idx, value_col_idx) + 1:
                actual_status_idx = len(row) - 1

            raw_status = (
                row[actual_status_idx].strip()
                if (actual_status_idx is not None and len(row) > actual_status_idx)
                else ""
            )

            if "17" in basename or "registry" in basename.lower():
                report_type = REPORT_TYPE_DAILY_REGISTERS
            elif expected_profile == "-A":
                report_type = REPORT_TYPE_DAILY_PRODUCTION
            else:
                report_type = REPORT_TYPE_DAILY_CONSUMPTION

            semantic = resolve_status_semantic(raw_status, report_type=report_type)

            if semantic == StatusSemantic.PLACEHOLDER:
                _LOGGER.debug(
                    "Denní záznam %s v %s má stav neměřené hodnoty '%s', přeskočeno",
                    row[date_col_idx].strip(),
                    basename,
                    raw_status,
                )
                continue

            if semantic == StatusSemantic.VALID:
                is_valid = True
            elif semantic == StatusSemantic.INVALID:
                is_valid = False
                self.invalid_rows_count += 1
                _LOGGER.debug(
                    "Denní záznam %s v %s má neplatný stav: '%s'",
                    row[date_col_idx].strip(),
                    basename,
                    raw_status,
                )
                continue
            else:
                self.invalid_rows_count += 1
                _LOGGER.error(
                    "Denní záznam %s v %s obsahuje neznámý stav validity '%s' (FAIL-CLOSED)",
                    row[date_col_idx].strip(),
                    basename,
                    raw_status,
                )
                raise PndParseError(
                    f"Neznámý nebo nepodporovaný stav validity '{raw_status}' v souboru '{basename}'."
                )

            date_str = row[date_col_idx].strip()
            val_str = row[value_col_idx].strip()

            start_time, _ = parse_cez_datetime(date_str)
            raw_val = parse_float_value(val_str)
            row_kwh = round(raw_val * unit_scale, 4)

            # Accumulate sum per day to support single-day totals, multi-day exports, and multi-row interval exports
            date_key = start_time.date()
            if date_key not in daily_accum:
                daily_accum[date_key] = (start_time, 0.0)
            st_prev, sum_prev = daily_accum[date_key]
            # If date_str specifies a full day (without interval minutes), row_kwh is the full day's value
            # If date_str has interval time (15-min), accumulate them
            daily_accum[date_key] = (start_time, round(sum_prev + row_kwh, 4))

        if daily_accum:
            latest_date = max(daily_accum.keys())
            last_valid_result = daily_accum[latest_date]

        return last_valid_result

    def _find_file(self, download_dir: str, patterns: List[str]) -> Optional[str]:
        """Exact matching for expected allowed files only, rejecting symlinks (SEC04-06)."""
        if not os.path.isdir(download_dir):
            return None

        for pat in patterns:
            if pat not in ALLOWED_CSV_FILES:
                continue
            target_path = os.path.join(download_dir, pat)
            if os.path.isfile(target_path) and not os.path.islink(target_path):
                return target_path

        return None

    def parse(
        self,
        download_dir: str,
        report_paths: Optional[Dict[str, Union[str, SealedReport]]] = None,
    ) -> ParsedPndData:
        """Parse reports and always release process-local browser report ownership."""
        owned = [value for value in (report_paths or {}).values() if isinstance(value, SealedReport)]
        seen_ids: Set[int] = set()
        seen_inodes: Set[Tuple[int, int]] = set()
        try:
            for report in owned:
                if id(report) in seen_ids:
                    raise PndParseError("Sealed report ownership was reused.")
                seen_ids.add(id(report))
                if report.size <= 0:
                    raise PndParseError("Sealed report je prázdný.")
                if report.size > MAX_CSV_FILE_SIZE:
                    raise PndParseError("Sealed report překročil maximální limit 5 MB.")
                verify_sealed_fd(report.fd, report.size, report.digest)
                report_stat = os.fstat(report.fd)
                inode = (report_stat.st_dev, report_stat.st_ino)
                if inode in seen_inodes:
                    raise PndParseError("Sealed report descriptors alias one another.")
                seen_inodes.add(inode)
            return self._parse_impl(download_dir, report_paths)
        finally:
            close_sealed_reports(owned)

    def _parse_impl(
        self,
        download_dir: str,
        report_paths: Optional[Dict[str, Union[str, SealedReport]]] = None,
    ) -> ParsedPndData:
        """Parse downloaded CSV files, preferring paths returned by the downloader."""
        def returned_path(key: str, fallback: str) -> Union[str, SealedReport]:
            candidate = report_paths.get(key) if isinstance(report_paths, dict) else None
            if isinstance(candidate, SealedReport):
                return candidate
            if (
                isinstance(candidate, str)
                and candidate.lower().endswith(".csv")
                and os.path.abspath(os.path.dirname(candidate)) == os.path.abspath(download_dir)
            ):
                return candidate
            return fallback

        consumption_file = returned_path("range_consumption", "") or self._find_file(
            download_dir,
            [
                "range-consumption.csv",
                "range_consumption.csv",
                "range_consumption_sample.csv",
                "range_consumption_with_na.csv",
            ],
        ) or os.path.join(download_dir, "range-consumption.csv")

        production_file = returned_path("range_production", "") or self._find_file(
            download_dir,
            [
                "range-production.csv",
                "range_production.csv",
                "range_production_sample.csv",
                "range_production_with_na.csv",
            ],
        ) or os.path.join(download_dir, "range-production.csv")

        daily_cons_file = returned_path("daily_consumption", "") or self._find_file(
            download_dir,
            [
                "daily-consumption.csv",
                "daily_consumption.csv",
                "daily_consumption_sample.csv",
                "daily_consumption_with_na.csv",
            ],
        ) or os.path.join(download_dir, "daily-consumption.csv")

        daily_prod_file = returned_path("daily_production", "") or self._find_file(
            download_dir,
            [
                "daily-production.csv",
                "daily_production.csv",
                "daily_production_sample.csv",
            ],
        ) or os.path.join(download_dir, "daily-production.csv")

        # Parse intervals with profile validation
        cons_intervals = self._parse_interval_file(consumption_file, expected_profile="+A")
        if not cons_intervals:
            raise PndParseError("No valid consumption interval records found (ERR_PARSER)")

        try:
            prod_intervals = self._parse_interval_file(production_file, expected_profile="-A")
        except FileNotFoundError:
            prod_intervals = {}

        # Collect all start times
        all_start_times = sorted(set(cons_intervals.keys()) | set(prod_intervals.keys()))

        interval_records: List[IntervalRecord] = []
        for st in all_start_times:
            if st in cons_intervals:
                end_time, cons_kwh, is_valid_cons = cons_intervals[st]
            else:
                end_time, _, _ = prod_intervals[st]
                cons_kwh = 0.0
                is_valid_cons = False

            if st in prod_intervals:
                _, prod_kwh, is_valid_prod = prod_intervals[st]
            else:
                prod_kwh = 0.0
                is_valid_prod = True

            # Combined validity: True if and only if all present streams are valid
            combined_is_valid = is_valid_cons and is_valid_prod

            interval_records.append(
                IntervalRecord(
                    start_time=st,
                    end_time=end_time,
                    consumption_kwh=round(cons_kwh, 4),
                    production_kwh=round(prod_kwh, 4),
                    is_vt=True,
                    is_valid=combined_is_valid,
                    is_valid_consumption=is_valid_cons,
                    is_valid_production=is_valid_prod,
                )
            )

        # Parse daily summaries
        daily_cons = (
            self._parse_daily_file(daily_cons_file, expected_profile="+A")
            if daily_cons_file
            and (isinstance(daily_cons_file, SealedReport) or os.path.isfile(daily_cons_file))
            else None
        )
        daily_prod = (
            self._parse_daily_file(daily_prod_file, expected_profile="-A")
            if daily_prod_file
            and (isinstance(daily_prod_file, SealedReport) or os.path.isfile(daily_prod_file))
            else None
        )

        summary_date = datetime.now() - timedelta(days=1)
        total_consumption = 0.0
        total_production = 0.0

        if daily_cons:
            summary_date = daily_cons[0]
            total_consumption = daily_cons[1]
        elif interval_records:
            summary_date = interval_records[0].start_time
            total_consumption = sum(r.consumption_kwh for r in interval_records if r.is_valid_consumption)

        if daily_prod:
            total_production = daily_prod[1]
        elif interval_records:
            total_production = sum(r.production_kwh for r in interval_records if r.is_valid_production)

        daily_summary = DailySummary(
            date=summary_date,
            total_consumption_kwh=round(total_consumption, 4),
            total_production_kwh=round(total_production, 4),
            app_version=self.app_version,
        )

        # Diagnostic validation of interval count
        num_intervals = len(interval_records)
        target_name = os.path.basename(
            consumption_file.logical_name if isinstance(consumption_file, SealedReport) else consumption_file
        )
        if num_intervals not in (96, 92, 100) and num_intervals % 96 != 0 and num_intervals > 0:
            _LOGGER.warning(
                "Neočekávaný počet 15min intervalů v %s: získáno %d, očekáváno 96 (resp. 92/100 při DST nebo násobek pro období). "
                "ČEZ PND pravděpodobně ještě nedopočítal data za celý den.",
                target_name,
                num_intervals,
            )
        else:
            _LOGGER.debug("Parsed %d 15-minute intervals successfully from %s", num_intervals, target_name)

        return ParsedPndData(
            intervals=interval_records,
            daily_summary=daily_summary,
            detected_encoding=self.detected_encoding,
            total_rows=self.total_rows_parsed,
            invalid_rows_count=self.invalid_rows_count,
            duplicate_rows_count=self.duplicate_rows_count,
        )
