"""Price schedule helpers for CEZ Distribuce PND cost statistics."""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable


class PriceScheduleError(ValueError):
    """Base error for an invalid price schedule."""


class PriceCurrencyMismatchError(PriceScheduleError):
    """Raised when a schedule mixes currencies."""


def _date_string(value: Any) -> str:
    """Return an ISO date after strict validation."""
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return value.isoformat()
    try:
        return date.fromisoformat(str(value).strip()).isoformat()
    except (TypeError, ValueError) as err:
        raise PriceScheduleError("Price validity must be an ISO date") from err


def _price_string(value: Any) -> str:
    """Return a stable, non-negative decimal representation."""
    try:
        price = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as err:
        raise PriceScheduleError("Price must be numeric") from err
    if not price.is_finite() or price < 0 or price > Decimal("10000"):
        raise PriceScheduleError("Price must be between 0 and 10000")
    normalized = format(price.normalize(), "f")
    return "0" if normalized in {"-0", ""} else normalized


def merge_price_period(
    schedule: Iterable[dict[str, Any]],
    *,
    valid_from: Any,
    price_vt: Any,
    price_nt: Any,
    currency: str,
) -> list[dict[str, str]]:
    """Validate a schedule and add or replace one effective price period."""
    currency = str(currency).strip().upper()
    if not currency:
        raise PriceScheduleError("Home Assistant currency is not configured")

    normalized: list[dict[str, str]] = []
    for raw in schedule:
        raw_currency = str(raw.get("currency", "")).strip().upper()
        if raw_currency != currency:
            raise PriceCurrencyMismatchError(
                f"Stored currency {raw_currency or 'unknown'} differs from {currency}"
            )
        normalized.append(
            {
                "valid_from": _date_string(raw.get("valid_from")),
                "price_vt": _price_string(raw.get("price_vt")),
                "price_nt": _price_string(raw.get("price_nt")),
                "currency": currency,
            }
        )

    period = {
        "valid_from": _date_string(valid_from),
        "price_vt": _price_string(price_vt),
        "price_nt": _price_string(price_nt),
        "currency": currency,
    }
    normalized = [p for p in normalized if p["valid_from"] != period["valid_from"]]
    normalized.append(period)
    normalized.sort(key=lambda item: item["valid_from"])
    return normalized


def price_period_for(
    schedule: Iterable[dict[str, Any]], when: date | datetime
) -> dict[str, str] | None:
    """Return the latest price period effective at a date."""
    target = _date_string(when)
    eligible = [period for period in schedule if _date_string(period["valid_from"]) <= target]
    if not eligible:
        return None
    return max(eligible, key=lambda item: _date_string(item["valid_from"]))
