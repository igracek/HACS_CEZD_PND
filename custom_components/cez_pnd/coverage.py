"""Requested local-day coverage. Unknown measurements never become zeroes."""
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

ZONE = ZoneInfo('Europe/Prague')
UTC = timezone.utc
QUARTER = timedelta(minutes=15)


def day_grid(day):
    """Return UTC quarter starts between two local midnights (92/96/100)."""
    start = datetime.combine(day, time(), ZONE).astimezone(UTC)
    end = datetime.combine(day + timedelta(days=1), time(), ZONE).astimezone(UTC)
    return {start + QUARTER * i for i in range(int((end-start)/QUARTER))}


def utc_end(value):
    """Reject ambiguous/nonexistent naive clock readings, not guess a fold."""
    if value.tzinfo:
        return value.astimezone(UTC)
    first = value.replace(tzinfo=ZONE, fold=0)
    second = value.replace(tzinfo=ZONE, fold=1)
    if first.utcoffset() != second.utcoffset():
        return None
    result = first.astimezone(UTC)
    if result.astimezone(ZONE).replace(tzinfo=None) != value:
        return None
    return result


def assess(parsed, days):
    """Attach per-day/profile counts and constrain records to the UTC grid.

    Naive repeated autumn times have no proven portal fold contract: omit them
    and leave that day incomplete. Do not collapse them into a measured hour.
    """
    grids = {day.isoformat(): day_grid(day) for day in days}
    coverage = {}
    for key, grid in grids.items():
        profiles = coverage.setdefault(key, {})
        for profile in ('+A', '-A'):
            counts = dict(expected=len(grid), raw=0, valid=0, unknown=0,
                          invalid=0, missing=len(grid), duplicate=0,
                          out_of_range=0, ambiguous=0)
            seen = set()
            for start, end, semantic in parsed.raw_slots.get(profile, []):
                # Attribution uses interval start's local calendar day.
                local_day = start.astimezone(ZONE).date() if start.tzinfo else start.date()
                if local_day.isoformat() != key:
                    counts['out_of_range'] += int(local_day.isoformat() not in grids)
                    continue
                counts['raw'] += 1
                utc = utc_end(end)
                slot = utc - QUARTER if utc else None
                if slot is None:
                    counts['ambiguous'] += 1
                    continue
                if slot not in grid or (end-start) != QUARTER:
                    counts['out_of_range'] += 1
                    continue
                if slot in seen:
                    counts['duplicate'] += 1
                    continue
                seen.add(slot)
                if semantic == 'valid':
                    counts['valid'] += 1
                elif semantic == 'placeholder':
                    counts['unknown'] += 1
                else:
                    counts['invalid'] += 1
            counts['missing'] -= len(seen)
            counts['complete'] = (counts['valid'] == len(grid) and not
                                  (counts['out_of_range'] or counts['ambiguous']))
            profiles[profile] = counts
    allowed = set().union(*grids.values()) if grids else set()
    accepted = []
    for record in parsed.intervals:
        # Validate the parser's original interval before UTC normalization.
        # A date-only/zero-duration row must never acquire a measured quarter.
        if record.end_time - record.start_time != QUARTER:
            continue
        end = utc_end(record.end_time)
        if end is None or end-QUARTER not in allowed:
            continue
        record.end_time = end
        record.start_time = end-QUARTER
        accepted.append(record)
    parsed.intervals = accepted
    parsed.coverage = coverage
    return coverage
