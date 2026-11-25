"""
FootprintIQ - Canonical Timezone & Timestamp Formatting Utilities

Design:
- Persist all database timestamps in UTC.
- Convert strictly at the presentation layer to IST (Asia/Kolkata, UTC+05:30)
  using Python's standard zoneinfo database (never hardcoded offset math).
- Handle legacy naive timestamps safely by assuming UTC when tzinfo is missing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

UTC_TZ = timezone.utc
IST_TZ = ZoneInfo("Asia/Kolkata")
IST_TIMEZONE_NAME = "Asia/Kolkata"
IST_LABEL = "IST"


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC_TZ)


def utc_now_naive() -> datetime:
    """Return UTC naive datetime for SQL Server DateTime columns storing UTC."""
    return datetime.now(UTC_TZ).replace(tzinfo=None)


def parse_timestamp_utc(value: Any) -> Optional[datetime]:
    """
    Parse a datetime, epoch float/int, or ISO-8601 string into UTC-aware datetime.
    Legacy naive datetimes/strings without timezone suffix are safely interpreted as UTC.
    """
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC_TZ)
        return value.astimezone(UTC_TZ)

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC_TZ)
        except (OSError, OverflowError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None

    upper = text.upper()
    if upper.endswith(" IST"):
        body = text[:-4].strip()
        for fmt in ("%d %b %Y, %I:%M %p", "%d %b %Y, %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                parsed = datetime.strptime(body, fmt).replace(tzinfo=IST_TZ)
                return parsed.astimezone(UTC_TZ)
            except ValueError:
                continue

    if upper.endswith(" UTC") or upper.endswith(" GMT"):
        text = text[:-4].strip()

    iso_candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC_TZ)
        return parsed.astimezone(UTC_TZ)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
        "%B %d, %Y %H:%M",
    ):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC_TZ)
        except ValueError:
            continue

    return None


def to_ist(value: Any) -> Optional[datetime]:
    """Convert any UTC/aware/legacy-naive timestamp to Asia/Kolkata timezone."""
    dt_utc = parse_timestamp_utc(value)
    if dt_utc is None:
        return None
    return dt_utc.astimezone(IST_TZ)


def ist_iso(value: Any) -> Optional[str]:
    """Return ISO-8601 string in +05:30 offset (e.g., 2026-11-12T23:30:00+05:30)."""
    dt_ist = to_ist(value)
    return dt_ist.isoformat() if dt_ist else None


def format_ist(value: Any, include_seconds: bool = False, default: str = "—") -> str:
    """
    Format timestamp into standard Indian Standard Time display string:
    e.g., '12 Nov 2026, 11:30 PM IST'
    """
    dt_ist = to_ist(value)
    if dt_ist is None:
        return default
    hour_12 = dt_ist.hour % 12 or 12
    sec_part = f":{dt_ist.second:02d}" if include_seconds else ""
    am_pm = "AM" if dt_ist.hour < 12 else "PM"
    return f"{dt_ist.day:02d} {dt_ist.strftime('%b %Y')}, {hour_12}:{dt_ist.minute:02d}{sec_part} {am_pm} IST"


def format_ist_short(value: Any, default: str = "—") -> str:
    """Compact readable IST timestamp for dense tables (e.g., '12 Nov, 11:30 PM IST')."""
    dt_ist = to_ist(value)
    if dt_ist is None:
        return default
    hour_12 = dt_ist.hour % 12 or 12
    am_pm = "AM" if dt_ist.hour < 12 else "PM"
    return f"{dt_ist.day:02d} {dt_ist.strftime('%b')}, {hour_12}:{dt_ist.minute:02d} {am_pm} IST"


def format_ist_date(value: Any, default: str = "—") -> str:
    """Date-only representation in IST (e.g., '12 Nov 2026 (IST)')."""
    dt_ist = to_ist(value)
    if dt_ist is None:
        return default
    return f"{dt_ist.day:02d} {dt_ist.strftime('%b %Y')}"


def duration_human(
    start: Any = None,
    end: Any = None,
    duration_seconds: Optional[float] = None,
    default: str = "—",
) -> str:
    """Format duration between two timestamps or explicit seconds concisely."""
    secs = duration_seconds
    if secs is None and start is not None and end is not None:
        dt_start = parse_timestamp_utc(start)
        dt_end = parse_timestamp_utc(end)
        if dt_start and dt_end:
            secs = max(0.0, (dt_end - dt_start).total_seconds())
    if secs is None:
        return default
    total = int(round(max(0.0, float(secs))))
    if total < 60:
        return f"{total}s"
    mins, rem_secs = divmod(total, 60)
    if mins < 60:
        return f"{mins}m {rem_secs}s"
    hours, rem_mins = divmod(mins, 60)
    return f"{hours}h {rem_mins}m"

