"""UTC boundaries: SQLite-owned naive strings are UTC; source times need offsets."""

from datetime import datetime, timezone
from markupsafe import Markup, escape


def parse_timestamp(value, *, sqlite_utc=False):
    if not value:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            if not sqlite_utc:
                return None
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def epoch_seconds(value):
    timestamp = parse_timestamp(value)
    return timestamp.timestamp() if timestamp else None


def utc_now_text():
    """Explicit UTC for new contact writes; the host clock remains authoritative."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _display(value, fallback, *, sqlite_utc):
    timestamp = parse_timestamp(value, sqlite_utc=sqlite_utc)
    if timestamp is None:
        return escape(fallback if not value else f'{value} (timezone unavailable)')
    iso = timestamp.isoformat().replace('+00:00', 'Z')
    text = timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
    return Markup('<time data-cdss-time datetime="{}" title="{}">{}</time>').format(iso, text, text)


def database_time(value, fallback='Time unavailable'):
    return _display(value, fallback, sqlite_utc=True)


def source_time(value, fallback='Time unavailable'):
    return _display(value, fallback, sqlite_utc=False)


def register_timestamp_filters(app):
    app.jinja_env.filters.update(db_time=database_time, source_time=source_time)
