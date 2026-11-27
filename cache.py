"""Store API lookup results in a local JSON file."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Next to cache.py, so every run uses the same file regardless of cwd.
CACHE_FILE = Path(__file__).parent / "lookup_cache.json"

# Detections can change within hours; older results are looked up again.
CACHE_MAX_AGE_HOURS = 6


def load_cache():
    """Load cached lookup results from CACHE_FILE.

    Return an empty dict if the file is missing or not valid JSON.
    """
    # The cache is only a copy; if it's missing or broken, start empty.
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache):
    """Write cache to CACHE_FILE, replacing its previous contents."""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)


def current_timestamp():
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def is_fresh(timestamp):
    """Return True if timestamp is less than CACHE_MAX_AGE_HOURS old.

    Return False for a bad timestamp, so the result is looked up again.
    """
    # ValueError: bad format; TypeError: not a string or no time zone.
    try:
        checked_at = datetime.fromisoformat(timestamp)
        age = datetime.now(timezone.utc) - checked_at
    except (ValueError, TypeError):
        return False

    return age < timedelta(hours=CACHE_MAX_AGE_HOURS)
