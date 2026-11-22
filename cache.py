"""Store API lookup results in a local JSON file."""

import json

CACHE_FILE = "lookup_cache.json"

# Detections can change within hours; older results are looked up again.
CACHE_MAX_AGE_HOURS = 6


def load_cache():
    """Load cached lookup results from CACHE_FILE.

    Return an empty dict if the file does not exist or is not valid
    JSON.
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
        json.dump(cache, f, indent=2)
