"""
License validation for self-hosted SecureLink instances.

When LICENSE_KEY is set in the environment, this module validates it against
securelinkapp.com and caches the result. The cached tier controls which features
are available on the self-hosted instance.

Without a valid license key, the instance runs in free tier only.
"""
import json
import os
import tempfile
import time
import threading
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)

VALIDATION_URL = 'https://securelinkapp.com/api/license/validate'
CACHE_TTL = 86400          # re-validate every 24 hours
CACHE_GRACE = 86400 * 7   # keep stale cache for 7 days if validation fails
CACHE_FILE = os.path.join(tempfile.gettempdir(), 'securelink_license.json')

_lock = threading.Lock()
_cached_tier: str | None = None
_cache_expires: float = 0


def get_instance_tier() -> str:
    """
    Return the tier unlocked by LICENSE_KEY ('free', 'pro', or 'enterprise').
    Falls back to 'free' if no key is set or validation fails with no cache.
    """
    global _cached_tier, _cache_expires

    from config import Config
    key = Config.LICENSE_KEY
    if not key:
        return 'free'

    now = time.time()
    with _lock:
        if _cached_tier is not None and now < _cache_expires:
            return _cached_tier

    # Validate remotely (outside the lock so we don't block requests)
    tier = _validate_remote(key)

    with _lock:
        _cached_tier = tier
        _cache_expires = now + CACHE_TTL

    _save_cache(tier)
    return tier


def is_self_hosted() -> bool:
    """True when a LICENSE_KEY env var is present (i.e. running as self-hosted)."""
    from config import Config
    return bool(Config.LICENSE_KEY)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_remote(key: str) -> str:
    """Call securelinkapp.com to validate the key. Returns tier string."""
    try:
        payload = json.dumps({'key': key}).encode()
        req = urllib.request.Request(
            VALIDATION_URL,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            tier = data.get('tier', 'free')
            logger.info(f'License validated — tier: {tier}')
            return tier
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.warning('License key invalid or inactive — falling back to free tier')
        else:
            logger.warning(f'License validation HTTP error {e.code} — using cache')
        return _load_cache() or 'free'
    except Exception as exc:
        logger.warning(f'License validation failed ({exc}) — using cache')
        return _load_cache() or 'free'


def _load_cache() -> str | None:
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        if time.time() < data.get('expires', 0):
            return data.get('tier')
    except Exception:
        pass
    return None


def _save_cache(tier: str) -> None:
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump({'tier': tier, 'expires': time.time() + CACHE_GRACE}, f)
    except Exception:
        pass


def validate_on_startup() -> None:
    """Call once at startup to warm the cache and log the result."""
    from config import Config
    if not Config.LICENSE_KEY:
        return
    tier = get_instance_tier()
    logger.info(f'Self-hosted instance — license tier: {tier}')
