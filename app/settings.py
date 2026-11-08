"""
Runtime settings, read from the environment on every use.

WAZUH_UTILS_API_KEY / WAZUH_UTILS_API_KEY_FILE
    The bearer token callers (CoPilot) must send as ``Authorization: Bearer <key>``.
    Prefer the _FILE form (a root-only file) in the systemd unit. When a key is
    configured it is required on every route. Without one, the legacy
    /sysmon-config route stays open for backwards compatibility and
    /shared-files refuses to work at all.
WAZUH_UTILS_ALLOWED_SHA256
    Optional comma-separated allow-list for /shared-files, as ``name:sha256``
    entries (or bare sha256). When set, a stolen key alone cannot place arbitrary
    code: only these exact scripts, under these names.
WAZUH_UTILS_SHARED_DIR
    The Wazuh shared groups directory (default /var/ossec/etc/shared).
"""
import os
from pathlib import Path
from typing import FrozenSet
from typing import Optional
from typing import Tuple

DEFAULT_SHARED_DIR = "/var/ossec/etc/shared"


def shared_dir() -> Path:
    return Path(os.environ.get("WAZUH_UTILS_SHARED_DIR", DEFAULT_SHARED_DIR))


def api_key() -> Tuple[Optional[str], Optional[str]]:
    """``(key, problem)``. A key file that is set but unreadable is a problem, not
    "no key": that must fail closed instead of silently opening the routes."""
    key = os.environ.get("WAZUH_UTILS_API_KEY", "").strip()
    if key:
        return key, None
    path = os.environ.get("WAZUH_UTILS_API_KEY_FILE", "").strip()
    if not path:
        return None, None
    try:
        key = Path(path).read_text().strip()
    except OSError as e:
        return None, f"WAZUH_UTILS_API_KEY_FILE is set but unreadable: {e}"
    if not key:
        return None, "WAZUH_UTILS_API_KEY_FILE is set but empty"
    return key, None


def allowed_sha256() -> Optional[FrozenSet[str]]:
    """Entries are ``<file name>:<sha256>`` (bound to that name, preferred) or a bare
    ``<sha256>`` (allowed under any allow-listed name)."""
    raw = os.environ.get("WAZUH_UTILS_ALLOWED_SHA256", "")
    values = frozenset(v.strip().lower() for v in raw.split(",") if v.strip())
    return values or None


def hash_allowed(name: str, digest: str, pinned: FrozenSet[str]) -> bool:
    return name.lower() + ":" + digest in pinned or digest in pinned
