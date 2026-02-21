"""Settings loader — two-file architecture (user + defaults).

NetSight uses two settings files at the project root:

- ``settings_user.toml``    — active settings the app reads from. Editable by
  the user directly or via the TUI Settings tab.
- ``settings_default.toml`` — immutable reference of built-in defaults. Used
  only when the user resets to defaults.

Usage::

    from backend.settings import load_settings, save_settings, reset_to_defaults

    settings = load_settings()                          # reads settings_user.toml
    settings = load_settings("custom.toml")            # explicit path
    settings = load_settings(None)                      # pure defaults (no file)

    detector = AnomalyDetector(**settings.anomaly_kwargs())

    # Modify and persist
    settings.anomaly.chatty_pps = 100.0
    save_settings(settings)                              # writes settings_user.toml

    # Reset to defaults
    settings = reset_to_defaults()                       # copies default → user
"""

from __future__ import annotations

import logging
import textwrap
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Project root: two levels up from this file (backend/settings.py → repo root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_USER_SETTINGS_PATH = _PROJECT_ROOT / "settings_user.toml"
_DEFAULT_SETTINGS_PATH = _PROJECT_ROOT / "settings_default.toml"


# ---------------------------------------------------------------------------
# Defaults — mirror AnomalyDetector.__init__ keyword defaults
# ---------------------------------------------------------------------------

_ANOMALY_DEFAULTS: dict[str, float | int] = {
    "window_seconds": 10.0,
    "cooldown_seconds": 30.0,
    "max_anomalies": 500,
    "chatty_pps": 50.0,
    "broadcast_pps": 30.0,
    "timesync_pps": 10.0,
    "unconfirmed_flood_pps": 30.0,
    "router_discovery_pps": 20.0,
    "error_pps": 10.0,
    "reject_pps": 5.0,
    "abort_pps": 5.0,
}


@dataclass
class AnomalySettings:
    """Anomaly detection thresholds and parameters."""

    chatty_pps: float = 50.0
    broadcast_pps: float = 30.0
    timesync_pps: float = 10.0
    unconfirmed_flood_pps: float = 30.0
    router_discovery_pps: float = 20.0
    error_pps: float = 10.0
    reject_pps: float = 5.0
    abort_pps: float = 5.0
    window_seconds: float = 10.0
    max_anomalies: int = 500
    cooldown_seconds: float = 30.0

    def to_kwargs(self) -> dict[str, float | int]:
        """Return a dict suitable for ``AnomalyDetector(**kwargs)``."""
        return {
            "chatty_pps": self.chatty_pps,
            "broadcast_pps": self.broadcast_pps,
            "timesync_pps": self.timesync_pps,
            "unconfirmed_flood_pps": self.unconfirmed_flood_pps,
            "router_discovery_pps": self.router_discovery_pps,
            "error_pps": self.error_pps,
            "reject_pps": self.reject_pps,
            "abort_pps": self.abort_pps,
            "window_seconds": self.window_seconds,
            "max_anomalies": self.max_anomalies,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class Settings:
    """Top-level settings container."""

    anomaly: AnomalySettings = field(default_factory=AnomalySettings)
    settings_path: str | None = None  # path that was loaded, for diagnostics

    def anomaly_kwargs(self) -> dict[str, float | int]:
        """Shortcut: return kwargs for ``AnomalyDetector(...)``."""
        return self.anomaly.to_kwargs()


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_settings(path: str | Path | None = _USER_SETTINGS_PATH) -> Settings:
    """Load settings from a TOML file, falling back to defaults.

    Args:
        path: Path to settings file. Defaults to ``settings_user.toml``
              in the project root. If ``None``, returns pure defaults
              without reading any file. If the file doesn't exist, logs
              a debug message and returns defaults.

    Returns:
        A ``Settings`` instance with all values populated.
    """
    settings = Settings()

    if path is None:
        logger.debug("Settings: using built-in defaults (no file specified)")
        return settings

    toml_path = Path(path)
    if not toml_path.is_file():
        logger.debug("Settings: %s not found, using built-in defaults", toml_path)
        return settings

    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        logger.warning("Settings: failed to parse %s, using defaults", toml_path, exc_info=True)
        return settings

    settings.settings_path = str(toml_path)

    # --- anomaly_detection section ---
    anomaly_data = data.get("anomaly_detection", {})
    anomaly = settings.anomaly

    _VALID_KEYS = set(_ANOMALY_DEFAULTS.keys())
    for key, value in anomaly_data.items():
        if key not in _VALID_KEYS:
            logger.warning("Settings: unknown key 'anomaly_detection.%s' — ignored", key)
            continue

        expected_type = type(_ANOMALY_DEFAULTS[key])
        # Accept int for float fields
        if expected_type is float and isinstance(value, int):
            value = float(value)
        elif expected_type is int and isinstance(value, float) and value == int(value):
            value = int(value)

        if not isinstance(value, expected_type):
            logger.warning(
                "Settings: anomaly_detection.%s expected %s, got %s — using default",
                key,
                expected_type.__name__,
                type(value).__name__,
            )
            continue

        setattr(anomaly, key, value)

    logger.info("Settings: loaded from %s", toml_path)
    return settings


def get_defaults() -> AnomalySettings:
    """Return a fresh ``AnomalySettings`` with built-in defaults.

    If ``settings_default.toml`` exists, reads values from it so that
    the single source of truth for defaults is the file.  Falls back
    to the dataclass defaults if the file is missing.
    """
    if _DEFAULT_SETTINGS_PATH.is_file():
        s = load_settings(_DEFAULT_SETTINGS_PATH)
        return s.anomaly
    return AnomalySettings()


def reset_to_defaults() -> Settings:
    """Reset user settings to defaults.

    Reads ``settings_default.toml``, writes its contents to
    ``settings_user.toml``, and returns the resulting ``Settings``.
    """
    defaults = get_defaults()
    settings = Settings(anomaly=defaults, settings_path=str(_USER_SETTINGS_PATH))
    save_settings(settings, _USER_SETTINGS_PATH)
    return settings


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

# Human-readable descriptions for each setting, used in the generated TOML.
_ANOMALY_DESCRIPTIONS: dict[str, str] = {
    "window_seconds": "Sliding window duration for all rate calculations (seconds).",
    "cooldown_seconds": (
        "Minimum time between repeated alerts of the same type (seconds).\n"
        "# Prevents alert fatigue during sustained events."
    ),
    "max_anomalies": "Maximum number of anomaly records to keep in memory.",
    "chatty_pps": (
        "Per-source-IP packets/sec threshold. A single device exceeding this\n"
        "# rate is flagged as \"chatty.\""
    ),
    "broadcast_pps": "Discovery flood: Who-Is, I-Am, Who-Has, I-Have (pps).",
    "timesync_pps": "TimeSynchronization / UTC-TimeSynchronization flood (pps).",
    "unconfirmed_flood_pps": "UnconfirmedCOVNotification / WriteGroup flood (pps).",
    "router_discovery_pps": "Router discovery flood: Who-Is-Router / I-Am-Router (pps).",
    "error_pps": "Aggregate error PDU rate (BACnet-Error responses, pps).",
    "reject_pps": "Aggregate reject PDU rate (BACnet-Reject responses, pps).",
    "abort_pps": "Aggregate abort PDU rate (BACnet-Abort responses, pps).",
}

# Logical grouping and order for the TOML output.
_ANOMALY_GROUPS: list[tuple[str, list[str]]] = [
    ("General", ["window_seconds", "cooldown_seconds", "max_anomalies"]),
    ("Chatty Device", ["chatty_pps"]),
    (
        "Broadcast Storm",
        ["broadcast_pps", "timesync_pps", "unconfirmed_flood_pps", "router_discovery_pps"],
    ),
    ("Error / Reject / Abort Rates", ["error_pps", "reject_pps", "abort_pps"]),
]


def _format_value(value: float | int) -> str:
    """Format a numeric value for TOML output."""
    if isinstance(value, int):
        return str(value)
    # Always show at least one decimal for float
    if value == int(value):
        return f"{value:.1f}"
    return str(value)


def save_settings(settings: Settings, path: str | Path | None = None) -> Path:
    """Write the current settings to a TOML file.

    Generates a well-commented, human-readable TOML file grouped by category.

    Args:
        settings: The ``Settings`` instance to persist.
        path: Destination path. Falls back to ``settings.settings_path``,
              then to the default ``settings.toml`` in the project root.

    Returns:
        The ``Path`` that was written to.

    Raises:
        OSError: If the file cannot be written.
    """
    if path is not None:
        out = Path(path)
    elif settings.settings_path:
        out = Path(settings.settings_path)
    else:
        out = _USER_SETTINGS_PATH

    kwargs = settings.anomaly.to_kwargs()
    defaults = _ANOMALY_DEFAULTS

    lines: list[str] = [
        "# " + "─" * 68,
        "# NetSight — User Settings",
        "# " + "─" * 68,
        "# Your customized thresholds and parameters.",
        "# Edit this file or use the TUI Settings tab to tune anomaly detection.",
        "#",
        "# All rate thresholds are in packets-per-second (pps).",
        "# Time values are in seconds.",
        "#",
        "# To restore defaults, use the TUI Settings tab \"Reset to Defaults\"",
        "# button, which copies settings_default.toml into this file.",
        "# " + "─" * 68,
        "",
        "[anomaly_detection]",
    ]

    for group_name, keys in _ANOMALY_GROUPS:
        lines.append("")
        lines.append(f"# ── {group_name} " + "─" * max(1, 58 - len(group_name)))
        lines.append("")
        for key in keys:
            desc = _ANOMALY_DESCRIPTIONS.get(key, "")
            if desc:
                for desc_line in desc.split("\n"):
                    lines.append(f"# {desc_line}")
            val = kwargs.get(key, defaults[key])
            default_val = defaults[key]
            if val != default_val:
                lines.append(f"# default: {_format_value(default_val)}")
            lines.append(f"{key} = {_format_value(val)}")
            lines.append("")

    content = "\n".join(lines)
    out.write_text(content, encoding="utf-8")
    settings.settings_path = str(out)
    logger.info("Settings: saved to %s", out)
    return out
