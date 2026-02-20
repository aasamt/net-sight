"""Tests for the settings loader (backend.settings)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from backend.settings import (
    AnomalySettings,
    Settings,
    get_defaults,
    load_settings,
    reset_to_defaults,
    save_settings,
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_defaults_no_file():
    """load_settings(None) returns built-in defaults."""
    settings = load_settings(None)
    assert settings.anomaly.chatty_pps == 50.0
    assert settings.anomaly.broadcast_pps == 30.0
    assert settings.anomaly.timesync_pps == 10.0
    assert settings.anomaly.unconfirmed_flood_pps == 30.0
    assert settings.anomaly.router_discovery_pps == 20.0
    assert settings.anomaly.error_pps == 10.0
    assert settings.anomaly.reject_pps == 5.0
    assert settings.anomaly.abort_pps == 5.0
    assert settings.anomaly.window_seconds == 10.0
    assert settings.anomaly.max_anomalies == 500
    assert settings.anomaly.cooldown_seconds == 30.0
    assert settings.settings_path is None


def test_defaults_missing_file():
    """A nonexistent path returns defaults without error."""
    settings = load_settings("/nonexistent/path/settings.toml")
    assert settings.anomaly.chatty_pps == 50.0
    assert settings.settings_path is None


# ---------------------------------------------------------------------------
# Partial overrides
# ---------------------------------------------------------------------------


def test_partial_override():
    """Only specified keys are overridden; others keep defaults."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = 100.0
cooldown_seconds = 5.0
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 100.0
    assert settings.anomaly.cooldown_seconds == 5.0
    # Defaults preserved
    assert settings.anomaly.broadcast_pps == 30.0
    assert settings.anomaly.window_seconds == 10.0
    assert settings.settings_path == f.name


def test_integer_coercion():
    """Integer values are coerced to float for float fields."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = 100
window_seconds = 5
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 100.0
    assert isinstance(settings.anomaly.chatty_pps, float)
    assert settings.anomaly.window_seconds == 5.0


def test_max_anomalies_int():
    """max_anomalies accepts integer values."""
    toml_content = b"""\
[anomaly_detection]
max_anomalies = 1000
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.max_anomalies == 1000
    assert isinstance(settings.anomaly.max_anomalies, int)


# ---------------------------------------------------------------------------
# Full override
# ---------------------------------------------------------------------------


def test_full_override():
    """All anomaly_detection keys can be set."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = 25.0
broadcast_pps = 15.0
timesync_pps = 5.0
unconfirmed_flood_pps = 20.0
router_discovery_pps = 10.0
error_pps = 3.0
reject_pps = 2.0
abort_pps = 1.5
window_seconds = 5.0
max_anomalies = 200
cooldown_seconds = 10.0
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    a = settings.anomaly
    assert a.chatty_pps == 25.0
    assert a.broadcast_pps == 15.0
    assert a.timesync_pps == 5.0
    assert a.unconfirmed_flood_pps == 20.0
    assert a.router_discovery_pps == 10.0
    assert a.error_pps == 3.0
    assert a.reject_pps == 2.0
    assert a.abort_pps == 1.5
    assert a.window_seconds == 5.0
    assert a.max_anomalies == 200
    assert a.cooldown_seconds == 10.0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_unknown_key_ignored():
    """Unknown keys produce a warning but don't crash."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = 100.0
nonexistent_key = 42
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 100.0


def test_wrong_type_uses_default():
    """A value of the wrong type falls back to the default."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = "not_a_number"
broadcast_pps = 15.0
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 50.0  # default
    assert settings.anomaly.broadcast_pps == 15.0  # overridden


def test_empty_file():
    """An empty TOML file returns all defaults."""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(b"")
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 50.0


def test_malformed_toml():
    """A malformed TOML file returns defaults without crashing."""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(b"[invalid toml {{{{")
        f.flush()
        settings = load_settings(f.name)

    assert settings.anomaly.chatty_pps == 50.0
    assert settings.settings_path is None


# ---------------------------------------------------------------------------
# to_kwargs integration
# ---------------------------------------------------------------------------


def test_anomaly_kwargs():
    """anomaly_kwargs() returns dict matching AnomalyDetector.__init__ params."""
    settings = load_settings(None)
    kwargs = settings.anomaly_kwargs()
    expected_keys = {
        "chatty_pps", "broadcast_pps", "timesync_pps", "unconfirmed_flood_pps",
        "router_discovery_pps", "error_pps", "reject_pps", "abort_pps",
        "window_seconds", "max_anomalies", "cooldown_seconds",
    }
    assert set(kwargs.keys()) == expected_keys

    # Should work with AnomalyDetector
    from backend.analysis.anomaly_detector import AnomalyDetector
    detector = AnomalyDetector(**kwargs)
    assert detector._chatty_pps == 50.0


def test_anomaly_kwargs_with_overrides():
    """Custom settings produce correct kwargs."""
    toml_content = b"""\
[anomaly_detection]
chatty_pps = 200.0
cooldown_seconds = 0.0
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        f.write(toml_content)
        f.flush()
        settings = load_settings(f.name)

    kwargs = settings.anomaly_kwargs()
    assert kwargs["chatty_pps"] == 200.0
    assert kwargs["cooldown_seconds"] == 0.0
    assert kwargs["broadcast_pps"] == 30.0  # default


# ---------------------------------------------------------------------------
# get_defaults
# ---------------------------------------------------------------------------


def test_get_defaults():
    """get_defaults() returns AnomalySettings with all built-in values."""
    defaults = get_defaults()
    assert isinstance(defaults, AnomalySettings)
    assert defaults.chatty_pps == 50.0
    assert defaults.broadcast_pps == 30.0
    assert defaults.window_seconds == 10.0


# ---------------------------------------------------------------------------
# save_settings round-trip
# ---------------------------------------------------------------------------


def test_save_and_reload():
    """Settings saved to a file can be loaded back identically."""
    settings = load_settings(None)
    settings.anomaly.chatty_pps = 123.0
    settings.anomaly.cooldown_seconds = 0.5

    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        out_path = f.name

    save_settings(settings, out_path)

    reloaded = load_settings(out_path)
    assert reloaded.anomaly.chatty_pps == 123.0
    assert reloaded.anomaly.cooldown_seconds == 0.5
    # Defaults preserved
    assert reloaded.anomaly.broadcast_pps == 30.0
    assert reloaded.anomaly.window_seconds == 10.0
    os.remove(out_path)


def test_save_creates_readable_toml():
    """Saved file should be valid TOML with comments."""
    settings = load_settings(None)

    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        out_path = f.name

    save_settings(settings, out_path)

    content = Path(out_path).read_text()
    assert "[anomaly_detection]" in content
    assert "chatty_pps" in content
    assert "#" in content  # Has comments
    os.remove(out_path)


def test_save_marks_non_default_values():
    """Non-default values should have a '# default:' comment."""
    settings = load_settings(None)
    settings.anomaly.chatty_pps = 999.0

    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        out_path = f.name

    save_settings(settings, out_path)

    content = Path(out_path).read_text()
    assert "# default: 50.0" in content
    assert "chatty_pps = 999.0" in content
    os.remove(out_path)


def test_save_uses_settings_path_if_set():
    """save_settings with no explicit path uses settings.settings_path."""
    with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
        out_path = f.name

    settings = load_settings(None)
    settings.settings_path = out_path

    result_path = save_settings(settings)
    assert str(result_path) == out_path
    assert Path(out_path).exists()
    os.remove(out_path)


# ---------------------------------------------------------------------------
# reset_to_defaults
# ---------------------------------------------------------------------------


def test_reset_to_defaults(tmp_path, monkeypatch):
    """reset_to_defaults copies default_settings.toml into user_settings.toml."""
    import backend.settings as _mod

    default_file = tmp_path / "default_settings.toml"
    user_file = tmp_path / "user_settings.toml"

    # Write a defaults file with known values
    default_file.write_text(
        "[anomaly_detection]\nchatty_pps = 50.0\nbroadcast_pps = 30.0\n"
    )

    # Write a user file with custom values
    user_file.write_text(
        "[anomaly_detection]\nchatty_pps = 999.0\nbroadcast_pps = 1.0\n"
    )

    monkeypatch.setattr(_mod, "_DEFAULT_SETTINGS_PATH", default_file)
    monkeypatch.setattr(_mod, "_USER_SETTINGS_PATH", user_file)

    result = reset_to_defaults()
    assert result.anomaly.chatty_pps == 50.0
    assert result.anomaly.broadcast_pps == 30.0

    # Verify user_settings.toml was overwritten
    reloaded = load_settings(user_file)
    assert reloaded.anomaly.chatty_pps == 50.0


def test_get_defaults_reads_default_settings_file(tmp_path, monkeypatch):
    """get_defaults reads from default_settings.toml when it exists."""
    import backend.settings as _mod

    default_file = tmp_path / "default_settings.toml"
    default_file.write_text(
        "[anomaly_detection]\nchatty_pps = 50.0\nwindow_seconds = 10.0\n"
    )
    monkeypatch.setattr(_mod, "_DEFAULT_SETTINGS_PATH", default_file)

    defaults = get_defaults()
    assert defaults.chatty_pps == 50.0
    assert defaults.window_seconds == 10.0


def test_get_defaults_fallback_no_file(tmp_path, monkeypatch):
    """get_defaults falls back to dataclass defaults if file missing."""
    import backend.settings as _mod

    monkeypatch.setattr(_mod, "_DEFAULT_SETTINGS_PATH", tmp_path / "nonexistent.toml")
    defaults = get_defaults()
    assert defaults.chatty_pps == 50.0


# ---------------------------------------------------------------------------
# Direct-run support
# ---------------------------------------------------------------------------

_DIRECT_RUN = [
    test_defaults_no_file,
    test_defaults_missing_file,
    test_partial_override,
    test_integer_coercion,
    test_max_anomalies_int,
    test_full_override,
    test_unknown_key_ignored,
    test_wrong_type_uses_default,
    test_empty_file,
    test_malformed_toml,
    test_anomaly_kwargs,
    test_anomaly_kwargs_with_overrides,
    test_get_defaults,
    test_save_and_reload,
    test_save_creates_readable_toml,
    test_save_marks_non_default_values,
    test_save_uses_settings_path_if_set,
    # These require pytest (monkeypatch / tmp_path):
    # test_reset_to_defaults,
    # test_get_defaults_reads_default_settings_file,
    # test_get_defaults_fallback_no_file,
]

if __name__ == "__main__":
    for fn in _DIRECT_RUN:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {e}")
