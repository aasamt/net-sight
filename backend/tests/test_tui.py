"""Phase 5b tests — TUI dashboard, --plain flag, --tui-packets flag.

Tests cover:
- CLI flag parsing (--plain, --tui-packets)
- Widget initialization and data flow
- TUI app lifecycle (Textual Pilot headless tests)
- Pcap replay end-to-end in TUI mode
- Keyboard bindings (pause/resume, save)
- Plain mode backward compatibility
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_DIRECT_RUN = __name__ == "__main__"

from backend.main import build_parser, run_tui
from backend.models.packet import ParsedPacket
from backend.settings import Settings
from backend.tui.app import NetSightApp
from backend.tui.widgets import (
    AnomalyLog,
    DevicePanel,
    PacketTable,
    SettingsPanel,
    StatsPanel,
    TopTalkersPanel,
)
from backend.transport.pcap_replay import PcapReplayCapture


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_PCAP = os.path.join(
    os.path.dirname(__file__), "fixtures", "test_bacnet.pcap"
)


def _make_transport() -> PcapReplayCapture:
    """Create a PcapReplayCapture for the test pcap file."""
    return PcapReplayCapture(file_path=SAMPLE_PCAP)


def _make_app(**kwargs: object) -> NetSightApp:
    """Create a NetSightApp instance for testing."""
    transport = _make_transport()
    defaults = {
        "is_live": False,
        "source_name": "test_bacnet.pcap",
        "max_rows": 50,
        "settings": Settings(),  # pure defaults, independent of settings_user.toml
    }
    defaults.update(kwargs)
    return NetSightApp(transport, **defaults)


# ---------------------------------------------------------------------------
# CLI Flag Tests
# ---------------------------------------------------------------------------

class TestCLIFlags:
    """Test --plain and --tui-packets argument parsing."""

    def test_plain_flag_default_false(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap"])
        assert args.plain is False

    def test_plain_flag_enabled(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap", "--plain"])
        assert args.plain is True

    def test_tui_packets_default_50(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap"])
        assert args.tui_packets == 50

    def test_tui_packets_custom(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap", "--tui-packets", "100"])
        assert args.tui_packets == 100

    def test_tui_packets_with_plain(self) -> None:
        """--tui-packets and --plain can coexist (tui-packets is ignored)."""
        parser = build_parser()
        args = parser.parse_args(["-f", "test.pcap", "--plain", "--tui-packets", "25"])
        assert args.plain is True
        assert args.tui_packets == 25

    def test_plain_with_interface(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-i", "en0", "--plain"])
        assert args.plain is True
        assert args.interface == "en0"


# ---------------------------------------------------------------------------
# Widget Unit Tests (synchronous init/structure checks)
# ---------------------------------------------------------------------------

class TestWidgetStructure:
    """Test widget initialization (without mounting in a full app)."""

    def test_packet_table_max_rows(self) -> None:
        pt = PacketTable(max_rows=25)
        assert pt.max_rows == 25

    def test_packet_table_default_max_rows(self) -> None:
        pt = PacketTable()
        assert pt.max_rows == 50

    def test_anomaly_log_max_entries(self) -> None:
        log = AnomalyLog(max_entries=100)
        assert log._entries.maxlen == 100


# ---------------------------------------------------------------------------
# TUI App Initialization Tests
# ---------------------------------------------------------------------------

class TestAppInit:
    """Test NetSightApp initialization without running."""

    def test_app_creates_analysis_engines(self) -> None:
        app = _make_app()
        assert app._device_registry is not None
        assert app._traffic_stats is not None
        assert app._anomaly_detector is not None

    def test_app_default_state(self) -> None:
        app = _make_app()
        assert app._packet_count == 0
        assert app._paused is False
        assert app._replay_complete is False
        assert app._dropped_count == 0

    def test_app_pcap_mode(self) -> None:
        app = _make_app(is_live=False)
        assert app._is_live is False

    def test_app_live_mode(self) -> None:
        app = _make_app(is_live=True)
        assert app._is_live is True

    def test_app_max_rows(self) -> None:
        app = _make_app(max_rows=100)
        assert app._max_rows == 100

    def test_app_save_path(self) -> None:
        app = _make_app(save_path="/tmp/test.jsonl")
        assert app._save_path == "/tmp/test.jsonl"


# ---------------------------------------------------------------------------
# TUI App Pilot Tests (headless Textual testing)
# ---------------------------------------------------------------------------

class TestTUIEndToEnd:
    """End-to-end TUI tests using Textual's headless Pilot mode."""

    @pytest.fixture
    def pcap_app(self) -> NetSightApp:
        return _make_app()

    async def test_pcap_replay_processes_all_packets(self, pcap_app: NetSightApp) -> None:
        """TUI should process all 5 packets from the test pcap."""
        async with pcap_app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            assert pcap_app._packet_count == 5
            assert pcap_app._replay_complete is True
            await pilot.press("q")

    async def test_devices_discovered(self, pcap_app: NetSightApp) -> None:
        """TUI should discover devices from I-Am packets."""
        async with pcap_app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            devices = pcap_app._device_registry.get_all_devices()
            assert len(devices) == 2
            await pilot.press("q")

    async def test_stats_accumulated(self, pcap_app: NetSightApp) -> None:
        """Traffic stats should accumulate from all packets."""
        async with pcap_app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            assert pcap_app._traffic_stats.total_packets == 5
            assert pcap_app._traffic_stats.total_bytes > 0
            await pilot.press("q")

    async def test_packets_stored_for_save(self, pcap_app: NetSightApp) -> None:
        """All parsed packets should be stored for save functionality."""
        async with pcap_app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            assert len(pcap_app._parsed_packets) == 5
            assert all(isinstance(p, ParsedPacket) for p in pcap_app._parsed_packets)
            await pilot.press("q")

    async def test_pause_toggle(self, pcap_app: NetSightApp) -> None:
        """P key should toggle pause state."""
        async with pcap_app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(1)
            assert pcap_app._paused is False
            await pilot.press("p")
            assert pcap_app._paused is True
            await pilot.press("p")
            assert pcap_app._paused is False
            await pilot.press("q")

    async def test_save_creates_jsonl(self) -> None:
        """S key should save packets to a JSONL file."""
        app = _make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            await pilot.press("s")
            await asyncio.sleep(0.5)
            # Find the generated file
            import glob
            files = glob.glob("netsight_capture_*.jsonl")
            assert len(files) >= 1, "Save action should create a JSONL file"
            # Verify content
            with open(files[0]) as f:
                lines = f.readlines()
            assert len(lines) == 5
            # Cleanup
            for f in files:
                os.remove(f)
            await pilot.press("q")

    async def test_save_with_path(self) -> None:
        """Auto-save via save_path should write packets incrementally."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            app = _make_app(save_path=tmp_path)
            async with app.run_test(size=(120, 40)) as pilot:
                await asyncio.sleep(2)
                await pilot.press("q")

            with open(tmp_path) as f:
                lines = f.readlines()
            assert len(lines) == 5
        finally:
            os.unlink(tmp_path)

    async def test_quit_stops_transport(self) -> None:
        """Q key should stop the transport and exit."""
        app = _make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(1)
            await pilot.press("q")
        # App should have exited cleanly

    async def test_custom_max_rows(self) -> None:
        """Custom max_rows should be passed to PacketTable."""
        app = _make_app(max_rows=10)
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(1)
            packet_table = app.query_one("#packet-panel", PacketTable)
            assert packet_table.max_rows == 10
            await pilot.press("q")

    async def test_status_bar_shows_replay_complete(self) -> None:
        """App should mark replay as complete after pcap finishes."""
        app = _make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(2)
            assert app._replay_complete is True
            assert app._packet_count == 5
            await pilot.press("q")

    async def test_widget_hierarchy(self) -> None:
        """Verify all expected widgets are present in the app."""
        app = _make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(0.5)
            assert app.query_one("#packet-panel", PacketTable)
            assert app.query_one("#stats-panel", StatsPanel)
            assert app.query_one("#device-panel", DevicePanel)
            assert app.query_one("#top-talkers-panel", TopTalkersPanel)
            assert app.query_one("#anomaly-panel", AnomalyLog)
            await pilot.press("q")


# ---------------------------------------------------------------------------
# Plain Mode Backward Compatibility
# ---------------------------------------------------------------------------

class TestPlainMode:
    """Verify --plain mode still works (calls run_capture)."""

    async def test_plain_mode_runs_capture(self) -> None:
        """--plain should call run_capture instead of run_tui."""
        from backend.main import main

        with patch("backend.main.run_capture") as mock_capture:
            mock_capture.return_value = None
            with patch(
                "sys.argv",
                ["netsight", "-f", SAMPLE_PCAP, "--plain"],
            ):
                with patch("asyncio.run") as mock_run:
                    main()
                    mock_run.assert_called_once()

    def test_plain_flag_not_set_calls_tui(self) -> None:
        """Without --plain, should call run_tui."""
        from backend.main import main

        with patch("backend.main.run_tui") as mock_tui:
            with patch(
                "sys.argv",
                ["netsight", "-f", SAMPLE_PCAP],
            ):
                main()
                mock_tui.assert_called_once()


# ---------------------------------------------------------------------------
# run_tui Function Tests
# ---------------------------------------------------------------------------

class TestRunTuiFunction:
    """Test the run_tui() helper function."""

    def test_run_tui_with_file(self) -> None:
        """run_tui should create app with PcapReplayCapture for -f flag."""
        parser = build_parser()
        args = parser.parse_args(["-f", SAMPLE_PCAP])

        with patch("backend.tui.app.NetSightApp.run") as mock_run:
            run_tui(args)
            mock_run.assert_called_once()

    def test_run_tui_with_interface(self) -> None:
        """run_tui should create app with BACnetIPCapture for -i flag."""
        parser = build_parser()
        args = parser.parse_args(["-i", "en0"])

        with patch("backend.tui.app.NetSightApp.run") as mock_run:
            run_tui(args)
            mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# Settings Tab Tests
# ---------------------------------------------------------------------------

class TestSettingsTab:
    """Test the Settings tab in the TUI."""

    def test_app_has_settings(self) -> None:
        """App should have a _settings attribute."""
        app = _make_app()
        assert app._settings is not None
        assert app._settings.anomaly.chatty_pps == 50.0

    def test_app_custom_settings(self) -> None:
        """App should accept custom settings."""
        from backend.settings import Settings

        settings = Settings()
        settings.anomaly.chatty_pps = 999.0
        app = _make_app(settings=settings)
        assert app._settings.anomaly.chatty_pps == 999.0
        assert app._anomaly_detector._chatty_pps == 999.0

    async def test_settings_panel_present(self) -> None:
        """Settings tab should exist in the TUI."""
        app = _make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(0.5)
            panel = app.query_one("#settings-panel-tab", SettingsPanel)
            assert panel is not None
            await pilot.press("q")

    async def test_settings_panel_loads_values(self) -> None:
        """Settings panel should display current values after mount."""
        from backend.settings import Settings

        settings = Settings()
        settings.anomaly.chatty_pps = 75.0
        app = _make_app(settings=settings)
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(0.5)
            panel = app.query_one("#settings-panel-tab", SettingsPanel)
            values = panel.get_values()
            assert values["chatty_pps"] == 75.0
            await pilot.press("q")

    async def test_settings_reset_restores_defaults(self, tmp_path, monkeypatch) -> None:
        """Reset button should restore all values to defaults."""
        import backend.settings as _mod

        from textual.widgets import Button

        # Isolate from real settings files
        default_file = tmp_path / "settings_default.toml"
        user_file = tmp_path / "settings_user.toml"
        default_file.write_text("[anomaly_detection]\nchatty_pps = 50.0\n")
        user_file.write_text("[anomaly_detection]\nchatty_pps = 999.0\n")
        monkeypatch.setattr(_mod, "_DEFAULT_SETTINGS_PATH", default_file)
        monkeypatch.setattr(_mod, "_USER_SETTINGS_PATH", user_file)

        settings = Settings()
        settings.anomaly.chatty_pps = 999.0
        settings.settings_path = str(user_file)
        app = _make_app(settings=settings)
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(0.5)
            # Simulate reset
            app._reset_settings_to_defaults()
            await asyncio.sleep(0.2)
            assert app._settings.anomaly.chatty_pps == 50.0
            assert app._anomaly_detector._chatty_pps == 50.0
            await pilot.press("q")

    async def test_settings_apply_updates_detector(self) -> None:
        """Saving settings should update the running anomaly detector."""
        import tempfile

        from backend.settings import Settings

        settings = Settings()
        # Use a temp file so we don't modify the real settings.toml
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            settings.settings_path = f.name

        app = _make_app(settings=settings)
        async with app.run_test(size=(120, 40)) as pilot:
            await asyncio.sleep(0.5)
            # Modify the chatty_pps input
            from textual.widgets import Input

            inp = app.query_one("#setting-chatty_pps", Input)
            inp.value = "200"
            # Trigger save
            app._apply_and_save_settings()
            await asyncio.sleep(0.2)
            assert app._anomaly_detector._chatty_pps == 200.0
            assert app._settings.anomaly.chatty_pps == 200.0
            await pilot.press("q")

        os.unlink(f.name)


# ---------------------------------------------------------------------------
# Run standalone
# ---------------------------------------------------------------------------

if _DIRECT_RUN:
    pytest.main([__file__, "-v", "--tb=short"])
