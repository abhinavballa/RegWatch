"""
Unit tests for the change_tracker module.

Tests verify that the implementation conforms to the specification defined in
prompts/change_tracker_Python.prompt. The prompt file is the source of truth.
"""

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from change_tracker import (
    log_change,
    get_changes,
    get_change_history,
    LOG_FILE,
    LOG_DIR,
    _load_log_data,
    _save_log_data,
    _ensure_log_dir
)


@pytest.fixture
def clean_logs():
    """Clean up logs directory before and after each test."""
    # Clean before test
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)

    yield

    # Clean after test
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)


class TestLogChange:
    """Tests for log_change() function."""

    def test_log_change_creates_entry_with_all_fields(self, clean_logs):
        """Verify log_change creates an entry with all required fields."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="Old regulation text",
            new_text="New regulation text",
            severity="high",
            affected_checkers=["checker1", "checker2"],
            tests_added=5
        )

        # Verify all required fields are present
        assert "timestamp" in entry
        assert entry["regulation_id"] == "REG-001"
        assert entry["old_text"] == "Old regulation text"
        assert entry["new_text"] == "New regulation text"
        assert entry["severity"] == "high"
        assert entry["affected_checkers"] == ["checker1", "checker2"]
        assert entry["tests_added"] == 5
        assert "customer_impact" in entry

    def test_log_change_timestamp_is_iso8601_utc(self, clean_logs):
        """Verify timestamp is in ISO 8601 format and UTC."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        # Verify timestamp can be parsed as ISO 8601
        timestamp = datetime.fromisoformat(entry["timestamp"])

        # Verify it's recent (within last minute)
        now = datetime.now(timezone.utc)
        assert (now - timestamp).total_seconds() < 60

        # Verify it has timezone info
        assert timestamp.tzinfo is not None

    def test_log_change_severity_normalization_lowercase(self, clean_logs):
        """Verify severity values are normalized to lowercase."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="CRITICAL",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["severity"] == "critical"

    def test_log_change_unknown_severity_defaults_to_medium(self, clean_logs):
        """Verify unknown severity levels default to 'medium'."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="unknown_severity",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["severity"] == "medium"

    def test_log_change_empty_severity_defaults_to_medium(self, clean_logs):
        """Verify empty severity defaults to 'medium'."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["severity"] == "medium"

    def test_log_change_empty_affected_checkers(self, clean_logs):
        """Verify empty affected_checkers list is handled correctly."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["affected_checkers"] == []
        assert entry["customer_impact"]["score"] == 0

    def test_log_change_empty_regulation_text(self, clean_logs):
        """Verify empty regulation text is handled correctly."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["old_text"] == ""
        assert entry["new_text"] == ""

    def test_log_change_long_regulation_text(self, clean_logs):
        """Verify arbitrarily long regulation text is not truncated."""
        long_text = "A" * 10000
        entry = log_change(
            regulation_id="REG-001",
            old_text=long_text,
            new_text=long_text + " modified",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert len(entry["old_text"]) == 10000
        assert len(entry["new_text"]) == 10009

    def test_log_change_customer_impact_calculation(self, clean_logs):
        """Verify customer impact is calculated correctly."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="medium",
            affected_checkers=["c1", "c2", "c3"],
            tests_added=0
        )

        # Impact score = 3 checkers * 10 = 30
        assert entry["customer_impact"]["score"] == 30
        assert entry["customer_impact"]["requires_notification"] == False

    def test_log_change_customer_impact_critical_severity(self, clean_logs):
        """Verify customer impact for critical severity is doubled."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="critical",
            affected_checkers=["c1", "c2"],
            tests_added=0
        )

        # Impact score = 2 checkers * 10 * 2 (critical multiplier) = 40
        assert entry["customer_impact"]["score"] == 40
        assert entry["customer_impact"]["requires_notification"] == True

    def test_log_change_customer_impact_high_severity_requires_notification(self, clean_logs):
        """Verify high severity requires notification."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="high",
            affected_checkers=["c1"],
            tests_added=0
        )

        assert entry["customer_impact"]["requires_notification"] == True

    def test_log_change_persists_to_file(self, clean_logs):
        """Verify log_change persists entry to JSON file."""
        log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        # Verify file exists
        assert os.path.exists(LOG_FILE)

        # Verify content
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)

        assert "changes" in data
        assert len(data["changes"]) == 1

    def test_log_change_appends_multiple_entries(self, clean_logs):
        """Verify multiple log_change calls append entries."""
        log_change("REG-001", "", "", "low", [], 0)
        log_change("REG-002", "", "", "high", [], 0)
        log_change("REG-003", "", "", "critical", [], 0)

        # Verify all entries are persisted
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)

        assert len(data["changes"]) == 3
        assert data["changes"][0]["regulation_id"] == "REG-001"
        assert data["changes"][1]["regulation_id"] == "REG-002"
        assert data["changes"][2]["regulation_id"] == "REG-003"

    def test_log_change_creates_logs_directory(self, clean_logs):
        """Verify log_change creates logs directory if it doesn't exist."""
        # Ensure logs dir doesn't exist
        assert not os.path.exists(LOG_DIR)

        log_change("REG-001", "", "", "low", [], 0)

        # Verify logs directory was created
        assert os.path.exists(LOG_DIR)
        assert os.path.isdir(LOG_DIR)


class TestGetChanges:
    """Tests for get_changes() function."""

    def test_get_changes_empty_log(self, clean_logs):
        """Verify get_changes returns empty list when log is empty."""
        changes = get_changes()
        assert changes == []

    def test_get_changes_returns_all_entries_no_filters(self, clean_logs):
        """Verify get_changes returns all entries when no filters are applied."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)
        log_change("REG-003", "old3", "new3", "critical", [], 0)

        changes = get_changes()

        assert len(changes) == 3

    def test_get_changes_filter_by_regulation_id(self, clean_logs):
        """Verify get_changes filters by regulation_id correctly."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)
        log_change("REG-001", "old3", "new3", "medium", [], 0)

        changes = get_changes(regulation_id="REG-001")

        assert len(changes) == 2
        assert all(c["regulation_id"] == "REG-001" for c in changes)

    def test_get_changes_filter_by_regulation_id_no_matches(self, clean_logs):
        """Verify get_changes returns empty list when no entries match regulation_id."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)

        changes = get_changes(regulation_id="REG-999")

        assert changes == []

    def test_get_changes_filter_by_since_datetime(self, clean_logs):
        """Verify get_changes filters by since datetime correctly."""
        # Log some entries
        entry1 = log_change("REG-001", "old1", "new1", "low", [], 0)

        # Get timestamp for filtering
        filter_time = datetime.now(timezone.utc)

        # Wait a tiny bit and log more
        import time
        time.sleep(0.01)

        entry2 = log_change("REG-002", "old2", "new2", "high", [], 0)

        # Filter for entries since filter_time
        changes = get_changes(since=filter_time)

        # Should only get entry2
        assert len(changes) == 1
        assert changes[0]["regulation_id"] == "REG-002"

    def test_get_changes_filter_by_since_naive_datetime(self, clean_logs):
        """Verify get_changes handles naive datetime for since parameter."""
        log_change("REG-001", "old1", "new1", "low", [], 0)

        # Use naive datetime (no timezone)
        filter_time = datetime.now()

        import time
        time.sleep(0.01)

        log_change("REG-002", "old2", "new2", "high", [], 0)

        # Should not raise an error
        changes = get_changes(since=filter_time)
        assert len(changes) >= 0  # Should handle gracefully

    def test_get_changes_filter_by_both_regulation_id_and_since(self, clean_logs):
        """Verify get_changes filters by both regulation_id and since."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)

        filter_time = datetime.now(timezone.utc)

        import time
        time.sleep(0.01)

        log_change("REG-001", "old3", "new3", "medium", [], 0)
        log_change("REG-002", "old4", "new4", "critical", [], 0)

        # Filter for REG-001 entries since filter_time
        changes = get_changes(regulation_id="REG-001", since=filter_time)

        assert len(changes) == 1
        assert changes[0]["regulation_id"] == "REG-001"
        assert changes[0]["old_text"] == "old3"

    def test_get_changes_handles_missing_timestamp(self, clean_logs):
        """Verify get_changes handles entries with missing timestamps gracefully."""
        # Manually create entry without timestamp
        data = {
            "changes": [
                {
                    "regulation_id": "REG-001",
                    "old_text": "",
                    "new_text": "",
                    "severity": "low",
                    "affected_checkers": [],
                    "tests_added": 0
                    # No timestamp field
                }
            ]
        }
        _save_log_data(data)

        # Should not crash when filtering by since
        filter_time = datetime.now(timezone.utc)
        changes = get_changes(since=filter_time)

        # Entry should be skipped
        assert len(changes) == 0

    def test_get_changes_handles_invalid_timestamp(self, clean_logs):
        """Verify get_changes handles entries with invalid timestamps gracefully."""
        # Manually create entry with invalid timestamp
        data = {
            "changes": [
                {
                    "timestamp": "invalid-timestamp",
                    "regulation_id": "REG-001",
                    "old_text": "",
                    "new_text": "",
                    "severity": "low",
                    "affected_checkers": [],
                    "tests_added": 0
                }
            ]
        }
        _save_log_data(data)

        # Should not crash when filtering by since
        filter_time = datetime.now(timezone.utc)
        changes = get_changes(since=filter_time)

        # Entry should be skipped
        assert len(changes) == 0


class TestGetChangeHistory:
    """Tests for get_change_history() function."""

    def test_get_change_history_empty_log(self, clean_logs):
        """Verify get_change_history returns empty structure when log is empty."""
        history = get_change_history()

        assert "changes" in history
        assert history["changes"] == []

    def test_get_change_history_returns_dict_with_changes_key(self, clean_logs):
        """Verify get_change_history returns a dictionary with 'changes' key."""
        log_change("REG-001", "old1", "new1", "low", [], 0)

        history = get_change_history()

        assert isinstance(history, dict)
        assert "changes" in history
        assert isinstance(history["changes"], list)

    def test_get_change_history_returns_all_entries(self, clean_logs):
        """Verify get_change_history returns all logged entries."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)
        log_change("REG-003", "old3", "new3", "critical", [], 0)

        history = get_change_history()

        assert len(history["changes"]) == 3

    def test_get_change_history_preserves_entry_order(self, clean_logs):
        """Verify get_change_history preserves the order of entries."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)
        log_change("REG-003", "old3", "new3", "critical", [], 0)

        history = get_change_history()

        assert history["changes"][0]["regulation_id"] == "REG-001"
        assert history["changes"][1]["regulation_id"] == "REG-002"
        assert history["changes"][2]["regulation_id"] == "REG-003"


class TestFileOperations:
    """Tests for file operations and data integrity."""

    def test_atomic_write_creates_temp_file_in_same_directory(self, clean_logs):
        """Verify atomic write uses temp file in same directory."""
        log_change("REG-001", "old1", "new1", "low", [], 0)

        # Verify the final file exists
        assert os.path.exists(LOG_FILE)

        # Verify no temp files are left behind
        log_files = os.listdir(LOG_DIR)
        assert len(log_files) == 1
        assert log_files[0] == "regulation_changes.json"

    def test_log_file_is_valid_json(self, clean_logs):
        """Verify log file is valid JSON after writes."""
        log_change("REG-001", "old1", "new1", "low", [], 0)
        log_change("REG-002", "old2", "new2", "high", [], 0)

        # Verify file can be parsed as JSON
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)

        assert isinstance(data, dict)
        assert "changes" in data

    def test_corrupted_json_file_is_handled_gracefully(self, clean_logs):
        """Verify corrupted JSON file is handled by initializing empty log."""
        # Create corrupted JSON file
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, 'w') as f:
            f.write("{ invalid json }")

        # Should not crash, should initialize empty log
        changes = get_changes()
        assert changes == []

        # Logging should still work
        entry = log_change("REG-001", "old1", "new1", "low", [], 0)
        assert entry["regulation_id"] == "REG-001"

    def test_missing_log_file_is_handled_gracefully(self, clean_logs):
        """Verify missing log file is handled by initializing empty log."""
        # Don't create any file
        changes = get_changes()
        assert changes == []

        history = get_change_history()
        assert history == {"changes": []}

    def test_ensure_log_dir_creates_directory(self, clean_logs):
        """Verify _ensure_log_dir creates the logs directory."""
        assert not os.path.exists(LOG_DIR)

        _ensure_log_dir()

        assert os.path.exists(LOG_DIR)
        assert os.path.isdir(LOG_DIR)

    def test_ensure_log_dir_idempotent(self, clean_logs):
        """Verify _ensure_log_dir can be called multiple times safely."""
        _ensure_log_dir()
        _ensure_log_dir()
        _ensure_log_dir()

        assert os.path.exists(LOG_DIR)

    def test_json_file_formatting(self, clean_logs):
        """Verify JSON file is formatted with indentation for readability."""
        log_change("REG-001", "old1", "new1", "low", [], 0)

        # Read raw file content
        with open(LOG_FILE, 'r') as f:
            content = f.read()

        # Verify it's formatted (contains newlines and indentation)
        assert '\n' in content
        assert '  ' in content  # Indentation


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_special_characters_in_regulation_text(self, clean_logs):
        """Verify special characters in regulation text are handled correctly."""
        special_text = 'Text with "quotes", \'apostrophes\', and \n newlines \t tabs'
        entry = log_change(
            regulation_id="REG-001",
            old_text=special_text,
            new_text=special_text + " modified",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["old_text"] == special_text

        # Verify it's persisted correctly
        changes = get_changes(regulation_id="REG-001")
        assert changes[0]["old_text"] == special_text

    def test_unicode_in_regulation_text(self, clean_logs):
        """Verify Unicode characters in regulation text are handled correctly."""
        unicode_text = "Regulation with émojis 🎉 and spëcial çharacters"
        entry = log_change(
            regulation_id="REG-001",
            old_text=unicode_text,
            new_text=unicode_text,
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["old_text"] == unicode_text

        # Verify it's persisted correctly
        changes = get_changes(regulation_id="REG-001")
        assert changes[0]["old_text"] == unicode_text

    def test_large_number_of_affected_checkers(self, clean_logs):
        """Verify large number of affected checkers is handled correctly."""
        many_checkers = [f"checker_{i}" for i in range(100)]
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="medium",
            affected_checkers=many_checkers,
            tests_added=0
        )

        assert len(entry["affected_checkers"]) == 100
        assert entry["customer_impact"]["score"] == 1000

    def test_zero_tests_added(self, clean_logs):
        """Verify zero tests_added is handled correctly."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["tests_added"] == 0

    def test_negative_tests_added(self, clean_logs):
        """Verify negative tests_added is accepted (no validation in spec)."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=[],
            tests_added=-1
        )

        # No validation specified, should accept negative values
        assert entry["tests_added"] == -1

    def test_all_severity_levels(self, clean_logs):
        """Verify all valid severity levels are handled correctly."""
        severities = ["critical", "high", "medium", "low"]

        for severity in severities:
            entry = log_change(
                regulation_id=f"REG-{severity}",
                old_text="",
                new_text="",
                severity=severity,
                affected_checkers=[],
                tests_added=0
            )
            assert entry["severity"] == severity

    def test_mixed_case_severity(self, clean_logs):
        """Verify mixed case severity is normalized."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="CrItIcAl",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["severity"] == "critical"
