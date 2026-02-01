"""
Unit tests for the change_tracker module.

This test suite verifies that the change_tracker module conforms to the PDD specification
for the RegWatch compliance monitoring system's audit trail functionality.
"""

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

# Import the module under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from change_tracker import log_change, get_changes, get_change_history, LOG_FILE, LOG_DIR


@pytest.fixture
def clean_log_file():
    """
    Fixture to ensure a clean state for each test.
    Backs up the existing log file if it exists, removes it, and restores it after the test.
    """
    backup_path = None

    # Backup existing log file
    if os.path.exists(LOG_FILE):
        backup_path = LOG_FILE + '.backup'
        shutil.copy(LOG_FILE, backup_path)
        os.remove(LOG_FILE)

    # Remove log directory if it exists
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)

    yield

    # Cleanup after test
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)

    # Restore backup if it existed
    if backup_path and os.path.exists(backup_path):
        os.makedirs(LOG_DIR, exist_ok=True)
        shutil.move(backup_path, LOG_FILE)


class TestLogChange:
    """Tests for the log_change function."""

    def test_log_change_creates_log_directory(self, clean_log_file):
        """Test that log_change creates the logs directory if it doesn't exist."""
        assert not os.path.exists(LOG_DIR)

        log_change(
            regulation_id="REG-001",
            old_text="Old requirement",
            new_text="New requirement",
            severity="medium",
            affected_checkers=["checker1"],
            tests_added=2
        )

        assert os.path.exists(LOG_DIR)
        assert os.path.isdir(LOG_DIR)

    def test_log_change_creates_json_file(self, clean_log_file):
        """Test that log_change creates the JSON log file."""
        assert not os.path.exists(LOG_FILE)

        log_change(
            regulation_id="REG-001",
            old_text="Old requirement",
            new_text="New requirement",
            severity="high",
            affected_checkers=["checker1", "checker2"],
            tests_added=3
        )

        assert os.path.exists(LOG_FILE)
        assert os.path.isfile(LOG_FILE)

    def test_log_change_returns_complete_entry(self, clean_log_file):
        """Test that log_change returns a properly structured entry."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="Old text",
            new_text="New text",
            severity="critical",
            affected_checkers=["checker1", "checker2"],
            tests_added=5
        )

        # Verify all required fields are present
        assert "timestamp" in entry
        assert "regulation_id" in entry
        assert "old_text" in entry
        assert "new_text" in entry
        assert "severity" in entry
        assert "affected_checkers" in entry
        assert "tests_added" in entry
        assert "customer_impact" in entry

        # Verify field values
        assert entry["regulation_id"] == "REG-001"
        assert entry["old_text"] == "Old text"
        assert entry["new_text"] == "New text"
        assert entry["severity"] == "critical"
        assert entry["affected_checkers"] == ["checker1", "checker2"]
        assert entry["tests_added"] == 5

        # Verify customer_impact structure
        assert "score" in entry["customer_impact"]
        assert "requires_notification" in entry["customer_impact"]

    def test_log_change_timestamp_is_iso8601(self, clean_log_file):
        """Test that the timestamp is in ISO 8601 format."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="Old",
            new_text="New",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        # Verify timestamp can be parsed as ISO 8601
        timestamp = entry["timestamp"]
        parsed = datetime.fromisoformat(timestamp)
        assert parsed is not None

        # Verify it's recent (within the last minute)
        now = datetime.now(timezone.utc)
        time_diff = now - parsed
        assert time_diff.total_seconds() < 60

    def test_log_change_severity_normalization(self, clean_log_file):
        """Test that severity levels are normalized to lowercase."""
        # Test uppercase
        entry1 = log_change("REG-001", "old", "new", "HIGH", ["checker1"], 1)
        assert entry1["severity"] == "high"

        # Test mixed case
        entry2 = log_change("REG-002", "old", "new", "CriTicAl", ["checker1"], 1)
        assert entry2["severity"] == "critical"

        # Test lowercase (already normalized)
        entry3 = log_change("REG-003", "old", "new", "medium", ["checker1"], 1)
        assert entry3["severity"] == "medium"

    def test_log_change_unknown_severity_defaults_to_medium(self, clean_log_file):
        """Test that unknown severity levels default to 'medium'."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="old",
            new_text="new",
            severity="unknown",
            affected_checkers=["checker1"],
            tests_added=1
        )

        assert entry["severity"] == "medium"

    def test_log_change_empty_severity_defaults_to_medium(self, clean_log_file):
        """Test that empty severity defaults to 'medium'."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="old",
            new_text="new",
            severity="",
            affected_checkers=["checker1"],
            tests_added=1
        )

        assert entry["severity"] == "medium"

    def test_log_change_empty_affected_checkers(self, clean_log_file):
        """Test handling of empty affected_checkers list."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="old",
            new_text="new",
            severity="low",
            affected_checkers=[],
            tests_added=0
        )

        assert entry["affected_checkers"] == []
        assert entry["customer_impact"]["score"] == 0

    def test_log_change_empty_regulation_text(self, clean_log_file):
        """Test handling of empty old_text and new_text."""
        entry = log_change(
            regulation_id="REG-001",
            old_text="",
            new_text="",
            severity="low",
            affected_checkers=["checker1"],
            tests_added=0
        )

        assert entry["old_text"] == ""
        assert entry["new_text"] == ""

    def test_log_change_long_regulation_text(self, clean_log_file):
        """Test that arbitrarily long regulation text is handled correctly."""
        long_text = "A" * 10000  # 10KB of text

        entry = log_change(
            regulation_id="REG-001",
            old_text=long_text,
            new_text=long_text + "B",
            severity="medium",
            affected_checkers=["checker1"],
            tests_added=1
        )

        assert entry["old_text"] == long_text
        assert entry["new_text"] == long_text + "B"

    def test_log_change_customer_impact_calculation(self, clean_log_file):
        """Test that customer_impact is calculated correctly."""
        # Test with 2 affected checkers and medium severity
        entry1 = log_change("REG-001", "old", "new", "medium", ["c1", "c2"], 1)
        assert entry1["customer_impact"]["score"] == 20  # 2 * 10
        assert entry1["customer_impact"]["requires_notification"] is False

        # Test with 3 affected checkers and critical severity
        entry2 = log_change("REG-002", "old", "new", "critical", ["c1", "c2", "c3"], 1)
        assert entry2["customer_impact"]["score"] == 60  # 3 * 10 * 2
        assert entry2["customer_impact"]["requires_notification"] is True

        # Test with high severity
        entry3 = log_change("REG-003", "old", "new", "high", ["c1"], 1)
        assert entry3["customer_impact"]["score"] == 10  # 1 * 10
        assert entry3["customer_impact"]["requires_notification"] is True

        # Test with low severity
        entry4 = log_change("REG-004", "old", "new", "low", ["c1"], 1)
        assert entry4["customer_impact"]["score"] == 10  # 1 * 10
        assert entry4["customer_impact"]["requires_notification"] is False

    def test_log_change_multiple_entries_append(self, clean_log_file):
        """Test that multiple log_change calls append entries."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)
        log_change("REG-003", "old3", "new3", "high", ["c3"], 3)

        history = get_change_history()
        assert len(history["changes"]) == 3
        assert history["changes"][0]["regulation_id"] == "REG-001"
        assert history["changes"][1]["regulation_id"] == "REG-002"
        assert history["changes"][2]["regulation_id"] == "REG-003"

    def test_log_change_persists_to_json_file(self, clean_log_file):
        """Test that logged changes are persisted to the JSON file."""
        log_change("REG-001", "old", "new", "medium", ["checker1"], 1)

        # Read the file directly
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)

        assert "changes" in data
        assert len(data["changes"]) == 1
        assert data["changes"][0]["regulation_id"] == "REG-001"


class TestGetChanges:
    """Tests for the get_changes function."""

    def test_get_changes_no_filters_returns_all(self, clean_log_file):
        """Test that get_changes with no filters returns all entries."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)
        log_change("REG-003", "old3", "new3", "high", ["c3"], 3)

        changes = get_changes()
        assert len(changes) == 3

    def test_get_changes_filter_by_regulation_id(self, clean_log_file):
        """Test filtering by regulation_id."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)
        log_change("REG-001", "old3", "new3", "high", ["c3"], 3)

        changes = get_changes(regulation_id="REG-001")
        assert len(changes) == 2
        assert all(c["regulation_id"] == "REG-001" for c in changes)

    def test_get_changes_filter_by_nonexistent_regulation_id(self, clean_log_file):
        """Test filtering by a regulation_id that doesn't exist."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)

        changes = get_changes(regulation_id="REG-999")
        assert len(changes) == 0

    def test_get_changes_filter_by_since_datetime(self, clean_log_file):
        """Test filtering by since datetime."""
        # Log first entry
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)

        # Create a cutoff time
        cutoff_time = datetime.now(timezone.utc)

        # Wait a small amount and log more entries
        import time
        time.sleep(0.1)

        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)
        log_change("REG-003", "old3", "new3", "high", ["c3"], 3)

        # Filter for changes after cutoff
        changes = get_changes(since=cutoff_time)
        assert len(changes) >= 2  # Should include REG-002 and REG-003

    def test_get_changes_filter_by_both_parameters(self, clean_log_file):
        """Test filtering by both regulation_id and since datetime."""
        # Log first entries
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)

        cutoff_time = datetime.now(timezone.utc)

        import time
        time.sleep(0.1)

        # Log more entries
        log_change("REG-001", "old3", "new3", "high", ["c3"], 3)
        log_change("REG-002", "old4", "new4", "critical", ["c4"], 4)

        # Filter for REG-001 changes after cutoff
        changes = get_changes(regulation_id="REG-001", since=cutoff_time)
        assert len(changes) >= 1
        assert all(c["regulation_id"] == "REG-001" for c in changes)

    def test_get_changes_with_empty_log(self, clean_log_file):
        """Test get_changes when no changes have been logged."""
        changes = get_changes()
        assert changes == []

    def test_get_changes_with_missing_log_file(self, clean_log_file):
        """Test get_changes when the log file doesn't exist."""
        # Ensure log file doesn't exist
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)

        changes = get_changes()
        assert changes == []

    def test_get_changes_since_timezone_aware(self, clean_log_file):
        """Test that since parameter works with timezone-aware datetimes."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)

        # Use a timezone-aware datetime in the past
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        changes = get_changes(since=past_time)

        assert len(changes) == 1

    def test_get_changes_since_timezone_naive(self, clean_log_file):
        """Test that since parameter works with timezone-naive datetimes."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)

        # Use a timezone-naive datetime in the past
        past_time = datetime.now() - timedelta(hours=1)
        changes = get_changes(since=past_time)

        assert len(changes) == 1


class TestGetChangeHistory:
    """Tests for the get_change_history function."""

    def test_get_change_history_returns_dict_with_changes_key(self, clean_log_file):
        """Test that get_change_history returns a dict with 'changes' key."""
        log_change("REG-001", "old", "new", "medium", ["c1"], 1)

        history = get_change_history()
        assert isinstance(history, dict)
        assert "changes" in history
        assert isinstance(history["changes"], list)

    def test_get_change_history_returns_all_entries(self, clean_log_file):
        """Test that get_change_history returns all logged entries."""
        log_change("REG-001", "old1", "new1", "low", ["c1"], 1)
        log_change("REG-002", "old2", "new2", "medium", ["c2"], 2)
        log_change("REG-003", "old3", "new3", "high", ["c3"], 3)

        history = get_change_history()
        assert len(history["changes"]) == 3

    def test_get_change_history_empty_when_no_changes(self, clean_log_file):
        """Test that get_change_history returns empty list when no changes logged."""
        history = get_change_history()
        assert history == {"changes": []}

    def test_get_change_history_with_missing_log_file(self, clean_log_file):
        """Test get_change_history when log file doesn't exist."""
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)

        history = get_change_history()
        assert history == {"changes": []}


class TestFileOperations:
    """Tests for file I/O operations and data integrity."""

    def test_corrupted_json_file_handled_gracefully(self, clean_log_file):
        """Test that corrupted JSON files are handled gracefully."""
        # Create log directory
        os.makedirs(LOG_DIR, exist_ok=True)

        # Write corrupted JSON
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("{invalid json content")

        # Should return empty changes without raising an exception
        history = get_change_history()
        assert history == {"changes": []}

        # Should be able to log new changes
        entry = log_change("REG-001", "old", "new", "medium", ["c1"], 1)
        assert entry["regulation_id"] == "REG-001"

    def test_atomic_write_creates_valid_json(self, clean_log_file):
        """Test that atomic write operations create valid JSON."""
        log_change("REG-001", "old", "new", "medium", ["c1"], 1)

        # Verify JSON is valid
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)

        assert "changes" in data
        assert isinstance(data["changes"], list)

    def test_json_file_is_readable_and_formatted(self, clean_log_file):
        """Test that the JSON file is formatted (indented) for readability."""
        log_change("REG-001", "old", "new", "medium", ["c1"], 1)

        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for indentation (formatted JSON)
        assert '\n' in content
        assert '  ' in content or '\t' in content

    def test_log_file_path_constant(self, clean_log_file):
        """Test that LOG_FILE constant is correctly set."""
        from change_tracker import LOG_FILE
        assert LOG_FILE == os.path.join("logs", "regulation_changes.json")


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_special_characters_in_regulation_text(self, clean_log_file):
        """Test handling of special characters in regulation text."""
        special_text = 'Test with "quotes", newlines\n\n, tabs\t, and unicode: café, 日本語'

        entry = log_change(
            regulation_id="REG-001",
            old_text=special_text,
            new_text=special_text + " modified",
            severity="medium",
            affected_checkers=["c1"],
            tests_added=1
        )

        assert entry["old_text"] == special_text
        assert entry["new_text"] == special_text + " modified"

        # Verify it's persisted correctly
        history = get_change_history()
        assert history["changes"][0]["old_text"] == special_text

    def test_special_characters_in_regulation_id(self, clean_log_file):
        """Test handling of special characters in regulation_id."""
        special_id = "REG-001/v2.0_HIPAA§164.312(a)(1)"

        entry = log_change(
            regulation_id=special_id,
            old_text="old",
            new_text="new",
            severity="medium",
            affected_checkers=["c1"],
            tests_added=1
        )

        assert entry["regulation_id"] == special_id

        # Verify filtering works
        changes = get_changes(regulation_id=special_id)
        assert len(changes) == 1
        assert changes[0]["regulation_id"] == special_id

    def test_zero_tests_added(self, clean_log_file):
        """Test that zero tests_added is handled correctly."""
        entry = log_change("REG-001", "old", "new", "low", ["c1"], 0)
        assert entry["tests_added"] == 0

    def test_large_number_of_affected_checkers(self, clean_log_file):
        """Test handling of a large number of affected checkers."""
        many_checkers = [f"checker_{i}" for i in range(100)]

        entry = log_change(
            regulation_id="REG-001",
            old_text="old",
            new_text="new",
            severity="critical",
            affected_checkers=many_checkers,
            tests_added=50
        )

        assert len(entry["affected_checkers"]) == 100
        assert entry["customer_impact"]["score"] == 2000  # 100 * 10 * 2

    def test_multiple_changes_same_regulation_different_times(self, clean_log_file):
        """Test logging multiple changes to the same regulation."""
        import time

        log_change("REG-001", "v1", "v2", "low", ["c1"], 1)
        time.sleep(0.1)
        log_change("REG-001", "v2", "v3", "medium", ["c1", "c2"], 2)
        time.sleep(0.1)
        log_change("REG-001", "v3", "v4", "high", ["c1", "c2", "c3"], 3)

        changes = get_changes(regulation_id="REG-001")
        assert len(changes) == 3

        # Verify they're in chronological order
        timestamps = [datetime.fromisoformat(c["timestamp"]) for c in changes]
        assert timestamps[0] < timestamps[1] < timestamps[2]


class TestDataIntegrity:
    """Tests for data integrity and consistency."""

    def test_returned_entry_matches_stored_entry(self, clean_log_file):
        """Test that the entry returned by log_change matches what's stored."""
        returned_entry = log_change(
            regulation_id="REG-001",
            old_text="old",
            new_text="new",
            severity="high",
            affected_checkers=["c1", "c2"],
            tests_added=3
        )

        history = get_change_history()
        stored_entry = history["changes"][0]

        # Compare all fields
        assert returned_entry == stored_entry

    def test_timestamp_consistency(self, clean_log_file):
        """Test that timestamps are consistent across calls."""
        entry = log_change("REG-001", "old", "new", "medium", ["c1"], 1)

        # Retrieve the entry
        changes = get_changes(regulation_id="REG-001")
        assert len(changes) == 1

        # Timestamps should match
        assert changes[0]["timestamp"] == entry["timestamp"]

    def test_all_severity_levels(self, clean_log_file):
        """Test all valid severity levels."""
        severities = ["critical", "high", "medium", "low"]

        for sev in severities:
            entry = log_change(f"REG-{sev}", "old", "new", sev, ["c1"], 1)
            assert entry["severity"] == sev

    def test_customer_impact_notification_logic(self, clean_log_file):
        """Test that requires_notification is set correctly for all severities."""
        # Critical and high should require notification
        entry1 = log_change("REG-001", "old", "new", "critical", ["c1"], 1)
        assert entry1["customer_impact"]["requires_notification"] is True

        entry2 = log_change("REG-002", "old", "new", "high", ["c1"], 1)
        assert entry2["customer_impact"]["requires_notification"] is True

        # Medium and low should not require notification
        entry3 = log_change("REG-003", "old", "new", "medium", ["c1"], 1)
        assert entry3["customer_impact"]["requires_notification"] is False

        entry4 = log_change("REG-004", "old", "new", "low", ["c1"], 1)
        assert entry4["customer_impact"]["requires_notification"] is False
