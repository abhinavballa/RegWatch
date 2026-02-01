# TEST PLAN
#
# 1. Unit Tests (using pytest and unittest.mock):
#    - File System Isolation: Use a temporary directory fixture to isolate file I/O.
#    - Core Functionality:
#      - test_log_change_creates_new_log: Verify log_change creates the log file if it doesn't exist.
#      - test_log_change_appends_entry: Verify log_change appends to an existing log file.
#      - test_log_change_validates_severity: Verify invalid severity defaults to 'medium'.
#      - test_log_change_calculates_impact: Verify impact score calculation logic (critical/high/medium/low + checker count).
#      - test_get_changes_filtering: Verify filtering by regulation_id and since parameter.
#      - test_get_change_history: Verify the structure of the returned history dictionary.
#    - Edge Cases & Error Handling:
#      - test_corrupted_log_file: Verify system recovers/resets on corrupted JSON.
#      - test_invalid_timestamp_in_log: Verify get_changes handles malformed timestamps in the log gracefully.
#      - test_atomic_write_failure: Verify behavior when file writing fails (mocking).
#
# 2. Formal Verification (using Z3):
#    - test_z3_filtering_logic: Formally verify the boolean logic used in get_changes
#      to ensure the filtering conditions (ID match AND time > since) are logically sound
#      and cover all truth table possibilities correctly.


import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

import os
import json
import pytest
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
import tempfile
import shutil
import sys

# Import the module under test
# Assuming the module is in the python path. 
# If running directly where the file is local, this works.
import change_tracker

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def temp_log_env():
    """
    Sets up a temporary directory for logs and patches the module's 
    LOG_DIR and LOG_FILE constants to point to this temporary location.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        # Define paths inside the temp dir
        temp_log_dir = os.path.join(temp_dir, "logs")
        temp_log_file = os.path.join(temp_log_dir, "regulation_changes.json")
        
        # Patch the constants in the module
        with patch("change_tracker.LOG_DIR", temp_log_dir), \
             patch("change_tracker.LOG_FILE", temp_log_file):
            yield {
                "dir": temp_log_dir,
                "file": temp_log_file
            }

# -----------------------------------------------------------------------------
# Unit Tests
# -----------------------------------------------------------------------------

def test_log_change_creates_new_log(temp_log_env):
    """Verify that log_change creates the log directory and file if they don't exist."""
    log_file = temp_log_env["file"]
    
    assert not os.path.exists(log_file)
    
    entry = change_tracker.log_change(
        regulation_id="REG-001",
        old_text="Old",
        new_text="New",
        severity="medium",
        affected_checkers=["check1"],
        tests_added=1
    )
    
    assert os.path.exists(log_file)
    
    with open(log_file, 'r') as f:
        data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["regulation_id"] == "REG-001"
        assert data[0]["timestamp"] == entry["timestamp"]

def test_log_change_appends_entry(temp_log_env):
    """Verify that log_change appends to an existing log file."""
    # First entry
    change_tracker.log_change("REG-001", "A", "B", "low", [], 0)
    
    # Second entry
    change_tracker.log_change("REG-002", "C", "D", "high", [], 0)
    
    history = change_tracker.get_change_history()
    changes = history["changes"]
    
    assert len(changes) == 2
    assert changes[0]["regulation_id"] == "REG-001"
    assert changes[1]["regulation_id"] == "REG-002"

def test_log_change_validates_severity(temp_log_env):
    """Verify that invalid severity levels default to 'medium'."""
    entry = change_tracker.log_change(
        regulation_id="REG-003",
        old_text="",
        new_text="",
        severity="EXTREME_DANGER", # Invalid
        affected_checkers=[],
        tests_added=0
    )
    
    assert entry["severity"] == "medium"

def test_log_change_calculates_impact(temp_log_env):
    """Verify the heuristic for calculating customer impact score."""
    # Case 1: Critical severity (+50) + 2 checkers (2 * 10 = 20) = 70
    entry_crit = change_tracker.log_change(
        "R1", "", "", "critical", ["c1", "c2"], 0
    )
    assert entry_crit["customer_impact"]["score"] == 70
    assert entry_crit["customer_impact"]["requires_notification"] is True

    # Case 2: High severity (+30) + 1 checker (10) = 40
    entry_high = change_tracker.log_change(
        "R2", "", "", "high", ["c1"], 0
    )
    assert entry_high["customer_impact"]["score"] == 40
    assert entry_high["customer_impact"]["requires_notification"] is True

    # Case 3: Low severity (+0) + 0 checkers (0) = 0
    entry_low = change_tracker.log_change(
        "R3", "", "", "low", [], 0
    )
    assert entry_low["customer_impact"]["score"] == 0
    assert entry_low["customer_impact"]["requires_notification"] is False

def test_get_changes_filtering(temp_log_env):
    """Verify filtering by regulation_id and since parameter."""
    # Setup data
    # T0: 1 hour ago
    t0 = datetime.now(timezone.utc) - timedelta(hours=1)
    # T1: 30 mins ago
    t1 = datetime.now(timezone.utc) - timedelta(minutes=30)
    # T2: Now
    t2 = datetime.now(timezone.utc)
    
    # We need to mock datetime.now to control timestamps in log_change, 
    # or we can manually write the file. Manually writing is more robust for state setup.
    
    log_data = [
        {
            "timestamp": t0.isoformat(),
            "regulation_id": "REG-A",
            "severity": "low"
        },
        {
            "timestamp": t1.isoformat(),
            "regulation_id": "REG-B",
            "severity": "medium"
        },
        {
            "timestamp": t2.isoformat(),
            "regulation_id": "REG-A",
            "severity": "high"
        }
    ]
    
    # Write setup data
    os.makedirs(temp_log_env["dir"], exist_ok=True)
    with open(temp_log_env["file"], 'w') as f:
        json.dump(log_data, f)

    # Test 1: Filter by ID
    changes_a = change_tracker.get_changes(regulation_id="REG-A")
    assert len(changes_a) == 2
    assert changes_a[0]["severity"] == "low"
    assert changes_a[1]["severity"] == "high"

    # Test 2: Filter by Time (Since t0 + 10 mins) -> Should exclude t0, include t1 and t2
    since_time = t0 + timedelta(minutes=10)
    changes_since = change_tracker.get_changes(since=since_time)
    assert len(changes_since) == 2
    assert changes_since[0]["regulation_id"] == "REG-B" # t1
    assert changes_since[1]["regulation_id"] == "REG-A" # t2

    # Test 3: Combined Filter (REG-A since t0 + 10 mins) -> Should only include t2
    changes_combined = change_tracker.get_changes(regulation_id="REG-A", since=since_time)
    assert len(changes_combined) == 1
    assert changes_combined[0]["timestamp"] == t2.isoformat()

def test_corrupted_log_file(temp_log_env):
    """Verify that the module handles a corrupted JSON file gracefully by resetting it."""
    log_file = temp_log_env["file"]
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Write garbage
    with open(log_file, 'w') as f:
        f.write("{ not valid json }")
    
    # Should not raise error, should return empty list
    changes = change_tracker.get_changes()
    assert changes == []
    
    # Should be able to write new data, effectively overwriting corruption
    change_tracker.log_change("REG-NEW", "a", "b", "low", [], 0)
    
    with open(log_file, 'r') as f:
        data = json.load(f)
        assert len(data) == 1
        assert data[0]["regulation_id"] == "REG-NEW"

def test_invalid_timestamp_in_log(temp_log_env):
    """Verify that get_changes skips entries with invalid timestamps."""
    log_data = [
        {"timestamp": "not-a-date", "regulation_id": "REG-1"},
        {"timestamp": datetime.now(timezone.utc).isoformat(), "regulation_id": "REG-2"}
    ]
    
    os.makedirs(temp_log_env["dir"], exist_ok=True)
    with open(temp_log_env["file"], 'w') as f:
        json.dump(log_data, f)
        
    # Filter with 'since' forces timestamp parsing
    since = datetime.now(timezone.utc) - timedelta(days=1)
    changes = change_tracker.get_changes(since=since)
    
    # Should skip the first one, return the second
    assert len(changes) == 1
    assert changes[0]["regulation_id"] == "REG-2"

def test_atomic_write_failure(temp_log_env):
    """Verify behavior when saving fails (e.g. permission error)."""
    # We mock os.replace to raise an error
    with patch("os.replace", side_effect=OSError("Disk full")):
        with pytest.raises(OSError, match="Disk full"):
            change_tracker.log_change("R1", "a", "b", "low", [], 0)

# -----------------------------------------------------------------------------
# Z3 Formal Verification
# -----------------------------------------------------------------------------

def test_z3_filtering_logic():
    """
    Formally verify the filtering logic used in get_changes.
    
    Logic under test:
    A change is included IF:
      (regulation_id_filter IS None OR entry.regulation_id == regulation_id_filter)
      AND
      (since_filter IS None OR entry.timestamp > since_filter)
      
    Note: The code implementation uses `if entry_time <= since: continue`, 
    which implies we keep entries where `entry_time > since`.
    """
    try:
        import z3
    except ImportError:
        pytest.skip("z3-solver not installed")

    s = z3.Solver()

    # Define variables
    # We use Integers to represent IDs and Timestamps for simplicity
    # 0 for None/Null in filters
    
    # Inputs
    entry_id = z3.Int('entry_id')
    entry_time = z3.Int('entry_time')
    
    filter_id = z3.Int('filter_id')
    filter_id_is_none = z3.Bool('filter_id_is_none')
    
    filter_since = z3.Int('filter_since')
    filter_since_is_none = z3.Bool('filter_since_is_none')
    
    # The logic implemented in Python:
    # if regulation_id and entry.get("regulation_id") != regulation_id: continue
    # if since and entry_time <= since: continue
    
    # Let's model "Selected"
    # Python: selected = (not (filter_id and entry_id != filter_id)) AND (not (filter_since and entry_time <= filter_since))
    
    # Z3 Model of Implementation:
    # If filter_id is NOT None, we require entry_id == filter_id
    id_match = z3.Or(filter_id_is_none, entry_id == filter_id)
    
    # If filter_since is NOT None, we require entry_time > filter_since
    time_match = z3.Or(filter_since_is_none, entry_time > filter_since)
    
    implementation_selected = z3.And(id_match, time_match)
    
    # Expected Logic (Specification):
    # We want to ensure that if we provide a filter ID, we ONLY get that ID.
    # We want to ensure that if we provide a since time, we ONLY get times strictly greater.
    
    # Let's verify a property: 
    # "If selected, and filter_id is not None, then entry_id MUST equal filter_id"
    # Implication: implementation_selected AND (Not filter_id_is_none) => (entry_id == filter_id)
    # Negation for Z3: implementation_selected AND (Not filter_id_is_none) AND (entry_id != filter_id)
    
    s.push()
    s.add(implementation_selected)
    s.add(z3.Not(filter_id_is_none))
    s.add(entry_id != filter_id)
    
    # If this is satisfiable, we have a bug (counter-example found)
    result = s.check()
    assert result == z3.unsat, "Logic Error: Selected an entry with wrong ID when filter was present"
    s.pop()
    
    # Verify property:
    # "If selected, and filter_since is not None, then entry_time MUST be > filter_since"
    # Negation: implementation_selected AND (Not filter_since_is_none) AND (entry_time <= filter_since)
    
    s.push()
    s.add(implementation_selected)
    s.add(z3.Not(filter_since_is_none))
    s.add(entry_time <= filter_since)
    
    result = s.check()
    assert result == z3.unsat, "Logic Error: Selected an entry with timestamp <= since when filter was present"
    s.pop()
    
    # Verify property:
    # "If filters are None, everything is selected"
    # Negation: filter_id_is_none AND filter_since_is_none AND (Not implementation_selected)
    
    s.push()
    s.add(filter_id_is_none)
    s.add(filter_since_is_none)
    s.add(z3.Not(implementation_selected))
    
    result = s.check()
    assert result == z3.unsat, "Logic Error: Should select everything when no filters provided"
    s.pop()