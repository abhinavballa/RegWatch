"""
RegWatch Change Tracker Module

This module provides a persistent audit trail for regulation updates within the
RegWatch compliance monitoring system. It manages a JSON-based log file to track
modifications to regulations, including severity, affected compliance checkers,
and impact metrics.

The module ensures data integrity through atomic file write operations and
provides querying capabilities for historical analysis.
"""

import json
import os
import tempfile
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Union

# Configure module-level logger
logger = logging.getLogger(__name__)

# Constants
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "regulation_changes.json")


def _ensure_log_dir() -> None:
    """Ensure the logs directory exists."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create log directory {LOG_DIR}: {e}")
        raise


def _load_log_data() -> Dict[str, List[Dict[str, Any]]]:
    """
    Load the change log data from the JSON file.
    
    Returns:
        A dictionary containing the list of changes. Returns an empty structure
        if the file does not exist or is corrupted.
    """
    if not os.path.exists(LOG_FILE):
        return {"changes": []}

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Could not read change log file {LOG_FILE} ({e}). Initializing new log.")
        return {"changes": []}


def _save_log_data(data: Dict[str, List[Dict[str, Any]]]) -> None:
    """
    Atomically save the change log data to the JSON file.
    
    Uses a write-to-temp-then-rename strategy to prevent data corruption
    during write operations.
    """
    _ensure_log_dir()
    
    # Create a temp file in the same directory to ensure atomic move works across filesystems
    try:
        # delete=False is required to close the file before renaming on Windows,
        # and generally safer for the rename operation.
        with tempfile.NamedTemporaryFile('w', dir=LOG_DIR, delete=False, encoding='utf-8') as tf:
            json.dump(data, tf, indent=2)
            temp_name = tf.name
        
        # Atomic replacement
        os.replace(temp_name, LOG_FILE)
    except OSError as e:
        logger.error(f"Failed to save change log to {LOG_FILE}: {e}")
        # Attempt to clean up temp file if it exists
        if 'temp_name' in locals() and os.path.exists(temp_name):
            try:
                os.remove(temp_name)
            except OSError:
                pass
        raise


def log_change(
    regulation_id: str,
    old_text: str,
    new_text: str,
    severity: str,
    affected_checkers: List[str],
    tests_added: int
) -> Dict[str, Any]:
    """
    Log a regulation change to the persistent audit trail.

    Args:
        regulation_id: Unique identifier for the regulation.
        old_text: The text of the regulation before the change.
        new_text: The text of the regulation after the change.
        severity: Impact level ('critical', 'high', 'medium', 'low').
        affected_checkers: List of compliance checker IDs affected by this change.
        tests_added: Number of new tests added to cover this change.

    Returns:
        The dictionary entry that was appended to the log.
    """
    # Validate and normalize inputs
    valid_severities = {"critical", "high", "medium", "low"}
    normalized_severity = severity.lower() if severity else "medium"
    if normalized_severity not in valid_severities:
        logger.warning(f"Unknown severity '{severity}', defaulting to 'medium'")
        normalized_severity = "medium"

    # Infer customer impact based on affected checkers count (heuristic)
    impact_score = len(affected_checkers) * 10
    if normalized_severity == "critical":
        impact_score *= 2
    
    customer_impact = {
        "score": impact_score,
        "requires_notification": normalized_severity in ("critical", "high")
    }

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "regulation_id": regulation_id,
        "old_text": old_text,
        "new_text": new_text,
        "severity": normalized_severity,
        "affected_checkers": affected_checkers or [],
        "tests_added": tests_added,
        "customer_impact": customer_impact
    }

    data = _load_log_data()
    data["changes"].append(entry)
    _save_log_data(data)

    return entry


def get_changes(
    regulation_id: Optional[str] = None,
    since: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve change log entries filtered by regulation ID and/or time.

    Args:
        regulation_id: If provided, filter for changes to this specific regulation.
        since: If provided, return only changes that occurred after this datetime.

    Returns:
        A list of matching change log entries.
    """
    data = _load_log_data()
    changes = data.get("changes", [])
    filtered_changes = []

    for entry in changes:
        # Filter by Regulation ID
        if regulation_id and entry.get("regulation_id") != regulation_id:
            continue

        # Filter by Date
        if since:
            try:
                # Parse ISO 8601 timestamp from log
                entry_time_str = entry.get("timestamp")
                if not entry_time_str:
                    continue
                
                entry_time = datetime.fromisoformat(entry_time_str)
                
                # Ensure comparison is timezone-aware if 'since' is timezone-aware
                if since.tzinfo is not None and entry_time.tzinfo is None:
                    # Assume UTC if log lacks timezone info but query has it
                    entry_time = entry_time.replace(tzinfo=timezone.utc)
                elif since.tzinfo is None and entry_time.tzinfo is not None:
                    # Strip timezone if query is naive (though not recommended)
                    entry_time = entry_time.replace(tzinfo=None)

                if entry_time < since:
                    continue
            except ValueError:
                logger.warning(f"Skipping entry with invalid timestamp: {entry}")
                continue

        filtered_changes.append(entry)

    return filtered_changes


def get_change_history() -> Dict[str, List[Dict[str, Any]]]:
    """
    Retrieve the complete history of all regulation changes.

    Returns:
        A dictionary with a "changes" key containing the list of all entries.
    """
    return _load_log_data()