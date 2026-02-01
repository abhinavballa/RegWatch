"""
RegWatch Change Tracker Module

This module provides a persistent audit trail for regulation updates within the
RegWatch compliance monitoring system. It manages the recording and retrieval
of regulation changes, ensuring data integrity through atomic file operations.

The module maintains a JSON-based log file (`logs/regulation_changes.json`)
tracking:
- Timestamp of changes
- Regulation identifiers
- Textual differences (old vs new)
- Severity levels
- Impact analysis (affected checkers, tests added)
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


def _load_log_data() -> List[Dict[str, Any]]:
    """
    Load the change log from disk.
    
    Returns:
        A list of change entries. Returns an empty list if the file 
        doesn't exist or is corrupted.
    """
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Ensure we return a list, even if the JSON structure is different
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "changes" in data:
                return data["changes"]
            else:
                logger.warning(f"Unexpected JSON structure in {LOG_FILE}. Initializing empty log.")
                return []
    except json.JSONDecodeError:
        logger.warning(f"Corrupted JSON in {LOG_FILE}. Initializing empty log.")
        return []
    except Exception as e:
        logger.error(f"Error reading {LOG_FILE}: {e}")
        return []


def _save_log_data(data: List[Dict[str, Any]]) -> None:
    """
    Atomically save the change log to disk.
    
    Uses a write-to-temp-then-rename strategy to prevent data corruption
    during write operations.
    
    Args:
        data: The list of change entries to save.
    """
    _ensure_log_dir()
    
    # Create a temporary file in the same directory to ensure atomic move works across filesystems
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=LOG_DIR, delete=False, encoding='utf-8') as tmp_file:
            json.dump(data, tmp_file, indent=2, ensure_ascii=False)
            tmp_path = tmp_file.name
        
        # Atomic replacement
        os.replace(tmp_path, LOG_FILE)
    except Exception as e:
        logger.error(f"Failed to save change log: {e}")
        # Clean up temp file if it exists and wasn't moved
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.remove(tmp_path)
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
    Record a new regulation change in the audit trail.

    Args:
        regulation_id: Unique identifier for the regulation.
        old_text: The text of the regulation before the change.
        new_text: The text of the regulation after the change.
        severity: Impact level ('critical', 'high', 'medium', 'low').
        affected_checkers: List of compliance checker IDs impacted.
        tests_added: Number of new tests added to cover this change.

    Returns:
        The created log entry dictionary.
    """
    # Validate severity
    valid_severities = {'critical', 'high', 'medium', 'low'}
    if severity.lower() not in valid_severities:
        logger.warning(f"Unknown severity '{severity}'. Defaulting to 'medium'.")
        severity = 'medium'

    # Infer customer impact based on affected checkers
    # Simple heuristic: More checkers affected = higher impact score
    impact_score = len(affected_checkers) * 10
    if severity == 'critical':
        impact_score += 50
    elif severity == 'high':
        impact_score += 30

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "regulation_id": regulation_id,
        "old_text": old_text,
        "new_text": new_text,
        "severity": severity.lower(),
        "affected_checkers": affected_checkers,
        "tests_added": tests_added,
        "customer_impact": {
            "score": impact_score,
            "requires_notification": severity in ('critical', 'high')
        }
    }

    current_log = _load_log_data()
    current_log.append(entry)
    _save_log_data(current_log)
    
    return entry


def get_changes(
    regulation_id: Optional[str] = None,
    since: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve regulation changes filtered by ID and time.

    Args:
        regulation_id: Optional ID to filter specific regulation changes.
        since: Optional datetime object. Only changes after this time are returned.

    Returns:
        A list of matching change log entries.
    """
    all_changes = _load_log_data()
    filtered_changes = []

    for entry in all_changes:
        # Filter by Regulation ID
        if regulation_id and entry.get("regulation_id") != regulation_id:
            continue

        # Filter by Time
        if since:
            try:
                entry_time_str = entry.get("timestamp")
                if not entry_time_str:
                    continue
                
                # Parse ISO 8601 string to datetime
                entry_time = datetime.fromisoformat(entry_time_str)
                
                # Ensure timezone awareness for comparison
                if since.tzinfo is None:
                    # If 'since' is naive, assume UTC for safety or raise error depending on policy.
                    # Here we assume the caller meant UTC if not specified.
                    since = since.replace(tzinfo=timezone.utc)
                
                if entry_time <= since:
                    continue
            except ValueError:
                logger.warning(f"Invalid timestamp format in log entry: {entry}")
                continue

        filtered_changes.append(entry)

    return filtered_changes


def get_change_history() -> Dict[str, List[Dict[str, Any]]]:
    """
    Retrieve the complete history of all regulation changes.

    Returns:
        A dictionary containing the full list of changes under the "changes" key.
    """
    return {
        "changes": _load_log_data()
    }