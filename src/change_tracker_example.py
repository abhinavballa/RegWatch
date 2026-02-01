import os
import sys
import logging
from datetime import datetime, timedelta, timezone

# Ensure the module can be imported by adding the parent directory to sys.path
# This assumes the example is running in a structure where src/change_tracker.py exists
# relative to this script.
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    # Import the module functions
    # Assuming the module is saved as 'src/change_tracker.py'
    from src import change_tracker
except ImportError:
    # Fallback for when running in the same directory as the module
    try:
        import change_tracker
    except ImportError:
        print("Error: Could not import 'change_tracker'. Ensure the module is in the python path.")
        sys.exit(1)

# Configure logging to see module output
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_example():
    """Demonstrates the usage of the change_tracker module."""
    print("=== RegWatch Change Tracker Example ===\n")

    # 1. Log a critical regulation change
    print("1. Logging a critical change to GDPR Article 17...")
    entry1 = change_tracker.log_change(
        regulation_id="GDPR-17",
        old_text="The data subject shall have the right to obtain from the controller the erasure of personal data...",
        new_text="The data subject shall have the IMMEDIATE right to obtain from the controller the erasure of personal data...",
        severity="critical",
        affected_checkers=["chk_erasure_timeliness", "chk_user_consent_flow"],
        tests_added=2
    )
    print(f"   -> Logged entry with timestamp: {entry1['timestamp']}")
    print(f"   -> Impact Score: {entry1['customer_impact']['score']}")

    # 2. Log a minor update (low severity)
    print("\n2. Logging a minor update to CCPA Section 100...")
    entry2 = change_tracker.log_change(
        regulation_id="CCPA-100",
        old_text="Consumers have the right to know.",
        new_text="Consumers have the right to know what personal information is collected.",
        severity="low",
        affected_checkers=["chk_disclosure_text"],
        tests_added=0
    )
    print(f"   -> Logged entry with timestamp: {entry2['timestamp']}")

    # 3. Retrieve full history
    print("\n3. Retrieving full change history...")
    history = change_tracker.get_change_history()
    all_changes = history["changes"]
    print(f"   -> Total changes recorded: {len(all_changes)}")

    # 4. Filter changes by Regulation ID
    print("\n4. Filtering changes for 'GDPR-17'...")
    gdpr_changes = change_tracker.get_changes(regulation_id="GDPR-17")
    for change in gdpr_changes:
        print(f"   -> Found change from {change['timestamp']} (Severity: {change['severity']})")

    # 5. Filter changes by Time (Since 1 hour ago)
    print("\n5. Filtering changes from the last hour...")
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_changes = change_tracker.get_changes(since=one_hour_ago)
    print(f"   -> Found {len(recent_changes)} changes in the last hour.")

    # 6. Demonstrate Error Handling / Defaulting
    print("\n6. Logging with invalid severity (should default to 'medium')...")
    entry3 = change_tracker.log_change(
        regulation_id="HIPAA-Security",
        old_text="Encrypt data.",
        new_text="Encrypt data at rest.",
        severity="EXTREME_DANGER",  # Invalid
        affected_checkers=["chk_encryption"],
        tests_added=1
    )
    print(f"   -> Logged severity: {entry3['severity']} (Expected: 'medium')")

    print("\n=== Example Complete ===")
    print(f"Check the '{change_tracker.LOG_FILE}' file to see the persistent JSON log.")

if __name__ == "__main__":
    run_example()