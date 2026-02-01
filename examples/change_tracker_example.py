import os
import sys
from datetime import datetime, timedelta, timezone

# Ensure the module can be imported from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

import change_tracker

def main():
    print("=== RegWatch Change Tracker Demo ===\n")

    # 1. Log a critical regulation change
    # This simulates an update to a GDPR regulation requiring immediate attention.
    print("Logging critical GDPR update...")
    entry1 = change_tracker.log_change(
        regulation_id="GDPR-Art-17",
        old_text="The data subject shall have the right to obtain erasure...",
        new_text="The data subject shall have the right to obtain erasure without undue delay...",
        severity="critical",
        affected_checkers=["chk_data_retention", "chk_user_deletion_flow"],
        tests_added=2
    )
    print(f"Logged entry ID: {entry1['regulation_id']} | Timestamp: {entry1['timestamp']}")

    # 2. Log a minor update
    # This simulates a low-impact clarification.
    print("\nLogging minor CCPA update...")
    entry2 = change_tracker.log_change(
        regulation_id="CCPA-Sec-1798",
        old_text="Business must disclose categories...",
        new_text="Business must disclose specific categories...",
        severity="low",
        affected_checkers=["chk_disclosure_form"],
        tests_added=0
    )
    print(f"Logged entry ID: {entry2['regulation_id']} | Impact Score: {entry2['customer_impact']['score']}")

    # 3. Retrieve specific changes (Filtering)
    # Fetch changes for GDPR-Art-17 specifically.
    print("\nQuerying history for 'GDPR-Art-17':")
    gdpr_changes = change_tracker.get_changes(regulation_id="GDPR-Art-17")
    for change in gdpr_changes:
        print(f"- [{change['severity'].upper()}] {change['regulation_id']}: {change['new_text'][:30]}...")

    # 4. Retrieve recent changes (Time-based)
    # Fetch changes that happened in the last 5 minutes.
    five_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    print(f"\nQuerying changes since {five_mins_ago.strftime('%H:%M:%S')}:")
    
    recent_changes = change_tracker.get_changes(since=five_mins_ago)
    print(f"Found {len(recent_changes)} recent changes.")

    # 5. View full history
    # Get the raw log data structure.
    print("\nFull Audit Trail Summary:")
    full_history = change_tracker.get_change_history()
    total_entries = len(full_history["changes"])
    print(f"Total records in log file: {total_entries}")
    
    # Verify file location
    print(f"\nLog file location: {os.path.abspath(change_tracker.LOG_FILE)}")

if __name__ == "__main__":
    main()