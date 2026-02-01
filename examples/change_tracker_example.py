import os
import sys
import logging
from datetime import datetime, timedelta, timezone

# Ensure the module can be imported (assuming it's in the same directory or python path)
# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    import change_tracker
except ImportError:
    print("Error: Could not import 'change_tracker'. Ensure the module file exists.")
    sys.exit(1)

# Configure logging to see module output
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    print("=== RegWatch Change Tracker Demo ===\n")

    # 1. Log a critical regulation update
    print("-> Logging a critical update to GDPR Article 17...")
    entry1 = change_tracker.log_change(
        regulation_id="GDPR-17",
        old_text="The data subject shall have the right to obtain from the controller the erasure of personal data...",
        new_text="The data subject shall have the IMMEDIATE right to obtain from the controller the erasure...",
        severity="critical",
        affected_checkers=["chk_data_retention", "chk_user_rights_portal"],
        tests_added=3
    )
    print(f"   Logged entry timestamp: {entry1['timestamp']}")
    print(f"   Customer Impact Score: {entry1['customer_impact']['score']}")

    # 2. Log a minor update (demonstrating default severity handling)
    print("\n-> Logging a minor update to CCPA-102...")
    change_tracker.log_change(
        regulation_id="CCPA-102",
        old_text="Businesses must disclose data sales.",
        new_text="Businesses must disclose data sales and sharing.",
        severity="low",  # Will result in lower impact score
        affected_checkers=["chk_privacy_policy_text"],
        tests_added=1
    )

    # 3. Retrieve full history
    print("\n-> Retrieving full change history...")
    history = change_tracker.get_change_history()
    print(f"   Total records found: {len(history['changes'])}")

    # 4. Filter changes by Regulation ID
    print("\n-> Filtering for 'GDPR-17' changes...")
    gdpr_changes = change_tracker.get_changes(regulation_id="GDPR-17")
    for change in gdpr_changes:
        print(f"   - [{change['timestamp']}] Severity: {change['severity']}")

    # 5. Filter changes by Time (e.g., changes in the last 5 minutes)
    five_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    print(f"\n-> Filtering for changes since {five_mins_ago.isoformat()}...")
    
    recent_changes = change_tracker.get_changes(since=five_mins_ago)
    print(f"   Found {len(recent_changes)} recent changes.")

    # 6. Verify persistence
    log_path = os.path.join("logs", "regulation_changes.json")
    if os.path.exists(log_path):
        print(f"\n-> Verified: Log file exists at {log_path}")
    else:
        print(f"\n-> Error: Log file was not created at {log_path}")

if __name__ == "__main__":
    main()