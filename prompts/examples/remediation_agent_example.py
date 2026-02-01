"""
Example usage of the RegWatch Remediation Agent.

This script demonstrates how to use the remediation agent to:
1. Update a local PDD prompt file with new compliance requirements.
2. Trigger a regeneration of the compliance checker via GitHub issues.
3. Create a remediation Pull Request for a hypothetical violation.

Prerequisites:
- Environment variables TOOLHOUSE_API_KEY and GITHUB_TOKEN must be set.
- A dummy prompt file (e.g., 'prompts/hipaa_checker.md') for demonstration.
"""

import os
import sys
import time
from pathlib import Path

# Add the project root to sys.path to allow importing from src
# This assumes the script is run from the project root or a subdirectory
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

try:
    from src.agents.remediation_agent import (
        update_prompt,
        regenerate_checker,
        create_remediation_pr,
        PermissionMode
    )
except ImportError as e:
    print(f"Error importing module: {e}")
    print("Ensure you are running this script with the correct python path.")
    sys.exit(1)

# Mock Data for Demonstration
MOCK_PROMPT_FILE = "prompts/example_checker.md"
MOCK_REPO_NAME = "acme/backend-service"  # Replace with a real repo you have access to for testing

def setup_mock_environment():
    """Creates a dummy prompt file for testing updates."""
    os.makedirs("prompts", exist_ok=True)
    if not os.path.exists(MOCK_PROMPT_FILE):
        with open(MOCK_PROMPT_FILE, "w", encoding="utf-8") as f:
            f.write("# HIPAA Compliance Checker\n\n## Overview\nChecks for PHI handling.\n\n# Requirements\n- Data must be encrypted at rest.\n")
        print(f"Created mock prompt file at {MOCK_PROMPT_FILE}")

def main():
    # 1. Setup
    setup_mock_environment()
    
    print("\n--- Step 1: Updating Prompt File ---")
    new_reqs = [
        "All access logs must be retained for 6 years.",
        "MFA is required for remote access."
    ]
    
    success = update_prompt(MOCK_PROMPT_FILE, new_reqs)
    if success:
        print("Prompt updated successfully. New content:")
        with open(MOCK_PROMPT_FILE, "r") as f:
            print(f.read())
    else:
        print("Failed to update prompt.")

    print("\n--- Step 2: Triggering Checker Regeneration ---")
    # Note: This requires a valid GITHUB_TOKEN and access to the REGWATCH_REPO
    if os.getenv("GITHUB_TOKEN"):
        print("Triggering PDD sync for 'checkers.hipaa'...")
        # In a real run, this would create a GitHub issue
        # sync_success = regenerate_checker("checkers.hipaa")
        # print(f"Sync trigger status: {sync_success}")
        print("(Skipping actual API call to avoid spamming real repos in this example)")
    else:
        print("Skipping Step 2: GITHUB_TOKEN not set.")

    print("\n--- Step 3: Creating Remediation PR ---")
    # Define a patch that fixes a violation
    # This simulates a fix for a hardcoded password
    patch_content = {
        "src/config.py": """
class Config:
    # Fixed: Removed hardcoded secret
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DEBUG = False
"""
    }

    if os.getenv("GITHUB_TOKEN") and os.getenv("TOOLHOUSE_API_KEY"):
        print("Attempting to create PR...")
        try:
            # We use REQUEST_APPROVAL mode to be safe
            pr_url = create_remediation_pr(
                customer_repo_name=MOCK_REPO_NAME,
                patch=patch_content,
                permission_mode=PermissionMode.REQUEST_APPROVAL.value,
                regulation_ref="HIPAA-164.312(a)(1)",
                violation_summary="Hardcoded database credentials found in config.py"
            )
            
            if pr_url:
                print(f"PR Created successfully: {pr_url}")
            else:
                print("PR was merged automatically or notification sent.")
                
        except Exception as e:
            print(f"PR creation failed (expected if repo doesn't exist): {e}")
    else:
        print("Skipping Step 3: Missing API keys (GITHUB_TOKEN or TOOLHOUSE_API_KEY).")

    # Cleanup
    if os.path.exists(MOCK_PROMPT_FILE):
        os.remove(MOCK_PROMPT_FILE)
        try:
            os.rmdir("prompts")
        except OSError:
            pass
        print("\nCleaned up mock files.")

if __name__ == "__main__":
    main()