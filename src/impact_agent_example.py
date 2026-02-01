import os
import sys
import json
import logging
from typing import Dict, List

# Add the project root to sys.path to allow importing the module
# This assumes the script is located in a subdirectory (e.g., examples/)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.append(project_root)

# Import the module functions
# Note: Adjust the import path based on your actual project structure
try:
    from src.agents.impact_agent import assess_impact, prioritize_customers
except ImportError:
    # Fallback for when running directly next to the file
    try:
        from impact_agent import assess_impact, prioritize_customers
    except ImportError:
        print("Error: Could not import impact_agent. Ensure the module is in the python path.")
        sys.exit(1)

# Configure logging to see the agent's progress
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

def main() -> None:
    """
    Demonstrates the workflow of the RegWatch Impact Agent:
    1. Setup mock environment (API keys, file paths).
    2. Define affected checkers and customer codebases.
    3. Run the impact assessment.
    4. Prioritize high-risk customers.
    5. Display the final report.
    """
    print("--- RegWatch Impact Agent Example ---\n")

    # 1. Setup Environment
    # The agent requires the TOOLHOUSE_API_KEY to execute code in sandboxes.
    if not os.getenv("TOOLHOUSE_API_KEY"):
        print("Warning: TOOLHOUSE_API_KEY not set. The agent may fail or use mock execution.")
        # For demonstration purposes, we might set a dummy key if the module supports mocking
        os.environ["TOOLHOUSE_API_KEY"] = "mock-api-key"

    # 2. Define Inputs
    
    # List of checker IDs that need to be run due to a regulation change.
    # These IDs must map to actual checker source files in the agent's configuration.
    affected_checkers: List[str] = [
        "hipaa_encryption_checker",
        "hipaa_access_control_checker"
    ]

    # Dictionary mapping Customer IDs to the local path of their codebase.
    # In a real scenario, these paths would point to cloned repositories.
    # Here we use dummy paths; the module's mock execution will handle them if SDK is missing.
    customer_codebases: Dict[str, str] = {
        "cust_001_health_corp": "/tmp/repos/health_corp_v2",
        "cust_002_med_start": "/tmp/repos/med_start_api",
        "cust_003_clinic_sys": "/tmp/repos/clinic_sys_backend",
        "cust_004_secure_records": "/tmp/repos/secure_records_legacy"
    }

    print(f"Checkers to run: {affected_checkers}")
    print(f"Customers to assess: {list(customer_codebases.keys())}")
    print("\nRunning assessment (this may take a moment)...\n")

    # 3. Run Impact Assessment
    # This function orchestrates the Toolhouse execution for every customer/checker pair.
    impact_report = assess_impact(affected_checkers, customer_codebases)

    if "error" in impact_report:
        print(f"Assessment failed: {impact_report['error']}")
        return

    # 4. Analyze Results
    print(f"Assessment Complete.")
    print(f"Total Violations Found: {impact_report.get('total_violations', 0)}")
    print(f"Severity Breakdown: {json.dumps(impact_report.get('severity_breakdown', {}), indent=2)}")
    
    # 5. Prioritize Customers
    # The module automatically prioritizes, but we can also call the function explicitly
    # if we want to re-sort or filter existing data.
    high_risk_list = prioritize_customers(impact_report)

    print("\n--- High Risk Customers (Prioritized) ---")
    for rank, customer in enumerate(high_risk_list, 1):
        print(f"\nRank {rank}: {customer['customer_id']}")
        print(f"  Risk Score:       {customer['risk_score']}")
        print(f"  Est. Fine:        ${customer['estimated_fine']:,.2f}")
        print(f"  Violations:       {customer['violations_count']}")
        print(f"  Remediation Est:  {customer['remediation_hours']} hours")
        print(f"  Severity Counts:  {customer['severity_counts']}")

if __name__ == "__main__":
    main()