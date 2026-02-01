import os
import sys
import json
from typing import NoReturn

# Ensure the module can be imported by adding the parent directory to sys.path
# Adjust this path based on your actual project structure
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the checker function from the module
# Note: This assumes hipaa_audit_logging_checker is available in the environment
try:
    from hipaa_audit_logging_checker import check_audit_logging
except ImportError:
    def check_audit_logging(filename: str) -> dict:
        """Mock function for demonstration if module is missing."""
        return {"status": "error", "message": f"Module not found. Would analyze {filename}"}

def create_sample_file(filename: str, content: str) -> None:
    """Helper to create a temporary Python file for analysis."""
    with open(filename, 'w') as f:
        f.write(content)
    print(f"Created sample file: {filename}")

def main() -> None:
    """
    Main execution logic to demonstrate HIPAA audit logging validation.
    """
    # 1. Define a sample Python file that violates HIPAA logging rules
    # - Accesses ePHI (patient records)
    # - Missing audit logs
    # - Insufficient retention policy
    non_compliant_code = """
import logging

# Violation: Retention is too short (needs 2190 days)
LOG_RETENTION_DAYS = 30 

def get_patient_diagnosis(patient_id):
    # Violation: Accessing ePHI without logging
    db.query(f"SELECT diagnosis FROM medical_records WHERE id={patient_id}")
    return "Flu"

def update_treatment_plan(patient_id, plan):
    # Violation: Logging exists but is missing required fields (user, action)
    db.save("treatment_plans", patient_id, plan)
    logging.info(f"Updated plan for {patient_id}")
"""

    # 2. Define a sample Python file that is compliant
    compliant_code = """
import logging

# Compliant: Retention meets 6-year requirement
LOG_RETENTION_DAYS = 2190 

# Compliant: Tamper-proof mode indicated
log_file = open("audit.log", "a") 

def get_patient_diagnosis(user_id, patient_id):
    # Compliant: Access is logged with all required fields
    result = db.query(f"SELECT diagnosis FROM medical_records WHERE id={patient_id}")
    
    logging.info(
        "ePHI Access",
        extra={
            "user": user_id,
            "action": "read_diagnosis",
            "resource": patient_id,
            "timestamp": "2023-10-27T10:00:00Z"
        }
    )
    return result
"""

    # Create temporary files
    bad_file = "unsafe_medical_app.py"
    good_file = "safe_medical_app.py"
    
    try:
        create_sample_file(bad_file, non_compliant_code)
        create_sample_file(good_file, compliant_code)

        print("\n--- Analyzing Non-Compliant File ---")
        # Run the checker
        report_bad = check_audit_logging(bad_file)
        
        # Pretty print the JSON result
        print(json.dumps(report_bad, indent=2))

        print("\n--- Analyzing Compliant File ---")
        # Run the checker
        report_good = check_audit_logging(good_file)
        
        # Pretty print the JSON result
        print(json.dumps(report_good, indent=2))

    finally:
        # Cleanup
        if os.path.exists(bad_file):
            os.remove(bad_file)
        if os.path.exists(good_file):
            os.remove(good_file)

if __name__ == "__main__":
    main()