import os
import json
import tempfile
from src.checkers.hipaa_audit_logging_checker import check_audit_logging

def create_sample_file(filename, content):
    """Helper to create a temporary Python file for analysis."""
    with open(filename, "w") as f:
        f.write(content)
    return filename

def main():
    # 1. Define sample code that VIOLATES HIPAA logging rules
    # - Accesses 'patient_record' (ePHI indicator)
    # - No logging calls
    # - Retention set too low (30 days vs 2190 required)
    non_compliant_code = """
import logging

# Violation: Retention is too short (needs 6 years/2190 days)
LOG_RETENTION_DAYS = 30 

def get_patient_diagnosis(patient_id):
    # Violation: Accesses ePHI but has no audit log
    db.query(f"SELECT * FROM patient_records WHERE id={patient_id}")
    return "Diagnosis: Healthy"
"""

    # 2. Define sample code that COMPLIES with HIPAA logging rules
    # - Accesses 'patient_record'
    # - Includes logging with user, action, and resource
    # - Retention set correctly
    # - References immutable storage
    compliant_code = """
import logging

# Compliance: Retention >= 6 years
LOG_RETENTION_DAYS = 2500
# Compliance: Immutable storage reference
LOG_STORAGE_CLASS = "S3_WORM_IMMUTABLE"

logger = logging.getLogger("audit")

def update_patient_treatment(user_id, patient_id, treatment):
    # Compliance: Audit log includes User, Action, and Resource
    logger.info(
        "User %s updated treatment for patient %s", 
        user_id, 
        patient_id, 
        extra={'action': 'update', 'resource': 'patient_record'}
    )
    
    # Compliance: SIEM integration reference
    splunk_forwarder.send_event("treatment_update")
    
    db.save(patient_id, treatment)
"""

    # Create temporary files to analyze
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = os.path.join(tmpdir, "bad_api.py")
        good_file = os.path.join(tmpdir, "good_api.py")
        
        create_sample_file(bad_file, non_compliant_code)
        create_sample_file(good_file, compliant_code)

        print("--- Analyzing Non-Compliant Code ---")
        report_bad = check_audit_logging(bad_file)
        
        print(f"Compliant: {report_bad['compliant']}")
        print(f"Severity: {report_bad['severity']}")
        print("Findings:")
        print(json.dumps(report_bad['findings'], indent=2))

        print("\n" + "="*40 + "\n")

        print("--- Analyzing Compliant Code ---")
        report_good = check_audit_logging(good_file)
        
        print(f"Compliant: {report_good['compliant']}")
        print(f"Severity: {report_good['severity']}")
        if report_good['findings']:
            print("Findings:")
            print(json.dumps(report_good['findings'], indent=2))
        else:
            print("No violations found.")

if __name__ == "__main__":
    main()