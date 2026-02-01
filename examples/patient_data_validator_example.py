#!/usr/bin/env python
"""
Patient Data Validator Example
This example demonstrates the usage of the patient_data_validator module.
"""

import os
import sys

# Bootstrap: If not running in the project's venv, re-exec with the venv python
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
VENV_PYTHON = os.path.join(PROJECT_ROOT, '.venv', 'bin', 'python')

# Check if we're running in the venv, if not and venv exists, re-exec
if os.path.exists(VENV_PYTHON) and sys.executable != VENV_PYTHON:
    import subprocess
    # Re-execute this script with the venv python
    result = subprocess.run([VENV_PYTHON, __file__] + sys.argv[1:])
    sys.exit(result.returncode)

# Now we can safely import dependencies
import pandas as pd
from datetime import datetime, timedelta

# Ensure the module can be imported by adding the parent directory to sys.path
# Adjust this path based on your actual project structure relative to this script
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.validators import patient_data_validator as validator

def create_dummy_csv(filename: str, num_records: int = 5):
    """Creates a dummy CSV file with a mix of valid and invalid records."""
    
    now = datetime.now()
    
    data = {
        'patient_id': [],
        'consent_signed': [],
        'consent_date': [],
        'encrypted_ssn': [],
        'encrypted_medical_record': [],
        'last_access_date': [],
        'last_access_user': [],
        'created_date': [],
        'data_retention_expires': []
    }

    # 1. Valid Record
    data['patient_id'].append('P001')
    data['consent_signed'].append(True)
    data['consent_date'].append((now - timedelta(days=10)).isoformat())
    data['encrypted_ssn'].append('A8f#9kL$mP2zQ1w') # Long string simulating encryption
    data['encrypted_medical_record'].append('B7d@1jN%nR3xS2y')
    data['last_access_date'].append((now - timedelta(hours=2)).isoformat())
    data['last_access_user'].append('dr_smith')
    data['created_date'].append((now - timedelta(days=30)).isoformat())
    data['data_retention_expires'].append(None)

    # 2. Invalid: Missing Consent
    data['patient_id'].append('P002')
    data['consent_signed'].append(False)
    data['consent_date'].append(None)
    data['encrypted_ssn'].append('C6c^2hO&oT4vU3z')
    data['encrypted_medical_record'].append('D5b*3gP(pU5wV4a')
    data['last_access_date'].append((now - timedelta(hours=5)).isoformat())
    data['last_access_user'].append('nurse_joy')
    data['created_date'].append((now - timedelta(days=10)).isoformat())
    data['data_retention_expires'].append(None)

    # 3. Invalid: Unencrypted Data (Short strings)
    data['patient_id'].append('P003')
    data['consent_signed'].append(True)
    data['consent_date'].append((now - timedelta(days=5)).isoformat())
    data['encrypted_ssn'].append('1234') # Too short
    data['encrypted_medical_record'].append('flu') # Too short
    data['last_access_date'].append((now - timedelta(hours=1)).isoformat())
    data['last_access_user'].append('admin_user')
    data['created_date'].append((now - timedelta(days=5)).isoformat())
    data['data_retention_expires'].append(None)

    # 4. Invalid: Retention Policy Exceeded (> 7 years)
    data['patient_id'].append('P004')
    data['consent_signed'].append(True)
    data['consent_date'].append((now - timedelta(days=3000)).isoformat())
    data['encrypted_ssn'].append('E4a!4fQ)qV6xW5b')
    data['encrypted_medical_record'].append('F3z#5eR*rW7yX6c')
    data['last_access_date'].append((now - timedelta(days=1)).isoformat())
    data['last_access_user'].append('archivist')
    data['created_date'].append((now - timedelta(days=365 * 8)).isoformat()) # 8 years old
    data['data_retention_expires'].append(None)

    # 5. Invalid: Missing Access Logs for old record
    data['patient_id'].append('P005')
    data['consent_signed'].append(True)
    data['consent_date'].append((now - timedelta(days=100)).isoformat())
    data['encrypted_ssn'].append('G2y$6dS&sX8zY7d')
    data['encrypted_medical_record'].append('H1x%7cT^tY9aZ8e')
    data['last_access_date'].append(None) # Missing
    data['last_access_user'].append(None) # Missing
    data['created_date'].append((now - timedelta(days=100)).isoformat())
    data['data_retention_expires'].append(None)

    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Created dummy file: {filename}")
    return df

def print_report(report):
    """Helper to pretty print the validation report."""
    print("\n" + "="*40)
    print("VALIDATION REPORT SUMMARY")
    print("="*40)
    print(f"Total Records:      {report['total']}")
    print(f"Compliant:          {report['compliant']}")
    print(f"Non-Compliant:      {report['non_compliant']}")
    print("-" * 40)
    
    if report['violations']:
        print(f"Found {len(report['violations'])} violations:")
        # Group by patient for readability
        violations_by_patient = {}
        for v in report['violations']:
            pid = v['patient_id']
            if pid not in violations_by_patient:
                violations_by_patient[pid] = []
            violations_by_patient[pid].append(v)

        for pid, violations in violations_by_patient.items():
            print(f"\nPatient ID: {pid}")
            for v in violations:
                print(f"  [{v['severity'].upper()}] {v['violation_type']} ({v['field_name']})")
                print(f"    -> {v['description']}")
    else:
        print("No violations found. All records are compliant.")
    print("="*40 + "\n")

def main():
    # 1. Validate an in-memory DataFrame
    print("--- Scenario 1: Validating In-Memory DataFrame ---")
    
    # Create dummy data directly
    df = create_dummy_csv("temp_patient_records.csv")
    
    # Run validation
    print("Running validation on DataFrame...")
    df_report = validator.validate_dataframe(df)
    print_report(df_report)

    # 2. Validate a CSV file (simulating a file upload)
    print("--- Scenario 2: Validating CSV File (Simulating Upload) ---")
    csv_filename = "temp_patient_records.csv"
    
    if os.path.exists(csv_filename):
        print(f"Reading and validating file: {csv_filename}")
        
        # This function handles chunking automatically for large files
        file_report = validator.validate_records(csv_filename)
        print_report(file_report)
        
        # Cleanup
        os.remove(csv_filename)
        print("Cleaned up temporary file.")
    else:
        print("Error: CSV file creation failed.")

if __name__ == "__main__":
    main()