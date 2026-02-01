import pandas as pd
import os
from datetime import datetime, timedelta
import sys

# Ensure the module can be imported by adding the parent directory to sys.path
# Adjust this path based on your actual project structure relative to this script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../lib")))

from src.validators.patient_data_validator import validate_records, validate_dataframe

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
    df_report = validate_dataframe(df)
    print_report(df_report)

    # 2. Validate a CSV file (simulating a file upload)
    print("--- Scenario 2: Validating CSV File (Simulating Upload) ---")
    csv_filename = "temp_patient_records.csv"
    
    if os.path.exists(csv_filename):
        print(f"Reading and validating file: {csv_filename}")
        
        # This function handles chunking automatically for large files
        file_report = validate_records(csv_filename)
        print_report(file_report)
        
        # Cleanup
        os.remove(csv_filename)
        print("Cleaned up temporary file.")
    else:
        print("Error: CSV file creation failed.")

if __name__ == "__main__":
    main()