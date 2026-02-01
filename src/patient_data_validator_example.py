import pandas as pd
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Ensure the module can be imported by adding the current directory to sys.path
# Adjust this path if your module is in a different directory relative to this script
sys.path.append(os.path.dirname(__file__))

try:
    import patient_data_validator as validator
except ImportError:
    # Mocking the validator for the sake of a runnable example if the module is missing
    class MockValidator:
        @staticmethod
        def validate_records(filename: str) -> Dict[str, Any]:
            return {"total": 5, "compliant": 2, "non_compliant": 3, "violations": []}
        
        @staticmethod
        def validate_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
            return {"total": len(df), "compliant": len(df), "non_compliant": 0, "violations": []}
    validator = MockValidator()

def create_dummy_csv(filename: str) -> str:
    """Creates a dummy CSV file with compliant and non-compliant records."""
    
    # Helper to get a date string relative to now
    def days_ago(days: int) -> str:
        return (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    data = {
        'patient_id': ['P001', 'P002', 'P003', 'P004', 'P005'],
        'consent_signed': [True, False, True, True, True],
        'consent_date': [days_ago(10), days_ago(5), days_ago(365), days_ago(1), days_ago(100)],
        # P002: Missing consent (False)
        
        'encrypted_ssn': [
            'A8f9#kL2$mP',   # Valid
            'A8f9#kL2$mP',   # Valid
            '123',           # Invalid: Too short (heuristic check)
            'B7d8@jK1%nO',   # Valid
            'C6c7!hJ0^lI'    # Valid
        ],
        
        'encrypted_medical_record': [
            'X9e0&iN3*oQ',   # Valid
            'X9e0&iN3*oQ',   # Valid
            'X9e0&iN3*oQ',   # Valid
            '',              # Invalid: Empty
            'Y8d9%hM2(nP'    # Valid
        ],
        
        'last_access_date': [
            days_ago(1), 
            days_ago(2), 
            days_ago(5), 
            None,            # Invalid: Missing access log for old record
            None             # Valid: New record (created today)
        ],
        
        'last_access_user': [
            'admin_user', 
            'dr_smith', 
            'nurse_joy', 
            None,            # Invalid
            None             # Valid: New record
        ],
        
        'created_date': [
            days_ago(100), 
            days_ago(100), 
            days_ago(3000),  # Invalid: > 7 years (approx 2555 days)
            days_ago(50), 
            days_ago(0)      # New record
        ]
    }
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Created dummy file: {filename}")
    return filename

def print_report(report: Dict[str, Any], source_name: str) -> None:
    """Pretty prints the validation report."""
    print(f"\n--- Validation Report for: {source_name} ---")
    print(f"Total Records: {report['total']}")
    print(f"Compliant:     {report['compliant']}")
    print(f"Non-Compliant: {report['non_compliant']}")
    
    if report.get('violations'):
        print("\nViolations Found:")
        # Group by patient for readability
        sorted_violations = sorted(report['violations'], key=lambda x: x['patient_id'])
        
        print(f"{'Patient ID':<12} | {'Severity':<10} | {'Field':<25} | {'Issue'}")
        print("-" * 80)
        
        for v in sorted_violations:
            print(f"{v['patient_id']:<12} | {v['severity']:<10} | {v['field_name']:<25} | {v['violation_type']}")
    else:
        print("\nNo violations found. All records are compliant.")
    print("-" * 80)

def main() -> None:
    # 1. Validate from a CSV file (Simulating a batch upload)
    csv_filename = 'dummy_patient_records.csv'
    try:
        create_dummy_csv(csv_filename)
        
        print("\nRunning CSV Validation (Chunked)...")
        csv_report = validator.validate_records(csv_filename)
        print_report(csv_report, "CSV File Upload")
        
    except Exception as e:
        print(f"An error occurred during CSV validation: {e}")
    finally:
        # Cleanup
        if os.path.exists(csv_filename):
            os.remove(csv_filename)

    # 2. Validate an in-memory DataFrame (Simulating real-time processing)
    print("\nRunning DataFrame Validation (In-Memory)...")
    
    # Create a single compliant record
    compliant_data = {
        'patient_id': ['P999'],
        'consent_signed': [True],
        'consent_date': [datetime.now() - timedelta(days=1)],
        'encrypted_ssn': ['ValidEncryptedString123'],
        'encrypted_medical_record': ['ValidEncryptedData456'],
        'last_access_date': [datetime.now()],
        'last_access_user': ['system_audit'],
        'created_date': [datetime.now() - timedelta(days=30)]
    }
    df_compliant = pd.DataFrame(compliant_data)
    
    df_report = validator.validate_dataframe(df_compliant)
    print_report(df_report, "Single Record DataFrame")

if __name__ == "__main__":
    main()