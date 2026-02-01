import os
import sys
import json

# Ensure the module can be imported. 
# In a real project, this would likely be installed or in the PYTHONPATH.
# For this example, we assume the module is in a sibling directory 'src/checkers'.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.checkers.hipaa_encryption_checker import check_encryption
except ImportError:
    print("Error: Could not import 'check_encryption'. Ensure 'src/checkers/hipaa_encryption_checker.py' exists.")
    sys.exit(1)

def create_dummy_vulnerable_file(filepath: str) -> None:
    """Creates a temporary Python file with intentional HIPAA violations for demonstration."""
    content = """
import hashlib
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# VIOLATION 1: Hardcoded Secret
API_KEY = \"12345-secret-key-hardcoded-in-source\"

# VIOLATION 2: Weak Hashing Algorithm (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    
    # VIOLATION 3: Unencrypted PHI Field (SSN)
    ssn = Column(String) 
    
    # VIOLATION 4: Unencrypted PHI Field (Medical Record Number)
    medical_record_number = Column(String)

# VIOLATION 5: Database Connection without TLS enforcement
DB_URL = \"postgres://user:pass@localhost:5432/medical_db\"
"""
    with open(filepath, "w") as f:
        f.write(content)
    print(f"Created dummy file for scanning: {filepath}")

def main() -> None:
    # 1. Setup: Create a dummy file to scan
    target_file = "vulnerable_patient_service.py"
    create_dummy_vulnerable_file(target_file)

    print("\n--- Starting HIPAA Encryption Compliance Scan ---\n")

    # 2. Run the checker
    # The function accepts a file path or a directory path.
    report = check_encryption(target_file)

    # 3. Process the results
    print(f"Compliance Status: {'✅ COMPLIANT' if report['compliant'] else '❌ NON-COMPLIANT'}")
    print(f"Overall Severity: {report['severity'].upper()}")
    print(f"Regulation: {report['regulation_reference']}")
    
    if report['findings']:
        print(f"\nFound {len(report['findings'])} violations:")
        print("-" * 60)
        
        for i, finding in enumerate(report['findings'], 1):
            print(f"Finding #{i}: {finding['violation_type']}")
            print(f"  Severity:    {finding['severity'].upper()}")
            print(f"  Line:        {finding['line_number']}")
            print(f"  Description: {finding['description']}")
            print(f"  Remediation: {finding['remediation_suggestion']}")
            print("-" * 60)
    else:
        print("\nNo violations found. Code appears compliant.")

    # Cleanup
    if os.path.exists(target_file):
        os.remove(target_file)
        print(f"\nCleaned up dummy file: {target_file}")

if __name__ == "__main__":
    main()