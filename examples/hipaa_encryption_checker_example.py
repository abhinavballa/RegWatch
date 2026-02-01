import os
import sys
import json

# Ensure the module can be imported by adding the parent directory to sys.path
# Adjust this path based on your actual project structure relative to this script
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.checkers.hipaa_encryption_checker import check_encryption

def create_dummy_vulnerable_code(filename: str) -> str:
    """Creates a temporary Python file with intentional HIPAA violations for demonstration."""
    code = """
import sqlalchemy
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# VIOLATION 1: Hardcoded secret key
API_SECRET_KEY = "12345-abcde-secret-key-here"

# VIOLATION 2: Weak hashing algorithm
def hash_password(pwd):
    import hashlib
    return hashlib.md5(pwd.encode()).hexdigest()

# VIOLATION 3: Database connection without TLS
DB_URI = "postgresql://user:pass@localhost:5432/medical_db?sslmode=disable"

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    
    # VIOLATION 4: Unencrypted PHI field (SSN)
    ssn = Column(String(11)) 
    
    # Compliant field (generic data)
    favorite_color = Column(String(50))
"""
    with open(filename, "w") as f:
        f.write(code)
    return filename

def main() -> None:
    # 1. Setup a target file to scan
    target_file = "temp_vulnerable_service.py"
    create_dummy_vulnerable_code(target_file)
    
    print(f"Scanning {target_file} for HIPAA encryption compliance...\n")

    # 2. Run the checker
    # The function accepts a file path or a directory path
    try:
        report = check_encryption(target_file)

        # 3. Process the results
        print(f"Compliance Status: {'PASSED' if report['compliant'] else 'FAILED'}")
        print(f"Overall Severity:  {report['severity'].upper()}")
        print(f"Regulation Ref:    {report['regulation_reference']}")
        print("-" * 60)

        if report["findings"]:
            print(f"Found {len(report['findings'])} violations:\n")
            for i, finding in enumerate(report["findings"], 1):
                print(f"{i}. [{finding['severity'].upper()}] {finding['violation_type']}")
                print(f"   Line: {finding['line_number']}")
                print(f"   File: {finding['file']}")
                print(f"   Issue: {finding['description']}")
                print(f"   Fix: {finding['remediation_suggestion']}")
                print("")
        else:
            print("No violations found.")
    except Exception as e:
        print(f"An error occurred during scanning: {e}")
    finally:
        # Cleanup
        if os.path.exists(target_file):
            os.remove(target_file)

if __name__ == "__main__":
    main()