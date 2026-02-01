import os
import json

import tempfile
from typing import Any, Dict
from hipaa_access_control_checker import check_access_control

def run_example() -> None:
    """
    Demonstrates how to use the HIPAA Access Control Checker.
    
    This example:
    1. Creates a temporary Python file with some intentional HIPAA violations.
    2. Runs the checker against this file.
    3. Prints the compliance report.
    """
    
    # 1. Create a dummy Python file with intentional violations
    # Violations included:
    # - Unauthenticated ePHI access (get_patient_records)
    # - Session timeout too long (30 minutes)
    # - User model missing unique ID
    
    vulnerable_code = """
import os
from flask import Flask, session

app = Flask(__name__)

# VIOLATION: Session timeout is 30 minutes (1800s), exceeding the 15-minute (900s) limit
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# VIOLATION: User model lacks a clear unique ID field (like 'id', 'uuid', 'pk')
class User:
    def __init__(self, username, email):
        self.username = username
        self.email = email
        self.role = 'user'

# VIOLATION: Accessing ePHI without an auth decorator (@login_required)
@app.route('/api/patient/<name>')
def get_patient_records(name):
    # This function accesses Protected Health Information (PHI)
    return {"patient": name, "diagnosis": "flu"}

# COMPLIANT: This function has authentication
@app.route('/api/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return "Admin Panel"
"""

    # Create a temporary file to analyze
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(vulnerable_code)
        tmp_path = tmp.name

    try:
        print(f"Analyzing file: {tmp_path}...\n")

        # 2. Run the checker
        report: Dict[str, Any] = check_access_control(tmp_path)

        # 3. Display results
        status = '✅ COMPLIANT' if report.get('compliant') else '❌ NON-COMPLIANT'
        print(f"Compliance Status: {status}")
        print(f"Overall Severity: {report.get('severity')}")
        print(f"Regulation: {report.get('regulation_reference')}")
        print("-" * 60)
        
        findings = report.get('findings', [])
        if findings:
            print(f"Found {len(findings)} violations:\n")
            for i, finding in enumerate(findings, 1):
                print(f"Finding #{i}: {finding.get('violation_type')}")
                print(f"  Line: {finding.get('line_number')}")
                print(f"  Severity: {finding.get('severity')}")
                print(f"  Description: {finding.get('description')}")
                print(f"  Fix: {finding.get('remediation_suggestion')}")
                print("-" * 40)
        else:
            print("No violations found.")

    except Exception as e:
        print(f"An error occurred during analysis: {e}")

    finally:
        # Cleanup
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == "__main__":
    run_example()