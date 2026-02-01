import os
import json
import tempfile
from src.checkers.hipaa_access_control_checker import check_access_control

def run_demo():
    """
    Demonstrates the usage of the HIPAA Access Control Checker.
    
    This example creates a temporary Python file with some intentional 
    HIPAA violations (and some compliant code) to show how the 
    checker analyzes the AST and reports findings.
    """

    # 1. Create a sample Python file with mixed compliance
    #    - Has a User model (Good)
    #    - Has an unauthenticated PHI endpoint (Bad)
    #    - Has a secure session timeout (Good)
    #    - Has an insecure session timeout (Bad)
    sample_code = """
from flask import Flask, session
from flask_login import login_required

app = Flask(__name__)

# VIOLATION: Session timeout > 900s (15 mins)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600 

class User:
    # COMPLIANT: User model has a unique ID
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@app.route('/public')
def index():
    return "Welcome"

@app.route('/patient/records')
# VIOLATION: Accesses PHI ('patient') but missing @login_required
def get_patient_records():
    # This function accesses ePHI
    return "Patient Diagnosis: Healthy"

@app.route('/lab/results')
@login_required
# COMPLIANT: Accesses PHI ('lab') and is authenticated
def get_lab_results():
    return "Lab Results: Negative"
    """

    # Write the sample code to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(sample_code)
        tmp_path = tmp.name

    try:
        print(f"Analyzing file: {tmp_path}...\n")

        # 2. Run the checker
        #    The function takes a file path and returns a dictionary report.
        report = check_access_control(tmp_path)

        # 3. Process the results
        print(f"Compliance Status: {'✅ COMPLIANT' if report['compliant'] else '❌ NON-COMPLIANT'}")
        print(f"Overall Severity:  {report['severity']}")
        print(f"Framework:         {report['meta']['framework_detected']}")
        print("-" * 60)

        if report['findings']:
            print("Findings:")
            for i, finding in enumerate(report['findings'], 1):
                print(f"\n{i}. [{finding['severity']}] {finding['violation_type']}")
                print(f"   Line: {finding['line_number']}")
                print(f"   Issue: {finding['description']}")
                print(f"   Fix:   {finding['remediation_suggestion']}")
        else:
            print("No violations found.")

    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == "__main__":
    run_demo()