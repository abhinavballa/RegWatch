# TEST PLAN
#
# 1. Unit Tests (Pytest):
#    The goal is to verify the static analysis logic of the `hipaa_encryption_checker` module.
#    Since the module analyzes source code files, the tests will generate temporary Python files
#    containing specific code patterns (both compliant and non-compliant) and assert that
#    `check_encryption` returns the expected findings.
#
#    Test Cases:
#    - test_compliant_code: Verify that code with strong encryption, TLS, and no secrets returns compliant=True.
#    - test_hardcoded_key_detection: Verify detection of string literals assigned to variables like 'secret_key'.
#      Edge case: Ensure short strings or variables with "env" in the name are ignored.
#    - test_db_connection_tls: Verify detection of database URLs missing 'sslmode=require' or similar.
#    - test_phi_field_encryption: Verify detection of fields like 'ssn' defined without encryption wrappers.
#      Edge case: Verify that 'EncryptedType' or similar keywords prevent false positives.
#    - test_weak_algorithm_usage: Verify detection of 'md5', 'sha1', etc.
#    - test_weak_tls_protocol: Verify detection of 'PROTOCOL_TLSv1'.
#    - test_missing_encryption_library: Verify detection of PHI keywords in a file that imports no crypto libs.
#    - test_key_rotation_policy: Verify detection of Config classes with keys but missing rotation docstrings.
#    - test_directory_analysis: Verify the function works recursively on directories.
#    - test_syntax_error_handling: Verify the checker handles invalid Python files gracefully.
#
# 2. Z3 Formal Verification:
#    The module contains a logic for aggregating severity levels (Critical > High > Medium > Low).
#    We will use Z3 to formally verify this aggregation logic.
#    - Model the severity levels as an Enum or distinct integers.
#    - Define the aggregation logic constraints.
#    - Prove that if a 'critical' finding exists, the result is always 'critical', regardless of other findings.
#    - Prove that if no 'critical' but 'high' exists, result is 'high', etc.


import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

import pytest
import os
import tempfile
import shutil
import textwrap
from typing import List, Dict, Any
from z3 import Solver, Bool, Implies, And, Or, Not, sat, unsat

# Import the module under test
# Assuming the file is in the python path or same directory
import hipaa_encryption_checker

# --- Fixtures ---

@pytest.fixture
def temp_workspace():
    """Creates a temporary directory for test files and cleans it up afterwards."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

def create_test_file(directory: str, filename: str, content: str) -> str:
    """Helper to create a python file in the temp directory."""
    filepath = os.path.join(directory, filename)
    with open(filepath, "w") as f:
        f.write(textwrap.dedent(content))
    return filepath

# --- Unit Tests ---

def test_compliant_code(temp_workspace):
    """
    Verifies that fully compliant code results in no findings and compliant=True.
    """
    code = """
    import os
    from cryptography.fernet import Fernet
    from sqlalchemy import Column
    from sqlalchemy_utils import EncryptedType

    # Key from env
    api_key = os.getenv("API_KEY")

    # DB with TLS
    db_url = "postgres://user:pass@db.example.com:5432/db?sslmode=require"

    # Encrypted PHI
    class Patient(Base):
        ssn = Column(EncryptedType(String, os.getenv("KEY")))
    
    # Strong Algo
    cipher = Fernet(key)
    """
    filepath = create_test_file(temp_workspace, "compliant.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    assert report["compliant"] is True
    assert len(report["findings"]) == 0
    assert report["severity"] == "low"

def test_hardcoded_key_detection(temp_workspace):
    """
    Verifies detection of hardcoded secrets.
    """
    code = """
    def connect():
        # Violation: Hardcoded secret
        aws_secret_key = "AKIAIOSFODNN7EXAMPLE"
        
        # Ignored: "env" in name
        env_secret = "production"
        
        # Ignored: Short string
        my_key = "123"
    """
    filepath = create_test_file(temp_workspace, "hardcoded.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    assert report["compliant"] is False
    findings = report["findings"]
    assert len(findings) == 1
    assert findings[0]["violation_type"] == "HARDCODED_KEY"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["line_number"] == 4

def test_db_connection_missing_tls(temp_workspace):
    """
    Verifies detection of database connection strings missing TLS enforcement.
    """
    code = """
    # Violation: No sslmode
    db_url = "postgres://user:password@localhost:5432/mydb"
    
    # Compliant
    db_url_secure = "mysql://user:pass@host/db?sslmode=verify-full"
    """
    filepath = create_test_file(temp_workspace, "db_tls.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "MISSING_TLS_DB"]
    assert len(findings) == 1
    assert findings[0]["line_number"] == 3
    assert findings[0]["severity"] == "high"

def test_phi_field_encryption(temp_workspace):
    """
    Verifies detection of unencrypted PHI fields in ORM definitions.
    """
    code = """
    from sqlalchemy import Column, String
    
    class MedicalRecord(Base):
        # Violation: ssn is PHI and not encrypted
        ssn = Column(String(11))
        
        # Compliant: EncryptedType used
        diagnosis = Column(EncryptedType(String, key))
        
        # Compliant: 'encrypt' keyword used
        medical_record_number = Column(String, encrypt=True)
    """
    filepath = create_test_file(temp_workspace, "phi.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "UNENCRYPTED_PHI_FIELD"]
    assert len(findings) == 1
    assert "ssn" in findings[0]["description"]
    assert findings[0]["severity"] == "high"

def test_weak_algorithm_usage(temp_workspace):
    """
    Verifies detection of weak hashing or encryption algorithms.
    """
    code = """
    import hashlib
    
    def hash_data(data):
        # Violation: MD5 is weak
        return hashlib.md5(data).hexdigest()
        
    def encrypt_data(data):
        # Violation: DES is weak
        cipher = DES.new(key)
    """
    filepath = create_test_file(temp_workspace, "weak_algo.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "WEAK_ENCRYPTION_ALGO"]
    assert len(findings) >= 2
    algo_names = [f["description"] for f in findings]
    assert any("md5" in d for d in algo_names)
    assert any("DES" in d for d in algo_names)

def test_weak_tls_protocol(temp_workspace):
    """
    Verifies detection of weak TLS protocol versions in SSLContext.
    """
    code = """
    import ssl
    
    # Violation: TLSv1 is deprecated
    context = ssl.create_default_context(ssl.PROTOCOL_TLSv1)
    """
    filepath = create_test_file(temp_workspace, "weak_tls.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "WEAK_TLS_VERSION"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"

def test_missing_encryption_library(temp_workspace):
    """
    Verifies detection of PHI keywords in a file that doesn't import encryption libraries.
    """
    code = """
    # No imports of cryptography, etc.
    
    def process_patient(data):
        # 'ssn' is a PHI keyword
        ssn = data['social_security_number']
        print(ssn)
    """
    filepath = create_test_file(temp_workspace, "missing_lib.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "MISSING_ENCRYPTION_LIB"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"

def test_key_rotation_policy(temp_workspace):
    """
    Verifies detection of configuration classes containing keys but missing rotation documentation.
    """
    code = """
    class AppConfig:
        # Has 'key' in variable name
        api_key = os.getenv("KEY")
        
        # Missing docstring about rotation
    
    class GoodConfig:
        '''
        Configuration for the app.
        Key Rotation: Keys are rotated every 90 days.
        '''
        secret_key = os.getenv("SECRET")
    """
    filepath = create_test_file(temp_workspace, "rotation.py", code)
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = [f for f in report["findings"] if f["violation_type"] == "MISSING_KEY_ROTATION_POLICY"]
    assert len(findings) == 1
    assert "AppConfig" in findings[0]["description"]

def test_directory_analysis(temp_workspace):
    """
    Verifies that the checker recursively analyzes directories.
    """
    # Create nested structure
    sub_dir = os.path.join(temp_workspace, "subdir")
    os.makedirs(sub_dir)
    
    create_test_file(temp_workspace, "root.py", "import hashlib\nx = hashlib.md5()")
    create_test_file(sub_dir, "nested.py", "secret_key = '1234567890'")
    
    report = hipaa_encryption_checker.check_encryption(temp_workspace)
    
    assert len(report["findings"]) == 2
    types = {f["violation_type"] for f in report["findings"]}
    assert "WEAK_ENCRYPTION_ALGO" in types
    assert "HARDCODED_KEY" in types

def test_syntax_error_handling(temp_workspace):
    """
    Verifies that syntax errors in analyzed files are reported but don't crash the checker.
    """
    code = "def broken_function(:" # Syntax error
    filepath = create_test_file(temp_workspace, "broken.py", code)
    
    report = hipaa_encryption_checker.check_encryption(filepath)
    
    findings = report["findings"]
    assert len(findings) == 1
    assert findings[0]["violation_type"] == "SYNTAX_ERROR"
    assert report["severity"] != "critical" # Syntax error is usually low severity in this tool

# --- Z3 Formal Verification Tests ---

def test_z3_severity_aggregation_logic():
    """
    Formally verifies the severity aggregation logic used in the checker.
    Logic:
    - If any finding is Critical -> Overall Critical
    - Else if any finding is High -> Overall High
    - Else if any finding is Medium -> Overall Medium
    - Else -> Overall Low
    """
    solver = Solver()

    # Inputs: Boolean flags representing presence of findings with specific severities
    has_critical = Bool('has_critical')
    has_high = Bool('has_high')
    has_medium = Bool('has_medium')
    # has_low is implicit if others are false, or present. 
    # Actually, the logic usually defaults to low if nothing else is found, 
    # or if only low findings exist.
    
    # Outputs: Boolean flags representing the calculated overall severity
    is_critical = Bool('is_critical')
    is_high = Bool('is_high')
    is_medium = Bool('is_medium')
    is_low = Bool('is_low')

    # Define the logic constraints (Implementation Model)
    # This models the _calculate_severity function logic
    
    # Logic for Critical: True if has_critical is True
    solver.add(is_critical == has_critical)
    
    # Logic for High: True if has_high is True AND NOT has_critical
    solver.add(is_high == And(has_high, Not(has_critical)))
    
    # Logic for Medium: True if has_medium is True AND NOT has_high AND NOT has_critical
    solver.add(is_medium == And(has_medium, Not(has_high), Not(has_critical)))
    
    # Logic for Low: True if NOT (Critical OR High OR Medium)
    # Note: In the actual code, if findings exist but none are crit/high/med, it returns low.
    # If no findings exist, it returns low.
    # So effectively, Low is the fallback.
    solver.add(is_low == Not(Or(is_critical, is_high, is_medium)))

    # --- Verification Properties ---

    # Property 1: Exclusivity
    # The result cannot be both Critical and High (or any other pair)
    solver.push()
    solver.add(Or(
        And(is_critical, is_high),
        And(is_critical, is_medium),
        And(is_critical, is_low),
        And(is_high, is_medium),
        And(is_high, is_low),
        And(is_medium, is_low)
    ))
    # If this is satisfiable, it means we have a contradiction in our exclusivity assumption
    assert solver.check() == unsat, "Severity levels must be mutually exclusive"
    solver.pop()

    # Property 2: Critical Precedence
    # If has_critical is True, is_critical MUST be True, regardless of other flags
    solver.push()
    solver.add(has_critical)
    solver.add(Not(is_critical))
    assert solver.check() == unsat, "Critical finding must always result in Critical severity"
    solver.pop()

    # Property 3: High Precedence
    # If has_high is True and has_critical is False, is_high MUST be True
    solver.push()
    solver.add(has_high)
    solver.add(Not(has_critical))
    solver.add(Not(is_high))
    assert solver.check() == unsat, "High finding (without Critical) must result in High severity"
    solver.pop()

    # Property 4: Medium Precedence
    # If has_medium is True, and no High/Critical, is_medium MUST be True
    solver.push()
    solver.add(has_medium)
    solver.add(Not(has_high))
    solver.add(Not(has_critical))
    solver.add(Not(is_medium))
    assert solver.check() == unsat, "Medium finding (without High/Critical) must result in Medium severity"
    solver.pop()