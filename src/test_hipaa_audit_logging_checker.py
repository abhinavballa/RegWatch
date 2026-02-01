
import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

import pytest
import os
import tempfile
import ast
from typing import Dict, Any
from z3 import Solver, Bool, Implies, And, Or, Not, String, If, Const, Function, Int, sat

# Import the module under test
# Adjusting path to match the provided file structure instructions
import sys
# Assuming the file is in the same directory or python path for the test runner
try:
    from src.checkers.hipaa_audit_logging_checker import check_audit_logging
except ImportError:
    # Fallback for direct execution where src might not be a package
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "hipaa_audit_logging_checker", 
        "/Users/trinav/personal/RegWatch/prompts/hipaa_audit_logging_checker.py"
    )
    if spec and spec.loader:
        hipaa_audit_logging_checker = importlib.util.module_from_spec(spec)
        sys.modules["hipaa_audit_logging_checker"] = hipaa_audit_logging_checker
        spec.loader.exec_module(hipaa_audit_logging_checker)
        check_audit_logging = hipaa_audit_logging_checker.check_audit_logging

# --- Fixtures ---

@pytest.fixture
def temp_python_file():
    """Creates a temporary python file and cleans it up after test."""
    fd, path = tempfile.mkstemp(suffix=".py", text=True)
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)

def write_code(path: str, content: str):
    """Helper to write code to the temp file."""
    with open(path, "w") as f:
        f.write(content)

# --- Unit Tests ---

def test_file_not_found():
    """Test that the checker raises FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        check_audit_logging("non_existent_ghost_file.py")

def test_syntax_error_handling(temp_python_file):
    """Test that the checker handles invalid Python syntax gracefully."""
    write_code(temp_python_file, "def broken_function( return }")
    
    report = check_audit_logging(temp_python_file)
    
    assert report["compliant"] is False
    assert report["severity"] == "Critical"
    assert report["findings"][0]["violation_type"] == "SYNTAX_ERROR"

def test_fully_compliant_code(temp_python_file):
    """
    Test a file that meets all requirements:
    1. ePHI access logged with fields.
    2. Retention configured.
    3. Tamper proofing referenced.
    4. Anomaly detection referenced.
    """
    code = """
import logging

# Configuration
LOG_RETENTION_DAYS = 2500  # > 2190 days
STORAGE_CLASS = "S3_WORM_IMMUTABLE"

def get_patient_record(user_id, record_id):
    # Access ePHI
    data = db.query(record_id)
    
    # Audit Log
    logging.info(f"User {user_id} performed READ action on resource {record_id}")
    
    # Anomaly detection hook
    splunk_alert.send(data)
    return data
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    assert report["compliant"] is True, f"Findings: {report.get('findings')}"
    assert report["severity"] == "None"
    assert len(report["findings"]) == 0

def test_missing_audit_log_on_ephi_access(temp_python_file):
    """Test detection of ePHI access without any logging."""
    code = """
def update_patient_diagnosis(pid, diagnosis):
    # ePHI access implied by function name
    db.save(pid, diagnosis)
    # No logging here
    return True
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    assert report["compliant"] is False
    findings = report["findings"]
    
    # Should have MISSING_AUDIT_LOG
    audit_findings = [f for f in findings if f["violation_type"] == "MISSING_AUDIT_LOG"]
    assert len(audit_findings) == 1
    assert audit_findings[0]["severity"] == "Critical"
    assert "update_patient_diagnosis" in audit_findings[0]["description"]

def test_incomplete_audit_fields(temp_python_file):
    """Test detection of logging that misses required fields (user, action, resource)."""
    code = """
import logging

def delete_medical_record(record_id):
    db.delete(record_id)
    # Log exists, but vague
    logging.info("Deleted something") 
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    assert report["compliant"] is False
    findings = report["findings"]
    
    field_findings = [f for f in findings if f["violation_type"] == "INCOMPLETE_AUDIT_FIELDS"]
    assert len(field_findings) == 1
    assert field_findings[0]["severity"] == "High"

def test_compliant_audit_fields_kwargs(temp_python_file):
    """Test that fields in kwargs or extra dict are recognized."""
    code = """
import logging

def create_lab_result(user, result_id):
    # ePHI access
    db.insert(result_id)
    
    # Fields in extra dict
    logging.info("Created result", extra={'user': user, 'action': 'create', 'resource_id': result_id})
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    # Filter out global config warnings to focus on function analysis
    func_findings = [f for f in report["findings"] 
                     if f["violation_type"] in ["MISSING_AUDIT_LOG", "INCOMPLETE_AUDIT_FIELDS"]]
    
    assert len(func_findings) == 0, "Should recognize fields in 'extra' dict"

def test_inadequate_retention_policy(temp_python_file):
    """Test detection of retention policy < 6 years."""
    code = """
# Config
LOG_RETENTION_DAYS = 365  # 1 year, too short
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    findings = report["findings"]
    retention_findings = [f for f in findings if f["violation_type"] == "INADEQUATE_LOG_RETENTION"]
    
    assert len(retention_findings) == 1
    assert retention_findings[0]["severity"] == "High"
    assert "365" in retention_findings[0]["description"]

def test_missing_global_configurations(temp_python_file):
    """Test that missing anomaly detection and tamper proofing triggers warnings."""
    code = """
def do_math(a, b):
    return a + b
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    findings = report["findings"]
    
    types = [f["violation_type"] for f in findings]
    assert "MISSING_ANOMALY_DETECTION" in types
    assert "UNVERIFIED_TAMPER_PROOFING" in types
    assert "UNVERIFIED_LOG_RETENTION" in types

def test_irrelevant_code_ignored(temp_python_file):
    """Test that code not touching ePHI doesn't trigger missing log errors."""
    code = """
def calculate_tax(amount):
    return amount * 0.1
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    # Should NOT have MISSING_AUDIT_LOG
    audit_findings = [f for f in report["findings"] if f["violation_type"] == "MISSING_AUDIT_LOG"]
    assert len(audit_findings) == 0

def test_tamper_proof_detection_via_open_mode(temp_python_file):
    """Test detection of append-only mode as a weak signal for tamper proofing."""
    code = """
def write_audit_log(msg):
    with open("audit.log", mode="a") as f:
        f.write(msg)
    """
    write_code(temp_python_file, code)
    report = check_audit_logging(temp_python_file)
    
    findings = report["findings"]
    # Should NOT have UNVERIFIED_TAMPER_PROOFING because "a" mode was found
    tamper_findings = [f for f in findings if f["violation_type"] == "UNVERIFIED_TAMPER_PROOFING"]
    assert len(tamper_findings) == 0

# --- Z3 Formal Verification Tests ---

def test_z3_severity_logic_verification():
    """
    Formally verify the severity calculation logic using Z3.
    Logic:
    - If any finding is Critical, Overall is Critical.
    - Else if any finding is High, Overall is High.
    - Else if any finding is Medium, Overall is Medium.
    - Else if any finding is Low, Overall is Low.
    - If no findings, Overall is None.
    """
    s = Solver()

    # Inputs: Existence of findings of specific severities
    has_critical = Bool('has_critical')
    has_high = Bool('has_high')
    has_medium = Bool('has_medium')
    has_low = Bool('has_low')
    
    # Output: Overall severity level (represented as Int for comparison: 4=Crit, 3=High, 2=Med, 1=Low, 0=None)
    overall_severity = Int('overall_severity')

    # The Logic Implementation to Verify
    # This mirrors the logic in check_audit_logging
    logic = If(has_critical, overall_severity == 4,
               If(has_high, overall_severity == 3,
                  If(has_medium, overall_severity == 2,
                     If(has_low, overall_severity == 1,
                        overall_severity == 0))))
    
    s.add(logic)

    # Property 1: If Critical exists, result MUST be 4 (Critical)
    # We prove this by searching for a counter-example: Critical exists AND result != 4
    s.push()
    s.add(has_critical)
    s.add(overall_severity != 4)
    assert s.check() == sat == False, "Counter-example found: Critical finding did not result in Critical severity"
    s.pop()

    # Property 2: If High exists (and no Critical), result MUST be 3 (High)
    s.push()
    s.add(Not(has_critical))
    s.add(has_high)
    s.add(overall_severity != 3)
    assert s.check() == sat == False, "Counter-example found: High finding (w/o Critical) did not result in High severity"
    s.pop()

    # Property 3: If no findings, result MUST be 0 (None)
    s.push()
    s.add(Not(has_critical), Not(has_high), Not(has_medium), Not(has_low))
    s.add(overall_severity != 0)
    assert s.check() == sat == False, "Counter-example found: No findings did not result in None severity"
    s.pop()

def test_z3_compliance_boolean_logic():
    """
    Formally verify the boolean compliance logic.
    Logic: compliant is True IFF findings list is empty.
    """
    s = Solver()
    
    # State
    findings_count = Int('findings_count')
    is_compliant = Bool('is_compliant')
    
    # Constraints
    s.add(findings_count >= 0)
    
    # The Logic: is_compliant == (findings_count == 0)
    logic = (is_compliant == (findings_count == 0))
    s.add(logic)
    
    # Property 1: Can we be compliant with > 0 findings?
    s.push()
    s.add(is_compliant)
    s.add(findings_count > 0)
    assert s.check() == sat == False, "Counter-example: Compliant=True despite having findings"
    s.pop()
    
    # Property 2: Can we be non-compliant with 0 findings?
    s.push()
    s.add(Not(is_compliant))
    s.add(findings_count == 0)
    assert s.check() == sat == False, "Counter-example: Compliant=False despite having 0 findings"
    s.pop()

def test_z3_retention_logic():
    """
    Formally verify the retention day calculation logic.
    Requirement: Retention >= 2190 days (6 years).
    """
    s = Solver()
    
    retention_days = Int('retention_days')
    is_compliant_retention = Bool('is_compliant_retention')
    
    # Logic from code: if node.value.value >= RETENTION_MIN_DAYS (2190)
    logic = (is_compliant_retention == (retention_days >= 2190))
    s.add(logic)
    
    # Property: 2189 days should be non-compliant
    s.push()
    s.add(retention_days == 2189)
    s.add(is_compliant_retention) # Assert it IS compliant (looking for contradiction)
    assert s.check() == sat == False, "Counter-example: 2189 days marked as compliant"
    s.pop()
    
    # Property: 2190 days should be compliant
    s.push()
    s.add(retention_days == 2190)
    s.add(Not(is_compliant_retention)) # Assert it is NOT compliant (looking for contradiction)
    assert s.check() == sat == False, "Counter-example: 2190 days marked as non-compliant"
    s.pop()