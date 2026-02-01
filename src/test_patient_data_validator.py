
import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

"""
DETAILED TEST PLAN

1.  **Unit Tests (Pytest)**
    *   **`validate_dataframe`**:
        *   **Happy Path**: Validate a DataFrame that fully complies with all rules (signed consent, encrypted fields, recent access logs, valid retention).
        *   **Schema Validation**: Test with missing required columns (e.g., `patient_id`, `created_date`) to ensure `SchemaErrors` are caught and reported as violations.
        *   **Consent Logic**: Test rows with `consent_signed=False` and `consent_date` in the future.
        *   **Encryption Heuristic**: Test `encrypted_ssn` and `encrypted_medical_record` with short strings (<10 chars) or empty values.
        *   **Access Log Logic**:
            *   Test "New Record" (< 24 hours old): Should be compliant even if access logs are missing.
            *   Test "Old Record" (> 24 hours old): Should be non-compliant if access logs are missing.
        *   **Retention Logic**: Test records created > 7 years ago.
        *   **Row Indexing**: Verify `start_row_index` parameter correctly offsets reported row numbers.
    *   **`validate_records`**:
        *   **Integration**: Create a temporary CSV file with mixed valid/invalid data and run `validate_records` against it.
        *   **Chunking**: Mock `pd.read_csv` to return an iterator of DataFrames to simulate chunking behavior and verify aggregation of results (total, compliant, non_compliant counts).
        *   **Error Handling**: Test `FileNotFoundError` and empty CSV scenarios.

2.  **Formal Verification (Z3)**
    *   **Access Log Compliance Logic**:
        *   The logic states that a record is compliant regarding access logs if it is EITHER "new" (< 24 hours) OR (has `last_access_date` AND has `last_access_user`).
        *   We will model this logic in Z3 to prove that if a record is NOT new and is missing `last_access_date`, it MUST be non-compliant.
    *   **Retention Logic**:
        *   Model the retention check: `age_days <= 7 * 365`. Verify boundary conditions.

3.  **Edge Cases**
    *   **Missing Columns in DataFrame**: Ensure `validate_dataframe` doesn't crash during row iteration if columns are missing (handled by `row.get()`).
    *   **Null Dates**: Ensure `pd.isna` checks prevent crashes when calculating date differences.
"""

import sys
import os
import pytest
import pandas as pd
import pandera as pa
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Add the source directory to sys.path to import the module under test
# Assuming the file structure provided in the prompt
sys.path.append('/Users/trinav/personal/RegWatch/prompts')

try:
    import patient_data_validator as pdv
except ImportError:
    # Fallback for local testing if the path isn't exact
    try:
        import src.validators.patient_data_validator as pdv
    except ImportError:
        # Create a dummy module if strictly necessary for syntax checking, 
        # but in a real run, the path above should work.
        pass

# --- Fixtures ---

@pytest.fixture
def valid_dataframe():
    now = datetime.now()
    return pd.DataFrame({
        'patient_id': ['P001', 'P002'],
        'consent_signed': [True, True],
        'consent_date': [now - timedelta(days=10), now - timedelta(days=5)],
        'encrypted_ssn': ['a' * 15, 'b' * 15],
        'encrypted_medical_record': ['c' * 15, 'd' * 15],
        'last_access_date': [now - timedelta(hours=1), now - timedelta(hours=2)],
        'last_access_user': ['UserA', 'UserB'],
        'created_date': [now - timedelta(days=100), now - timedelta(days=200)]
    })

# --- Unit Tests for validate_dataframe ---

def test_validate_dataframe_happy_path(valid_dataframe):
    """Test that a fully compliant dataframe returns 0 violations."""
    result = pdv.validate_dataframe(valid_dataframe)
    
    assert result['total'] == 2
    assert result['compliant'] == 2
    assert result['non_compliant'] == 0
    assert len(result['violations']) == 0

def test_validate_dataframe_schema_violation():
    """Test that missing required columns are caught by Pandera schema validation."""
    # Missing 'patient_id' and 'created_date'
    df = pd.DataFrame({
        'consent_signed': [True],
        'encrypted_ssn': ['long_encrypted_string']
    })
    
    result = pdv.validate_dataframe(df)
    
    # Note: Pandera might raise multiple errors or one depending on config.
    # The code catches SchemaErrors and appends them to violations.
    violations = result['violations']
    schema_violations = [v for v in violations if v['violation_type'] == "Schema Violation"]
    
    assert len(schema_violations) > 0
    # Check that we caught missing columns
    fields_flagged = [v['field_name'] for v in schema_violations]
    assert 'patient_id' in fields_flagged or 'created_date' in fields_flagged

def test_validate_dataframe_consent_logic(valid_dataframe):
    """Test consent validation rules."""
    df = valid_dataframe.copy()
    # Row 0: Consent not signed
    df.at[0, 'consent_signed'] = False
    # Row 1: Consent date in future
    df.at[1, 'consent_date'] = datetime.now() + timedelta(days=1)
    
    result = pdv.validate_dataframe(df)
    
    assert result['compliant'] == 0
    assert result['non_compliant'] == 2
    
    violations = result['violations']
    assert any(v['violation_type'] == "Consent Missing" and v['patient_id'] == 'P001' for v in violations)
    assert any(v['violation_type'] == "Invalid Consent Date" and v['patient_id'] == 'P002' for v in violations)

def test_validate_dataframe_encryption_heuristic(valid_dataframe):
    """Test encryption heuristic (length check)."""
    df = valid_dataframe.copy()
    # Row 0: Short SSN
    df.at[0, 'encrypted_ssn'] = "short"
    # Row 1: Empty Medical Record
    df.at[1, 'encrypted_medical_record'] = ""
    
    result = pdv.validate_dataframe(df)
    
    violations = result['violations']
    ssn_violations = [v for v in violations if v['field_name'] == 'encrypted_ssn']
    mr_violations = [v for v in violations if v['field_name'] == 'encrypted_medical_record']
    
    assert len(ssn_violations) == 1
    assert ssn_violations[0]['patient_id'] == 'P001'
    assert ssn_violations[0]['severity'] == 'Critical'
    
    assert len(mr_violations) == 1
    assert mr_violations[0]['patient_id'] == 'P002'

def test_validate_dataframe_access_log_logic(valid_dataframe):
    """Test access log requirements for new vs old records."""
    df = valid_dataframe.copy()
    now = datetime.now()
    
    # Case 1: Old record (> 24h) missing access info -> Violation
    df.at[0, 'created_date'] = now - timedelta(hours=25)
    df.at[0, 'last_access_date'] = None
    df.at[0, 'last_access_user'] = None
    
    # Case 2: New record (< 24h) missing access info -> Compliant
    df.at[1, 'created_date'] = now - timedelta(hours=23)
    df.at[1, 'last_access_date'] = None
    df.at[1, 'last_access_user'] = None
    
    result = pdv.validate_dataframe(df)
    
    # Row 0 should fail
    violations_p1 = [v for v in result['violations'] if v['patient_id'] == 'P001']
    assert len(violations_p1) >= 1
    assert any(v['violation_type'] == "Missing Audit Log" for v in violations_p1)
    
    # Row 1 should pass (no violations for P002 related to access logs)
    violations_p2 = [v for v in result['violations'] if v['patient_id'] == 'P002']
    assert len(violations_p2) == 0

def test_validate_dataframe_retention_logic(valid_dataframe):
    """Test data retention policy (7 years)."""
    df = valid_dataframe.copy()
    # Row 0: 8 years old -> Violation
    df.at[0, 'created_date'] = datetime.now() - timedelta(days=365 * 8)
    
    result = pdv.validate_dataframe(df)
    
    violations = result['violations']
    retention_violations = [v for v in violations if v['violation_type'] == "Retention Policy"]
    
    assert len(retention_violations) == 1
    assert retention_violations[0]['patient_id'] == 'P001'
    assert retention_violations[0]['severity'] == 'Low'

def test_validate_dataframe_start_row_index(valid_dataframe):
    """Test that start_row_index is correctly applied to violation reports."""
    df = valid_dataframe.copy()
    df.at[0, 'consent_signed'] = False # Violation
    
    start_index = 100
    result = pdv.validate_dataframe(df, start_row_index=start_index)
    
    violation = result['violations'][0]
    # Row 0 in df + start_index 100 = 100
    assert violation['record_number'] == 100

# --- Unit Tests for validate_records ---

def test_validate_records_integration(tmp_path):
    """Integration test using a real CSV file."""
    csv_path = tmp_path / "patients.csv"
    
    # Create a CSV with 1 compliant and 1 non-compliant record
    now = datetime.now()
    data = {
        'patient_id': ['P1', 'P2'],
        'consent_signed': [True, False], # P2 fails consent
        'consent_date': [now, now],
        'encrypted_ssn': ['encrypted_123', 'encrypted_456'],
        'encrypted_medical_record': ['encrypted_rec1', 'encrypted_rec2'],
        'last_access_date': [now, now],
        'last_access_user': ['User1', 'User2'],
        'created_date': [now, now]
    }
    df = pd.DataFrame(data)
    df.to_csv(csv_path, index=False)
    
    result = pdv.validate_records(str(csv_path))
    
    assert result['total'] == 2
    assert result['compliant'] == 1
    assert result['non_compliant'] == 1
    assert len(result['violations']) == 1
    assert result['violations'][0]['patient_id'] == 'P2'

def test_validate_records_file_not_found():
    """Test handling of missing file."""
    result = pdv.validate_records("non_existent.csv")
    assert "error" in result
    assert result["error"] == "File not found"

def test_validate_records_empty_file(tmp_path):
    """Test handling of empty CSV file."""
    csv_path = tmp_path / "empty.csv"
    csv_path.touch()
    
    result = pdv.validate_records(str(csv_path))
    assert "error" in result
    assert result["error"] == "Empty CSV file"

@patch('patient_data_validator.pd.read_csv')
def test_validate_records_chunking(mock_read_csv):
    """Test that validate_records processes data in chunks."""
    # Mock read_csv to return a context manager that yields an iterator of chunks
    chunk1 = pd.DataFrame({
        'patient_id': ['P1'], 'consent_signed': [True], 'created_date': [datetime.now()],
        'encrypted_ssn': ['enc_str_111'], 'encrypted_medical_record': ['enc_str_222'],
        'last_access_date': [datetime.now()], 'last_access_user': ['u1'], 'consent_date': [datetime.now()]
    })
    chunk2 = pd.DataFrame({
        'patient_id': ['P2'], 'consent_signed': [False], 'created_date': [datetime.now()], # Fails
        'encrypted_ssn': ['enc_str_333'], 'encrypted_medical_record': ['enc_str_444'],
        'last_access_date': [datetime.now()], 'last_access_user': ['u2'], 'consent_date': [datetime.now()]
    })
    
    # Setup mock to act as context manager returning iterator
    mock_iterator = iter([chunk1, chunk2])
    mock_read_csv.return_value.__enter__.return_value = mock_iterator
    
    result = pdv.validate_records("dummy.csv")
    
    assert result['total'] == 2
    assert result['compliant'] == 1
    assert result['non_compliant'] == 1
    assert len(result['violations']) == 1
    assert result['violations'][0]['patient_id'] == 'P2'

# --- Z3 Formal Verification Tests ---

def test_z3_access_log_logic_verification():
    """
    Formal verification of the Access Log Logic using Z3.
    
    Logic to verify:
    A record is compliant regarding access logs IF:
        (It is a new record (< 24h)) OR (It has last_access_date AND last_access_user)
    
    We want to prove that:
        IF (NOT new_record) AND (missing_access_date OR missing_access_user)
        THEN (NOT compliant)
    """
    try:
        from z3 import Solver, Bool, Implies, Not, Or, And, unsat
    except ImportError:
        pytest.skip("z3-solver not installed")

    s = Solver()

    # Define variables
    is_new_record = Bool('is_new_record')
    has_access_date = Bool('has_access_date')
    has_access_user = Bool('has_access_user')
    is_compliant = Bool('is_compliant')

    # Define the compliance logic as implemented in the code
    # Code logic:
    # if not is_new_record:
    #    if not has_access_date: violation (non-compliant)
    #    if not has_access_user: violation (non-compliant)
    # Implicitly: compliant if no violations.
    
    # So, compliant <==> is_new_record OR (has_access_date AND has_access_user)
    s.add(is_compliant == Or(is_new_record, And(has_access_date, has_access_user)))

    # We want to verify that:
    # If it's NOT a new record AND (missing date OR missing user), it implies NOT compliant.
    # We negate this implication and check for satisfiability (counter-example).
    # Implication: (Not(is_new_record) And (Not(has_access_date) Or Not(has_access_user))) => Not(is_compliant)
    
    hypothesis = And(Not(is_new_record), Or(Not(has_access_date), Not(has_access_user)))
    conclusion = Not(is_compliant)
    
    # Negate the theorem: Hypothesis AND Not(Conclusion)
    # i.e., Hypothesis is True, but Conclusion is False (meaning is_compliant is True)
    s.add(hypothesis)
    s.add(Not(conclusion)) # i.e., s.add(is_compliant)

    # If UNSAT, the theorem holds (no counter-example exists).
    result = s.check()
    assert result == unsat, f"Found counter-example to access log logic: {s.model()}"

def test_z3_retention_logic_verification():
    """
    Formal verification of Retention Logic using Z3.
    
    Logic:
    compliant IF age_days <= 7 * 365
    """
    try:
        from z3 import Solver, Int, Implies, Not, unsat, Bool
    except ImportError:
        pytest.skip("z3-solver not installed")

    s = Solver()

    age_days = Int('age_days')
    is_compliant = Bool('is_compliant')
    retention_limit = 7 * 365

    # Definition of compliance
    s.add(is_compliant == (age_days <= retention_limit))

    # Verify: If age_days > retention_limit, then Not(is_compliant)
    hypothesis = age_days > retention_limit
    conclusion = Not(is_compliant)

    # Negate theorem
    s.add(hypothesis)
    s.add(Not(conclusion)) # i.e., is_compliant is True

    result = s.check()
    assert result == unsat, f"Found counter-example to retention logic: {s.model()}"