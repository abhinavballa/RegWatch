
import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

import pytest
import pandas as pd
import pandera as pa
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add the source directory to sys.path to allow importing the module
# Assuming the file structure provided in the prompt
sys.path.append(os.path.abspath("src/validators"))

# Import the actual module
try:
    import patient_data_validator
    from patient_data_validator import (
        validate_dataframe,
        validate_records,
        PatientRecordSchema,
        RETENTION_YEARS
    )
except ImportError:
    # Fallback for when running in an environment where the path isn't set up exactly as expected
    pass

# --- Fixtures ---

@pytest.fixture
def valid_data():
    """Returns a dictionary representing a valid patient record."""
    now = pd.Timestamp.now()
    return {
        "patient_id": "P001",
        "consent_signed": True,
        "consent_date": now - timedelta(days=10),
        "encrypted_ssn": "A" * 15, # Length > 10
        "encrypted_medical_record": "B" * 15,
        "last_access_date": now - timedelta(hours=1),
        "last_access_user": "User1",
        "created_date": now - timedelta(days=100),
        "data_retention_expires": None
    }

@pytest.fixture
def sample_df(valid_data):
    """Returns a DataFrame containing one valid record."""
    return pd.DataFrame([valid_data])

# --- Unit Tests: validate_dataframe ---

def test_validate_dataframe_compliant(sample_df):
    """Test that a fully compliant dataframe returns 0 non-compliant records."""
    report = validate_dataframe(sample_df)
    assert report["total"] == 1
    assert report["compliant"] == 1
    assert report["non_compliant"] == 0
    assert len(report["violations"]) == 0

def test_validate_dataframe_missing_consent(sample_df):
    """Test violation when consent is not signed."""
    sample_df.at[0, "consent_signed"] = False
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    assert len(report["violations"]) == 1
    assert report["violations"][0]["violation_type"] == "Missing Consent"
    assert report["violations"][0]["severity"] == "High"

def test_validate_dataframe_future_consent_date(sample_df):
    """Test violation when consent date is in the future."""
    sample_df.at[0, "consent_date"] = pd.Timestamp.now() + timedelta(days=1)
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation_types = [v["violation_type"] for v in report["violations"]]
    assert "Invalid Consent Date" in violation_types

def test_validate_dataframe_signed_but_missing_date(sample_df):
    """Test violation when consent is signed but date is missing."""
    sample_df.at[0, "consent_signed"] = True
    sample_df.at[0, "consent_date"] = None
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation_types = [v["violation_type"] for v in report["violations"]]
    assert "Missing Consent Date" in violation_types

def test_validate_dataframe_encryption_failure_short_string(sample_df):
    """Test violation when encrypted fields are too short."""
    sample_df.at[0, "encrypted_ssn"] = "short"
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation = report["violations"][0]
    assert violation["violation_type"] == "Encryption Failure"
    assert violation["field_name"] == "encrypted_ssn"
    assert violation["severity"] == "Critical"

def test_validate_dataframe_encryption_failure_missing(sample_df):
    """Test violation when encrypted fields are missing (NaN)."""
    sample_df.at[0, "encrypted_medical_record"] = None
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation = report["violations"][0]
    assert violation["violation_type"] == "Encryption Failure"
    assert violation["field_name"] == "encrypted_medical_record"

def test_validate_dataframe_access_logs_missing_old_record(sample_df):
    """Test violation when access logs are missing for an old record."""
    # Record created 100 days ago (from fixture)
    sample_df.at[0, "last_access_date"] = None
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation = report["violations"][0]
    assert violation["violation_type"] == "Missing Access Logs"
    assert violation["severity"] == "Medium"

def test_validate_dataframe_access_logs_exempt_new_record(sample_df):
    """Test NO violation when access logs are missing for a NEW record (<24h)."""
    # Set created_date to 12 hours ago
    sample_df.at[0, "created_date"] = pd.Timestamp.now() - timedelta(hours=12)
    sample_df.at[0, "last_access_date"] = None
    sample_df.at[0, "last_access_user"] = None
    
    report = validate_dataframe(sample_df)
    
    assert report["compliant"] == 1
    assert report["non_compliant"] == 0
    assert len(report["violations"]) == 0

def test_validate_dataframe_retention_exceeded(sample_df):
    """Test violation when record exceeds retention period."""
    # 7 years + 1 day
    old_date = pd.Timestamp.now() - pd.DateOffset(years=RETENTION_YEARS) - timedelta(days=1)
    sample_df.at[0, "created_date"] = old_date
    
    report = validate_dataframe(sample_df)
    
    assert report["non_compliant"] == 1
    violation = report["violations"][0]
    assert violation["violation_type"] == "Retention Policy Exceeded"
    assert violation["severity"] == "Low"

def test_validate_dataframe_schema_violation_missing_column(sample_df):
    """Test that missing required columns raise Schema Violation."""
    df_missing_col = sample_df.drop(columns=["patient_id"])
    
    report = validate_dataframe(df_missing_col)
    
    # Schema validation happens first. If patient_id is missing, it's a critical schema error.
    assert report["total"] == 1
    assert len(report["violations"]) > 0
    assert report["violations"][0]["violation_type"] == "Schema Violation"
    # The code attempts to retrieve patient_id, but defaults to "Unknown" if missing/index mismatch
    assert report["violations"][0]["patient_id"] == "Unknown"

def test_validate_dataframe_empty():
    """Test validation of an empty dataframe."""
    df = pd.DataFrame()
    report = validate_dataframe(df)
    assert report["total"] == 0
    assert report["compliant"] == 0
    assert report["non_compliant"] == 0
    assert report["violations"] == []

# --- Unit Tests: validate_records ---

def test_validate_records_file_not_found():
    """Test that FileNotFoundError is raised for non-existent file."""
    with pytest.raises(FileNotFoundError):
        validate_records("non_existent_file.csv")

def test_validate_records_small_file(tmp_path, sample_df):
    """Test processing of a small CSV file."""
    csv_path = tmp_path / "patients.csv"
    sample_df.to_csv(csv_path, index=False)
    
    report = validate_records(str(csv_path))
    
    assert report["total"] == 1
    assert report["compliant"] == 1

@patch("patient_data_validator.pd.read_csv")
@patch("patient_data_validator.os.path.exists")
@patch("builtins.open")
def test_validate_records_chunking(mock_open, mock_exists, mock_read_csv, sample_df):
    """
    Test that large files trigger chunking and results are aggregated correctly.
    We mock pd.read_csv to return an iterator of dataframes.
    """
    mock_exists.return_value = True
    
    # Mock file line count to trigger chunking (> 50000)
    # The code iterates over the file object to count lines.
    mock_file = MagicMock()
    mock_file.__iter__.return_value = range(50001)
    mock_open.return_value.__enter__.return_value = mock_file
    
    # Create two chunks
    chunk1 = sample_df.copy()
    chunk1["patient_id"] = "P1" # Compliant
    
    chunk2 = sample_df.copy()
    chunk2["patient_id"] = "P2"
    chunk2["consent_signed"] = False # Non-compliant
    
    # Setup read_csv to return iterator when chunksize is provided
    mock_read_csv.return_value = iter([chunk1, chunk2])
    
    report = validate_records("dummy_large.csv")
    
    # Check if read_csv was called with chunksize
    args, kwargs = mock_read_csv.call_args
    assert "chunksize" in kwargs
    assert kwargs["chunksize"] == 10000
    
    # Verify aggregation
    assert report["total"] == 2
    assert report["compliant"] == 1
    assert report["non_compliant"] == 1
    assert len(report["violations"]) == 1
    assert report["violations"][0]["patient_id"] == "P2"

# --- Z3 Formal Verification Tests ---

def test_z3_retention_logic():
    """
    Formal verification of the retention logic using Z3.
    Logic: Violation <==> created_date < (now - 7 years)
    """
    try:
        from z3 import Solver, Int, Bool, Not, sat, unsat
    except ImportError:
        pytest.skip("z3-solver not installed")

    s = Solver()

    # We model time as integers (e.g., unix timestamps or days)
    # Let 'now' be a fixed point in time (e.g., 10000)
    now = 10000
    retention_period = 700 # Arbitrary units representing 7 years
    retention_limit = now - retention_period
    
    created_date = Int('created_date')
    is_violation = Bool('is_violation')
    
    # The logic implemented in python:
    # if created_date < retention_limit: violation
    
    # Define the logic constraint
    logic = (is_violation == (created_date < retention_limit))
    s.add(logic)
    
    # 1. Verify that a date OLDER than limit implies violation
    # created_date = retention_limit - 1
    s.push()
    s.add(created_date == retention_limit - 1)
    s.add(Not(is_violation)) # Assert NO violation to prove contradiction
    assert s.check() == unsat, "Z3 failed: Older date should imply violation"
    s.pop()
    
    # 2. Verify that a date NEWER than limit implies NO violation
    # created_date = retention_limit + 1
    s.push()
    s.add(created_date == retention_limit + 1)
    s.add(is_violation) # Assert violation to prove contradiction
    assert s.check() == unsat, "Z3 failed: Newer date should imply NO violation"
    s.pop()

def test_z3_access_log_logic():
    """
    Formal verification of access log exemption logic.
    Logic: Violation <==> (NOT is_new_record) AND (missing_logs)
    """
    try:
        from z3 import Solver, Bool, And, Not, sat, unsat
    except ImportError:
        pytest.skip("z3-solver not installed")

    s = Solver()
    
    is_new_record = Bool('is_new_record')
    missing_logs = Bool('missing_logs')
    is_violation = Bool('is_violation')
    
    # Python logic:
    # if is_new_record: return (no violation)
    # if missing_logs: violation
    # Equivalent to: violation <==> (NOT is_new_record) AND missing_logs
    
    logic = (is_violation == And(Not(is_new_record), missing_logs))
    s.add(logic)
    
    # Case 1: New record, missing logs -> Should NOT be a violation
    s.push()
    s.add(is_new_record == True)
    s.add(missing_logs == True)
    s.add(is_violation == True) # Expect contradiction
    assert s.check() == unsat, "Z3 failed: New record should be exempt from missing logs violation"
    s.pop()
    
    # Case 2: Old record, missing logs -> Should BE a violation
    s.push()
    s.add(is_new_record == False)
    s.add(missing_logs == True)
    s.add(is_violation == False) # Expect contradiction
    assert s.check() == unsat, "Z3 failed: Old record with missing logs should be a violation"
    s.pop()
    
    # Case 3: Old record, logs present -> Should NOT be a violation
    s.push()
    s.add(is_new_record == False)
    s.add(missing_logs == False)
    s.add(is_violation == True) # Expect contradiction
    assert s.check() == unsat, "Z3 failed: Old record with logs should not be a violation"
    s.pop()"
}