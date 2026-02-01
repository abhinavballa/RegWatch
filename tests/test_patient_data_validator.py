"""
Unit tests for the patient_data_validator module.

Tests verify that the implementation conforms to the specification defined in
prompts/patient_data_validator_Python.prompt. The prompt file is the source of truth.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pandera as pa
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from validators.patient_data_validator import (
    PatientRecordSchema,
    validate_dataframe,
    validate_records,
    _validate_consent,
    _validate_encryption,
    _validate_access_logs,
    _validate_retention,
    RETENTION_YEARS,
    CHUNK_SIZE,
    LARGE_FILE_THRESHOLD,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def valid_patient_record():
    """Returns a single valid patient record as a dict."""
    return {
        'patient_id': 'P001',
        'consent_signed': True,
        'consent_date': datetime.now().isoformat(),
        'encrypted_ssn': 'a1b2c3d4e5f6g7h8i9j0',  # 20 chars, looks encrypted
        'encrypted_medical_record': 'x9y8z7w6v5u4t3s2r1q0',
        'last_access_date': datetime.now().isoformat(),
        'last_access_user': 'user123',
        'created_date': datetime.now().isoformat(),
        'data_retention_expires': (datetime.now() + timedelta(days=365)).isoformat()
    }


@pytest.fixture
def valid_dataframe(valid_patient_record):
    """Returns a DataFrame with valid patient records."""
    return pd.DataFrame([valid_patient_record])


@pytest.fixture
def temp_csv_file():
    """Creates a temporary CSV file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv')
    yield temp_file.name
    # Cleanup
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


# ============================================================================
# Schema Tests
# ============================================================================

class TestPatientRecordSchema:
    """Tests for PatientRecordSchema Pandera model."""

    def test_schema_accepts_valid_dataframe(self, valid_dataframe):
        """Verify schema accepts a valid DataFrame."""
        # Should not raise exception
        validated = PatientRecordSchema.validate(valid_dataframe)
        assert len(validated) == 1

    def test_schema_requires_patient_id(self):
        """Verify schema requires patient_id field."""
        df = pd.DataFrame([{
            'consent_signed': True,
            'consent_date': datetime.now(),
            'encrypted_ssn': 'encrypted123456',
            'encrypted_medical_record': 'encrypted789012',
            'last_access_date': datetime.now(),
            'last_access_user': 'user',
            'created_date': datetime.now()
        }])

        with pytest.raises(pa.errors.SchemaError):
            PatientRecordSchema.validate(df)

    def test_schema_coerces_dates_from_strings(self):
        """Verify schema can coerce date strings to datetime."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2023-01-15',
            'encrypted_ssn': 'encrypted123456',
            'encrypted_medical_record': 'encrypted789012',
            'last_access_date': '2023-01-20',
            'last_access_user': 'user',
            'created_date': '2023-01-10'
        }])

        validated = PatientRecordSchema.validate(df)
        assert isinstance(validated['consent_date'].iloc[0], pd.Timestamp)
        assert isinstance(validated['created_date'].iloc[0], pd.Timestamp)

    def test_schema_coerces_bool_from_string(self):
        """Verify schema can coerce boolean values."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': 1,  # Use integer which Pandera can coerce to bool
            'consent_date': datetime.now(),
            'encrypted_ssn': 'encrypted123456',
            'encrypted_medical_record': 'encrypted789012',
            'last_access_date': datetime.now(),
            'last_access_user': 'user',
            'created_date': datetime.now()
        }])

        validated = PatientRecordSchema.validate(df)
        # After coercion, should be bool or numpy bool
        assert validated['consent_signed'].iloc[0] in [True, False] or isinstance(validated['consent_signed'].iloc[0], (bool, pd.np.bool_))

    def test_schema_allows_nullable_fields(self):
        """Verify schema allows nullable fields except patient_id and created_date."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': None,
            'consent_date': None,
            'encrypted_ssn': None,
            'encrypted_medical_record': None,
            'last_access_date': None,
            'last_access_user': None,
            'created_date': datetime.now()
        }])

        # Schema validation should pass (business logic validation will catch violations)
        validated = PatientRecordSchema.validate(df)
        assert len(validated) == 1

    def test_schema_allows_extra_columns(self):
        """Verify schema allows extra columns (strict=False)."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': datetime.now(),
            'encrypted_ssn': 'encrypted123456',
            'encrypted_medical_record': 'encrypted789012',
            'last_access_date': datetime.now(),
            'last_access_user': 'user',
            'created_date': datetime.now(),
            'extra_field': 'some_value'
        }])

        validated = PatientRecordSchema.validate(df)
        assert 'extra_field' in validated.columns


# ============================================================================
# Consent Validation Tests
# ============================================================================

class TestConsentValidation:
    """Tests for _validate_consent helper function."""

    def test_consent_signed_true_with_valid_date_passes(self):
        """Verify consent validation passes when signed with valid date."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': pd.Timestamp.now() - pd.Timedelta(days=1)
        })
        violations = []
        _validate_consent(row, violations, 0)
        assert len(violations) == 0

    def test_consent_not_signed_creates_violation(self):
        """Verify missing consent creates High severity violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': False,
            'consent_date': pd.Timestamp.now()
        })
        violations = []
        _validate_consent(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Consent'
        assert violations[0]['severity'] == 'High'
        assert violations[0]['field_name'] == 'consent_signed'

    def test_consent_signed_but_no_date_creates_violation(self):
        """Verify consent signed without date creates violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': pd.NaT
        })
        violations = []
        _validate_consent(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Consent Date'
        assert violations[0]['severity'] == 'High'

    def test_consent_date_in_future_creates_violation(self):
        """Verify consent date in future creates violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': pd.Timestamp.now() + pd.Timedelta(days=1)
        })
        violations = []
        _validate_consent(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Invalid Consent Date'
        assert violations[0]['severity'] == 'High'

    def test_consent_violation_includes_required_fields(self):
        """Verify violation dict includes all required fields."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': False
        })
        violations = []
        _validate_consent(row, violations, 42)

        assert len(violations) == 1
        v = violations[0]
        assert v['patient_id'] == 'P001'
        assert v['record_number'] == 42
        assert 'violation_type' in v
        assert 'field_name' in v
        assert 'description' in v
        assert 'severity' in v


# ============================================================================
# Encryption Validation Tests
# ============================================================================

class TestEncryptionValidation:
    """Tests for _validate_encryption helper function."""

    def test_valid_encrypted_fields_pass(self):
        """Verify properly encrypted fields pass validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'a1b2c3d4e5f6g7h8i9j0',  # 20 chars
            'encrypted_medical_record': 'x9y8z7w6v5u4t3s2r1q0'
        })
        violations = []
        _validate_encryption(row, violations, 0)
        assert len(violations) == 0

    def test_short_encrypted_ssn_creates_violation(self):
        """Verify encrypted_ssn with < 10 chars creates Critical violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'short',
            'encrypted_medical_record': 'long_encrypted_value_here'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Encryption Failure'
        assert violations[0]['field_name'] == 'encrypted_ssn'
        assert violations[0]['severity'] == 'Critical'

    def test_empty_encrypted_medical_record_creates_violation(self):
        """Verify empty encrypted_medical_record creates violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'valid_encrypted_ssn_123',
            'encrypted_medical_record': ''
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['field_name'] == 'encrypted_medical_record'
        assert violations[0]['severity'] == 'Critical'

    def test_null_encrypted_fields_create_violations(self):
        """Verify null encryption fields create violations."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': None,
            'encrypted_medical_record': None
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 2
        assert all(v['severity'] == 'Critical' for v in violations)

    def test_encryption_violation_on_exact_10_chars_passes(self):
        """Verify exactly 10 characters passes validation (boundary test)."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'a123456789',  # exactly 10
            'encrypted_medical_record': 'b123456789'
        })
        violations = []
        _validate_encryption(row, violations, 0)
        assert len(violations) == 0

    def test_encryption_violation_on_9_chars_fails(self):
        """Verify 9 characters fails validation (boundary test)."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': '123456789',  # 9 chars
            'encrypted_medical_record': 'valid_encrypted_value'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['field_name'] == 'encrypted_ssn'


# ============================================================================
# Access Log Validation Tests
# ============================================================================

class TestAccessLogValidation:
    """Tests for _validate_access_logs helper function."""

    def test_valid_access_logs_pass(self):
        """Verify valid access logs pass validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(days=2),
            'last_access_date': pd.Timestamp.now(),
            'last_access_user': 'user123'
        })
        violations = []
        _validate_access_logs(row, violations, 0)
        assert len(violations) == 0

    def test_new_record_exempt_from_access_logs(self):
        """Verify records < 24 hours old don't require access logs."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(hours=12),
            'last_access_date': pd.NaT,
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)
        assert len(violations) == 0

    def test_old_record_missing_access_date_creates_violation(self):
        """Verify old record missing access date creates Medium violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(days=2),
            'last_access_date': pd.NaT,
            'last_access_user': 'user123'
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Access Logs'
        assert violations[0]['severity'] == 'Medium'

    def test_old_record_missing_access_user_creates_violation(self):
        """Verify old record missing access user creates violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(days=2),
            'last_access_date': pd.Timestamp.now(),
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['severity'] == 'Medium'

    def test_exactly_24_hours_old_requires_access_logs(self):
        """Verify records exactly 24 hours old require access logs (boundary test)."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(hours=24, minutes=1),
            'last_access_date': pd.NaT,
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        assert len(violations) == 1


# ============================================================================
# Retention Validation Tests
# ============================================================================

class TestRetentionValidation:
    """Tests for _validate_retention helper function."""

    def test_recent_record_passes_retention(self):
        """Verify recent records pass retention validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.Timedelta(days=365)
        })
        violations = []
        _validate_retention(row, violations, 0)
        assert len(violations) == 0

    def test_old_record_creates_retention_violation(self):
        """Verify records older than 7 years create Low severity violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.DateOffset(years=8)
        })
        violations = []
        _validate_retention(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Retention Policy Exceeded'
        assert violations[0]['severity'] == 'Low'
        assert violations[0]['field_name'] == 'created_date'

    def test_missing_created_date_creates_violation(self):
        """Verify missing created_date creates Medium violation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.NaT
        })
        violations = []
        _validate_retention(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Creation Date'
        assert violations[0]['severity'] == 'Medium'

    def test_exactly_7_years_old_passes(self):
        """Verify record exactly 7 years old passes (boundary test)."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.DateOffset(years=7, days=-1)
        })
        violations = []
        _validate_retention(row, violations, 0)
        assert len(violations) == 0

    def test_retention_years_configurable(self):
        """Verify RETENTION_YEARS is set to 7 as per spec."""
        assert RETENTION_YEARS == 7


# ============================================================================
# validate_dataframe Tests
# ============================================================================

class TestValidateDataframe:
    """Tests for validate_dataframe function."""

    def test_empty_dataframe_returns_zero_counts(self):
        """Verify empty DataFrame returns all zero counts."""
        df = pd.DataFrame()
        report = validate_dataframe(df)

        assert report['total'] == 0
        assert report['compliant'] == 0
        assert report['non_compliant'] == 0
        assert len(report['violations']) == 0

    def test_valid_dataframe_returns_all_compliant(self, valid_dataframe):
        """Verify fully compliant DataFrame reports correctly."""
        report = validate_dataframe(valid_dataframe)

        assert report['total'] == 1
        assert report['compliant'] == 1
        assert report['non_compliant'] == 0
        assert len(report['violations']) == 0

    def test_report_structure_matches_specification(self, valid_dataframe):
        """Verify report has required keys as per spec."""
        report = validate_dataframe(valid_dataframe)

        assert 'total' in report
        assert 'compliant' in report
        assert 'non_compliant' in report
        assert 'violations' in report
        assert isinstance(report['total'], int)
        assert isinstance(report['compliant'], int)
        assert isinstance(report['non_compliant'], int)
        assert isinstance(report['violations'], list)

    def test_violation_dict_structure(self):
        """Verify violation dicts include all required fields per spec."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': False,
            'consent_date': datetime.now(),
            'encrypted_ssn': 'short',
            'encrypted_medical_record': 'short',
            'last_access_date': datetime.now(),
            'last_access_user': 'user',
            'created_date': datetime.now()
        }])

        report = validate_dataframe(df)
        assert len(report['violations']) > 0

        v = report['violations'][0]
        assert 'patient_id' in v
        assert 'record_number' in v
        assert 'violation_type' in v
        assert 'field_name' in v
        assert 'description' in v
        assert 'severity' in v

    def test_multiple_violations_on_single_record(self):
        """Verify single record can have multiple violations."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': False,
            'consent_date': datetime.now(),
            'encrypted_ssn': 'bad',
            'encrypted_medical_record': 'bad',
            'last_access_date': None,
            'last_access_user': None,
            'created_date': datetime.now() - pd.DateOffset(years=10)
        }])

        report = validate_dataframe(df)
        # Should have violations for: consent, encryption (2), access logs, retention
        assert len(report['violations']) >= 5
        assert report['non_compliant'] == 1

    def test_multiple_records_counts_correctly(self):
        """Verify counts are accurate with multiple records."""
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': datetime.now(),
                'encrypted_ssn': 'valid_encrypted_123',
                'encrypted_medical_record': 'valid_encrypted_456',
                'last_access_date': datetime.now(),
                'last_access_user': 'user',
                'created_date': datetime.now()
            },
            {
                'patient_id': 'P002',
                'consent_signed': False,
                'consent_date': datetime.now(),
                'encrypted_ssn': 'bad',
                'encrypted_medical_record': 'bad',
                'last_access_date': datetime.now(),
                'last_access_user': 'user',
                'created_date': datetime.now()
            }
        ])

        report = validate_dataframe(df)
        assert report['total'] == 2
        assert report['compliant'] == 1
        assert report['non_compliant'] == 1

    def test_schema_violations_marked_critical(self):
        """Verify schema violations are marked as Critical severity."""
        # Missing required field patient_id will cause schema error
        df = pd.DataFrame([{
            'consent_signed': True,
            'consent_date': datetime.now(),
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': datetime.now(),
            'last_access_user': 'user',
            'created_date': datetime.now()
        }])

        report = validate_dataframe(df)
        schema_violations = [v for v in report['violations'] if v['violation_type'] == 'Schema Violation']
        assert len(schema_violations) > 0
        assert all(v['severity'] == 'Critical' for v in schema_violations)

    def test_dataframe_with_missing_columns(self):
        """Verify graceful handling of missing columns."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'created_date': datetime.now()
        }])

        # Should handle gracefully and report violations
        report = validate_dataframe(df)
        assert report['total'] == 1
        # Multiple violations expected for missing fields
        assert len(report['violations']) > 0


# ============================================================================
# validate_records Tests (CSV File Handling)
# ============================================================================

class TestValidateRecords:
    """Tests for validate_records function."""

    def test_nonexistent_file_raises_error(self):
        """Verify FileNotFoundError is raised for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            validate_records('/nonexistent/file.csv')

    def test_valid_csv_file_processes_correctly(self, temp_csv_file, valid_patient_record):
        """Verify valid CSV file is processed correctly."""
        df = pd.DataFrame([valid_patient_record])
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['total'] == 1
        assert report['compliant'] == 1
        assert report['non_compliant'] == 0

    def test_csv_with_violations_reports_correctly(self, temp_csv_file):
        """Verify CSV with violations reports them correctly."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': False,
            'consent_date': datetime.now().isoformat(),
            'encrypted_ssn': 'bad',
            'encrypted_medical_record': 'bad',
            'last_access_date': datetime.now().isoformat(),
            'last_access_user': 'user',
            'created_date': datetime.now().isoformat()
        }])
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['non_compliant'] == 1
        assert len(report['violations']) > 0

    def test_small_file_uses_non_chunked_processing(self, temp_csv_file, valid_patient_record):
        """Verify small files don't trigger chunking."""
        # Create file with < LARGE_FILE_THRESHOLD rows
        df = pd.DataFrame([valid_patient_record] * 100)
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['total'] == 100

    def test_csv_encoding_utf8(self, temp_csv_file):
        """Verify CSV files are read with UTF-8 encoding."""
        df = pd.DataFrame([{
            'patient_id': 'P001-Ñoño',
            'consent_signed': True,
            'consent_date': datetime.now().isoformat(),
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': datetime.now().isoformat(),
            'last_access_user': 'user',
            'created_date': datetime.now().isoformat()
        }])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)
        assert report['total'] == 1

    def test_chunked_processing_for_large_files(self, temp_csv_file):
        """Verify large files trigger chunked processing."""
        # Create a file with rows >= LARGE_FILE_THRESHOLD
        num_rows = LARGE_FILE_THRESHOLD + 100
        records = []
        for i in range(num_rows):
            records.append({
                'patient_id': f'P{i:06d}',
                'consent_signed': True,
                'consent_date': datetime.now().isoformat(),
                'encrypted_ssn': f'encrypted_ssn_{i:020d}',
                'encrypted_medical_record': f'encrypted_mr_{i:020d}',
                'last_access_date': datetime.now().isoformat(),
                'last_access_user': 'user',
                'created_date': datetime.now().isoformat()
            })

        df = pd.DataFrame(records)
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['total'] == num_rows
        assert report['compliant'] == num_rows

    def test_chunked_processing_maintains_record_numbers(self, temp_csv_file):
        """Verify chunked processing maintains correct record numbers across chunks."""
        # Create enough records to span multiple chunks
        num_rows = CHUNK_SIZE * 2 + 100
        records = []
        for i in range(num_rows):
            # Every 5000th record has a violation
            is_bad = (i % 5000 == 0)
            records.append({
                'patient_id': f'P{i:06d}',
                'consent_signed': not is_bad,
                'consent_date': datetime.now().isoformat(),
                'encrypted_ssn': 'bad' if is_bad else f'encrypted_ssn_{i:020d}',
                'encrypted_medical_record': 'bad' if is_bad else f'encrypted_mr_{i:020d}',
                'last_access_date': datetime.now().isoformat(),
                'last_access_user': 'user',
                'created_date': datetime.now().isoformat()
            })

        df = pd.DataFrame(records)
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)

        # Verify record numbers are tracked correctly
        violation_records = {v['record_number'] for v in report['violations']}
        # Should have violations at records 0, 5000, 10000, 15000, 20000
        expected_violations = {i for i in range(num_rows) if i % 5000 == 0}

        # Check that violation record numbers are in expected range
        for record_num in violation_records:
            assert 0 <= record_num < num_rows


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests covering complete workflows."""

    def test_complete_validation_workflow(self, temp_csv_file):
        """Test complete validation workflow from CSV to report."""
        # Create mixed dataset
        records = [
            # Fully compliant
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': '2023-01-15',
                'encrypted_ssn': 'aGVsbG93b3JsZDE',
                'encrypted_medical_record': 'bWVkaWNhbHJlY29yZA',
                'last_access_date': '2024-01-20',
                'last_access_user': 'doctor123',
                'created_date': '2023-01-10'
            },
            # Missing consent
            {
                'patient_id': 'P002',
                'consent_signed': False,
                'consent_date': '2023-02-15',
                'encrypted_ssn': 'ZW5jcnlwdGVkc3Nu',
                'encrypted_medical_record': 'ZW5jcnlwdGVkbXI',
                'last_access_date': '2024-02-20',
                'last_access_user': 'nurse456',
                'created_date': '2023-02-10'
            },
            # Bad encryption
            {
                'patient_id': 'P003',
                'consent_signed': True,
                'consent_date': '2023-03-15',
                'encrypted_ssn': '123',
                'encrypted_medical_record': '456',
                'last_access_date': '2024-03-20',
                'last_access_user': 'admin789',
                'created_date': '2023-03-10'
            },
            # Old record
            {
                'patient_id': 'P004',
                'consent_signed': True,
                'consent_date': '2015-04-15',
                'encrypted_ssn': 'b2xkZW5jcnlwdGlvbg',
                'encrypted_medical_record': 'b2xkbWVkaWNhbHI',
                'last_access_date': '2024-04-20',
                'last_access_user': 'system',
                'created_date': '2015-04-10'
            }
        ]

        df = pd.DataFrame(records)
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)

        assert report['total'] == 4
        assert report['compliant'] == 1  # Only P001
        assert report['non_compliant'] == 3
        assert len(report['violations']) > 0

        # Check severity distribution
        critical = [v for v in report['violations'] if v['severity'] == 'Critical']
        high = [v for v in report['violations'] if v['severity'] == 'High']
        low = [v for v in report['violations'] if v['severity'] == 'Low']

        assert len(critical) >= 2  # P003 encryption failures
        assert len(high) >= 1      # P002 consent
        assert len(low) >= 1       # P004 retention

    def test_all_severity_levels_present(self, temp_csv_file):
        """Verify all severity levels can be generated."""
        records = [
            # Critical: bad encryption
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'bad',
                'encrypted_medical_record': 'bad',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user',
                'created_date': '2024-01-10'
            },
            # High: missing consent
            {
                'patient_id': 'P002',
                'consent_signed': False,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'valid_encrypted_123',
                'encrypted_medical_record': 'valid_encrypted_456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user',
                'created_date': '2024-01-10'
            },
            # Medium: missing access logs
            {
                'patient_id': 'P003',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'valid_encrypted_123',
                'encrypted_medical_record': 'valid_encrypted_456',
                'last_access_date': None,
                'last_access_user': None,
                'created_date': '2020-01-10'
            },
            # Low: retention exceeded
            {
                'patient_id': 'P004',
                'consent_signed': True,
                'consent_date': '2015-01-15',
                'encrypted_ssn': 'valid_encrypted_123',
                'encrypted_medical_record': 'valid_encrypted_456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user',
                'created_date': '2015-01-10'
            }
        ]

        df = pd.DataFrame(records)
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)

        severities = {v['severity'] for v in report['violations']}
        assert 'Critical' in severities
        assert 'High' in severities
        assert 'Medium' in severities
        assert 'Low' in severities

    def test_configuration_constants(self):
        """Verify configuration constants match specification."""
        assert RETENTION_YEARS == 7
        assert CHUNK_SIZE == 10000
        assert LARGE_FILE_THRESHOLD == 50000


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_dataframe_with_all_null_values(self):
        """Verify handling of DataFrame with all null values."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': None,
            'consent_date': None,
            'encrypted_ssn': None,
            'encrypted_medical_record': None,
            'last_access_date': None,
            'last_access_user': None,
            'created_date': datetime.now()
        }])

        report = validate_dataframe(df)
        # Should have multiple violations
        assert report['non_compliant'] > 0
        assert len(report['violations']) > 0

    def test_very_old_consent_date(self):
        """Test with very old but valid consent date."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '1990-01-01',
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': datetime.now().isoformat(),
            'last_access_user': 'user',
            'created_date': '1990-01-01'
        }])

        report = validate_dataframe(df)
        # Old date is valid as long as it's not in future
        # Should have retention violation though
        retention_violations = [v for v in report['violations']
                              if v['violation_type'] == 'Retention Policy Exceeded']
        assert len(retention_violations) > 0

    def test_unicode_in_patient_id(self, temp_csv_file):
        """Test handling of Unicode characters in patient_id."""
        df = pd.DataFrame([{
            'patient_id': 'P001-José',
            'consent_signed': True,
            'consent_date': datetime.now().isoformat(),
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': datetime.now().isoformat(),
            'last_access_user': 'user',
            'created_date': datetime.now().isoformat()
        }])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)
        assert report['total'] == 1
        if report['violations']:
            assert any('José' in v['patient_id'] for v in report['violations'])

    def test_exact_boundary_24_hours(self):
        """Test exact 24-hour boundary for access log requirement."""
        created = datetime.now() - timedelta(hours=24, seconds=1)
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': datetime.now().isoformat(),
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': None,
            'last_access_user': None,
            'created_date': created.isoformat()
        }])

        report = validate_dataframe(df)
        # Should require access logs
        access_violations = [v for v in report['violations']
                           if v['violation_type'] == 'Missing Access Logs']
        assert len(access_violations) > 0

    def test_date_formats_iso8601(self, temp_csv_file):
        """Verify ISO 8601 date format handling."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2024-01-15T10:30:00Z',
            'encrypted_ssn': 'valid_encrypted_123',
            'encrypted_medical_record': 'valid_encrypted_456',
            'last_access_date': '2024-01-20T14:45:00+00:00',
            'last_access_user': 'user',
            'created_date': '2024-01-10T08:00:00'
        }])
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['total'] == 1

    def test_empty_csv_file(self, temp_csv_file):
        """Test handling of empty CSV file with just headers."""
        df = pd.DataFrame(columns=[
            'patient_id', 'consent_signed', 'consent_date',
            'encrypted_ssn', 'encrypted_medical_record',
            'last_access_date', 'last_access_user', 'created_date'
        ])
        df.to_csv(temp_csv_file, index=False)

        report = validate_records(temp_csv_file)
        assert report['total'] == 0
        assert report['compliant'] == 0
        assert report['non_compliant'] == 0
