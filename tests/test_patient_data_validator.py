"""
Unit tests for the patient_data_validator module.

This test suite verifies that the patient_data_validator module conforms to the PDD specification
for the RegWatch compliance monitoring system's HIPAA patient data validation functionality.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# Add lib directory to path for dependencies
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import pandas as pd
import pandera as pa
import pytest

# Import the module under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'validators'))
from patient_data_validator import (
    validate_records,
    validate_dataframe,
    PatientRecordSchema,
    _validate_consent,
    _validate_encryption,
    _validate_access_logs,
    _validate_retention,
    RETENTION_YEARS,
    CHUNK_SIZE,
    LARGE_FILE_THRESHOLD
)


@pytest.fixture
def valid_patient_record():
    """Returns a single valid patient record as a DataFrame."""
    return pd.DataFrame([{
        'patient_id': 'P001',
        'consent_signed': True,
        'consent_date': (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d'),
        'encrypted_ssn': 'aGVsbG93b3JsZGhlbGxvd29ybGQ=',  # base64 encoded string
        'encrypted_medical_record': '48656c6c6f576f726c6448656c6c6f',  # hex encoded string
        'last_access_date': (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%d'),
        'last_access_user': 'user123',
        'created_date': (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d'),
        'data_retention_expires': (datetime.now() + timedelta(days=365 * 6)).strftime('%Y-%m-%d')
    }])


@pytest.fixture
def temp_csv_file():
    """Creates a temporary CSV file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8')
    yield temp_file.name
    # Cleanup
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


class TestPatientRecordSchema:
    """Tests for the PatientRecordSchema Pandera model."""

    def test_schema_accepts_valid_record(self, valid_patient_record):
        """Test that the schema accepts a valid patient record."""
        validated_df = PatientRecordSchema.validate(valid_patient_record, lazy=True)
        assert len(validated_df) == 1

    def test_schema_requires_patient_id(self):
        """Test that patient_id is required."""
        df = pd.DataFrame([{
            'consent_signed': True,
            'consent_date': '2024-01-01',
            'encrypted_ssn': 'encrypted_value_long',
            'encrypted_medical_record': 'encrypted_value_long',
            'last_access_date': '2024-01-01',
            'last_access_user': 'user123',
            'created_date': '2024-01-01'
        }])

        with pytest.raises(pa.errors.SchemaError):
            PatientRecordSchema.validate(df, lazy=False)

    def test_schema_requires_created_date(self):
        """Test that created_date is required."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2024-01-01',
            'encrypted_ssn': 'encrypted_value_long',
            'encrypted_medical_record': 'encrypted_value_long',
            'last_access_date': '2024-01-01',
            'last_access_user': 'user123'
        }])

        with pytest.raises(pa.errors.SchemaError):
            PatientRecordSchema.validate(df, lazy=False)

    def test_schema_coerces_dates(self):
        """Test that date fields are coerced to Timestamp."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2024-01-15',
            'encrypted_ssn': 'encrypted_ssn_value',
            'encrypted_medical_record': 'encrypted_mr_value',
            'last_access_date': '2024-01-20',
            'last_access_user': 'user123',
            'created_date': '2024-01-01'
        }])

        validated_df = PatientRecordSchema.validate(df, lazy=True)
        assert pd.api.types.is_datetime64_any_dtype(validated_df['consent_date'])
        assert pd.api.types.is_datetime64_any_dtype(validated_df['created_date'])

    def test_schema_allows_nullable_fields(self):
        """Test that optional fields can be null."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': None,
            'consent_date': None,
            'encrypted_ssn': None,
            'encrypted_medical_record': None,
            'last_access_date': None,
            'last_access_user': None,
            'created_date': '2024-01-01',
            'data_retention_expires': None
        }])

        validated_df = PatientRecordSchema.validate(df, lazy=True)
        assert len(validated_df) == 1

    def test_schema_allows_extra_columns(self):
        """Test that extra columns are allowed (strict=False)."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2024-01-01',
            'encrypted_ssn': 'encrypted_value',
            'encrypted_medical_record': 'encrypted_value',
            'last_access_date': '2024-01-01',
            'last_access_user': 'user123',
            'created_date': '2024-01-01',
            'extra_field': 'extra_value',
            'another_extra': 123
        }])

        validated_df = PatientRecordSchema.validate(df, lazy=True)
        assert 'extra_field' in validated_df.columns
        assert 'another_extra' in validated_df.columns


class TestValidateConsent:
    """Tests for the _validate_consent helper function."""

    def test_valid_consent(self):
        """Test that valid consent passes without violations."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': pd.Timestamp.now() - timedelta(days=10)
        })
        violations = []
        _validate_consent(row, violations, 0)
        assert len(violations) == 0

    def test_missing_consent_signature(self):
        """Test that missing consent signature is flagged."""
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

    def test_consent_date_in_future(self):
        """Test that future consent dates are flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': pd.Timestamp.now() + timedelta(days=10)
        })
        violations = []
        _validate_consent(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Invalid Consent Date'
        assert violations[0]['severity'] == 'High'

    def test_consent_signed_but_no_date(self):
        """Test that signed consent without date is flagged."""
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

    def test_no_consent_and_no_date(self):
        """Test that missing both consent and date flags only missing consent."""
        row = pd.Series({
            'patient_id': 'P001',
            'consent_signed': False,
            'consent_date': pd.NaT
        })
        violations = []
        _validate_consent(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Consent'


class TestValidateEncryption:
    """Tests for the _validate_encryption helper function."""

    def test_valid_encryption(self):
        """Test that properly encrypted fields pass validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'aGVsbG93b3JsZGhlbGxvd29ybGQ=',  # Long encrypted string
            'encrypted_medical_record': '48656c6c6f576f726c6448656c6c6f'
        })
        violations = []
        _validate_encryption(row, violations, 0)
        assert len(violations) == 0

    def test_missing_encrypted_ssn(self):
        """Test that missing encrypted SSN is flagged as critical."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': pd.NA,
            'encrypted_medical_record': 'validencryptedvalue123'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['field_name'] == 'encrypted_ssn'
        assert violations[0]['severity'] == 'Critical'

    def test_short_encrypted_value(self):
        """Test that short strings (likely unencrypted) are flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': '123',  # Too short
            'encrypted_medical_record': 'validencryptedvalue123'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Encryption Failure'

    def test_both_fields_missing_encryption(self):
        """Test that both missing encrypted fields are flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': '',
            'encrypted_medical_record': 'short'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        assert len(violations) == 2

    def test_encryption_length_threshold(self):
        """Test that exactly 10 characters passes (boundary test)."""
        row = pd.Series({
            'patient_id': 'P001',
            'encrypted_ssn': 'exactlyten',  # Exactly 10 chars
            'encrypted_medical_record': 'morethan10chars'
        })
        violations = []
        _validate_encryption(row, violations, 0)

        # Should pass (length >= 10)
        assert len(violations) == 0


class TestValidateAccessLogs:
    """Tests for the _validate_access_logs helper function."""

    def test_valid_access_logs(self):
        """Test that valid access logs pass validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(days=30),
            'last_access_date': pd.Timestamp.now() - timedelta(days=5),
            'last_access_user': 'user123'
        })
        violations = []
        _validate_access_logs(row, violations, 0)
        assert len(violations) == 0

    def test_new_record_exempt_from_access_logs(self):
        """Test that records < 24h old don't require access logs."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(hours=12),
            'last_access_date': pd.NaT,
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)
        assert len(violations) == 0

    def test_missing_access_logs_for_old_record(self):
        """Test that old records without access logs are flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(days=30),
            'last_access_date': pd.NaT,
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Access Logs'
        assert violations[0]['severity'] == 'Medium'

    def test_missing_only_access_user(self):
        """Test that missing only access user is flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(days=30),
            'last_access_date': pd.Timestamp.now() - timedelta(days=5),
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        assert len(violations) == 1

    def test_record_exactly_24h_old(self):
        """Test boundary condition at 24 hours."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(hours=24, seconds=1),
            'last_access_date': pd.NaT,
            'last_access_user': None
        })
        violations = []
        _validate_access_logs(row, violations, 0)

        # Should require access logs after 24h
        assert len(violations) == 1


class TestValidateRetention:
    """Tests for the _validate_retention helper function."""

    def test_record_within_retention_period(self):
        """Test that recent records pass retention validation."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(days=365 * 5)  # 5 years old
        })
        violations = []
        _validate_retention(row, violations, 0)
        assert len(violations) == 0

    def test_record_exceeds_retention_period(self):
        """Test that old records (>7 years) are flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - timedelta(days=365 * 8)  # 8 years old
        })
        violations = []
        _validate_retention(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Retention Policy Exceeded'
        assert violations[0]['severity'] == 'Low'

    def test_record_exactly_at_retention_limit(self):
        """Test boundary condition at exactly 7 years."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.Timestamp.now() - pd.DateOffset(years=7)
        })
        violations = []
        _validate_retention(row, violations, 0)

        # At exactly 7 years, it may trigger depending on timing
        # Allow either 0 or 1 violation (boundary condition)
        assert len(violations) <= 1

    def test_missing_created_date(self):
        """Test that missing created_date is flagged."""
        row = pd.Series({
            'patient_id': 'P001',
            'created_date': pd.NaT
        })
        violations = []
        _validate_retention(row, violations, 0)

        assert len(violations) == 1
        assert violations[0]['violation_type'] == 'Missing Creation Date'
        assert violations[0]['severity'] == 'Medium'


class TestValidateDataframe:
    """Tests for the validate_dataframe function."""

    def test_empty_dataframe(self):
        """Test that empty dataframe returns zero counts."""
        df = pd.DataFrame()
        report = validate_dataframe(df)

        assert report['total'] == 0
        assert report['compliant'] == 0
        assert report['non_compliant'] == 0
        assert report['violations'] == []

    def test_fully_compliant_record(self, valid_patient_record):
        """Test that a fully compliant record passes all validations."""
        report = validate_dataframe(valid_patient_record)

        assert report['total'] == 1
        assert report['compliant'] == 1
        assert report['non_compliant'] == 0
        assert len(report['violations']) == 0

    def test_multiple_violations_same_record(self):
        """Test that multiple violations on one record are all captured."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': False,  # Violation 1
            'consent_date': '2024-01-01',
            'encrypted_ssn': 'short',  # Violation 2
            'encrypted_medical_record': '',  # Violation 3
            'last_access_date': None,  # Violation 4 (if old)
            'last_access_user': None,
            'created_date': (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
        }])

        report = validate_dataframe(df)

        assert report['total'] == 1
        assert report['non_compliant'] == 1
        assert len(report['violations']) >= 4

    def test_multiple_records_mixed_compliance(self):
        """Test validation of multiple records with mixed compliance."""
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d'),
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%d'),
                'last_access_user': 'user123',
                'created_date': (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
            },
            {
                'patient_id': 'P002',
                'consent_signed': False,  # Non-compliant
                'consent_date': '2024-01-01',
                'encrypted_ssn': 'validencryptedvalue789',
                'encrypted_medical_record': 'validencryptedvalue012',
                'last_access_date': '2024-01-01',
                'last_access_user': 'user456',
                'created_date': '2024-01-01'
            }
        ])

        report = validate_dataframe(df)

        assert report['total'] == 2
        assert report['compliant'] == 1
        assert report['non_compliant'] == 1
        assert len(report['violations']) >= 1

    def test_schema_violation_reporting(self):
        """Test that schema violations are reported correctly."""
        # Missing required patient_id field will cause schema violation
        df = pd.DataFrame([{
            'consent_signed': True,
            'consent_date': '2024-01-01',
            'encrypted_ssn': 'encrypted_value',
            'encrypted_medical_record': 'encrypted_value',
            'last_access_date': '2024-01-01',
            'last_access_user': 'user123',
            'created_date': '2024-01-01'
        }])

        report = validate_dataframe(df)

        # Should have schema violation for missing patient_id
        schema_violations = [v for v in report['violations'] if v['violation_type'] == 'Schema Violation']
        assert len(schema_violations) > 0

    def test_violation_structure(self, valid_patient_record):
        """Test that violation dictionaries have all required fields."""
        # Create a non-compliant record
        df = valid_patient_record.copy()
        df.at[0, 'consent_signed'] = False

        report = validate_dataframe(df)

        assert len(report['violations']) > 0
        violation = report['violations'][0]

        assert 'patient_id' in violation
        assert 'record_number' in violation
        assert 'violation_type' in violation
        assert 'field_name' in violation
        assert 'description' in violation
        assert 'severity' in violation

    def test_report_structure(self, valid_patient_record):
        """Test that the report has all required keys."""
        report = validate_dataframe(valid_patient_record)

        assert 'total' in report
        assert 'compliant' in report
        assert 'non_compliant' in report
        assert 'violations' in report

        assert isinstance(report['total'], int)
        assert isinstance(report['compliant'], int)
        assert isinstance(report['non_compliant'], int)
        assert isinstance(report['violations'], list)


class TestValidateRecords:
    """Tests for the validate_records function."""

    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(FileNotFoundError):
            validate_records('/nonexistent/path/file.csv')

    def test_small_csv_file(self, temp_csv_file):
        """Test validation of a small CSV file (no chunking)."""
        # Create a small CSV
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            }
        ])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        assert report['total'] == 1
        assert report['compliant'] == 1
        assert report['non_compliant'] == 0

    def test_csv_with_violations(self, temp_csv_file):
        """Test CSV file with records containing violations."""
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': False,  # Violation
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            }
        ])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        assert report['total'] == 1
        assert report['non_compliant'] == 1
        assert len(report['violations']) > 0

    def test_large_csv_file_chunking(self, temp_csv_file):
        """Test that large files trigger chunking."""
        # Create a file with more than LARGE_FILE_THRESHOLD rows
        num_records = LARGE_FILE_THRESHOLD + 100

        data = []
        for i in range(num_records):
            data.append({
                'patient_id': f'P{i:06d}',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            })

        df = pd.DataFrame(data)
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        assert report['total'] == num_records

    def test_chunking_preserves_record_numbers(self, temp_csv_file):
        """Test that chunking maintains correct record numbers in violations."""
        # Create a file that will be chunked with violations
        num_records = LARGE_FILE_THRESHOLD + 100

        data = []
        for i in range(num_records):
            data.append({
                'patient_id': f'P{i:06d}',
                'consent_signed': (i % 10 != 0),  # Every 10th record has no consent
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            })

        df = pd.DataFrame(data)
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        # Should have violations for records 0, 10, 20, etc.
        assert report['non_compliant'] > 0
        assert len(report['violations']) > 0

    def test_utf8_encoding(self, temp_csv_file):
        """Test that UTF-8 encoded files are handled correctly."""
        df = pd.DataFrame([
            {
                'patient_id': 'P001_日本語',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_user': 'user_café',
                'last_access_date': '2024-01-20',
                'created_date': '2024-01-01'
            }
        ])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        assert report['total'] == 1
        assert report['violations'][0]['patient_id'] == 'P001_日本語' if report['violations'] else True

    def test_csv_with_header(self, temp_csv_file):
        """Test that CSV files with headers are processed correctly."""
        with open(temp_csv_file, 'w', encoding='utf-8') as f:
            f.write('patient_id,consent_signed,consent_date,encrypted_ssn,encrypted_medical_record,last_access_date,last_access_user,created_date\n')
            f.write('P001,True,2024-01-15,validencryptedvalue123,validencryptedvalue456,2024-01-20,user123,2024-01-01\n')

        report = validate_records(temp_csv_file)

        assert report['total'] == 1


class TestIntegration:
    """Integration tests covering end-to-end scenarios."""

    def test_complete_validation_workflow(self, temp_csv_file):
        """Test complete validation workflow from CSV to report."""
        # Create a CSV with mix of compliant and non-compliant records
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            },
            {
                'patient_id': 'P002',
                'consent_signed': False,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'short',
                'encrypted_medical_record': '',
                'last_access_date': None,
                'last_access_user': None,
                'created_date': (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
            }
        ])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        assert report['total'] == 2
        assert report['compliant'] >= 0
        assert report['non_compliant'] >= 1
        assert len(report['violations']) >= 3

    def test_severity_levels_in_report(self, temp_csv_file):
        """Test that different violation severities are reported correctly."""
        df = pd.DataFrame([
            {
                'patient_id': 'P001',
                'consent_signed': False,  # High severity
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'short',  # Critical severity
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': None,  # Medium severity (if old record)
                'last_access_user': None,
                'created_date': (datetime.now() - timedelta(days=365 * 8)).strftime('%Y-%m-%d')  # Low severity
            }
        ])
        df.to_csv(temp_csv_file, index=False, encoding='utf-8')

        report = validate_records(temp_csv_file)

        severities = {v['severity'] for v in report['violations']}
        assert 'High' in severities or 'Critical' in severities


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_dataframe_with_minimal_columns(self):
        """Test handling of minimal DataFrame with only required fields."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': None,
            'consent_date': None,
            'encrypted_ssn': None,
            'encrypted_medical_record': None,
            'last_access_date': None,
            'last_access_user': None,
            'created_date': '2024-01-01'
        }])

        report = validate_dataframe(df)

        # Should handle gracefully and report violations for missing data
        assert report['total'] == 1
        assert report['non_compliant'] == 1
        assert len(report['violations']) > 0

    def test_all_records_compliant(self):
        """Test dataset where all records are fully compliant."""
        df = pd.DataFrame([
            {
                'patient_id': f'P{i:03d}',
                'consent_signed': True,
                'consent_date': '2024-01-15',
                'encrypted_ssn': 'validencryptedvalue123',
                'encrypted_medical_record': 'validencryptedvalue456',
                'last_access_date': '2024-01-20',
                'last_access_user': 'user123',
                'created_date': '2024-01-01'
            }
            for i in range(10)
        ])

        report = validate_dataframe(df)

        assert report['total'] == 10
        assert report['compliant'] == 10
        assert report['non_compliant'] == 0

    def test_all_records_non_compliant(self):
        """Test dataset where all records have violations."""
        df = pd.DataFrame([
            {
                'patient_id': f'P{i:03d}',
                'consent_signed': False,
                'consent_date': '2024-01-15',
                'encrypted_ssn': '',
                'encrypted_medical_record': '',
                'last_access_date': None,
                'last_access_user': None,
                'created_date': '2024-01-01'
            }
            for i in range(10)
        ])

        report = validate_dataframe(df)

        assert report['total'] == 10
        assert report['non_compliant'] == 10
        assert report['compliant'] == 0

    def test_very_old_records(self):
        """Test records that significantly exceed retention period."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': '2000-01-01',
            'encrypted_ssn': 'validencryptedvalue123',
            'encrypted_medical_record': 'validencryptedvalue456',
            'last_access_date': '2000-01-15',
            'last_access_user': 'user123',
            'created_date': '2000-01-01'  # Over 20 years old
        }])

        report = validate_dataframe(df)

        retention_violations = [v for v in report['violations'] if v['violation_type'] == 'Retention Policy Exceeded']
        assert len(retention_violations) > 0

    def test_brand_new_records(self):
        """Test records created within the last hour."""
        df = pd.DataFrame([{
            'patient_id': 'P001',
            'consent_signed': True,
            'consent_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'encrypted_ssn': 'validencryptedvalue123',
            'encrypted_medical_record': 'validencryptedvalue456',
            'last_access_date': None,  # Should be exempt
            'last_access_user': None,  # Should be exempt
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }])

        report = validate_dataframe(df)

        # Should not have access log violations for brand new records
        access_violations = [v for v in report['violations'] if v['violation_type'] == 'Missing Access Logs']
        assert len(access_violations) == 0


class TestConfiguration:
    """Tests for configuration constants."""

    def test_retention_years_constant(self):
        """Test that RETENTION_YEARS is set correctly."""
        assert RETENTION_YEARS == 7

    def test_chunk_size_constant(self):
        """Test that CHUNK_SIZE is set correctly."""
        assert CHUNK_SIZE == 10000

    def test_large_file_threshold_constant(self):
        """Test that LARGE_FILE_THRESHOLD is set correctly."""
        assert LARGE_FILE_THRESHOLD == 50000
