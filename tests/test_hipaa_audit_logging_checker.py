"""
Unit tests for the hipaa_audit_logging_checker module.

Tests verify that the implementation conforms to the specification defined in
prompts/hipaa_audit_logging_checker_Python.prompt. The prompt file is the source of truth.

This module tests HIPAA § 164.312(b) audit logging compliance checks including:
- ePHI access detection and logging verification
- Required log fields validation (timestamp, user, action, resource)
- Log retention policy detection (>= 6 years / 2190 days)
- Tamper-proof logging mechanisms
- Anomaly detection integration
"""

import os
import tempfile
import pytest
from pathlib import Path

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'checkers'))

from hipaa_audit_logging_checker import (
    check_audit_logging,
    AuditLoggingVisitor,
    REGULATION_REFERENCE,
    PHI_KEYWORDS,
    ACCESS_KEYWORDS,
    REQUIRED_LOG_FIELDS
)


@pytest.fixture
def temp_python_file():
    """Create a temporary Python file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
    yield temp_file.name
    # Cleanup
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


class TestCheckAuditLoggingBasic:
    """Basic tests for check_audit_logging function."""

    def test_nonexistent_file(self):
        """Test handling of nonexistent file."""
        result = check_audit_logging("/nonexistent/path/file.py")

        assert result["compliant"] is False
        assert result["severity"] == "Critical"
        assert result["regulation_reference"] == REGULATION_REFERENCE
        assert len(result["findings"]) == 1
        assert result["findings"][0]["violation_type"] == "File Error"

    def test_syntax_error_in_file(self, temp_python_file):
        """Test handling of file with syntax errors."""
        with open(temp_python_file, 'w') as f:
            f.write("def invalid syntax here\n")

        result = check_audit_logging(temp_python_file)

        assert result["compliant"] is False
        assert result["severity"] == "Critical"
        assert result["findings"][0]["violation_type"] == "Syntax Error"

    def test_empty_file_missing_configs(self, temp_python_file):
        """Test empty file generates warnings about missing configurations."""
        with open(temp_python_file, 'w') as f:
            f.write("# Empty Python file\n")

        result = check_audit_logging(temp_python_file)

        assert result["compliant"] is False
        assert result["severity"] == "Medium"
        # Should have 3 findings: missing retention, tamper-proof, anomaly detection
        assert len(result["findings"]) == 3
        violation_types = {f["violation_type"] for f in result["findings"]}
        assert "Missing Retention Policy" in violation_types
        assert "Missing Tamper-Proofing" in violation_types
        assert "Missing Anomaly Detection" in violation_types

    def test_compliant_code_with_all_configs(self, temp_python_file):
        """Test compliant code with all required configurations."""
        code = """
import logging

RETENTION_DAYS = 2190

def log_access():
    with open('audit.log', mode='a') as f:
        f.write('audit entry')

def setup_monitoring():
    splunk.send_alert()
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert result["compliant"] is True
        assert result["severity"] == "Pass"
        assert len(result["findings"]) == 0


class TestEphiAccessDetection:
    """Tests for ePHI access detection."""

    def test_missing_audit_log_for_ephi_access(self, temp_python_file):
        """Test detection of ePHI access without corresponding audit log."""
        code = """
def get_patient_record(patient_id):
    return database.fetch_patient(patient_id)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert result["compliant"] is False
        assert result["severity"] == "Critical"
        # Should have missing audit log + 3 missing configs
        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 1
        assert critical_findings[0]["violation_type"] == "Missing Audit Log"
        assert "get_patient_record" in critical_findings[0]["description"]
        assert critical_findings[0]["line_number"] == 3

    def test_ephi_create_operation_without_logging(self, temp_python_file):
        """Test detection of ePHI create operation without logging."""
        code = """
def create_patient(data):
    return patient_db.insert(data)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 1
        assert critical_findings[0]["violation_type"] == "Missing Audit Log"

    def test_ephi_update_operation_without_logging(self, temp_python_file):
        """Test detection of ePHI update operation without logging."""
        code = """
def update_medical_record(record_id, data):
    return medical_db.update(record_id, data)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 1
        assert critical_findings[0]["violation_type"] == "Missing Audit Log"

    def test_ephi_delete_operation_without_logging(self, temp_python_file):
        """Test detection of ePHI delete operation without logging."""
        code = """
def delete_patient(patient_id):
    return patient_db.delete(patient_id)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 1

    def test_ephi_access_via_query_argument(self, temp_python_file):
        """Test detection of ePHI access via query arguments with PHI table names."""
        code = """
def get_records():
    return db.query("SELECT * FROM patients")
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 1
        assert critical_findings[0]["violation_type"] == "Missing Audit Log"

    def test_ephi_access_with_logging_present(self, temp_python_file):
        """Test ePHI access with logging present in same function."""
        code = """
import logging

def get_patient_record(patient_id):
    result = database.fetch(patient_id)
    logging.info("Access recorded")
    return result
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        # Should not have Critical findings, but may have High for incomplete log
        critical_findings = [f for f in result["findings"] if f["severity"] == "Critical"]
        assert len(critical_findings) == 0


class TestLogFieldValidation:
    """Tests for required log field validation."""

    def test_incomplete_log_missing_all_fields(self, temp_python_file):
        """Test detection of incomplete log missing all required fields."""
        code = """
import logging

def get_patient_data(patient_id):
    result = patient_db.fetch(patient_id)
    logging.info("Access occurred")
    return result
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        high_findings = [f for f in result["findings"] if f["severity"] == "High"]
        assert len(high_findings) >= 1
        incomplete_logs = [f for f in high_findings if f["violation_type"] == "Incomplete Audit Log"]
        assert len(incomplete_logs) == 1

    def test_complete_log_with_all_required_fields(self, temp_python_file):
        """Test log with all required fields (user, action, resource)."""
        code = """
import logging

def get_patient_data(patient_id):
    result = database.fetch(patient_id)
    logging.info("Patient access", extra={"user": "john", "action": "read", "resource": "patient-123"})
    return result
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        # Should not have incomplete log findings
        incomplete_logs = [f for f in result["findings"] if f["violation_type"] == "Incomplete Audit Log"]
        assert len(incomplete_logs) == 0

    def test_log_with_user_field_variations(self, temp_python_file):
        """Test log field detection with variations (user, userid, actor)."""
        code = """
import logging

def update_patient(patient_id):
    result = database.update(patient_id)
    logging.info("Update", extra={"userid": "john", "action": "update", "patient": "123"})
    return result
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        incomplete_logs = [f for f in result["findings"] if f["violation_type"] == "Incomplete Audit Log"]
        assert len(incomplete_logs) == 0

    def test_log_fields_in_message_string(self, temp_python_file):
        """Test detection of log fields mentioned in message string."""
        code = """
import logging

def create_patient(data):
    result = database.create(data)
    logging.info("User admin performed action create on resource patient-456")
    return result
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        incomplete_logs = [f for f in result["findings"] if f["violation_type"] == "Incomplete Audit Log"]
        assert len(incomplete_logs) == 0


class TestRetentionPolicy:
    """Tests for log retention policy detection."""

    def test_missing_retention_policy(self, temp_python_file):
        """Test detection of missing retention policy."""
        code = """
def some_function():
    pass
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        retention_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Retention Policy"]
        assert len(retention_findings) == 1
        assert retention_findings[0]["severity"] == "Medium"

    def test_insufficient_retention_days(self, temp_python_file):
        """Test detection of insufficient retention period (< 2190 days)."""
        code = """
RETENTION_DAYS = 365
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        retention_findings = [f for f in result["findings"] if "Retention" in f["violation_type"]]
        # Should find insufficient retention
        insufficient = [f for f in retention_findings if f["severity"] == "High"]
        assert len(insufficient) == 1
        assert "365 days" in insufficient[0]["description"]

    def test_valid_retention_policy_2190_days(self, temp_python_file):
        """Test valid retention policy at exactly 2190 days."""
        code = """
RETENTION_DAYS = 2190
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        retention_findings = [f for f in result["findings"] if "Missing Retention Policy" in f["violation_type"]]
        assert len(retention_findings) == 0

    def test_valid_retention_policy_above_minimum(self, temp_python_file):
        """Test valid retention policy above minimum (> 2190 days)."""
        code = """
LOG_RETENTION_PERIOD = 2555
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        retention_findings = [f for f in result["findings"] if "Missing Retention Policy" in f["violation_type"]]
        assert len(retention_findings) == 0

    def test_retention_policy_with_days_suffix(self, temp_python_file):
        """Test detection of retention policy with 'days' in variable name."""
        code = """
retention_period_days = 3650
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        retention_findings = [f for f in result["findings"] if "Missing Retention Policy" in f["violation_type"]]
        assert len(retention_findings) == 0


class TestTamperProofLogging:
    """Tests for tamper-proof logging mechanism detection."""

    def test_missing_tamper_proof_config(self, temp_python_file):
        """Test detection of missing tamper-proof logging."""
        code = """
def log_data():
    pass
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 1
        assert tamper_findings[0]["severity"] == "Medium"

    def test_append_only_mode_positional_arg(self, temp_python_file):
        """Test detection of append-only file mode as positional argument."""
        code = """
def log_audit():
    with open("audit.log", 'a') as f:
        f.write("entry")
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 0

    def test_append_only_mode_keyword_arg(self, temp_python_file):
        """Test detection of append-only file mode as keyword argument."""
        code = """
def log_audit():
    f = open("audit.log", mode='a')
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 0

    def test_log_signing_detection(self, temp_python_file):
        """Test detection of cryptographic log signing."""
        code = """
def sign_log_entry(entry):
    return crypto.sign_log(entry)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 0

    def test_immutable_storage_detection(self, temp_python_file):
        """Test detection of immutable storage references."""
        code = """
def store_log():
    s3_immutable.put_object(Bucket="logs")
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 0

    def test_worm_storage_detection(self, temp_python_file):
        """Test detection of WORM (Write Once Read Many) storage."""
        code = """
def configure_worm_storage():
    storage.enable_worm_mode()
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        tamper_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Tamper-Proofing"]
        assert len(tamper_findings) == 0


class TestAnomalyDetection:
    """Tests for anomaly detection integration."""

    def test_missing_anomaly_detection(self, temp_python_file):
        """Test detection of missing anomaly detection integration."""
        code = """
def process_data():
    pass
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        anomaly_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Anomaly Detection"]
        assert len(anomaly_findings) == 1
        assert anomaly_findings[0]["severity"] == "Medium"

    def test_splunk_integration(self, temp_python_file):
        """Test detection of Splunk SIEM integration."""
        code = """
def send_to_splunk(data):
    splunk_client.send(data)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        anomaly_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Anomaly Detection"]
        assert len(anomaly_findings) == 0

    def test_elasticsearch_integration(self, temp_python_file):
        """Test detection of Elasticsearch integration."""
        code = """
from elasticsearch import Elasticsearch

def index_logs():
    elastic.index(document="log")
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        anomaly_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Anomaly Detection"]
        assert len(anomaly_findings) == 0

    def test_alerting_system_detection(self, temp_python_file):
        """Test detection of alerting system integration."""
        code = """
def send_alert(message):
    pagerduty_alert(message)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        anomaly_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Anomaly Detection"]
        assert len(anomaly_findings) == 0

    def test_siem_integration(self, temp_python_file):
        """Test detection of generic SIEM integration."""
        code = """
def log_to_siem(event):
    siem.log(event)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        anomaly_findings = [f for f in result["findings"] if f["violation_type"] == "Missing Anomaly Detection"]
        assert len(anomaly_findings) == 0


class TestSeverityCalculation:
    """Tests for overall severity calculation."""

    def test_critical_severity_for_missing_audit_log(self, temp_python_file):
        """Test that missing audit logs result in Critical severity."""
        code = """
def get_patient(id):
    return patient_db.fetch(id)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert result["severity"] == "Critical"

    def test_high_severity_for_incomplete_logs(self, temp_python_file):
        """Test High severity for incomplete audit logs."""
        code = """
import logging
RETENTION_DAYS = 2190

def get_patient_data(id):
    result = patient_db.fetch(id)
    logging.info("access")
    return result

def setup():
    open('audit.log', 'a')
    splunk_alert.init()
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        # Should be High due to incomplete log fields
        assert result["severity"] == "High"

    def test_medium_severity_for_config_issues(self, temp_python_file):
        """Test Medium severity for missing configurations only."""
        code = """
# No ePHI access, just missing configs
def utility_function():
    pass
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert result["severity"] == "Medium"

    def test_pass_severity_for_compliant_code(self, temp_python_file):
        """Test Pass severity for fully compliant code."""
        code = """
import logging

RETENTION_DAYS = 2190

def get_patient(id):
    result = db.fetch(id)
    logging.info("Access", extra={"user": "admin", "action": "read", "resource": id})
    return result

def setup():
    open('audit.log', 'a')
    splunk.init()
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert result["severity"] == "Pass"
        assert result["compliant"] is True


class TestRegulationReference:
    """Tests for regulation reference in results."""

    def test_regulation_reference_present(self, temp_python_file):
        """Test that regulation reference is included in results."""
        code = "pass"
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        assert "regulation_reference" in result
        assert result["regulation_reference"] == "HIPAA § 164.312(b) Audit Controls"

    def test_findings_include_remediation(self, temp_python_file):
        """Test that findings include remediation suggestions."""
        code = """
def delete_patient(id):
    db.remove(id)
"""
        with open(temp_python_file, 'w') as f:
            f.write(code)

        result = check_audit_logging(temp_python_file)

        for finding in result["findings"]:
            assert "remediation_suggestion" in finding
            assert "line_number" in finding
            assert "violation_type" in finding
            assert "description" in finding
            assert "severity" in finding
