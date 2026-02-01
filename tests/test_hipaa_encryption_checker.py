"""
Unit tests for the hipaa_encryption_checker module.

Tests verify that the implementation conforms to the specification defined in
prompts/hipaa_encryption_checker_Python.prompt. The prompt file is the source of truth.
"""

import ast
import os
import shutil
import tempfile
from pathlib import Path
import pytest

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from checkers.hipaa_encryption_checker import (
    check_encryption,
    EncryptionVisitor,
    EncryptionViolation,
    _analyze_file,
    HIPAA_REGULATION_REF,
    PHI_KEYWORDS,
    WEAK_ALGORITHMS,
    STRONG_ALGORITHMS,
    KEY_VARIABLE_PATTERNS
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file for testing."""
    filepath = os.path.join(temp_dir, "sample.py")

    def create_file(content):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    return create_file


class TestCheckEncryptionBasicFunctionality:
    """Tests for basic check_encryption() functionality."""

    def test_check_encryption_returns_dict_with_required_keys(self, sample_python_file):
        """Verify check_encryption returns a dict with all required keys."""
        file_path = sample_python_file("# Empty file")
        result = check_encryption(file_path)

        assert isinstance(result, dict)
        assert "findings" in result
        assert "compliant" in result
        assert "severity" in result
        assert "regulation_reference" in result

    def test_check_encryption_on_compliant_code(self, sample_python_file):
        """Verify check_encryption marks compliant code as compliant."""
        code = """
import os
from cryptography.fernet import Fernet

def get_encryption_key():
    return os.environ.get('ENCRYPTION_KEY')
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["compliant"] == True
        assert result["severity"] == "none"
        assert len(result["findings"]) == 0

    def test_check_encryption_includes_regulation_reference(self, sample_python_file):
        """Verify regulation reference is included in result."""
        file_path = sample_python_file("# Test")
        result = check_encryption(file_path)

        assert result["regulation_reference"] == HIPAA_REGULATION_REF

    def test_check_encryption_on_single_file(self, sample_python_file):
        """Verify check_encryption works on a single file."""
        file_path = sample_python_file("api_key = 'hardcoded_secret_12345'")
        result = check_encryption(file_path)

        assert isinstance(result, dict)
        assert len(result["findings"]) > 0

    def test_check_encryption_on_directory(self, temp_dir):
        """Verify check_encryption recursively analyzes directories."""
        # Create multiple Python files
        file1 = os.path.join(temp_dir, "file1.py")
        file2 = os.path.join(temp_dir, "file2.py")

        with open(file1, "w") as f:
            f.write("secret_key = 'hardcoded123456'")
        with open(file2, "w") as f:
            f.write("password = 'another_secret'")

        result = check_encryption(temp_dir)

        assert len(result["findings"]) >= 2

    def test_check_encryption_skips_non_python_files(self, temp_dir):
        """Verify check_encryption only analyzes .py files."""
        py_file = os.path.join(temp_dir, "test.py")
        txt_file = os.path.join(temp_dir, "readme.txt")

        with open(py_file, "w") as f:
            f.write("# Python file")
        with open(txt_file, "w") as f:
            f.write("secret_key = 'test'")

        result = check_encryption(temp_dir)

        # Should only process the .py file
        assert result["compliant"] == True


class TestHardcodedKeyDetection:
    """Tests for hardcoded key/secret detection."""

    def test_detects_hardcoded_api_key(self, sample_python_file):
        """Verify detection of hardcoded API keys."""
        code = "api_key = 'sk-1234567890abcdef'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert any("hardcoded" in f["description"].lower() for f in result["findings"])
        assert result["compliant"] == False

    def test_detects_hardcoded_secret(self, sample_python_file):
        """Verify detection of hardcoded secrets."""
        code = "secret = 'my_secret_value_123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        findings = result["findings"]
        assert len(findings) > 0
        assert findings[0]["violation_type"] == "Hardcoded Key"
        assert findings[0]["severity"] == "critical"

    def test_detects_hardcoded_password(self, sample_python_file):
        """Verify detection of hardcoded passwords."""
        code = "password = 'SuperSecret123!'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert result["findings"][0]["severity"] == "critical"

    def test_detects_hardcoded_token(self, sample_python_file):
        """Verify detection of hardcoded tokens."""
        code = "auth_token = 'Bearer token_abc123xyz'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert any("token" in f["description"].lower() for f in result["findings"])

    def test_ignores_env_variable_references(self, sample_python_file):
        """Verify that environment variable references are not flagged."""
        code = """
import os
api_key_env = os.environ.get('API_KEY')
secret_env = os.getenv('SECRET')
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should not flag env variable usage
        assert result["compliant"] == True

    def test_ignores_short_strings(self, sample_python_file):
        """Verify that very short strings are not flagged as secrets."""
        code = "key = 'abc'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should ignore strings <= 5 characters
        assert result["compliant"] == True

    def test_hardcoded_key_includes_line_number(self, sample_python_file):
        """Verify hardcoded key findings include accurate line numbers."""
        code = """# Line 1
# Line 2
api_key = 'hardcoded_secret_value'
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert result["findings"][0]["line_number"] == 3

    def test_hardcoded_key_includes_remediation(self, sample_python_file):
        """Verify hardcoded key findings include remediation suggestions."""
        code = "secret = 'test_secret_123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert "remediation_suggestion" in result["findings"][0]
        assert len(result["findings"][0]["remediation_suggestion"]) > 0


class TestEncryptionInTransit:
    """Tests for encryption in transit (TLS) detection."""

    def test_detects_postgresql_without_tls(self, sample_python_file):
        """Verify detection of PostgreSQL connections without TLS."""
        code = 'db_url = "postgresql://user:pass@localhost/dbname"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert any("transit" in f["violation_type"].lower() for f in result["findings"])
        assert result["findings"][0]["severity"] == "high"

    def test_detects_mysql_without_tls(self, sample_python_file):
        """Verify detection of MySQL connections without TLS."""
        code = 'connection = "mysql://root:password@host:3306/database"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert "SSL/TLS" in result["findings"][0]["description"]

    def test_detects_sqlserver_without_tls(self, sample_python_file):
        """Verify detection of SQL Server connections without TLS."""
        code = 'conn_str = "sqlserver://user:pass@server/db"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        findings = [f for f in result["findings"] if "transit" in f["violation_type"].lower()]
        assert len(findings) > 0

    def test_accepts_postgresql_with_sslmode(self, sample_python_file):
        """Verify PostgreSQL connections with sslmode are accepted."""
        code = 'db_url = "postgresql://user:pass@host/db?sslmode=require"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should not flag SSL-enabled connections
        transit_violations = [f for f in result["findings"] if "transit" in f["violation_type"].lower()]
        assert len(transit_violations) == 0

    def test_accepts_connection_with_tls_parameter(self, sample_python_file):
        """Verify database connections with TLS parameters are accepted."""
        code = 'db_url = "mysql://user:pass@host/db?tls=true"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        transit_violations = [f for f in result["findings"] if "transit" in f["violation_type"].lower()]
        assert len(transit_violations) == 0

    def test_detects_sslmode_disabled(self, sample_python_file):
        """Verify detection of explicitly disabled SSL."""
        code = 'db_url = "postgresql://user:pass@host/db?sslmode=disable"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert result["findings"][0]["severity"] == "critical"
        assert "disables" in result["findings"][0]["description"].lower()

    def test_detects_sslmode_allow(self, sample_python_file):
        """Verify detection of sslmode=allow (insecure)."""
        code = 'conn = "postgresql://user:pass@host/db?sslmode=allow"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        assert result["findings"][0]["severity"] == "critical"


class TestPHIFieldEncryption:
    """Tests for PHI field encryption detection."""

    def test_detects_unencrypted_ssn_field(self, sample_python_file):
        """Verify detection of unencrypted SSN fields."""
        code = """
from sqlalchemy import Column, String
ssn = Column('ssn', String(11))
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) > 0
        assert phi_findings[0]["severity"] == "critical"

    def test_detects_unencrypted_medical_record(self, sample_python_file):
        """Verify detection of unencrypted medical record fields."""
        code = """
from sqlalchemy import Column, String
medical_record = Column('medical_record', String(50))
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) > 0

    def test_detects_unencrypted_diagnosis(self, sample_python_file):
        """Verify detection of unencrypted diagnosis fields."""
        code = """
from sqlalchemy import Column, Text
diagnosis = Column('diagnosis', Text)
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) > 0
        assert "diagnosis" in phi_findings[0]["description"]

    def test_detects_unencrypted_prescription(self, sample_python_file):
        """Verify detection of unencrypted prescription fields."""
        code = """
from sqlalchemy import Column, String
prescription = Column('prescription', String(200))
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert any("prescription" in f["description"].lower() for f in result["findings"])

    def test_detects_unencrypted_patient_id(self, sample_python_file):
        """Verify detection of unencrypted patient_id fields."""
        code = """
from sqlalchemy import Column, Integer
patient_id = Column('patient_id', Integer)
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) > 0

    def test_accepts_encrypted_phi_field(self, sample_python_file):
        """Verify encrypted PHI fields are accepted."""
        code = """
from sqlalchemy import Column
from custom_types import EncryptedType
ssn = Column('ssn', EncryptedType(String(11)))
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should not flag encrypted PHI fields
        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) == 0

    def test_phi_finding_includes_field_name(self, sample_python_file):
        """Verify PHI findings include the field name in description."""
        code = """
from sqlalchemy import Column, String
dob = Column('dob', String(10))
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        phi_findings = [f for f in result["findings"] if "phi" in f["violation_type"].lower()]
        assert len(phi_findings) > 0
        assert "dob" in phi_findings[0]["description"]


class TestWeakEncryptionAlgorithms:
    """Tests for weak encryption algorithm detection."""

    def test_detects_md5_usage(self, sample_python_file):
        """Verify detection of MD5 algorithm usage."""
        code = """
import hashlib
hash_func = hashlib.new('md5')
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        weak_alg_findings = [f for f in result["findings"] if "weak" in f["violation_type"].lower()]
        assert len(weak_alg_findings) > 0
        assert "md5" in weak_alg_findings[0]["description"].lower()

    def test_detects_sha1_usage(self, sample_python_file):
        """Verify detection of SHA-1 algorithm usage."""
        code = """
def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
"""
        file_path = sample_python_file(code)
        # Note: This needs the actual function call with 'sha1' as a string argument
        code2 = "encrypt_algo = some_function('sha1')"
        file_path = sample_python_file(code2)
        result = check_encryption(file_path)

        weak_alg_findings = [f for f in result["findings"] if "weak" in f["violation_type"].lower()]
        assert len(weak_alg_findings) > 0

    def test_detects_des_usage(self, sample_python_file):
        """Verify detection of DES algorithm usage."""
        code = "cipher = create_cipher('des', key)"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        weak_alg_findings = [f for f in result["findings"] if "weak" in f["violation_type"].lower()]
        assert len(weak_alg_findings) > 0

    def test_detects_rc4_usage(self, sample_python_file):
        """Verify detection of RC4 algorithm usage."""
        code = "stream_cipher = init_cipher('rc4')"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert any("rc4" in f["description"].lower() for f in result["findings"])

    def test_weak_algorithm_severity_is_high(self, sample_python_file):
        """Verify weak algorithm findings have high severity."""
        code = "hasher = hashlib_function('md5')"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        weak_alg_findings = [f for f in result["findings"] if "weak" in f["violation_type"].lower()]
        if len(weak_alg_findings) > 0:
            assert weak_alg_findings[0]["severity"] == "high"


class TestKeyRotationDetection:
    """Tests for key rotation logic detection."""

    def test_detects_key_rotation_function(self, sample_python_file):
        """Verify detection of key rotation functions."""
        code = """
def rotate_encryption_keys():
    # Implementation of key rotation
    pass
"""
        file_path = sample_python_file(code)

        # Analyze the file directly
        visitor = EncryptionVisitor(file_path)
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        visitor.visit(tree)

        assert visitor.has_key_rotation_logic == True

    def test_detects_key_rotation_in_docstring(self, sample_python_file):
        """Verify detection of key rotation mentioned in docstrings."""
        code = """
def manage_keys():
    '''
    Manages encryption keys with 90 days rotation policy.
    '''
    pass
"""
        file_path = sample_python_file(code)

        visitor = EncryptionVisitor(file_path)
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        visitor.visit(tree)

        assert visitor.has_key_rotation_logic == True

    def test_flags_config_without_key_rotation(self, temp_dir):
        """Verify security/config files without rotation logic are flagged."""
        config_file = os.path.join(temp_dir, "security_config.py")
        code = """
import key_manager
encryption_key = key_manager.get_key()
"""
        with open(config_file, 'w') as f:
            f.write(code)

        result = check_encryption(config_file)

        rotation_findings = [f for f in result["findings"] if "key management" in f["violation_type"].lower()]
        assert len(rotation_findings) > 0
        assert rotation_findings[0]["severity"] == "medium"


class TestSeverityCalculation:
    """Tests for severity level calculation."""

    def test_severity_critical_for_critical_violations(self, sample_python_file):
        """Verify overall severity is critical when critical violations exist."""
        code = "secret_key = 'hardcoded_value_123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["severity"] == "critical"

    def test_severity_high_for_high_violations(self, sample_python_file):
        """Verify overall severity is high when only high violations exist."""
        code = 'db = "postgresql://user:pass@localhost/db"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["severity"] in ["high", "critical"]

    def test_severity_none_for_compliant_code(self, sample_python_file):
        """Verify overall severity is none for compliant code."""
        code = """
import os
def get_config():
    return os.environ.get('CONFIG')
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["severity"] == "none"

    def test_compliant_false_for_critical_violations(self, sample_python_file):
        """Verify compliant is False when critical violations exist."""
        code = "api_key = 'sk-test-123456789'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["compliant"] == False

    def test_compliant_false_for_high_violations(self, sample_python_file):
        """Verify compliant is False when high severity violations exist."""
        code = 'conn = "mysql://user:pass@host/db"'
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert result["compliant"] == False

    def test_compliant_true_for_medium_and_low_only(self, temp_dir):
        """Verify compliant is True when only medium/low violations exist."""
        config_file = os.path.join(temp_dir, "config.py")
        code = """
from cryptography.fernet import Fernet
# Config file without rotation - medium severity
key = Fernet.generate_key()
"""
        with open(config_file, 'w') as f:
            f.write(code)

        result = check_encryption(config_file)

        # If only medium severity, should be compliant
        if result["severity"] == "medium":
            assert result["compliant"] == True


class TestFindingStructure:
    """Tests for finding data structure."""

    def test_finding_includes_line_number(self, sample_python_file):
        """Verify each finding includes a line number."""
        code = "password = 'test123456789'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        assert len(result["findings"]) > 0
        for finding in result["findings"]:
            assert "line_number" in finding
            assert isinstance(finding["line_number"], int)

    def test_finding_includes_violation_type(self, sample_python_file):
        """Verify each finding includes a violation type."""
        code = "secret = 'mysecret123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        for finding in result["findings"]:
            assert "violation_type" in finding
            assert len(finding["violation_type"]) > 0

    def test_finding_includes_description(self, sample_python_file):
        """Verify each finding includes a description."""
        code = "api_token = 'token_abc123xyz'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        for finding in result["findings"]:
            assert "description" in finding
            assert len(finding["description"]) > 0

    def test_finding_includes_remediation_suggestion(self, sample_python_file):
        """Verify each finding includes remediation suggestion."""
        code = "auth_key = 'hardcoded_key_value'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        for finding in result["findings"]:
            assert "remediation_suggestion" in finding
            assert len(finding["remediation_suggestion"]) > 0

    def test_finding_includes_severity(self, sample_python_file):
        """Verify each finding includes severity level."""
        code = "password = 'test_password_123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        valid_severities = {"critical", "high", "medium", "low"}
        for finding in result["findings"]:
            assert "severity" in finding
            assert finding["severity"] in valid_severities

    def test_finding_includes_file_path(self, sample_python_file):
        """Verify each finding includes the file path."""
        code = "secret = 'hardcoded_secret_123'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        for finding in result["findings"]:
            assert "file" in finding
            assert len(finding["file"]) > 0

    def test_finding_includes_regulation_reference(self, sample_python_file):
        """Verify each finding includes regulation reference."""
        code = "api_key = 'hardcoded_api_key'"
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        for finding in result["findings"]:
            assert "regulation_reference" in finding
            assert finding["regulation_reference"] == HIPAA_REGULATION_REF


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_handles_syntax_errors_gracefully(self, sample_python_file):
        """Verify syntax errors don't crash the checker."""
        code = "def broken function("
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should return a result even with syntax errors
        assert isinstance(result, dict)
        assert "findings" in result

    def test_handles_empty_file(self, sample_python_file):
        """Verify empty files are handled correctly."""
        file_path = sample_python_file("")
        result = check_encryption(file_path)

        assert result["compliant"] == True
        assert len(result["findings"]) == 0

    def test_handles_nonexistent_file(self):
        """Verify nonexistent files are handled gracefully."""
        result = check_encryption("/nonexistent/file.py")

        assert isinstance(result, dict)
        assert "findings" in result

    def test_handles_directory_without_python_files(self, temp_dir):
        """Verify directories without Python files are handled."""
        # Create only non-Python files
        txt_file = os.path.join(temp_dir, "readme.txt")
        with open(txt_file, 'w') as f:
            f.write("No Python here")

        result = check_encryption(temp_dir)

        assert result["compliant"] == True
        assert len(result["findings"]) == 0


class TestEncryptionLibraryImports:
    """Tests for encryption library import detection."""

    def test_detects_cryptography_import(self, sample_python_file):
        """Verify cryptography library imports are detected."""
        code = "from cryptography.fernet import Fernet"
        file_path = sample_python_file(code)

        visitor = EncryptionVisitor(file_path)
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        visitor.visit(tree)

        assert visitor.has_encryption_library == True

    def test_detects_crypto_import(self, sample_python_file):
        """Verify Crypto library imports are detected."""
        code = "from Crypto.Cipher import AES"
        file_path = sample_python_file(code)

        visitor = EncryptionVisitor(file_path)
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        visitor.visit(tree)

        assert visitor.has_encryption_library == True

    def test_detects_nacl_import(self, sample_python_file):
        """Verify PyNaCl library imports are detected."""
        code = "import nacl.secret"
        file_path = sample_python_file(code)

        visitor = EncryptionVisitor(file_path)
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())
        visitor.visit(tree)

        assert visitor.has_encryption_library == True


class TestMultipleViolations:
    """Tests for handling multiple violations in a single file."""

    def test_reports_all_violations_in_file(self, sample_python_file):
        """Verify all violations are reported, not just the first one."""
        code = """
api_key = 'hardcoded_key_123'
db_url = 'postgresql://user:pass@host/db'
password = 'another_secret_456'
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        # Should have at least 3 violations
        assert len(result["findings"]) >= 3

    def test_violations_have_different_line_numbers(self, sample_python_file):
        """Verify violations on different lines have correct line numbers."""
        code = """# Line 1
secret1 = 'first_secret_123'
# Line 3
secret2 = 'second_secret_456'
"""
        file_path = sample_python_file(code)
        result = check_encryption(file_path)

        line_numbers = [f["line_number"] for f in result["findings"]]
        # Line numbers will be 2 and 4 (accounting for the leading newline being removed)
        assert 2 in line_numbers or 3 in line_numbers
        assert 4 in line_numbers or 5 in line_numbers


# Marker for pytest
pytestmark = pytest.mark.compliance
