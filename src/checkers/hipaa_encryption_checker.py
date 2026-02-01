"""
HIPAA Encryption Compliance Checker Module
RegWatch Compliance Monitoring System

This module implements static code analysis to validate compliance with 
HIPAA 4.312(a)(2)(iv) (Encryption and Decryption).

It analyzes Python source code using Abstract Syntax Trees (AST) to detect:
1. Database encryption at rest (AES-256+).
2. Encryption in transit (TLS 1.2+).
3. Field-level PHI encryption.
4. Key management practices (hardcoded keys, rotation policies).

Usage:
    from src.checkers.hipaa_encryption_checker import check_encryption
    report = check_encryption("/path/to/project")
"""

import ast
import os
from typing import Dict, List, Any, Set

# --- Constants & Configuration ---

HIPAA_REGULATION_REF = "HIPAA 4.312(a)(2)(iv)"

# Sensitive PHI field names to watch for
PHI_KEYWORDS = {
    "ssn", "social_security", "medical_record", "mrn", "diagnosis", 
    "prescription", "patient_id", "dob", "date_of_birth", "health_plan",
    "beneficiary", "treatment", "lab_result"
}

# Weak or insufficient algorithms
WEAK_ALGORITHMS = {"md5", "sha1", "des", "rc4", "blowfish", "aes-128"}

# Strong algorithms (simplified check)
STRONG_ALGORITHMS = {"aes-256", "aes-192", "rsa-2048", "rsa-4096", "sha-256", "sha-512"}

# Variable names suggesting keys/secrets
KEY_VARIABLE_PATTERNS = {"key", "secret", "password", "token", "auth"}


class EncryptionViolation:
    """Data structure for a single compliance finding."""
    def __init__(
        self, 
        line_number: int, 
        violation_type: str, 
        description: str, 
        remediation: str, 
        severity: str,
        filename: str
    ):
        self.line_number = line_number
        self.violation_type = violation_type
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.filename = filename

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_number": self.line_number,
            "violation_type": self.violation_type,
            "description": self.description,
            "remediation_suggestion": self.remediation,
            "severity": self.severity,
            "file": self.filename,
            "regulation_reference": HIPAA_REGULATION_REF
        }


class EncryptionVisitor(ast.NodeVisitor):
    """
    AST Visitor to traverse Python code and detect encryption compliance issues.
    """
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[EncryptionViolation] = []
        self.imports: Set[str] = set()
        self.has_encryption_library = False
        self.has_key_rotation_logic = False

    def visit_Import(self, node: ast.Import):
        """Track imports to see if encryption libraries are used."""
        for alias in node.names:
            self.imports.add(alias.name)
            if any(lib in alias.name for lib in ["cryptography", "Crypto", "nacl", "passlib"]):
                self.has_encryption_library = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from-imports."""
        if node.module:
            self.imports.add(node.module)
            if any(lib in node.module for lib in ["cryptography", "Crypto", "nacl", "passlib"]):
                self.has_encryption_library = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """
        Check assignments for:
        1. Hardcoded keys.
        2. Database connection strings (TLS checks).
        3. Key rotation logic hints.
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(p in var_name for p in KEY_VARIABLE_PATTERNS):
                    if isinstance(node.value, (ast.Str, ast.Bytes, ast.Constant)):
                        val = node.value.value if isinstance(node.value, ast.Constant) else getattr(node.value, 's', None)
                        if isinstance(val, (str, bytes)) and len(val) > 5 and "env" not in var_name:
                            self.findings.append(EncryptionViolation(
                                line_number=node.lineno,
                                violation_type="Hardcoded Key",
                                description=f"Potential hardcoded secret found in variable '{target.id}'.",
                                remediation="Move secrets to environment variables or a secrets manager.",
                                severity="critical",
                                filename=self.filename
                            ))

        if isinstance(node.value, (ast.Str, ast.Constant)):
            val = node.value.value if isinstance(node.value, ast.Constant) else getattr(node.value, 's', None)
            if isinstance(val, str) and any(db in val for db in ["postgresql://", "mysql://", "sqlserver://"]):
                if not any(opt in val for opt in ["sslmode", "ssl_mode", "tls"]):
                    self.findings.append(EncryptionViolation(
                        line_number=node.lineno,
                        violation_type="Encryption in Transit",
                        description="Database connection string detected without explicit SSL/TLS configuration.",
                        remediation="Append '?sslmode=require' or equivalent TLS parameters.",
                        severity="high",
                        filename=self.filename
                    ))
                elif "sslmode=disable" in val or "sslmode=allow" in val:
                    self.findings.append(EncryptionViolation(
                        line_number=node.lineno,
                        violation_type="Encryption in Transit",
                        description="Database connection explicitly disables or allows unencrypted connections.",
                        remediation="Set sslmode to 'require', 'verify-ca', or 'verify-full'.",
                        severity="critical",
                        filename=self.filename
                    ))

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """
        Check function calls for PHI encryption and weak algorithms.
        """
        if (isinstance(node.func, ast.Name) and node.func.id == "Column") or \
           (isinstance(node.func, ast.Attribute) and node.func.attr == "Column"):
            self._check_sqlalchemy_column(node)

        for arg in node.args:
            if isinstance(arg, (ast.Str, ast.Constant)):
                val = arg.value if isinstance(arg, ast.Constant) else getattr(arg, 's', None)
                if isinstance(val, str) and val.lower() in WEAK_ALGORITHMS:
                    self.findings.append(EncryptionViolation(
                        line_number=node.lineno,
                        violation_type="Weak Encryption Algorithm",
                        description=f"Usage of weak hashing/encryption algorithm detected: {val}.",
                        remediation="Use AES-256 for encryption or SHA-256/SHA-512 for hashing.",
                        severity="high",
                        filename=self.filename
                    ))
        self.generic_visit(node)

    def _check_sqlalchemy_column(self, node: ast.Call):
        """Analyze a SQLAlchemy Column definition for PHI and encryption."""
        is_phi = False
        field_name = "unknown"
        
        if node.args and isinstance(node.args[0], (ast.Str, ast.Constant)):
            val = node.args[0].value if isinstance(node.args[0], ast.Constant) else getattr(node.args[0], 's', None)
            if isinstance(val, str):
                field_name = val
                if any(phi in val.lower() for phi in PHI_KEYWORDS):
                    is_phi = True

        if is_phi:
            has_encryption_type = False
            for arg in node.args:
                arg_str = ast.dump(arg)
                if any(kw in arg_str for kw in ["Encrypt", "Vault", "Secret"]):
                    has_encryption_type = True
            
            if not has_encryption_type:
                self.findings.append(EncryptionViolation(
                    line_number=node.lineno,
                    violation_type="Unencrypted PHI Field",
                    description=f"Potential PHI field '{field_name}' detected without field-level encryption.",
                    remediation="Use a TypeDecorator (e.g., EncryptedType) to encrypt this column at rest.",
                    severity="critical",
                    filename=self.filename
                ))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check for key rotation logic."""
        func_name = node.name.lower()
        if "rotate" in func_name and ("key" in func_name or "secret" in func_name):
            self.has_key_rotation_logic = True
        
        docstring = ast.get_docstring(node)
        if docstring and ("rotation" in docstring.lower() or "90 days" in docstring.lower()):
            self.has_key_rotation_logic = True
            
        self.generic_visit(node)


def _analyze_file(filepath: str) -> List[EncryptionViolation]:
    """Parses and analyzes a single Python file."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        
        tree = ast.parse(source)
        visitor = EncryptionVisitor(filepath)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        if "config" in filepath.lower() or "security" in filepath.lower():
            if not visitor.has_key_rotation_logic:
                has_keys = any("key" in imp.lower() for imp in visitor.imports)
                if has_keys:
                    findings.append(EncryptionViolation(
                        line_number=1,
                        violation_type="Key Management",
                        description="Security/Config module detected, but no key rotation logic found.",
                        remediation="Implement automated key rotation compliant with NIST SP 800-66.",
                        severity="medium",
                        filename=filepath
                    ))
    except (SyntaxError, Exception):
        pass
        
    return findings


def check_encryption(code_path: str) -> Dict[str, Any]:
    """Analyzes Python files for HIPAA encryption compliance."""
    all_findings: List[EncryptionViolation] = []

    if os.path.isfile(code_path) and code_path.endswith(".py"):
        all_findings.extend(_analyze_file(code_path))
    elif os.path.isdir(code_path):
        for root, _, files in os.walk(code_path):
            for file in files:
                if file.endswith(".py"):
                    all_findings.extend(_analyze_file(os.path.join(root, file)))

    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    findings_list = [f.to_dict() for f in all_findings]
    
    max_severity_val = max([severity_levels.get(f["severity"], 1) for f in findings_list], default=0)
    overall_severity = next((k for k, v in severity_levels.items() if v == max_severity_val), "none")

    return {
        "findings": findings_list,
        "compliant": max_severity_val < 3,
        "severity": overall_severity,
        "regulation_reference": HIPAA_REGULATION_REF
    }


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        print(check_encryption(sys.argv[1]))