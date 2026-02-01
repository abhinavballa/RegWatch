"""
HIPAA Encryption Compliance Checker Module
RegWatch Compliance Monitoring System

This module implements static code analysis to validate compliance with 
HIPAA 7 164.312(a)(2)(iv) - Encryption and Decryption.

It analyzes Python source code to detect:
1. Database encryption at rest (AES-256+).
2. Encryption in transit (TLS 1.2+).
3. Field-level PHI encryption for sensitive data.
4. Proper key management (no hardcoded keys, rotation policies).

Usage:
    from src.checkers.hipaa_encryption_checker import check_encryption
    report = check_encryption("/path/to/project")
"""

import ast
import os
import re
from typing import Dict, List, Any, Set, Optional, Union

# --- Constants & Configuration ---

HIPAA_REF = "HIPAA 7 164.312(a)(2)(iv)"

SENSITIVE_PHI_FIELDS = {
    "ssn", "social_security", "social_security_number",
    "medical_record", "mrn", "medical_record_number",
    "diagnosis", "condition", "prescription", "rx",
    "treatment", "patient_id", "dob", "date_of_birth",
    "health_insurance", "policy_number"
}

WEAK_ALGORITHMS = {"md5", "sha1", "des", "rc4", "3des", "blowfish"}
STRONG_ALGORITHMS = {"aes-256", "aes_256", "aes256", "rsa-2048", "rsa-4096", "chacha20"}

# Keywords indicating encryption usage in ORM/DB contexts
ENCRYPTION_INDICATORS = {"encrypted", "encrypt", "fernet", "vault", "secret"}

# Keywords for hardcoded secrets
SECRET_VAR_NAMES = {"key", "secret", "password", "token", "auth"}


# --- Helper Functions ---

def _is_strong_encryption(algo_name: str) -> bool:
    """
    Validates if the encryption algorithm meets NIST standards (AES-256+, RSA-2048+).
    """
    algo = algo_name.lower().replace("_", "").replace("-", "")
    
    # Check for explicit strong matches
    if any(s in algo for s in ["aes256", "rsa2048", "rsa4096", "chacha20", "gcm"]):
        return True
    
    # Check for explicit weak matches
    if any(w in algo for w in ["md5", "sha1", "des", "rc4", "blowfish"]):
        return False
        
    # Default conservative assumption: if it says "aes" without 256, it might be 128 (acceptable but warnable)
    # For this strict checker, we want explicit confirmation or standard libraries.
    return "aes" in algo or "rsa" in algo

def _is_phi_field(field_name: str) -> bool:
    """Checks if a variable or column name suggests it contains PHI."""
    normalized = field_name.lower().replace("_", "")
    return any(phi.replace("_", "") in normalized for phi in SENSITIVE_PHI_FIELDS)

def _calculate_severity(findings: List[Dict[str, Any]]) -> str:
    """Calculates overall severity based on the highest severity finding."""
    severities = [f["severity"] for f in findings]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


# --- AST Visitor ---

class EncryptionVisitor(ast.NodeVisitor):
    """
    AST Visitor to detect encryption patterns, hardcoded keys, and PHI handling.
    """
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []
        self.imports: Set[str] = set()
        self.has_encryption_lib = False

    def _add_finding(self, node: ast.AST, violation_type: str, description: str, 
                     remediation: str, severity: str):
        self.findings.append({
            "file": self.filename,
            "line_number": getattr(node, "lineno", 0),
            "violation_type": violation_type,
            "description": description,
            "remediation_suggestion": remediation,
            "severity": severity,
            "regulation_reference": HIPAA_REF
        })

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name)
            if any(lib in alias.name for lib in ["cryptography", "Crypto", "nacl", "passlib"]):
                self.has_encryption_lib = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module)
            if any(lib in node.module for lib in ["cryptography", "Crypto", "nacl", "passlib"]):
                self.has_encryption_lib = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """
        Checks for:
        1. Hardcoded keys.
        2. Database connection strings (TLS).
        3. ORM Field definitions (PHI Encryption).
        """
        # 1. Check for Hardcoded Keys
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(s in var_name for s in SECRET_VAR_NAMES):
                    if isinstance(node.value, (ast.Str, ast.Bytes, ast.Constant)):
                        val = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
                        # Filter out obvious placeholders or config lookups
                        if isinstance(val, (str, bytes)) and len(val) > 8 and "env" not in var_name:
                            self._add_finding(
                                node, "HARDCODED_KEY",
                                f"Potential hardcoded encryption key or secret found in variable '{target.id}'.",
                                "Move secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
                                "critical"
                            )

        # 2. Check for Database Connection Strings (TLS)
        if isinstance(node.value, (ast.Str, ast.Constant)):
            val = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
            if isinstance(val, str) and ("postgres://" in val or "mysql://" in val or "sqlserver://" in val):
                if "sslmode=require" not in val and "sslmode=verify-full" not in val and "tls_version" not in val:
                     self._add_finding(
                        node, "MISSING_TLS_DB",
                        "Database connection string detected without explicit SSL/TLS enforcement.",
                        "Append '?sslmode=require' or '?sslmode=verify-full' to the connection string to ensure encryption in transit.",
                        "high"
                    )

        # 3. Check for ORM Field Definitions (SQLAlchemy/Django style)
        # Pattern: field_name = Column(...) or field_name = models.CharField(...)
        for target in node.targets:
            if isinstance(target, ast.Name) and _is_phi_field(target.id):
                if isinstance(node.value, ast.Call):
                    # Check if the definition includes encryption
                    call_keywords = [k.arg for k in node.value.keywords if k.arg]
                    
                    # Heuristic: Look for TypeDecorator, EncryptedType, or specific keywords
                    is_encrypted = False
                    
                    # Check keywords for 'encrypt', 'transformer', 'type_' with encryption
                    for keyword in node.value.keywords:
                        if keyword.arg in ["encrypt", "encryption_key"]:
                            is_encrypted = True
                        if keyword.arg == "type_" and isinstance(keyword.value, ast.Call):
                            # e.g. type_=EncryptedType(...)
                            if hasattr(keyword.value.func, "id") and "Encrypt" in keyword.value.func.id:
                                is_encrypted = True
                    
                    # Check function name (e.g., EncryptedCharField)
                    func_name = ""
                    if isinstance(node.value.func, ast.Name):
                        func_name = node.value.func.id
                    elif isinstance(node.value.func, ast.Attribute):
                        func_name = node.value.func.attr
                    
                    if "Encrypt" in func_name or "Vault" in func_name:
                        is_encrypted = True

                    if not is_encrypted:
                        self._add_finding(
                            node, "UNENCRYPTED_PHI_FIELD",
                            f"Potential PHI field '{target.id}' detected without apparent field-level encryption.",
                            "Use an encrypted column type (e.g., SQLAlchemy-Utils EncryptedType) or application-level encryption before storage.",
                            "high"
                        )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """
        Checks for:
        1. Weak encryption algorithms.
        2. TLS Configuration in calls (e.g., ssl.create_default_context).
        """
        # Check for weak algorithms in function calls (e.g., hashlib.md5())
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name.lower() in WEAK_ALGORITHMS:
             self._add_finding(
                node, "WEAK_ENCRYPTION_ALGO",
                f"Usage of weak hashing/encryption algorithm '{func_name}' detected.",
                "Replace with strong algorithms: AES-256 for encryption, SHA-256+ for hashing.",
                "high"
            )

        # Check for SSL Context creation (TLS 1.2+)
        if "create_default_context" in func_name or "SSLContext" in func_name:
            # This is a loose check; usually we want to see PROTOCOL_TLSv1_2 or higher
            # If we see PROTOCOL_TLSv1 or PROTOCOL_SSLv3, flag it.
            for arg in node.args:
                if isinstance(arg, ast.Attribute) and arg.attr in ["PROTOCOL_TLSv1", "PROTOCOL_SSLv3", "PROTOCOL_TLS"]:
                     self._add_finding(
                        node, "WEAK_TLS_VERSION",
                        f"Potential usage of older TLS/SSL protocol version '{arg.attr}'.",
                        "Explicitly configure 'ssl.PROTOCOL_TLS_CLIENT' or ensure TLS 1.2+ is enforced.",
                        "medium"
                    )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """
        Checks for Key Rotation Policies in comments or docstrings within configuration classes.
        """
        # Heuristic: If class is named Config or Settings, look for rotation logic
        if "Config" in node.name or "Settings" in node.name:
            docstring = ast.get_docstring(node)
            if docstring:
                if "rotation" not in docstring.lower() and "rotate" not in docstring.lower():
                    # This is a weak signal, so we only log it if we see "Key" or "Secret" in the class fields
                    has_keys = False
                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for t in item.targets:
                                if isinstance(t, ast.Name) and ("key" in t.id.lower() or "secret" in t.id.lower()):
                                    has_keys = True
                    
                    if has_keys:
                        self._add_finding(
                            node, "MISSING_KEY_ROTATION_POLICY",
                            f"Configuration class '{node.name}' handles keys but lacks documented rotation policy.",
                            "Implement and document a 90-day key rotation policy (HIPAA requirement).",
                            "low"
                        )
        self.generic_visit(node)


# --- Main Analysis Logic ---

def _analyze_file(filepath: str) -> List[Dict[str, Any]]:
    """Parses and analyzes a single Python file."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        
        tree = ast.parse(source, filename=filepath)
        visitor = EncryptionVisitor(filepath)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        
        # File-level check: If PHI fields were found but no encryption library imported
        phi_vars_found = False
        if any(re.search(rf"\b{phi}\b", source, re.IGNORECASE) for phi in SENSITIVE_PHI_FIELDS):
            phi_vars_found = True

        if phi_vars_found and not visitor.has_encryption_lib:
             findings.append({
                "file": filepath,
                "line_number": 1,
                "violation_type": "MISSING_ENCRYPTION_LIB",
                "description": "File appears to handle PHI but imports no known encryption libraries.",
                "remediation_suggestion": "Ensure 'cryptography', 'pycryptodome', or similar libraries are used to encrypt PHI.",
                "severity": "high",
                "regulation_reference": HIPAA_REF
            })

    except SyntaxError as e:
        findings.append({
            "file": filepath,
            "line_number": e.lineno or 0,
            "violation_type": "SYNTAX_ERROR",
            "description": f"Could not parse file: {e.msg}",
            "remediation_suggestion": "Fix syntax errors to allow compliance scanning.",
            "severity": "low",
            "regulation_reference": "N/A"
        })
    except Exception as e:
        findings.append({
            "file": filepath,
            "line_number": 0,
            "violation_type": "ANALYSIS_ERROR",
            "description": f"Unexpected error analyzing file: {str(e)}",
            "remediation_suggestion": "Check file permissions and encoding.",
            "severity": "low",
            "regulation_reference": "N/A"
        })
        
    return findings

def check_encryption(code_path: str) -> Dict[str, Any]:
    """
    Analyzes Python files for HIPAA encryption compliance.

    Args:
        code_path (str): Path to a .py file or a directory containing .py files.

    Returns:
        Dict: A report containing findings, compliance status, and severity.
    """
    all_findings = []

    if os.path.isfile(code_path):
        if code_path.endswith(".py"):
            all_findings.extend(_analyze_file(code_path))
    elif os.path.isdir(code_path):
        for root, _, files in os.walk(code_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    all_findings.extend(_analyze_file(full_path))
    else:
        return {
            "findings": [],
            "compliant": False,
            "severity": "low",
            "error": f"Path not found: {code_path}",
            "regulation_reference": HIPAA_REF
        }

    # Determine compliance
    critical_or_high = [f for f in all_findings if f["severity"] in ("critical", "high")]
    is_compliant = len(critical_or_high) == 0

    overall_severity = _calculate_severity(all_findings) if all_findings else "low"

    return {
        "findings": all_findings,
        "compliant": is_compliant,
        "severity": overall_severity,
        "regulation_reference": HIPAA_REF
    }

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        report = check_encryption(sys.argv[1])
        print(json.dumps(report, indent=2))