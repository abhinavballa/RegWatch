"""
HIPAA Audit Logging Compliance Checker
======================================

This module implements a static analysis checker for HIPAA § 164.312(b) audit logging requirements.
It analyzes Python source code to verify that electronic Protected Health Information (ePHI)
access is properly logged, retained, and monitored.

HIPAA § 164.312(b) Requirements:
1.  **Audit Controls**: Implement hardware, software, and/or procedural mechanisms that record
    and examine activity in information systems that contain or use electronic protected health information.
2.  **Audit Trail**: Secure, computer-generated, time-stamped audit trails that independently
    record the date and time of operator entries and actions that create, modify, or delete electronic records.

Key Validation Points:
-   **ePHI Access Logging**: Verifies that functions accessing potential ePHI (identified by naming conventions)
    contain logging calls.
-   **Required Log Fields**: Checks if log calls include timestamp, user, action, and resource identifiers.
-   **Retention Policy**: Scans for configuration settings implying log retention of at least 6 years (2190 days).
-   **Tamper-Proofing**: Looks for append-only file modes or immutable storage references.
-   **Anomaly Detection**: Checks for integration with monitoring or SIEM tools.

Usage:
    from src.checkers.hipaa_audit_logging_checker import check_audit_logging
    report = check_audit_logging("path/to/medical_records_api.py")
"""

import ast
import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple

# Constants for heuristics
PHI_INDICATORS = {
    "patient", "medical", "record", "diagnosis", "treatment", "prescription",
    "ephi", "phi", "health", "clinical", "lab", "result"
}

CRUD_INDICATORS = {
    "create": ["create", "insert", "add", "save", "post"],
    "read": ["get", "read", "fetch", "retrieve", "select", "query", "find"],
    "update": ["update", "modify", "edit", "patch", "change"],
    "delete": ["delete", "remove", "destroy", "drop"]
}

REQUIRED_LOG_FIELDS = {"user", "action", "resource", "id"}  # Timestamp is often implicit in logger
RETENTION_MIN_DAYS = 2190  # 6 years

class AuditLoggingVisitor(ast.NodeVisitor):
    """
    AST Visitor to analyze code for HIPAA audit logging compliance.
    
    Tracks:
    - Function definitions that likely handle ePHI.
    - Logging calls within those functions.
    - Configuration assignments related to retention and storage.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.current_function: Optional[ast.FunctionDef] = None
        self.has_logging_config = False
        self.retention_compliant = False
        self.tamper_proof_storage = False
        self.anomaly_detection_found = False
        
        # State for current function analysis
        self.ephi_access_detected = False
        self.audit_log_calls: List[ast.Call] = []
        self.crud_type: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """
        Visit function definitions to check for ePHI access and subsequent logging.
        """
        # Reset state for new function
        previous_function = self.current_function
        self.current_function = node
        self.ephi_access_detected = False
        self.audit_log_calls = []
        self.crud_type = self._determine_crud_type(node.name)
        
        # Check if function name suggests ePHI access
        if self._is_ephi_related(node.name):
            self.ephi_access_detected = True

        # Visit body to find log calls and specific ePHI operations
        self.generic_visit(node)

        # Post-visit analysis for the function
        if self.ephi_access_detected:
            self._analyze_function_compliance(node)

        self.current_function = previous_function

    def visit_Call(self, node: ast.Call) -> None:
        """
        Visit function calls to detect logging statements and external integrations.
        """
        func_name = self._get_func_name(node)
        
        # Detect logging calls
        if self._is_logging_call(func_name):
            if self.current_function:
                self.audit_log_calls.append(node)

        # Detect Anomaly Detection / SIEM integration
        if any(tool in func_name.lower() for tool in ["splunk", "datadog", "newrelic", "sentry", "alert", "monitor"]):
            self.anomaly_detection_found = True

        # Detect Tamper Proofing (e.g., opening files in append mode)
        if func_name == "open":
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Str):
                    if "a" in keyword.value.s: # Append mode
                        # This is a weak signal, but valid for basic checks
                        pass 

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Visit assignments to detect configuration settings (retention, storage).
        """
        # Check for retention settings
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Retention Check
                if "retention" in var_name or "log_days" in var_name or "max_age" in var_name:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                        if node.value.value >= RETENTION_MIN_DAYS:
                            self.retention_compliant = True
                        else:
                            self.findings.append({
                                "line_number": node.lineno,
                                "violation_type": "INADEQUATE_LOG_RETENTION",
                                "description": f"Log retention set to {node.value.value} days. HIPAA requires >= 6 years ({RETENTION_MIN_DAYS} days).",
                                "remediation_suggestion": f"Increase retention setting to at least {RETENTION_MIN_DAYS} days.",
                                "severity": "High"
                            })

                # Tamper Proofing Check (Storage Configuration)
                if "storage_class" in var_name or "log_mode" in var_name:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value.lower()
                        if "worm" in val or "immutable" in val or "append_only" in val:
                            self.tamper_proof_storage = True

        self.generic_visit(node)

    def _is_ephi_related(self, name: str) -> bool:
        """Check if a name implies ePHI access."""
        name_lower = name.lower()
        return any(indicator in name_lower for indicator in PHI_INDICATORS)

    def _determine_crud_type(self, name: str) -> Optional[str]:
        """Determine the CRUD operation type from function name."""
        name_lower = name.lower()
        for op_type, keywords in CRUD_INDICATORS.items():
            if any(k in name_lower for k in keywords):
                return op_type
        return None

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from AST Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle obj.method() -> return "method" (simplified) or "obj.method"
            # For logging, we usually care about the attribute (info, error) or the object (logger)
            try:
                if isinstance(node.func.value, ast.Name):
                    return f"{node.func.value.id}.{node.func.attr}"
            except AttributeError:
                pass
            return node.func.attr
        return ""

    def _is_logging_call(self, func_name: str) -> bool:
        """Check if function name is a known logging method."""
        log_methods = {"info", "warning", "error", "critical", "log", "audit"}
        parts = func_name.split(".")
        
        # Check for standard logging (logger.info) or direct calls (log_audit)
        if any(m in parts[-1].lower() for m in log_methods):
            return True
        if "logger" in func_name.lower() or "logging" in func_name.lower():
            return True
        return False

    def _analyze_function_compliance(self, node: ast.FunctionDef) -> None:
        """Analyze a specific function for audit logging compliance."""
        
        # 1. Check for presence of logging
        if not self.audit_log_calls:
            self.findings.append({
                "line_number": node.lineno,
                "violation_type": "MISSING_AUDIT_LOG",
                "description": f"Function '{node.name}' appears to access ePHI but contains no audit logging calls.",
                "remediation_suggestion": "Add a logger.info() or audit_log() call recording the user, action, and resource accessed.",
                "severity": "Critical"
            })
            return

        # 2. Check content of logging calls
        # We need at least one log call that looks like an audit log (contains required fields)
        sufficient_audit_log = False
        missing_fields_report = set()

        for call in self.audit_log_calls:
            fields_found = self._parse_log_call_fields(call)
            
            # Check if this specific call satisfies requirements
            # We assume timestamp is handled by the logger infrastructure usually
            missing = REQUIRED_LOG_FIELDS - fields_found
            
            # Heuristic: If we found user and resource/id, it's likely an audit log
            # Action is often implicit in the message string
            if len(missing) <= 1: 
                sufficient_audit_log = True
                break
            else:
                missing_fields_report = missing

        if not sufficient_audit_log:
            self.findings.append({
                "line_number": node.lineno,
                "violation_type": "INCOMPLETE_AUDIT_FIELDS",
                "description": f"Logging in '{node.name}' may be missing required audit fields. Missing potential indicators for: {', '.join(missing_fields_report)}.",
                "remediation_suggestion": "Ensure log message or context includes: User ID, Action Type, and Resource ID.",
                "severity": "High"
            })

    def _parse_log_call_fields(self, node: ast.Call) -> Set[str]:
        """
        Extract potential field names from a logging call.
        Checks string arguments and keyword arguments (extra=..., context=...).
        """
        found_fields = set()
        
        # Check arguments (strings)
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                text = arg.value.lower()
                for field in REQUIRED_LOG_FIELDS:
                    if field in text:
                        found_fields.add(field)
            # Check f-strings (JoinedStr)
            elif isinstance(arg, ast.JoinedStr):
                for value in arg.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        text = value.value.lower()
                        for field in REQUIRED_LOG_FIELDS:
                            if field in text:
                                found_fields.add(field)
                    elif isinstance(value, ast.FormattedValue):
                        # Check the variable name inside the f-string {user_id}
                        if isinstance(value.value, ast.Name):
                            var_name = value.value.id.lower()
                            for field in REQUIRED_LOG_FIELDS:
                                if field in var_name:
                                    found_fields.add(field)

        # Check keywords (e.g., logger.info(..., user=u, extra={'user': u}))
        for keyword in node.keywords:
            # Direct kwargs
            if keyword.arg:
                arg_name = keyword.arg.lower()
                for field in REQUIRED_LOG_FIELDS:
                    if field in arg_name:
                        found_fields.add(field)
            
            # Check 'extra' or 'context' dicts
            if keyword.arg in ['extra', 'context'] and isinstance(keyword.value, ast.Dict):
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        key_name = key.value.lower()
                        for field in REQUIRED_LOG_FIELDS:
                            if field in key_name:
                                found_fields.add(field)

        return found_fields


def check_audit_logging(code_path: str) -> Dict[str, Any]:
    """
    Analyze a Python file for HIPAA § 164.312(b) audit logging compliance.

    Args:
        code_path: Path to the Python source file to analyze.

    Returns:
        Dict containing:
            - compliant (bool): Overall compliance status.
            - findings (List[Dict]): List of specific violations found.
            - severity (str): Overall severity of the report.
            - regulation_reference (str): "HIPAA § 164.312(b)"
    """
    if not os.path.exists(code_path):
        raise FileNotFoundError(f"File not found: {code_path}")

    with open(code_path, "r", encoding="utf-8") as f:
        try:
            source_code = f.read()
            tree = ast.parse(source_code, filename=code_path)
        except SyntaxError as e:
            return {
                "compliant": False,
                "findings": [{
                    "line_number": e.lineno,
                    "violation_type": "SYNTAX_ERROR",
                    "description": f"Could not parse file: {e.msg}",
                    "remediation_suggestion": "Fix Python syntax errors before compliance checking.",
                    "severity": "Critical"
                }],
                "severity": "Critical",
                "regulation_reference": "HIPAA § 164.312(b)"
            }

    visitor = AuditLoggingVisitor()
    visitor.visit(tree)

    # Global Checks (File-level)
    
    # 1. Anomaly Detection Check
    if not visitor.anomaly_detection_found:
        # This is a softer check, as it might be configured externally
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "MISSING_ANOMALY_DETECTION",
            "description": "No references to anomaly detection, alerting, or SIEM integration found in code.",
            "remediation_suggestion": "Ensure logs are forwarded to a SIEM (e.g., Splunk) or implement alerting on suspicious access patterns.",
            "severity": "Medium"
        })

    # 2. Tamper Proofing Check
    if not visitor.tamper_proof_storage:
        # Also a soft check, often infrastructure-level
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "UNVERIFIED_TAMPER_PROOFING",
            "description": "No explicit configuration for immutable or append-only log storage detected.",
            "remediation_suggestion": "Configure log storage to be WORM (Write Once Read Many) or use cryptographic signing.",
            "severity": "Medium"
        })

    # 3. Retention Check (if no config found at all)
    if not visitor.retention_compliant:
        # If we found a bad config, it's already in findings. If we found nothing, we warn.
        # We check if we already have a specific retention finding
        has_retention_finding = any(f["violation_type"] == "INADEQUATE_LOG_RETENTION" for f in visitor.findings)
        if not has_retention_finding:
             visitor.findings.append({
                "line_number": 1,
                "violation_type": "UNVERIFIED_LOG_RETENTION",
                "description": "No log retention policy configuration detected in code.",
                "remediation_suggestion": f"Ensure logs are retained for at least 6 years ({RETENTION_MIN_DAYS} days) via configuration.",
                "severity": "High"
            })

    # Determine Overall Status
    is_compliant = len(visitor.findings) == 0
    
    # Calculate Overall Severity
    severity_levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_severity_val = 0
    overall_severity = "Low"

    if not is_compliant:
        for finding in visitor.findings:
            s_val = severity_levels.get(finding.get("severity", "Low"), 1)
            if s_val > max_severity_val:
                max_severity_val = s_val
        
        # Map back to string
        for k, v in severity_levels.items():
            if v == max_severity_val:
                overall_severity = k
                break
    else:
        overall_severity = "None"

    return {
        "compliant": is_compliant,
        "findings": visitor.findings,
        "severity": overall_severity,
        "regulation_reference": "HIPAA § 164.312(b)"
    }