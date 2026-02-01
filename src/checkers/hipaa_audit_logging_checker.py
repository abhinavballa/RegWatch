"""
HIPAA Audit Logging Compliance Checker.

This module implements static analysis checks for HIPAA § 164.312(b) audit logging requirements.
It analyzes Python source code to verify that:
1. Access to ePHI (Electronic Protected Health Information) is logged.
2. Audit logs contain required fields: timestamp, user, action, and resource.
3. Log retention policies meet the 6-year (2190 days) requirement.
4. Mechanisms for tamper-proof storage and anomaly detection are present.

The checker uses Python's AST (Abstract Syntax Tree) to inspect code structure without execution.
"""

import ast
import os
from typing import Dict, List, Any, Optional, Set

# HIPAA § 164.312(b) Audit Controls
REGULATION_REFERENCE = "HIPAA § 164.312(b) Audit Controls"

# Keywords suggesting ePHI interaction
PHI_KEYWORDS = {
    "patient", "medical", "diagnosis", "treatment", "prescription",
    "ssn", "dob", "health", "record", "clinical", "phi", "ephi"
}

# Keywords suggesting database or API access (CRUD operations)
ACCESS_KEYWORDS = {
    "create", "read", "update", "delete", "get", "fetch", "save",
    "insert", "select", "query", "find", "remove", "destroy"
}

# Required fields in audit logs
REQUIRED_LOG_FIELDS = {"user", "action", "resource", "timestamp"}


class AuditLoggingVisitor(ast.NodeVisitor):
    """
    AST Visitor to detect ePHI access and verify associated audit logging.
    """

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.current_function: Optional[ast.FunctionDef] = None
        self.log_calls_in_scope: List[ast.Call] = []
        self.has_retention_config = False
        self.has_tamper_proof_config = False
        self.has_anomaly_detection = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """
        Visit function definitions to check for ePHI access and subsequent logging.
        """
        self.current_function = node
        self.log_calls_in_scope = []

        # First pass: collect all logging calls in this function
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if self._is_logging_call(child):
                    self.log_calls_in_scope.append(child)

        # Second pass: check for ePHI access and verify logging coverage
        self.generic_visit(node)
        self.current_function = None

    def visit_Call(self, node: ast.Call) -> None:
        """
        Visit function calls to detect ePHI access operations.
        """
        if self.current_function:
            if self._is_ephi_access(node):
                if not self._is_covered_by_logging(node):
                    self.findings.append({
                        "line_number": node.lineno,
                        "violation_type": "Missing Audit Log",
                        "description": f"ePHI access detected in function '{self.current_function.name}' without corresponding audit log.",
                        "remediation_suggestion": "Add a logger.info() call recording user, action, and resource ID immediately after this operation.",
                        "severity": "Critical"
                    })
                else:
                    # If covered, validate the quality of the log (fields)
                    self._validate_log_quality(node)

        # Check for configuration patterns (retention, tamper-proofing)
        self._check_configuration_patterns(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Visit assignments to check for configuration variables (retention).
        """
        self._check_retention_config(node)
        self.generic_visit(node)

    def _is_ephi_access(self, node: ast.Call) -> bool:
        """
        Determine if a function call represents access to ePHI.
        """
        func_name = self._get_func_name(node)
        if not func_name:
            return False

        lower_name = func_name.lower()

        # Check if function name contains both PHI and Access keywords
        has_phi = any(k in lower_name for k in PHI_KEYWORDS)
        has_access = any(k in lower_name for k in ACCESS_KEYWORDS)

        # Also check arguments for PHI indicators (e.g., db.query("SELECT * FROM patients"))
        args_contain_phi = False
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if any(k in arg.value.lower() for k in PHI_KEYWORDS):
                    args_contain_phi = True
                    break
            # Handle f-strings (JoinedStr nodes)
            elif isinstance(arg, ast.JoinedStr):
                for value in arg.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        if any(k in value.value.lower() for k in PHI_KEYWORDS):
                            args_contain_phi = True
                            break
                if args_contain_phi:
                    break

        return (has_phi and has_access) or (has_access and args_contain_phi)

    def _is_logging_call(self, node: ast.Call) -> bool:
        """
        Determine if a call is a logging operation.
        """
        func_name = self._get_func_name(node)
        if not func_name:
            return False

        # Common logging patterns
        logging_methods = {"info", "warning", "error", "critical", "log", "audit"}
        parts = func_name.split('.')

        # Check for logger.info, logging.info, log.info, etc.
        if len(parts) > 1 and parts[-1] in logging_methods:
            return True

        # Check for specific audit functions
        if "audit" in func_name.lower() or "log_access" in func_name.lower():
            return True

        return False

    def _is_covered_by_logging(self, access_node: ast.Call) -> bool:
        """
        Check if an ePHI access node is "covered" by a logging call in the same scope.
        """
        if not self.log_calls_in_scope:
            return False

        # For static analysis baseline, existence in scope is accepted.
        return True

    def _validate_log_quality(self, access_node: ast.Call) -> None:
        """
        Check if the logging calls in scope contain the required audit fields.
        """
        sufficient_logging = False
        missing_fields = set()

        for log_call in self.log_calls_in_scope:
            fields_found = self._parse_log_call_fields(log_call)

            # Check if we have user, action, resource
            has_user = any(f in fields_found for f in ["user", "userid", "actor"])
            has_action = any(f in fields_found for f in ["action", "operation", "method"])
            has_resource = any(f in fields_found for f in ["resource", "record", "patient", "id"])

            if has_user and has_action and has_resource:
                sufficient_logging = True
                break

            if not has_user: missing_fields.add("user_id")
            if not has_action: missing_fields.add("action")
            if not has_resource: missing_fields.add("resource_id")

        if not sufficient_logging:
            self.findings.append({
                "line_number": access_node.lineno,
                "violation_type": "Incomplete Audit Log",
                "description": f"Audit log near ePHI access missing required fields: {', '.join(missing_fields)}.",
                "remediation_suggestion": "Ensure log message includes user_id, action type, and resource/record ID.",
                "severity": "High"
            })

    def _parse_log_call_fields(self, node: ast.Call) -> Set[str]:
        """
        Extract potential field names from a logging call.
        """
        found_fields = set()

        # Check keyword arguments
        for keyword in node.keywords:
            if keyword.arg:
                found_fields.add(keyword.arg.lower())

            # Check for 'extra' dict in standard python logging
            if keyword.arg == 'extra' and isinstance(keyword.value, ast.Dict):
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        found_fields.add(key.value.lower())

        # Check string arguments for keywords
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                text = arg.value.lower()
                for field in REQUIRED_LOG_FIELDS:
                    if field in text:
                        found_fields.add(field)

        return found_fields

    def _check_retention_config(self, node: ast.Assign) -> None:
        """
        Check assignments for retention policy configurations (>= 6 years).
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                if "retention" in name and ("days" in name or "period" in name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                        days = node.value.value
                        if days >= 2190:
                            self.has_retention_config = True
                        else:
                            self.findings.append({
                                "line_number": node.lineno,
                                "violation_type": "Insufficient Log Retention",
                                "description": f"Log retention configured for {days} days. HIPAA requires 6 years (approx 2190 days).",
                                "remediation_suggestion": "Update retention configuration to at least 2190 days.",
                                "severity": "High"
                            })

    def _check_configuration_patterns(self, node: ast.Call) -> None:
        """
        Check function calls for tamper-proofing and anomaly detection patterns.
        """
        func_name = self._get_func_name(node)
        if not func_name:
            return

        lower_name = func_name.lower()

        # Tamper-proofing: Append-only modes
        if "open" in lower_name:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and arg.value == 'a':
                    self.has_tamper_proof_config = True
            for kw in node.keywords:
                if kw.arg == 'mode' and isinstance(kw.value, ast.Constant) and kw.value.value == 'a':
                    self.has_tamper_proof_config = True

        if "sign" in lower_name and "log" in lower_name:
            self.has_tamper_proof_config = True

        if any(k in lower_name for k in ["immutable", "worm"]):
            self.has_tamper_proof_config = True

        # Anomaly Detection
        siem_tools = {"splunk", "elastic", "datadog", "newrelic", "pagerduty", "alert", "siem"}
        if any(tool in lower_name for tool in siem_tools):
            self.has_anomaly_detection = True

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """Helper to get the full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return None


def check_audit_logging(code_path: str) -> Dict[str, Any]:
    """
    Analyze a Python file for HIPAA § 164.312(b) audit logging compliance.
    """
    if not os.path.exists(code_path):
        return {
            "findings": [{"violation_type": "File Error", "description": "File not found", "severity": "Critical"}],
            "compliant": False,
            "severity": "Critical",
            "regulation_reference": REGULATION_REFERENCE
        }

    try:
        with open(code_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {
            "findings": [{"violation_type": "Syntax Error", "description": str(e), "severity": "Critical"}],
            "compliant": False,
            "severity": "Critical",
            "regulation_reference": REGULATION_REFERENCE
        }
    except Exception as e:
        return {
            "findings": [{"violation_type": "Analysis Error", "description": str(e), "severity": "Critical"}],
            "compliant": False,
            "severity": "Critical",
            "regulation_reference": REGULATION_REFERENCE
        }

    visitor = AuditLoggingVisitor()
    visitor.visit(tree)

    if not visitor.has_retention_config:
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "Missing Retention Policy",
            "description": "No log retention policy (>= 6 years) detected in this module.",
            "remediation_suggestion": "Ensure a retention policy of 2190 days is configured.",
            "severity": "Medium"
        })

    if not visitor.has_tamper_proof_config:
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "Missing Tamper-Proofing",
            "description": "No tamper-proof logging mechanisms detected.",
            "remediation_suggestion": "Configure logs to write to append-only files or immutable storage.",
            "severity": "Medium"
        })

    if not visitor.has_anomaly_detection:
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "Missing Anomaly Detection",
            "description": "No integration with anomaly detection or alerting systems detected.",
            "remediation_suggestion": "Integrate with SIEM or configure alerts for unusual access patterns.",
            "severity": "Medium"
        })

    severities = [f["severity"] for f in visitor.findings]
    if "Critical" in severities:
        overall_severity = "Critical"
    elif "High" in severities:
        overall_severity = "High"
    elif "Medium" in severities:
        overall_severity = "Medium"
    elif "Low" in severities:
        overall_severity = "Low"
    else:
        overall_severity = "Pass"

    return {
        "findings": visitor.findings,
        "compliant": len(visitor.findings) == 0,
        "severity": overall_severity,
        "regulation_reference": REGULATION_REFERENCE
    }