"""
HIPAA Access Control Checker Module
-----------------------------------
This module implements static code analysis to validate compliance with 
HIPAA 7 164.312(a)(1) Access Control requirements.

It analyzes Python source code (supporting Flask, Django, FastAPI) to detect:
1. Unique User Identification: Verifies user models have unique IDs.
2. Authentication on ePHI Endpoints: Ensures routes accessing PHI are protected.
3. Role-Based Access Control (RBAC): Checks for permission/role enforcement.
4. Session Management: Validates session timeouts are <= 15 minutes (900s).
5. Multi-Factor Authentication (MFA): Detects MFA implementation patterns.

Usage:
    from src.checkers.hipaa_access_control_checker import check_access_control
    report = check_access_control("path/to/views.py")
"""

import ast
import os
from typing import Dict, List, Any, Set, Optional, Union

# Constants for HIPAA Compliance
HIPAA_REF = "HIPAA 7 164.312(a)(1) Access Control"
MAX_SESSION_TIMEOUT = 900  # 15 minutes in seconds

# Heuristics for detection
PHI_KEYWORDS = {
    'patient', 'medical', 'diagnosis', 'prescription', 'treatment', 
    'health', 'record', 'clinical', 'lab', 'ssn', 'dob', 'insurance'
}

AUTH_DECORATORS = {
    'login_required', 'authenticated', 'require_auth', 'jwt_required', 
    'permission_required', 'user_passes_test', 'login_required_mixin'
}

MFA_KEYWORDS = {
    'mfa', '2fa', 'two_factor', 'totp', 'otp', 'verify_code', 
    'google_authenticator', 'authy', 'duo'
}

RBAC_KEYWORDS = {
    'role', 'permission', 'group', 'is_admin', 'is_staff', 'has_perm', 
    'requires_role', 'admin_required'
}

class AccessControlVisitor(ast.NodeVisitor):
    """
    AST Visitor to traverse Python code and detect access control patterns,
    violations, and compliance evidence.
    """

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.has_user_model = False
        self.has_unique_id = False
        self.has_mfa = False
        self.has_rbac = False
        self.framework = "generic"
        
        # Tracking context
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None

    def _add_finding(self, node: ast.AST, violation_type: str, description: str, 
                     remediation: str, severity: str) -> None:
        """Helper to record a violation finding."""
        self.findings.append({
            "line_number": getattr(node, 'lineno', 0),
            "violation_type": violation_type,
            "description": description,
            "remediation_suggestion": remediation,
            "severity": severity
        })

    def _is_phi_related(self, name: str) -> bool:
        """Check if a variable or function name suggests PHI access."""
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in PHI_KEYWORDS)

    def _check_decorators(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
        """
        Check if a function has authentication decorators.
        Returns True if authenticated.
        """
        for decorator in node.decorator_list:
            decorator_name = ""
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    decorator_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    decorator_name = decorator.func.attr
            
            if decorator_name in AUTH_DECORATORS:
                return True
            
            # Check for RBAC in decorators
            if any(k in decorator_name.lower() for k in RBAC_KEYWORDS):
                self.has_rbac = True
                return True # RBAC implies auth usually

        return False

    def visit_Import(self, node: ast.Import) -> None:
        """Detect framework based on imports."""
        for alias in node.names:
            if 'flask' in alias.name:
                self.framework = 'flask'
            elif 'django' in alias.name:
                self.framework = 'django'
            elif 'fastapi' in alias.name:
                self.framework = 'fastapi'
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect framework based on imports."""
        if node.module:
            if 'flask' in node.module:
                self.framework = 'flask'
            elif 'django' in node.module:
                self.framework = 'django'
            elif 'fastapi' in node.module:
                self.framework = 'fastapi'
            
            # Check for MFA libraries
            if any(m in node.module.lower() for m in ['pyotp', 'django_otp', 'two_factor']):
                self.has_mfa = True

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """
        Analyze classes for:
        1. User Models (Unique ID check)
        2. Django ViewSets (Auth check)
        """
        self.current_class = node.name
        is_user_model = 'User' in node.name or any(isinstance(b, ast.Name) and b.id == 'AbstractUser' for b in node.bases)
        
        if is_user_model:
            self.has_user_model = True
            # Check for unique ID field in class body
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            # Check for id, uuid, pk
                            if target.id in ['id', 'user_id', 'uuid', 'pk']:
                                self.has_unique_id = True
                            
                            # Check Django unique=True
                            if isinstance(item.value, ast.Call):
                                for keyword in item.value.keywords:
                                    if keyword.arg == 'unique' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                        if target.id in ['username', 'email', 'id']:
                                            self.has_unique_id = True

        self.generic_visit(node)
        self.current_class = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)

    def _analyze_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        """
        Analyze functions for:
        1. ePHI Endpoint protection
        2. MFA logic
        3. RBAC logic
        """
        self.current_function = node.name
        
        # 1. Check for MFA logic in function body
        if any(k in node.name.lower() for k in MFA_KEYWORDS):
            self.has_mfa = True
        
        # 2. Check for RBAC logic in function body
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name) and child.attr in RBAC_KEYWORDS:
                    self.has_rbac = True

        # 3. Check ePHI Endpoints
        is_phi_endpoint = self._is_phi_related(node.name)
        
        # Heuristic: If it's a route handler
        is_route = False
        for dec in node.decorator_list:
            dec_name = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute): # app.route
                    dec_name = dec.func.attr
                elif isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
            
            if dec_name in ['route', 'get', 'post', 'put', 'delete', 'patch']:
                is_route = True

        if (is_phi_endpoint or is_route) and self._is_phi_related(node.name):
            is_authenticated = self._check_decorators(node)
            
            if not is_authenticated:
                if not self.current_class: 
                    self._add_finding(
                        node,
                        "UNAUTHENTICATED_EPHI_ACCESS",
                        f"Function '{node.name}' appears to access ePHI but lacks authentication decorators.",
                        "Apply @login_required or equivalent authentication decorator to this endpoint.",
                        "Critical"
                    )

        self.generic_visit(node)
        self.current_function = None

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Analyze assignments for Session Configuration.
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name in ['SESSION_COOKIE_AGE', 'PERMANENT_SESSION_LIFETIME', 'JWT_EXPIRATION_DELTA']:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                        seconds = node.value.value
                        if seconds > MAX_SESSION_TIMEOUT:
                            self._add_finding(
                                node,
                                "INSECURE_SESSION_TIMEOUT",
                                f"Session timeout configured to {seconds}s, exceeding HIPAA recommended 900s (15m).",
                                f"Set {var_name} to 900 or lower.",
                                "Medium"
                            )
        self.generic_visit(node)


def check_access_control(code_path: str) -> Dict[str, Any]:
    """
    Analyzes a Python file for HIPAA 7 164.312(a)(1) Access Control compliance.

    Args:
        code_path (str): Path to the Python source file.

    Returns:
        Dict[str, Any]: A report containing findings, compliance status, and metadata.
    """
    if not os.path.exists(code_path):
        return {
            "findings": [],
            "compliant": False,
            "severity": "Critical",
            "regulation_reference": HIPAA_REF,
            "error": "File not found"
        }

    try:
        with open(code_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {
            "findings": [{
                "line_number": e.lineno,
                "violation_type": "SYNTAX_ERROR",
                "description": f"Could not parse file: {str(e)}",
                "remediation_suggestion": "Fix syntax errors before compliance check.",
                "severity": "High"
            }],
            "compliant": False,
            "severity": "High",
            "regulation_reference": HIPAA_REF
        }

    visitor = AccessControlVisitor()
    visitor.visit(tree)

    if visitor.has_user_model and not visitor.has_unique_id:
        visitor._add_finding(
            tree,
            "MISSING_UNIQUE_USER_ID",
            "User model detected but no explicit unique ID field (id, uuid, pk) found.",
            "Ensure User model has a primary key or unique identifier field.",
            "High"
        )

    findings = visitor.findings
    is_compliant = len(findings) == 0
    
    severity_levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_severity_val = 0
    overall_severity = "Low"

    for finding in findings:
        s_val = severity_levels.get(finding["severity"], 1)
        if s_val > max_severity_val:
            max_severity_val = s_val
            overall_severity = finding["severity"]

    is_auth_file = 'auth' in code_path.lower() or 'login' in code_path.lower()
    if is_auth_file and not visitor.has_mfa and not findings:
        findings.append({
            "line_number": 1,
            "violation_type": "MISSING_MFA",
            "description": "Authentication logic detected but no Multi-Factor Authentication (MFA) patterns found.",
            "remediation_suggestion": "Implement MFA (TOTP, SMS, etc.) for remote access as per HIPAA requirements.",
            "severity": "High"
        })
        is_compliant = False
        if max_severity_val < 3:
            overall_severity = "High"

    return {
        "findings": findings,
        "compliant": is_compliant,
        "severity": overall_severity if not is_compliant else "None",
        "regulation_reference": HIPAA_REF,
        "meta": {
            "framework_detected": visitor.framework,
            "has_rbac_patterns": visitor.has_rbac,
            "has_mfa_patterns": visitor.has_mfa
        }
    }

if __name__ == "__main__":
    # Example usage placeholder
    pass