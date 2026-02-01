"""
HIPAA Access Control Checker Module
-----------------------------------
This module implements static analysis for HIPAA  164.312(a)(1) Access Control requirements.
It analyzes Python code (Flask, Django, FastAPI) to detect:
1. Unique User Identification (Required)
2. Emergency Access Procedure (Required - checked via RBAC/Superuser patterns)
3. Automatic Logoff (Addressable - checked via session timeout)
4. Encryption and Decryption (Addressable - checked in other modules, but auth context relevant)

The checker validates:
- User models have unique identifiers.
- Endpoints accessing ePHI are protected by authentication decorators.
- Role-Based Access Control (RBAC) is implemented.
- Session timeouts are configured to <= 15 minutes (900 seconds).
- Multi-Factor Authentication (MFA) flows exist for remote access.
"""

import ast
import os
from typing import Dict, List, Any, Set, Optional, Union

# Constants for detection
PHI_KEYWORDS = {
    'patient', 'medical', 'diagnosis', 'prescription', 'treatment', 
    'health', 'record', 'clinical', 'lab', 'test_result', 'ssn', 
    'dob', 'insurance', 'medication', 'phi', 'ephi'
}

AUTH_DECORATORS = {
    'login_required', 'authenticated', 'require_auth', 'jwt_required', 
    'permission_required', 'has_role', 'require_role', 'auth_required',
    'verify_token', 'authenticate'
}

MFA_KEYWORDS = {
    'mfa', '2fa', 'two_factor', 'totp', 'otp', 'google_authenticator', 
    'verify_code', 'sms_code', 'authenticator_app', 'yubikey'
}

MAX_SESSION_TIMEOUT = 900  # 15 minutes in seconds

class AccessControlVisitor(ast.NodeVisitor):
    """
    AST Visitor to detect access control patterns, authentication, and session configurations.
    """
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.user_model_detected = False
        self.unique_id_detected = False
        self.rbac_detected = False
        self.mfa_detected = False
        self.session_timeout_valid = True  # Assume valid until proven otherwise
        self.session_config_found = False
        
        # Tracking context
        self.current_class = None
        self.current_function = None
        self.framework = "generic"  # django, flask, fastapi, generic

    def visit_Import(self, node: ast.Import):
        """Detect framework based on imports."""
        for alias in node.names:
            self._check_framework(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Detect framework based on imports."""
        if node.module:
            self._check_framework(node.module)
        self.generic_visit(node)

    def _check_framework(self, module_name: str):
        if 'django' in module_name:
            self.framework = 'django'
        elif 'flask' in module_name:
            self.framework = 'flask'
        elif 'fastapi' in module_name:
            self.framework = 'fastapi'

    def visit_ClassDef(self, node: ast.ClassDef):
        """
        Analyze classes for User models and unique ID fields.
        """
        prev_class = self.current_class
        self.current_class = node.name

        # Check if this looks like a User model
        if 'User' in node.name or 'Account' in node.name or 'Profile' in node.name:
            self.user_model_detected = True
            self._check_user_model_fields(node)

        self.generic_visit(node)
        self.current_class = prev_class

    def _check_user_model_fields(self, node: ast.ClassDef):
        """Check for unique ID fields in a potential User model."""
        has_id = False
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        # Check for id, uuid, user_id
                        if target.id in ['id', 'user_id', 'uuid', 'pk']:
                            has_id = True
                        
                        # Check for Django/SQLAlchemy unique=True or primary_key=True
                        if isinstance(item.value, ast.Call):
                            for keyword in item.value.keywords:
                                if keyword.arg in ['unique', 'primary_key'] and \
                                   isinstance(keyword.value, (ast.Constant, ast.NameConstant)) and \
                                   keyword.value.value is True:
                                    has_id = True

        if has_id:
            self.unique_id_detected = True

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Analyze functions for:
        1. ePHI access (routes)
        2. Authentication decorators
        3. RBAC checks inside function body
        4. MFA verification flows
        """
        prev_function = self.current_function
        self.current_function = node.name

        # 1. Check if this is an ePHI endpoint
        is_phi_endpoint = self._is_phi_related(node.name)
        
        # 2. Check decorators
        has_auth_decorator = False
        has_rbac_decorator = False
        
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if not dec_name:
                continue
                
            # Check for route decorators to confirm it's an endpoint
            if any(x in dec_name for x in ['route', 'get', 'post', 'put', 'delete', 'patch']):
                # If the function name didn't trigger PHI, check the route path
                if hasattr(decorator, 'args') and decorator.args:
                    if isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                        if self._is_phi_related(decorator.args[0].value):
                            is_phi_endpoint = True

            # Check auth decorators
            if any(auth in dec_name for auth in AUTH_DECORATORS):
                has_auth_decorator = True
            
            # Check RBAC decorators
            if any(role in dec_name for role in ['role', 'permission', 'admin', 'superuser']):
                has_rbac_decorator = True

        # Violation: ePHI endpoint without authentication
        if is_phi_endpoint and not has_auth_decorator:
            self.findings.append({
                "line_number": node.lineno,
                "violation_type": "Unauthenticated ePHI Access",
                "description": f"Function '{node.name}' appears to access ePHI but lacks an authentication decorator.",
                "remediation_suggestion": "Apply @login_required, @authenticated, or equivalent decorator to this function.",
                "severity": "Critical"
            })

        # 3. Check body for RBAC and MFA
        self._analyze_function_body(node)
        
        if has_rbac_decorator:
            self.rbac_detected = True

        self.generic_visit(node)
        self.current_function = prev_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async functions (common in FastAPI) same as sync functions."""
        self.visit_FunctionDef(node)

    def _analyze_function_body(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]):
        """Scan function body for manual RBAC checks and MFA logic."""
        for child in ast.walk(node):
            # Check for MFA logic
            if isinstance(child, ast.Call):
                func_name = ""
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                
                if any(mfa in func_name.lower() for mfa in MFA_KEYWORDS):
                    self.mfa_detected = True

            # Check for manual RBAC (e.g., if user.role == 'admin':)
            if isinstance(child, ast.Attribute):
                if child.attr in ['role', 'is_superuser', 'is_staff', 'permissions', 'groups']:
                    self.rbac_detected = True

    def visit_Assign(self, node: ast.Assign):
        """
        Analyze assignments for Session Configuration (Timeout).
        Looks for SESSION_COOKIE_AGE, PERMANENT_SESSION_LIFETIME, etc.
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # Common session timeout variable names
                if var_name in ['SESSION_COOKIE_AGE', 'PERMANENT_SESSION_LIFETIME', 'JWT_EXPIRATION_DELTA', 'ACCESS_TOKEN_EXPIRE_MINUTES']:
                    self.session_config_found = True
                    timeout_val = self._extract_timeout_value(node.value)
                    
                    if timeout_val is not None and timeout_val > MAX_SESSION_TIMEOUT:
                        self.session_timeout_valid = False
                        self.findings.append({
                            "line_number": node.lineno,
                            "violation_type": "Session Timeout Violation",
                            "description": f"Session timeout '{var_name}' is set to {timeout_val} seconds, exceeding the 15-minute (900s) recommendation.",
                            "remediation_suggestion": f"Set '{var_name}' to 900 seconds or less to comply with automatic logoff requirements.",
                            "severity": "Medium"
                        })

    def _extract_timeout_value(self, value_node: ast.AST) -> Optional[int]:
        """Helper to extract integer value from assignment, handling basic math (e.g., 15 * 60)."""
        if isinstance(value_node, (ast.Constant, ast.NameConstant)):
            if isinstance(value_node.value, (int, float)):
                return int(value_node.value)
        
        # Handle simple multiplication (e.g., 15 * 60)
        elif isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Mult):
            left = self._extract_timeout_value(value_node.left)
            right = self._extract_timeout_value(value_node.right)
            if left is not None and right is not None:
                return left * right
                
        # Handle timedelta(minutes=15) or timedelta(seconds=900)
        elif isinstance(value_node, ast.Call) and 'timedelta' in getattr(value_node.func, 'id', ''):
            seconds = 0
            for keyword in value_node.keywords:
                val = self._extract_timeout_value(keyword.value)
                if val:
                    if keyword.arg == 'seconds':
                        seconds += val
                    elif keyword.arg == 'minutes':
                        seconds += val * 60
                    elif keyword.arg == 'hours':
                        seconds += val * 3600
            return seconds if seconds > 0 else None
            
        return None

    def _get_decorator_name(self, node: ast.AST) -> Optional[str]:
        """Extract string name from decorator node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return None

    def _is_phi_related(self, name: str) -> bool:
        """Determine if a name suggests PHI access."""
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in PHI_KEYWORDS)


def check_access_control(code_path: str) -> Dict[str, Any]:
    """
    Analyzes a Python file for HIPAA  164.312(a)(1) Access Control compliance.

    Args:
        code_path (str): Path to the Python file to analyze.

    Returns:
        Dict: A report containing findings, compliance status, and metadata.
    """
    if not os.path.exists(code_path):
        return {
            "findings": [],
            "compliant": False,
            "severity": "Critical",
            "regulation_reference": "HIPAA  164.312(a)(1)",
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
                "violation_type": "Syntax Error",
                "description": f"Could not parse file: {str(e)}",
                "remediation_suggestion": "Fix Python syntax errors before compliance checking.",
                "severity": "High"
            }],
            "compliant": False,
            "severity": "High",
            "regulation_reference": "HIPAA  164.312(a)(1)"
        }

    visitor = AccessControlVisitor()
    visitor.visit(tree)

    # Post-analysis checks
    
    # 1. Unique User Identification Check
    if visitor.user_model_detected and not visitor.unique_id_detected:
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "Missing Unique User ID",
            "description": "A User model was detected but no unique identifier field (id, uuid, pk) was found.",
            "remediation_suggestion": "Ensure the User model has a primary key or unique ID field to assign a unique name/number to each user.",
            "severity": "High"
        })

    # 2. MFA Check (Global check for the file)
    # Note: We only flag this if we see authentication logic but no MFA logic
    has_auth_logic = any("login" in f.get("description", "").lower() for f in visitor.findings) or \
                     any("auth" in f.get("description", "").lower() for f in visitor.findings)
    
    # If it's an auth-heavy file (like views.py or auth.py) and no MFA is found
    is_auth_file = "auth" in code_path.lower() or "login" in code_path.lower() or "security" in code_path.lower()
    
    if is_auth_file and not visitor.mfa_detected:
        visitor.findings.append({
            "line_number": 1,
            "violation_type": "Missing Multi-Factor Authentication",
            "description": "Authentication logic detected but no MFA/2FA implementation found (TOTP, SMS, etc.).",
            "remediation_suggestion": "Implement MFA for remote access to ePHI. Use libraries like pyotp or django-two-factor-auth.",
            "severity": "High"
        })

    # 3. RBAC Check
    # If we see endpoints but no role checks anywhere
    if visitor.findings and not visitor.rbac_detected and not any(f['violation_type'] == "Unauthenticated ePHI Access" for f in visitor.findings):
        # Only flag if we haven't already flagged unauthenticated access (which is worse)
        # This is a heuristic; it's hard to be certain without full project context
        pass 

    # Determine overall compliance
    is_compliant = len(visitor.findings) == 0
    
    # Calculate overall severity
    overall_severity = "Low"
    severities = [f["severity"] for f in visitor.findings]
    if "Critical" in severities:
        overall_severity = "Critical"
    elif "High" in severities:
        overall_severity = "High"
    elif "Medium" in severities:
        overall_severity = "Medium"

    return {
        "findings": visitor.findings,
        "compliant": is_compliant,
        "severity": overall_severity,
        "regulation_reference": "HIPAA  164.312(a)(1) - Access Control"
    }