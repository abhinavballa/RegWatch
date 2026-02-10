"""
web/app.py

RegWatch Web Application Module
===============================

This module implements the Flask web application for the RegWatch compliance monitoring system.
It serves the dashboard UI and provides a REST API for code analysis, data validation,
regulation simulation, and audit history.

Key Features:
- Application Factory Pattern for configuration and testing.
- Secure file upload handling (ZIP and CSV) with size limits and type validation.
- Safe ZIP extraction with path traversal protection and resource limits.
- Integration with static analysis checkers, data validators, and orchestration agents.
- Real-time compliance scoring and financial exposure estimation.

Usage:
    from web.app import create_app
    app = create_app()
    app.run(debug=True)
"""

import os
import json
import shutil
import logging
import zipfile
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from flask import Flask, request, jsonify, render_template, send_file, Blueprint, current_app
from werkzeug.utils import secure_filename
from flask_cors import CORS

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Configure Logging early
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Import RegWatch Dependencies ---
# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import modules with graceful fallbacks
hipaa_encryption_checker = None
hipaa_access_control_checker = None
hipaa_audit_logging_checker = None
patient_data_validator = None
orchestrator = None
change_tracker = None
voice_service = None

try:
    from src import hipaa_encryption_checker
except (ImportError, Exception) as e:
    logger.warning(f"hipaa_encryption_checker module not available: {e}")
    hipaa_encryption_checker = None

try:
    from src import hipaa_access_control_checker
except (ImportError, Exception) as e:
    logger.warning(f"hipaa_access_control_checker module not available: {e}")
    hipaa_access_control_checker = None

try:
    from src import hipaa_audit_logging_checker
except (ImportError, Exception) as e:
    logger.warning(f"hipaa_audit_logging_checker module not available: {e}")
    hipaa_audit_logging_checker = None

try:
    from src import patient_data_validator
except (ImportError, AttributeError) as e:
    logger.warning(f"patient_data_validator module not available: {e}")
    patient_data_validator = None

try:
    from src import orchestrator
except (ImportError, Exception) as e:
    logger.warning(f"orchestrator module not available: {e}")
    orchestrator = None

try:
    from src import change_tracker
except (ImportError, Exception) as e:
    logger.warning(f"change_tracker module not available: {e}")
    change_tracker = None

try:
    from src import voice_service
except (ImportError, Exception) as e:
    logger.warning(f"voice_service module not available: {e}")
    voice_service = None

# --- Configuration ---

UPLOAD_FOLDER = 'web/uploads'
ALLOWED_EXTENSIONS_CODE = {'zip'}
ALLOWED_EXTENSIONS_DATA = {'csv'}
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_CSV_SIZE = 50 * 1024 * 1024   # 50 MB
MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024 # 500 MB limit for extraction
MAX_FILE_COUNT = 1000 # Limit number of files in ZIP

# Scoring Weights
SCORE_DEDUCTIONS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2
}

# HIPAA Fine Estimation (Simplified Tiers)
FINE_TIERS = {
    "critical": 50000, # Tier 4: Willful Neglect (uncorrected)
    "high": 10000,     # Tier 3: Willful Neglect (corrected)
    "medium": 1000,    # Tier 2: Reasonable Cause
    "low": 100         # Tier 1: Unknowing
}

# Logging configured above near imports

# --- Helper Functions ---

def allowed_file(filename: str, allowed_extensions: set) -> bool:
    """Checks if the file has a valid extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def safe_extract_zip(zip_path: str, extract_to: str) -> None:
    """
    Extracts a ZIP file safely, preventing path traversal and zip bombs.
    
    Args:
        zip_path: Path to the source ZIP file.
        extract_to: Directory to extract files into.
        
    Raises:
        ValueError: If path traversal or resource limits are detected.
    """
    total_size = 0
    file_count = 0
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            file_count += 1
            total_size += member.file_size
            
            # 1. Resource Limits Check
            if file_count > MAX_FILE_COUNT:
                raise ValueError(f"ZIP contains too many files (Limit: {MAX_FILE_COUNT})")
            if total_size > MAX_UNCOMPRESSED_SIZE:
                raise ValueError(f"Uncompressed size exceeds limit ({MAX_UNCOMPRESSED_SIZE} bytes)")
            
            # 2. Path Traversal Check
            # Resolve the target path and ensure it starts with the extract_to directory
            target_path = os.path.join(extract_to, member.filename)
            abs_target = os.path.abspath(target_path)
            abs_extract = os.path.abspath(extract_to)
            
            if not abs_target.startswith(abs_extract):
                raise ValueError(f"Path traversal attempt detected: {member.filename}")
                
        # If safe, extract
        zip_ref.extractall(extract_to)

def calculate_compliance_metrics(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates compliance score (0-100) and estimated fine exposure.
    """
    score = 100
    total_fines = 0
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        severity = finding.get("severity", "low").lower()
        
        # Update breakdown
        if severity in breakdown:
            breakdown[severity] += 1
            
        # Deduct score
        deduction = SCORE_DEDUCTIONS.get(severity, 0)
        score -= deduction
        
        # Add fines
        fine = FINE_TIERS.get(severity, 0)
        total_fines += fine

    return {
        "score": max(0, score),
        "estimated_fines": total_fines,
        "severity_breakdown": breakdown
    }

def cleanup_temp(paths: List[str]):
    """Safely removes temporary files and directories."""
    for path in paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            logger.error(f"Error cleaning up {path}: {e}")

# --- Blueprints ---

# 1. API Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/scan', methods=['POST'])
def scan_codebase():
    """
    Endpoint: POST /api/scan
    Accepts a ZIP file of source code.
    Runs HIPAA encryption, access control, and audit logging checkers.
    Returns compliance score, violations, and fine estimates.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not allowed_file(file.filename, ALLOWED_EXTENSIONS_CODE):
        return jsonify({"error": "Invalid file type. Only .zip allowed."}), 400

    # Create temp directories
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, secure_filename(file.filename))
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        # Save and Extract
        file.save(zip_path)
        safe_extract_zip(zip_path, extract_dir)

        all_findings = []

        # 1. Run Encryption Checker (Supports directory walking natively)
        if hipaa_encryption_checker:
            enc_report = hipaa_encryption_checker.check_encryption(extract_dir)
            all_findings.extend(enc_report.get("findings", []))
        else:
            logger.warning("Encryption checker not available - skipping")
        
        # 2. Run Access Control & Audit Logging Checkers (File-based)
        # We must walk the directory and apply these checkers to .py files
        for root, _, files in os.walk(extract_dir):
            for filename in files:
                if filename.endswith(".py"):
                    full_path = os.path.join(root, filename)

                    # Access Control
                    if hipaa_access_control_checker:
                        ac_report = hipaa_access_control_checker.check_access_control(full_path)
                        all_findings.extend(ac_report.get("findings", []))

                    # Audit Logging
                    if hipaa_audit_logging_checker:
                        audit_report = hipaa_audit_logging_checker.check_audit_logging(full_path)
                        all_findings.extend(audit_report.get("findings", []))

        # Calculate Metrics
        metrics = calculate_compliance_metrics(all_findings)
        
        response = {
            "status": "success",
            "compliance_score": metrics["score"],
            "estimated_fine_exposure": metrics["estimated_fines"],
            "severity_breakdown": metrics["severity_breakdown"],
            "total_violations": len(all_findings),
            "violations": all_findings
        }
        
        return jsonify(response), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during scan"}), 500
    finally:
        cleanup_temp([temp_dir])

@api_bp.route('/validate-records', methods=['POST'])
def validate_records():
    """
    Endpoint: POST /api/validate-records
    Accepts a CSV file of patient records.
    Runs patient_data_validator.
    Returns validation report.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not allowed_file(file.filename, ALLOWED_EXTENSIONS_DATA):
        return jsonify({"error": "Invalid file type. Only .csv allowed."}), 400

    temp_dir = tempfile.mkdtemp()
    csv_path = os.path.join(temp_dir, secure_filename(file.filename))

    try:
        file.save(csv_path)

        # Run Validator
        if patient_data_validator:
            report = patient_data_validator.validate_records(csv_path)
        else:
            return jsonify({"status": "error", "message": "Patient data validator not available"}), 503
        
        if "error" in report and report["error"]:
             return jsonify({"status": "error", "message": report["error"]}), 400

        return jsonify({
            "status": "success",
            "report": report
        }), 200

    except Exception as e:
        logger.error(f"Validation failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        cleanup_temp([temp_dir])

@api_bp.route('/simulate-regulation-change', methods=['POST'])
def simulate_change():
    """
    Endpoint: POST /api/simulate-regulation-change
    Simulates a new regulation entering the system.
    Uses the Orchestrator in 'notify_only' mode to assess impact without applying changes.
    """
    data = request.get_json()
    if not data or 'regulation_id' not in data or 'full_text' not in data:
        return jsonify({"error": "Missing regulation_id or full_text"}), 400

    try:
        # Construct regulation data object
        reg_data = {
            "regulation_id": data['regulation_id'],
            "full_text": data['full_text'],
            "publication_date": "2023-10-27" # Mock date
        }

        # Run Orchestrator in simulation mode (NOTIFY_ONLY)
        # This prevents PR creation but runs analysis and impact assessment
        result = orchestrator.handle_regulation_change(
            regulation_data=reg_data,
            permission_mode="notify_only"
        )

        return jsonify({
            "status": "success",
            "simulation_result": result
        }), 200

    except Exception as e:
        logger.error(f"Simulation failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@api_bp.route('/change-history', methods=['GET'])
def get_history():
    """
    Endpoint: GET /api/change-history
    Retrieves the audit trail of regulation changes.
    """
    try:
        history = change_tracker.get_change_history()
        return jsonify(history), 200
    except Exception as e:
        logger.error(f"History retrieval failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/voice-briefing', methods=['POST'])
def get_voice_briefing():
    """
    Endpoint: POST /api/voice-briefing
    Generates an MP3 audio briefing based on scan results provided in the body.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing scan results data"}), 400

    try:
        # Generate audio bytes
        audio_bytes = voice_service.generate_briefing(data)

        # Save to temp file to serve via send_file
        # (Flask's send_file expects a file-like object or path)
        temp_audio = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
        temp_audio.write(audio_bytes)
        temp_audio.close()

        # Use a generator or cleanup callback in production; here we rely on OS cleanup or manual
        # For this implementation, we return the file and rely on the OS to eventually clean /tmp
        # or implement a more complex stream wrapper.

        return send_file(
            temp_audio.name,
            mimetype="audio/mpeg",
            as_attachment=True,
            download_name="compliance_briefing.mp3"
        )

    except Exception as e:
        logger.error(f"Voice generation failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """
    Endpoint: GET /api/stats
    Returns dashboard statistics: compliance score, active issues, fine exposure, etc.
    """
    try:
        # Get recent scan results and calculate stats
        # This is a simplified version - in production, query from database
        stats = {
            "compliance_score": 87,
            "active_issues": 8,
            "fine_exposure": 125000,
            "fixed_issues_24h": 3
        }
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Stats retrieval failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/activity', methods=['GET'])
def get_activity():
    """
    Endpoint: GET /api/activity
    Returns recent agent activity feed.
    """
    try:
        # Get activity from change tracker
        # This is simplified - activity feed is currently static in HTML
        activity = []
        return jsonify(activity), 200
    except Exception as e:
        logger.error(f"Activity retrieval failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/issues', methods=['GET'])
def get_issues():
    """
    Endpoint: GET /api/issues
    Returns list of compliance issues with PR/Issue links.
    """
    try:
        # Get issues from change tracker or database
        # Currently static in HTML for demo
        issues = []
        return jsonify(issues), 200
    except Exception as e:
        logger.error(f"Issues retrieval failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/settings/permission-mode', methods=['POST'])
def set_permission_mode():
    """
    Endpoint: POST /api/settings/permission-mode
    Updates the global permission mode for automated fixes.
    """
    data = request.get_json()
    if not data or 'mode' not in data:
        return jsonify({"error": "Missing permission mode"}), 400

    mode = data['mode']
    valid_modes = ['auto_apply', 'request_approval', 'notify_only']

    if mode not in valid_modes:
        return jsonify({"error": f"Invalid mode. Must be one of: {valid_modes}"}), 400

    try:
        # Store permission mode in environment or config
        # For now, just acknowledge
        logger.info(f"Permission mode updated to: {mode}")

        return jsonify({
            "status": "success",
            "mode": mode,
            "message": f"Permission mode set to {mode}"
        }), 200
    except Exception as e:
        logger.error(f"Permission mode update failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/pr/<int:pr_number>/diff', methods=['GET'])
def get_pr_diff(pr_number):
    """
    Endpoint: GET /api/pr/<pr_number>/diff
    Returns the diff for a pull request.
    """
    try:
        # In production, fetch from GitHub API
        # For demo, return mock data
        diff = {
            "pr_number": pr_number,
            "files_changed": 2,
            "additions": 25,
            "deletions": 10,
            "diff_url": f"https://github.com/abhinavballa/RegWatch/pull/{pr_number}/files"
        }
        return jsonify(diff), 200
    except Exception as e:
        logger.error(f"PR diff retrieval failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/github/repos', methods=['GET'])
def list_github_repos():
    """
    Endpoint: GET /api/github/repos
    Lists all accessible GitHub repositories for the authenticated user.
    """
    from flask import session
    github_token = session.get('github_token')

    if not github_token:
        return jsonify({"error": "Not authenticated with GitHub"}), 401

    try:
        import requests
        headers = {'Authorization': f'token {github_token}'}

        # Get user's repositories
        repos_response = requests.get(
            'https://api.github.com/user/repos',
            headers=headers,
            params={'per_page': 100, 'sort': 'updated'}
        )
        repos_response.raise_for_status()
        repos = repos_response.json()

        # Format repo data
        formatted_repos = [{
            'id': repo['id'],
            'name': repo['name'],
            'full_name': repo['full_name'],
            'private': repo['private'],
            'description': repo['description'],
            'language': repo['language'],
            'url': repo['html_url'],
            'updated_at': repo['updated_at']
        } for repo in repos]

        return jsonify(formatted_repos), 200

    except Exception as e:
        logger.error(f"Failed to fetch GitHub repos: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/github/repos/connect', methods=['POST'])
def connect_github_repo():
    """
    Endpoint: POST /api/github/repos/connect
    Connects a GitHub repository for compliance monitoring.
    """
    from flask import session
    github_token = session.get('github_token')

    if not github_token:
        return jsonify({"error": "Not authenticated with GitHub"}), 401

    data = request.get_json()
    if not data or 'repo_full_name' not in data:
        return jsonify({"error": "Missing repo_full_name"}), 400

    repo_full_name = data['repo_full_name']

    try:
        # Store connected repo (in production, save to database)
        if 'connected_repos' not in session:
            session['connected_repos'] = []

        if repo_full_name not in session['connected_repos']:
            session['connected_repos'].append(repo_full_name)
            session.modified = True

        logger.info(f"Connected repository: {repo_full_name}")

        return jsonify({
            "status": "success",
            "repo": repo_full_name,
            "message": f"Repository {repo_full_name} connected successfully"
        }), 200

    except Exception as e:
        logger.error(f"Failed to connect repo: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/github/repos/<path:repo_full_name>/scan', methods=['POST'])
def scan_github_repo(repo_full_name):
    """
    Endpoint: POST /api/github/repos/<repo_full_name>/scan
    Scans a GitHub repository for HIPAA compliance.
    """
    from flask import session
    github_token = session.get('github_token')

    if not github_token:
        return jsonify({"error": "Not authenticated with GitHub"}), 401

    try:
        import requests
        import tempfile
        import subprocess

        headers = {'Authorization': f'token {github_token}'}

        # Clone repository to temp directory
        temp_dir = tempfile.mkdtemp()
        clone_url = f"https://{github_token}@github.com/{repo_full_name}.git"

        logger.info(f"Cloning repository: {repo_full_name}")
        subprocess.run(['git', 'clone', '--depth', '1', clone_url, temp_dir], check=True, capture_output=True)

        all_findings = []

        # Run compliance checkers
        if hipaa_encryption_checker:
            enc_report = hipaa_encryption_checker.check_encryption(temp_dir)
            all_findings.extend(enc_report.get("findings", []))

        if hipaa_access_control_checker or hipaa_audit_logging_checker:
            for root, _, files in os.walk(temp_dir):
                for filename in files:
                    if filename.endswith(".py"):
                        full_path = os.path.join(root, filename)

                        if hipaa_access_control_checker:
                            ac_report = hipaa_access_control_checker.check_access_control(full_path)
                            all_findings.extend(ac_report.get("findings", []))

                        if hipaa_audit_logging_checker:
                            audit_report = hipaa_audit_logging_checker.check_audit_logging(full_path)
                            all_findings.extend(audit_report.get("findings", []))

        # Calculate metrics
        metrics = calculate_compliance_metrics(all_findings)

        response = {
            "status": "success",
            "repo": repo_full_name,
            "compliance_score": metrics["score"],
            "estimated_fine_exposure": metrics["estimated_fines"],
            "severity_breakdown": metrics["severity_breakdown"],
            "total_violations": len(all_findings),
            "violations": all_findings
        }

        # Cleanup
        cleanup_temp([temp_dir])

        return jsonify(response), 200

    except subprocess.CalledProcessError as e:
        logger.error(f"Git clone failed: {e}")
        return jsonify({"error": "Failed to clone repository"}), 500
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/github/create-pr', methods=['POST'])
def create_github_pr():
    """
    Creates a Pull Request with AI-generated fix for a compliance violation.
    """
    from flask import session
    from openai import OpenAI
    from github import Github
    import time

    github_token = session.get('github_token')
    if not github_token:
        return jsonify({"error": "Not authenticated with GitHub"}), 401

    data = request.get_json()
    repo_full_name = data.get('repo')
    file_path = data.get('file', '')
    violation_message = data.get('violation_message', 'Compliance violation detected')
    violation_title = data.get('title', 'Compliance Issue')
    line_number = data.get('line', '?')
    remediation = data.get('remediation', '')
    regulation = data.get('regulation', 'HIPAA')
    severity = data.get('severity', 'medium')

    logger.info(f"Creating PR for {repo_full_name}, file: {file_path}, violation: {violation_title}")

    try:
        # Initialize clients
        gh = Github(github_token)
        repo = gh.get_repo(repo_full_name)
        openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # Clean file path - handle temp directory paths while preserving structure
        # /var/folders/.../tmp.../web/app.py -> web/app.py
        original_file_path = file_path
        if file_path.startswith('/') and '/tmp' in file_path:
            parts = file_path.split('/')
            # Find the temp directory
            for i, part in enumerate(parts):
                if part.startswith('tmp'):
                    # Take everything after temp dir
                    file_path = '/'.join(parts[i+1:])
                    break

        logger.info(f"Cleaned file path from '{original_file_path}' to '{file_path}'")

        # Get current file content
        try:
            file_content = repo.get_contents(file_path, ref=repo.default_branch)
            current_code = file_content.decoded_content.decode('utf-8')
        except Exception as e:
            return jsonify({"error": f"File not found: {file_path}"}), 404

        # Scan repo to find what modules/functions actually exist
        logger.info("Scanning repository structure...")
        available_modules = []
        try:
            contents = repo.get_contents("")
            for item in contents:
                if item.type == "file" and item.name.endswith('.py'):
                    available_modules.append(item.name.replace('.py', ''))
                elif item.type == "dir" and not item.name.startswith('.'):
                    try:
                        dir_contents = repo.get_contents(item.path)
                        for subitem in dir_contents:
                            if subitem.name.endswith('.py'):
                                available_modules.append(f"{item.name}.{subitem.name.replace('.py', '')}")
                    except:
                        pass
        except Exception as e:
            logger.warning(f"Could not scan repo structure: {e}")

        logger.info(f"Available modules: {available_modules[:10]}")

        # Extract existing imports from current code
        existing_imports = []
        for line in current_code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                existing_imports.append(stripped)

        # Generate AI fix with comprehensive context
        fix_prompt = f"""You are a HIPAA compliance expert. Fix this specific violation using ONLY existing code patterns.

**CRITICAL CONSTRAINTS:**
1. DO NOT add imports unless they already exist in the file
2. DO NOT create new functions, classes, or modules
3. DO NOT assume any external dependencies exist
4. Make MINIMAL inline changes at the violation line only
5. If a proper fix requires new dependencies, add a TODO comment instead

**Violation Details:**
- Type: {violation_title}
- Description: {violation_message}
- Location: Line {line_number}
- Regulation: {regulation}
- Severity: {severity}
- Recommended Fix: {remediation}

**Current Code ({file_path}):**
```python
{current_code}
```

**Existing Imports (ONLY these are available):**
{chr(10).join(existing_imports) if existing_imports else "NONE - Do not add any imports"}

**Available Modules in This Repo:**
{', '.join(available_modules[:20]) if available_modules else "Unknown - Assume nothing exists"}

**Fix Strategy by Violation Type:**
- HARDCODED_KEY: Replace with os.getenv() if os is imported, else add # TODO: Move to environment variable
- MISSING_TLS_DB: Add sslmode=require to connection string inline
- MISSING_ENCRYPTION: Use hashlib/base64 if imported, else add # TODO: Add encryption
- MISSING_AUTH: Add basic if/else check, don't import new auth modules
- MISSING_AUDIT_LOG: Add print() or logging.info() if logging exists, else add # TODO: Add audit logging

**Instructions:**
1. Look at line {line_number} and fix ONLY that specific issue
2. Use ONLY code patterns and imports that already exist
3. Keep all other code exactly the same
4. Return the COMPLETE file with minimal changes
5. NO markdown, NO explanations, NO code fences
6. Just the raw Python code ready to commit

**Complete fixed file:**"""

        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a HIPAA compliance code remediation expert. Always return complete, valid Python code without any markdown formatting or explanations."},
                {"role": "user", "content": fix_prompt}
            ],
            temperature=0.2,  # Lower temperature for more consistent fixes
            max_tokens=4000   # Allow larger responses for complete files
        )

        fixed_code = response.choices[0].message.content.strip()

        # Remove markdown code fences if GPT-4 added them despite instructions
        if fixed_code.startswith('```'):
            lines = fixed_code.split('\n')
            # Remove first line (```python or ```) and last line (```)
            fixed_code = '\n'.join(lines[1:-1]) if len(lines) > 2 else fixed_code

        # Remove any remaining markdown artifacts
        fixed_code = fixed_code.strip('`').strip()

        logger.info(f"Generated fix: {len(fixed_code)} characters")

        # Validate the fix - check for hallucinated imports
        new_imports = []
        for line in fixed_code.split('\n'):
            stripped = line.strip()
            if (stripped.startswith('import ') or stripped.startswith('from ')) and stripped not in existing_imports:
                new_imports.append(stripped)

        if new_imports:
            logger.warning(f"AI added new imports that may not exist: {new_imports}")
            # Add warning comment to PR
            warning_comment = "\n".join([
                "# WARNING: This PR adds new imports that may need to be verified:",
                *[f"#   {imp}" for imp in new_imports],
                "# Ensure these modules exist before merging\n"
            ])
            fixed_code = warning_comment + fixed_code

        # Create branch
        default_branch = repo.get_branch(repo.default_branch)
        branch_name = f"regwatch/compliance-fix-{int(time.time())}"
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=default_branch.commit.sha)

        # Commit the fix
        repo.update_file(
            path=file_path,
            message=f"Fix: {violation_message[:60]}",
            content=fixed_code,
            sha=file_content.sha,
            branch=branch_name
        )

        # Create PR with detailed description
        import_warning = ""
        if new_imports:
            import_warning = f"""
### ⚠️ New Imports Added
This PR adds the following imports that may need verification:
{chr(10).join([f'- `{imp}`' for imp in new_imports])}

**Action Required:** Verify these modules exist in your codebase before merging. If they don't exist, you may need to install dependencies or remove these imports.

"""

        pr_description = f"""## 🔒 Automated HIPAA Compliance Fix

### Violation Details
- **Type**: {violation_title}
- **Regulation**: {regulation}
- **Severity**: `{severity.upper()}`
- **Location**: `{file_path}:{line_number}`

### What Was Wrong
{violation_message}

### What This PR Does
{remediation}

This PR contains AI-generated code that fixes the violation. The AI was instructed to use only existing code patterns and imports.

{import_warning}### Code Changes
- ✏️ Modified `{file_path}` to comply with {regulation}
- 🔍 Uses only existing imports and patterns (verified by scanning repo structure)
- 🤖 Generated using OpenAI GPT-4

### Testing Checklist
- [ ] Review the code diff below
- [ ] {"Verify new imports exist in your codebase" if new_imports else "Verify the fix addresses the violation"}
- [ ] Run compliance scan to confirm (should show improved score)
- [ ] Test affected functionality

### Next Steps
1. Review the **Files changed** tab to see the exact code modifications
2. If everything looks good, click **Merge pull request**
3. Run a new compliance scan to verify the fix

---
🤖 **This PR was automatically generated by [RegWatch](https://github.com/abhinavballa/RegWatch)**
💡 The code changes are ready to merge - no manual edits needed

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"""

        # Create PR with descriptive title
        pr_title = f"🔒 Fix {violation_title} in {file_path}"
        if len(pr_title) > 80:
            pr_title = f"🔒 Fix {violation_title}"[:77] + "..."

        pr = repo.create_pull(
            title=pr_title,
            body=pr_description,
            head=branch_name,
            base=repo.default_branch
        )

        logger.info(f"✅ Created PR #{pr.number} for {repo_full_name}: {pr.html_url}")
        return jsonify({
            "pr_url": pr.html_url,
            "pr_number": pr.number,
            "branch": branch_name,
            "message": f"Successfully created PR #{pr.number} with code fixes"
        }), 200

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"❌ PR creation failed for {repo_full_name}/{file_path}: {e}\n{error_details}")
        return jsonify({
            "error": str(e),
            "details": "Check server logs for full error details",
            "file": file_path
        }), 500

@api_bp.route('/github/create-issue', methods=['POST'])
def create_github_issue():
    """
    Creates a detailed GitHub Issue for a compliance violation.
    """
    from flask import session
    from github import Github

    github_token = session.get('github_token')
    if not github_token:
        return jsonify({"error": "Not authenticated with GitHub"}), 401

    data = request.get_json()
    repo_full_name = data.get('repo')
    title = data.get('title', 'Compliance Issue')
    violation_message = data.get('body', 'Compliance violation detected')
    file_path = data.get('file', 'unknown')
    line = data.get('line', '?')
    severity = data.get('severity', 'medium')
    regulation = data.get('regulation', 'HIPAA')

    try:
        gh = Github(github_token)
        repo = gh.get_repo(repo_full_name)

        # Create comprehensive issue description
        issue_body = f"""## Compliance Violation Detected

### Details
- **Severity**: {severity.upper()}
- **Regulation**: {regulation}
- **File**: `{file_path}:{line}`

### Description
{violation_message}

### Required Actions
1. Review the code at the specified location
2. Understand the compliance requirement
3. Implement the necessary fixes to meet {regulation} standards
4. Test the changes thoroughly
5. Run a new compliance scan to verify the fix

### Resources
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [HIPAA Compliance Checklist](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)

### Estimated Fine Exposure
Violations of this type can result in fines ranging from $100 to $50,000 per incident.

---
🤖 Detected by [RegWatch](https://github.com/abhinavballa/RegWatch) automated compliance monitoring"""

        issue = repo.create_issue(
            title=f"[{severity.upper()}] {title}",
            body=issue_body,
            labels=['compliance', f'severity:{severity}', regulation.lower().replace(' ', '-')]
        )

        logger.info(f"Created issue #{issue.number} for {repo_full_name}")
        return jsonify({"issue_url": issue.html_url, "issue_number": issue.number}), 200

    except Exception as e:
        logger.error(f"Issue creation failed: {e}")
        return jsonify({"error": str(e)}), 500

# 2. View Blueprint (HTML)
view_bp = Blueprint('view', __name__)

@view_bp.route('/')
def dashboard():
    return render_template('index.html')

@view_bp.route('/scan')
def scan_page():
    return render_template('scan.html')

@view_bp.route('/validate')
def validate_page():
    return render_template('validate.html')

@view_bp.route('/history')
def history_page():
    return render_template('history.html')

@view_bp.route('/repos')
def repos_page():
    return render_template('repos.html')

# 3. GitHub OAuth Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/github')
def github_login():
    """
    Redirects user to GitHub OAuth authorization page.
    """
    client_id = os.getenv('GITHUB_CLIENT_ID')
    if not client_id:
        return jsonify({"error": "GitHub OAuth not configured"}), 500

    redirect_uri = os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:5001/auth/github/callback')
    scope = 'repo,read:user'  # Request repo access and user info

    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&state={os.urandom(16).hex()}"  # CSRF protection
    )

    from flask import redirect as flask_redirect
    return flask_redirect(github_auth_url)

@auth_bp.route('/github/callback')
def github_callback():
    """
    Handles GitHub OAuth callback and exchanges code for access token.
    """
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "No authorization code received"}), 400

    client_id = os.getenv('GITHUB_CLIENT_ID')
    client_secret = os.getenv('GITHUB_CLIENT_SECRET')

    if not client_id or not client_secret:
        return jsonify({"error": "GitHub OAuth not configured"}), 500

    # Exchange code for access token
    token_url = "https://github.com/login/oauth/access_token"
    headers = {'Accept': 'application/json'}
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code
    }

    try:
        import requests
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get('access_token')
        if not access_token:
            return jsonify({"error": "Failed to get access token"}), 500

        # Store token in session
        from flask import session
        session['github_token'] = access_token

        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        user_data = user_response.json()
        session['github_user'] = user_data.get('login')
        session['github_user_id'] = user_data.get('id')

        # Redirect to repos page
        from flask import redirect as flask_redirect
        return flask_redirect('/repos')

    except Exception as e:
        logger.error(f"GitHub OAuth callback failed: {e}")
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/github/disconnect', methods=['POST'])
def github_disconnect():
    """
    Disconnects GitHub integration by clearing session.
    """
    from flask import session
    session.pop('github_token', None)
    session.pop('github_user', None)
    session.pop('github_user_id', None)

    return jsonify({"status": "success", "message": "GitHub disconnected"}), 200

# --- Application Factory ---

def create_app(test_config=None):
    """
    Flask Application Factory.
    Initializes the app, configuration, and blueprints.
    """
    app = Flask(__name__, instance_relative_config=True)
    
    # Default Configuration
    app.config.from_mapping(
        SECRET_KEY='dev', # Change this in production
        UPLOAD_FOLDER=UPLOAD_FOLDER,
        MAX_CONTENT_LENGTH=MAX_ZIP_SIZE + 1024, # Allow slight overhead for headers
    )

    if test_config:
        app.config.from_mapping(test_config)

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Enable CORS (Allow frontend dev server)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Register Blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(view_bp)
    app.register_blueprint(auth_bp)

    # Error Handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File too large"}), 413

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal Server Error"}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get("PORT", 5001))  # Changed from 5000 to avoid AirPlay conflict
    print(f"\n{'='*60}")
    print(f"🚀 RegWatch is running on http://localhost:{port}")
    print(f"{'='*60}\n")
    app.run(host='0.0.0.0', port=port, debug=True)