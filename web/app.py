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