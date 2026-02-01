"""
RegWatch Impact Agent Module
----------------------------

This module is responsible for assessing the impact of regulation changes on customer codebases.
It utilizes the Toolhouse SDK to execute compliance checkers in isolated environments (sandboxes),
ensuring that customer code is analyzed securely without polluting the main application environment.

The agent performs the following steps:
1. Identifies affected customers and checkers.
2. Orchestrates the execution of checkers via Toolhouse.
3. Aggregates violation data.
4. Calculates Risk Scores, Estimated Fines, and Remediation Effort.
5. Prioritizes customers based on risk exposure.

Usage:
    from src.agents.impact_agent import assess_impact, prioritize_customers

    impact_report = assess_impact(affected_checkers, customer_codebases)
    prioritized_list = prioritize_customers(impact_report)
"""

import os
import json
import logging
from typing import List, Dict, Any

# Toolhouse SDK Import
# Assumes `pip install toolhouse-sdk` is present in the environment
try:
    from toolhouse import Toolhouse
except ImportError:
    # Fallback for development environments where SDK might not be installed
    # In production, this should raise an error.
    logging.warning("Toolhouse SDK not found. Mocking for linting purposes.")
    class Toolhouse:
        def __init__(self, provider=None, access_token=None): pass
        class bundle:
            class code_execution:
                @staticmethod
                def run(code: str, **kwargs): return "Mock Result"

# Configure Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# --- Configuration & Constants ---

# Fine Tiers based on HIPAA Penalty Tiers (Simplified for estimation)
FINE_TIER_4_CRITICAL = 50000  # Per violation
FINE_TIER_3_HIGH = 10000
FINE_TIER_2_MEDIUM = 1000
FINE_TIER_1_LOW = 100

# Remediation Effort (Hours per violation)
EFFORT_CRITICAL = 8
EFFORT_HIGH = 4
EFFORT_MEDIUM = 2
EFFORT_LOW = 1

# Risk Score Multipliers
RISK_MULT_CRITICAL = 10
RISK_MULT_HIGH = 5
RISK_MULT_MEDIUM = 2
RISK_MULT_LOW = 1

# Mapping checker IDs to their source file paths (Assumed project structure)
CHECKER_FILE_MAP = {
    "hipaa_encryption_checker": "src/checkers/hipaa_encryption_checker.py",
    "hipaa_access_control_checker": "src/checkers/hipaa_access_control_checker.py",
    "hipaa_audit_logging_checker": "src/checkers/hipaa_audit_logging_checker.py"
}


# --- Helper Functions ---

def _load_checker_source(checker_id: str) -> str:
    """
    Reads the source code of a compliance checker to inject into the sandbox.
    """
    path = CHECKER_FILE_MAP.get(checker_id)
    if not path or not os.path.exists(path):
        logger.error(f"Checker source not found for ID: {checker_id}")
        raise FileNotFoundError(f"Source code for {checker_id} not found at {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def _calculate_risk_metrics(violations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates risk score, estimated fines, and remediation hours based on violations.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for v in violations:
        severity = v.get("severity", "low").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["low"] += 1 # Default fallback

    # 1. Calculate Risk Score
    risk_score = (
        (counts["critical"] * RISK_MULT_CRITICAL) +
        (counts["high"] * RISK_MULT_HIGH) +
        (counts["medium"] * RISK_MULT_MEDIUM) +
        (counts["low"] * RISK_MULT_LOW)
    )

    # 2. Estimate Fines
    estimated_fine = (
        (counts["critical"] * FINE_TIER_4_CRITICAL) +
        (counts["high"] * FINE_TIER_3_HIGH) +
        (counts["medium"] * FINE_TIER_2_MEDIUM) +
        (counts["low"] * FINE_TIER_1_LOW)
    )

    # 3. Estimate Remediation Effort (Hours)
    remediation_hours = (
        (counts["critical"] * EFFORT_CRITICAL) +
        (counts["high"] * EFFORT_HIGH) +
        (counts["medium"] * EFFORT_MEDIUM) +
        (counts["low"] * EFFORT_LOW)
    )

    return {
        "counts": counts,
        "risk_score": risk_score,
        "estimated_fine": estimated_fine,
        "remediation_hours": remediation_hours
    }

def _construct_sandbox_script(checker_source: str, target_path: str, checker_func_name: str) -> str:
    """
    Constructs a self-contained Python script to run in the Toolhouse sandbox.
    """
    safe_path = target_path.replace("\\", "/")
    
    script = f"""
import sys
import json
import os

# --- INJECTED CHECKER SOURCE START ---
{checker_source}
# --- INJECTED CHECKER SOURCE END ---

if __name__ == "__main__":
    try:
        target_path = "{safe_path}"
        
        if not os.path.exists(target_path):
            print(json.dumps({{"error": "Target path not accessible in sandbox", "findings": []}}))
            sys.exit(0)

        if "{checker_func_name}" in globals():
            report = {checker_func_name}(target_path)
            print(json.dumps(report))
        else:
            print(json.dumps({{"error": "Checker entry point not found", "findings": []}}))
            
    except Exception as e:
        print(json.dumps({{"error": str(e), "findings": []}}))
"""
    return script

def _get_entry_point_name(checker_id: str) -> str:
    """Maps checker IDs to their main execution function name."""
    if "encryption" in checker_id:
        return "check_encryption"
    elif "access_control" in checker_id:
        return "check_access_control"
    elif "audit_logging" in checker_id:
        return "check_audit_logging"
    return "check_compliance"


# --- Main Exported Functions ---

def assess_impact(
    affected_checkers: List[str], 
    customer_codebases: Dict[str, str]
) -> Dict[str, Any]:
    """
    Runs compliance checkers on customer codebases using Toolhouse code execution.
    """
    api_key = os.getenv("TOOLHOUSE_API_KEY")
    if not api_key:
        logger.error("TOOLHOUSE_API_KEY not set.")
        return {"error": "Configuration missing"}
        
    th = Toolhouse(provider="openai", access_token=api_key)

    impact_report = {
        "customers_affected": [],
        "total_violations": 0,
        "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "high_risk_customers": []
    }

    for customer_id, code_path in customer_codebases.items():
        logger.info(f"Assessing impact for customer: {customer_id}")
        
        customer_violations = []
        execution_failed = False

        for checker_id in affected_checkers:
            try:
                checker_source = _load_checker_source(checker_id)
                entry_point = _get_entry_point_name(checker_id)
                sandbox_script = _construct_sandbox_script(checker_source, code_path, entry_point)

                logger.debug(f"Running {checker_id} via Toolhouse...")
                result_raw = th.bundle.code_execution.run(code=sandbox_script)
                
                if isinstance(result_raw, str):
                    clean_json = result_raw.strip().replace("```json", "").replace("```", "")
                    checker_output = json.loads(clean_json)
                else:
                    checker_output = result_raw

                if "error" in checker_output and checker_output["error"]:
                    logger.warning(f"Checker {checker_id} reported error for {customer_id}: {checker_output['error']}")
                
                findings = checker_output.get("findings", [])
                customer_violations.extend(findings)

            except Exception as e:
                logger.error(f"Failed to execute {checker_id} for {customer_id}: {e}")
                execution_failed = True

        if execution_failed and not customer_violations:
            continue

        metrics = _calculate_risk_metrics(customer_violations)
        
        customer_data = {
            "customer_id": customer_id,
            "violations_count": len(customer_violations),
            "severity_counts": metrics["counts"],
            "risk_score": metrics["risk_score"],
            "estimated_fine": metrics["estimated_fine"],
            "remediation_hours": metrics["remediation_hours"],
            "status": "assessed"
        }

        impact_report["customers_affected"].append(customer_data)
        impact_report["total_violations"] += len(customer_violations)
        
        for sev, count in metrics["counts"].items():
            impact_report["severity_breakdown"][sev] += count

    impact_report["high_risk_customers"] = prioritize_customers(impact_report)

    return impact_report


def prioritize_customers(impact_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Sorts customers by risk and fine exposure to prioritize remediation.
    """
    customers = impact_data.get("customers_affected", [])

    sorted_customers = sorted(
        customers,
        key=lambda c: (
            c["risk_score"], 
            c["estimated_fine"], 
            c["violations_count"]
        ),
        reverse=True
    )

    return sorted_customers[:20]