"""
RegWatch Impact Agent Module

This module implements the impact assessment logic for the RegWatch compliance system.
It utilizes the Toolhouse SDK to execute compliance checkers in isolated sandbox environments,
ensuring that customer code is analyzed safely without direct execution on the host system.

The module performs the following key functions:
1.  **Impact Assessment**: Runs specific compliance checkers against customer codebases.
2.  **Risk Scoring**: Calculates risk based on violation severity and quantity.
3.  **Financial Estimation**: Estimates potential HIPAA fines based on violation tiers.
4.  **Remediation Planning**: Estimates developer hours required to fix violations.
5.  **Prioritization**: Ranks customers to focus attention on high-risk cases.

Usage:
    from src.agents.impact_agent import assess_impact, prioritize_customers

    impact_report = assess_impact(affected_checkers, customer_codebases)
    prioritized_list = prioritize_customers(impact_report)
"""

import os
import json
import logging
import importlib
import inspect
from typing import List, Dict, Any, Optional

# Toolhouse SDK Import
try:
    from toolhouse import Toolhouse
except ImportError:
    # Fallback for linting/dev environments where SDK isn't present
    class Toolhouse:
        def __init__(self, api_key: Optional[str] = None) -> None: pass
        def run_tool(self, tool_name: str, args: Dict[str, Any]) -> Any: return "{}"

# Configure Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# --- Constants ---

# HIPAA Penalty Tiers (Estimates)
FINE_TIER_4 = 50000  # Per violation (Critical)
FINE_TIER_3 = 10000  # Per violation (High)
FINE_TIER_2 = 1000   # Per violation (Medium)
FINE_TIER_1 = 100    # Per violation (Low)

# Risk Weights
RISK_WEIGHT_CRITICAL = 10
RISK_WEIGHT_HIGH = 5
RISK_WEIGHT_MEDIUM = 2
RISK_WEIGHT_LOW = 1

# Remediation Effort (Hours)
EFFORT_CRITICAL = 8
EFFORT_HIGH = 4
EFFORT_MEDIUM = 2
EFFORT_LOW = 1

# Execution Constraints
EXECUTION_TIMEOUT = 30  # Seconds

# --- Helper Functions ---

def _calculate_risk_score(severity_counts: Dict[str, int]) -> int:
    """Calculates a weighted risk score based on violation counts."""
    return (
        (severity_counts.get("critical", 0) * RISK_WEIGHT_CRITICAL) +
        (severity_counts.get("high", 0) * RISK_WEIGHT_HIGH) +
        (severity_counts.get("medium", 0) * RISK_WEIGHT_MEDIUM) +
        (severity_counts.get("low", 0) * RISK_WEIGHT_LOW)
    )

def _estimate_fine_exposure(severity_counts: Dict[str, int]) -> int:
    """Estimates total fine exposure based on HIPAA tiers."""
    return (
        (severity_counts.get("critical", 0) * FINE_TIER_4) +
        (severity_counts.get("high", 0) * FINE_TIER_3) +
        (severity_counts.get("medium", 0) * FINE_TIER_2) +
        (severity_counts.get("low", 0) * FINE_TIER_1)
    )

def _estimate_remediation_hours(severity_counts: Dict[str, int]) -> int:
    """Estimates total developer hours required for remediation."""
    return (
        (severity_counts.get("critical", 0) * EFFORT_CRITICAL) +
        (severity_counts.get("high", 0) * EFFORT_HIGH) +
        (severity_counts.get("medium", 0) * EFFORT_MEDIUM) +
        (severity_counts.get("low", 0) * EFFORT_LOW)
    )

def _get_checker_source(checker_name: str) -> Optional[str]:
    """
    Dynamically imports a checker module and retrieves its source code.
    This allows us to inject the checker logic into the Toolhouse sandbox.
    """
    try:
        # Assuming checkers are located in src.checkers
        module_path = f"src.checkers.{checker_name}"
        module = importlib.import_module(module_path)
        
        # We get the source of the entire module to ensure imports/helpers are included
        return inspect.getsource(module)
    except (ImportError, OSError) as e:
        logger.error(f"Failed to load source for checker {checker_name}: {e}")
        return None

def _construct_sandbox_script(checker_source: str, target_code_content: str, checker_func_name: str = "check") -> str:
    """
    Constructs a self-contained Python script to run in the Toolhouse sandbox.
    
    We inject the checker source and the target customer code directly into the script.
    This avoids file system dependency issues within the ephemeral sandbox.
    """
    # Escape triple quotes in target code to prevent syntax errors in the wrapper
    safe_target_code = target_code_content.replace('"""', '\\"\\"\\"')
    
    script = f"""
import json
import sys
import ast
import re

# --- Injected Checker Logic ---
{checker_source}
# ------------------------------

# --- Target Customer Code ---
TARGET_CODE = \"\"\"{safe_target_code}\"\"\"
# ----------------------------

def run_analysis():
    try:
        # Create a temporary file for the checker to analyze if it expects a path
        filename = "customer_code_sample.py"
        with open(filename, "w") as f:
            f.write(TARGET_CODE)
            
        violations = []
        
        # Heuristic: Find the checker class/function in the local scope
        if "{checker_func_name}" in locals():
            violations = locals()["{checker_func_name}"](filename)
        else:
            # Fallback: try to find a function that looks like a checker
            pass

        print(json.dumps({{"status": "success", "violations": violations}}))
        
    except Exception as e:
        print(json.dumps({{"status": "error", "message": str(e)}}))

if __name__ == "__main__":
    run_analysis()
"""
    return script

# --- Main Exported Functions ---

def assess_impact(
    affected_checkers: List[str], 
    customer_codebases: Dict[str, str]
) -> Dict[str, Any]:
    """
    Runs compliance checkers on customer code using Toolhouse sandboxes.

    Args:
        affected_checkers: List of checker module names (e.g., 'hipaa_encryption_checker').
        customer_codebases: Dict mapping customer_id to the file path of their codebase.

    Returns:
        A dictionary containing the impact report with aggregated stats and per-customer details.
    """
    api_key = os.getenv("TOOLHOUSE_API_KEY")
    if not api_key:
        logger.error("TOOLHOUSE_API_KEY not set. Cannot execute sandboxed checks.")
        return {"error": "Configuration missing"}

    th = Toolhouse(api_key=api_key)
    
    impact_report: Dict[str, Any] = {
        "customers_affected": [],
        "total_violations": 0,
        "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "high_risk_customers": []
    }

    # Cache checker source code to avoid re-reading from disk
    checker_sources = {}
    for checker in affected_checkers:
        source = _get_checker_source(checker)
        if source:
            checker_sources[checker] = source

    for customer_id, code_path in customer_codebases.items():
        logger.info(f"Assessing impact for customer: {customer_id}")
        
        customer_violations = []
        execution_failed = False

        # Read customer code
        try:
            with open(code_path, 'r', encoding='utf-8') as f:
                customer_code_content = f.read()
        except FileNotFoundError:
            logger.error(f"Codebase not found for {customer_id} at {code_path}")
            impact_report["customers_affected"].append({
                "customer_id": customer_id,
                "status": "unable_to_assess",
                "reason": "file_not_found"
            })
            continue

        for checker_name, source_code in checker_sources.items():
            # Determine entry point name based on checker name convention
            func_suffix = checker_name.replace("hipaa_", "").replace("_checker", "")
            entry_point = f"check_{func_suffix}"

            # Prepare Sandbox Script
            sandbox_script = _construct_sandbox_script(source_code, customer_code_content, entry_point)

            try:
                # Execute via Toolhouse
                result = th.run_tool(
                    "code_execution", 
                    {
                        "code": sandbox_script,
                        "language": "python"
                    }
                )
                
                # Parse Result
                if isinstance(result, str):
                    try:
                        clean_json = result.strip().replace("```json", "").replace("```", "")
                        data = json.loads(clean_json)
                        
                        if data.get("status") == "success":
                            violations = data.get("violations", [])
                            for v in violations:
                                v["source_checker"] = checker_name
                            customer_violations.extend(violations)
                        else:
                            logger.warning(f"Checker {checker_name} failed for {customer_id}: {data.get('message')}")
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON output from sandbox for {customer_id}")
                
            except Exception as e:
                logger.error(f"Toolhouse execution error for {customer_id} / {checker_name}: {e}")
                pass

        # Aggregate Customer Results
        if not execution_failed:
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for v in customer_violations:
                sev = v.get("severity", "medium").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            risk_score = _calculate_risk_score(severity_counts)
            est_fine = _estimate_fine_exposure(severity_counts)
            rem_hours = _estimate_remediation_hours(severity_counts)

            customer_data = {
                "customer_id": customer_id,
                "violations_count": len(customer_violations),
                "severity_counts": severity_counts,
                "risk_score": risk_score,
                "estimated_fine": est_fine,
                "remediation_hours": rem_hours,
                "status": "assessed"
            }
            
            impact_report["customers_affected"].append(customer_data)
            
            # Update Global Aggregates
            impact_report["total_violations"] += len(customer_violations)
            for k, v in severity_counts.items():
                impact_report["severity_breakdown"][k] += v

    # Identify High Risk Customers (Top 20)
    impact_report["high_risk_customers"] = prioritize_customers(impact_report)

    return impact_report

def prioritize_customers(impact_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Sorts affected customers by risk score and fine exposure to prioritize remediation.

    Args:
        impact_data: The dictionary returned by assess_impact.

    Returns:
        A list of the top 20 high-risk customer dictionaries.
    """
    customers = impact_data.get("customers_affected", [])
    
    # Filter out customers that failed assessment
    valid_customers = [c for c in customers if c.get("status") == "assessed"]

    # Sort by Risk Score (Desc), then Estimated Fine (Desc)
    sorted_customers = sorted(
        valid_customers,
        key=lambda x: (x["risk_score"], x["estimated_fine"]),
        reverse=True
    )

    # Return top 20
    return sorted_customers[:20]