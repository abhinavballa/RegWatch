"""
src/orchestrator.py

RegWatch Orchestrator Module
============================

This central orchestration module coordinates the multi-agent workflow for the RegWatch
compliance monitoring system. It manages the lifecycle of regulation changes from
detection (scraping) to remediation (PR creation), enforcing strict safety guardrails
and permission modes.

Workflow Stages:
1. **Monitor**: Scraper Agent detects new or updated regulations.
2. **Analyze**: Analysis Agent determines semantic changes and severity.
3. **Assess**: Impact Agent identifies affected customer codebases and estimates risk.
4. **Remediate**: Remediation Agent updates prompts, regenerates checkers, and creates PRs.
5. **Notify**: Voice Service generates briefings; Change Tracker logs audit trails.

Safety Mechanisms:
- **Permission Modes**: Enforces `auto_apply`, `request_approval`, or `notify_only`.
- **Never-Auto-Apply Rules**: Blocks automatic application for encryption/auth changes or large patches.
- **Retry Logic**: Handles transient failures with exponential backoff.

Usage:
    from src.orchestrator import run_monitoring_cycle

    summary = run_monitoring_cycle()
    print(f"Processed {summary['changes_detected']} changes.")
"""

import logging
import time
import os
from typing import List, Dict, Any, Optional, Union
from enum import Enum
from datetime import datetime

# Import Agents and Services
try:
    # Agents are in src/ directory, not src/agents/
    from src import scraper_agent
    from src import analysis_agent
    from src import impact_agent
    from src import remediation_agent
    from src import change_tracker
    from src import voice_service
except ImportError:
    # Fallback for standalone testing or flat directory structures
    import scraper_agent
    import analysis_agent
    import impact_agent
    import remediation_agent
    import change_tracker
    import voice_service

# Configure Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Configuration & Constants ---

MAX_REGULATIONS_PER_CYCLE = 50
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # Seconds

# Customer Codebase Registry (In production, this would come from a DB)
# Mapping: Customer ID -> Path to local repo clone
CUSTOMER_CODEBASES = {
    "acme_corp": "./repos/acme-backend",
    "globex_inc": "./repos/globex-platform"
}

# Customer Repo Names (for GitHub API)
CUSTOMER_REPOS = {
    "acme_corp": "acme/backend",
    "globex_inc": "globex/platform"
}

class PermissionMode(str, Enum):
    AUTO_APPLY = "auto_apply"
    REQUEST_APPROVAL = "request_approval"
    NOTIFY_ONLY = "notify_only"

class WorkflowStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

# --- Helper Functions ---

def _retry_operation(func, *args, **kwargs):
    """
    Executes a function with exponential backoff retry logic.
    """
    delay = RETRY_BACKOFF_BASE
    last_exception = None
    
    for attempt in range(MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < MAX_RETRIES:
                logger.warning(f"Operation failed (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}. Retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            else:
                logger.error(f"Operation failed permanently after {MAX_RETRIES+1} attempts.")
    
    raise last_exception

def check_permission(change_type: str, affected_files: List[str], requested_mode: str) -> str:
    """
    Determines the appropriate permission action based on safety rules.
    
    Implements "Never-Auto-Apply" rules:
    1. Changes affecting > 10 files must be reviewed.
    2. Changes to encryption, access control, or auth logic must be reviewed.
    3. Production branch changes (handled in remediation agent) are implicitly reviewed via PR.

    Args:
        change_type: The category of change (e.g., 'encryption', 'editorial').
        affected_files: List of file paths modified by the patch.
        requested_mode: The configured preference (e.g., 'auto_apply').

    Returns:
        str: The enforced permission mode ('auto_apply', 'request_approval', 'notify_only').
    """
    # 1. Force review for large changes
    if len(affected_files) > 10:
        logger.warning(f"Safety Guardrail: {len(affected_files)} files affected. Downgrading to 'request_approval'.")
        return PermissionMode.REQUEST_APPROVAL.value

    # 2. Force review for sensitive domains
    sensitive_types = ['encryption', 'access_control', 'authentication', 'auth', 'security']
    if any(s in change_type.lower() for s in sensitive_types):
        logger.warning(f"Safety Guardrail: Sensitive change type '{change_type}'. Downgrading to 'request_approval'.")
        return PermissionMode.REQUEST_APPROVAL.value

    # 3. Respect 'notify_only' if requested
    if requested_mode == PermissionMode.NOTIFY_ONLY.value:
        return PermissionMode.NOTIFY_ONLY.value

    # 4. Default to requested mode (auto_apply or request_approval)
    return requested_mode

# --- Core Orchestration Functions ---

def handle_regulation_change(
    regulation_data: Dict[str, Any],
    permission_mode: str = PermissionMode.REQUEST_APPROVAL.value
) -> Dict[str, Any]:
    """
    Processes a single regulation change through the complete workflow:
    Analyze -> Log -> Assess Impact -> Remediate.

    Args:
        regulation_data: Dictionary containing 'regulation_id', 'full_text', etc.
        permission_mode: The desired permission mode for remediation.

    Returns:
        Dict containing the results of the processing steps.
    """
    reg_id = regulation_data.get('regulation_id', 'unknown')
    new_text = regulation_data.get('full_text', '')
    # In a real scenario, we'd fetch the old text from a DB. 
    # Here we assume the scraper might provide context or we treat it as a new entry.
    old_text = "" 

    workflow_result = {
        "regulation_id": reg_id,
        "status": WorkflowStatus.PENDING.value,
        "analysis": {},
        "impact": {},
        "remediation": [],
        "errors": []
    }

    logger.info(f"Starting workflow for regulation: {reg_id}")

    try:
        # --- Step 1: Analyze ---
        logger.info(f"[{reg_id}] Step 1: Analyzing changes...")
        analysis_result = _retry_operation(
            analysis_agent.analyze_change,
            old_text=old_text,
            new_text=new_text,
            regulation_id=reg_id
        )
        workflow_result["analysis"] = analysis_result

        # Log to Change Tracker
        change_tracker.log_change(
            regulation_id=reg_id,
            old_text=old_text,
            new_text=new_text,
            severity=analysis_result.get('severity', 'medium'),
            affected_checkers=analysis_result.get('affected_checkers', []),
            tests_added=0  # Placeholder until remediation is complete
        )

        # Stop if no substantive changes
        if analysis_result.get('change_type') == 'none':
            logger.info(f"[{reg_id}] No substantive changes detected. Workflow complete.")
            workflow_result["status"] = WorkflowStatus.SKIPPED.value
            return workflow_result

        # --- Step 2: Assess Impact ---
        logger.info(f"[{reg_id}] Step 2: Assessing impact...")
        affected_checkers = analysis_result.get('affected_checkers', [])
        
        if not affected_checkers:
            logger.info(f"[{reg_id}] No specific checkers mapped. Skipping impact assessment.")
            workflow_result["status"] = WorkflowStatus.COMPLETED.value
            return workflow_result

        impact_result = _retry_operation(
            impact_agent.assess_impact,
            affected_checkers=affected_checkers,
            customer_codebases=CUSTOMER_CODEBASES
        )
        workflow_result["impact"] = impact_result

        # --- Step 3: Remediate ---
        logger.info(f"[{reg_id}] Step 3: Remediation...")
        
        # 3a. Update Prompts & Regenerate Checkers (Internal System Update)
        substantive_changes = analysis_result.get('substantive_changes', [])
        for checker_id in affected_checkers:
            # Map checker ID to prompt file (Convention: prompts/{checker_id}.md)
            prompt_file = f"prompts/{checker_id}.md"
            
            # Update Prompt
            if os.path.exists(prompt_file):
                remediation_agent.update_prompt(prompt_file, substantive_changes)
            
            # Trigger PDD Sync
            # Map checker ID to module name (Convention: checkers.{checker_id})
            module_name = f"checkers.{checker_id}"
            remediation_agent.regenerate_checker(module_name)

        # 3b. Create Customer PRs (External Remediation)
        # We iterate through high-risk customers identified by impact agent
        high_risk_customers = impact_result.get('high_risk_customers', [])
        
        for customer in high_risk_customers:
            cust_id = customer['customer_id']
            repo_name = CUSTOMER_REPOS.get(cust_id)
            
            if not repo_name:
                logger.warning(f"No repo mapping for customer {cust_id}. Skipping PR.")
                continue

            # Generate a patch (Simulated here - normally generated by Toolhouse based on violations)
            # In a full implementation, we would ask Toolhouse to generate code fixes for the specific violations found.
            # For this orchestrator logic, we assume a patch dict is created.
            simulated_patch = {
                "src/config/security.py": "# Updated compliance settings\nENFORCE_ENCRYPTION = True"
            }

            # Enforce Permission Mode
            enforced_mode = check_permission(
                change_type=analysis_result.get('change_type', 'unknown'),
                affected_files=list(simulated_patch.keys()),
                requested_mode=permission_mode
            )

            pr_url = _retry_operation(
                remediation_agent.create_remediation_pr,
                customer_repo_name=repo_name,
                patch=simulated_patch,
                permission_mode=enforced_mode,
                regulation_ref=reg_id,
                violation_summary=analysis_result.get('summary', 'Compliance Update')
            )

            if pr_url:
                workflow_result["remediation"].append({
                    "customer_id": cust_id,
                    "action": "pr_created",
                    "url": pr_url,
                    "mode": enforced_mode
                })
            elif enforced_mode == PermissionMode.NOTIFY_ONLY.value:
                workflow_result["remediation"].append({
                    "customer_id": cust_id,
                    "action": "notification_sent",
                    "mode": enforced_mode
                })
            else:
                # Auto-applied (merged)
                workflow_result["remediation"].append({
                    "customer_id": cust_id,
                    "action": "merged",
                    "mode": enforced_mode
                })

        workflow_result["status"] = WorkflowStatus.COMPLETED.value

    except Exception as e:
        logger.error(f"[{reg_id}] Workflow failed: {e}", exc_info=True)
        workflow_result["status"] = WorkflowStatus.FAILED.value
        workflow_result["errors"].append(str(e))

    return workflow_result

def run_monitoring_cycle(
    default_permission_mode: str = PermissionMode.REQUEST_APPROVAL.value
) -> Dict[str, Any]:
    """
    Executes a complete monitoring cycle:
    1. Scrape new regulations.
    2. Process each regulation through the workflow.
    3. Generate voice briefings and alerts.
    
    Args:
        default_permission_mode: Default mode for remediation ('auto_apply', 'request_approval').

    Returns:
        Dict containing summary statistics of the cycle.
    """
    start_time = datetime.now()
    summary = {
        "cycle_id": f"cycle-{int(time.time())}",
        "start_time": start_time.isoformat(),
        "changes_detected": 0,
        "processed_count": 0,
        "actions_taken": [],
        "prs_created": [],
        "notifications_sent": [],
        "errors": []
    }

    logger.info("=== Starting RegWatch Monitoring Cycle ===")

    try:
        # --- Step 1: Monitor ---
        logger.info("Phase 1: Scraping regulations...")
        new_regulations = _retry_operation(scraper_agent.monitor_regulations)
        
        # Sort by date (newest first) and limit
        new_regulations.sort(key=lambda x: x.get('publication_date', ''), reverse=True)
        new_regulations = new_regulations[:MAX_REGULATIONS_PER_CYCLE]
        
        summary["changes_detected"] = len(new_regulations)
        logger.info(f"Detected {len(new_regulations)} new regulations.")

        # --- Step 2: Process Loop ---
        logger.info("Phase 2: Processing regulations...")
        
        critical_updates = [] # Track for voice alert

        for reg in new_regulations:
            result = handle_regulation_change(reg, default_permission_mode)
            summary["processed_count"] += 1
            
            # Aggregate results for summary
            if result["status"] == WorkflowStatus.FAILED.value:
                summary["errors"].extend(result["errors"])
            
            for action in result["remediation"]:
                summary["actions_taken"].append(f"{action['customer_id']}: {action['action']}")
                if action.get("url"):
                    summary["prs_created"].append(action["url"])

            # Check for critical severity for voice alerts
            severity = result.get("analysis", {}).get("severity", "low")
            if severity == "critical":
                critical_updates.append(f"Critical update for {result['regulation_id']}")

        # --- Step 3: Notify (Voice Service) ---
        logger.info("Phase 3: Generating notifications...")
        
        # Generate Executive Briefing
        # We construct a synthetic scan result object for the voice service
        scan_summary = {
            "total_violations": len(new_regulations),
            "severity_breakdown": {"critical": len(critical_updates), "high": 0, "medium": 0, "low": 0},
            "top_issues": [{"title": f"New Regulation: {r['regulation_id']}"} for r in new_regulations[:3]],
            "scan_date": start_time.strftime("%Y-%m-%d")
        }
        
        try:
            # Generate Briefing
            briefing_audio = voice_service.generate_briefing(scan_summary)
            # In production, we would upload this audio to S3 or email it.
            # Here we just log the size.
            logger.info(f"Generated briefing audio ({len(briefing_audio)} bytes).")
            summary["notifications_sent"].append("Executive Briefing Audio")

            # Generate Alerts for Critical Items
            for alert_msg in critical_updates:
                alert_audio = voice_service.alert(alert_msg)
                logger.info(f"Generated alert audio for: {alert_msg}")
                summary["notifications_sent"].append(f"Alert: {alert_msg}")

        except Exception as e:
            logger.error(f"Voice service failed: {e}")
            summary["errors"].append(f"Voice service error: {str(e)}")

    except Exception as e:
        logger.critical(f"Monitoring cycle failed catastrophically: {e}", exc_info=True)
        summary["errors"].append(f"Critical failure: {str(e)}")

    logger.info("=== Monitoring Cycle Complete ===")
    logger.info(f"Summary: {summary['changes_detected']} detected, {len(summary['prs_created'])} PRs created.")
    
    return summary

if __name__ == "__main__":
    # Standalone execution
    result = run_monitoring_cycle(default_permission_mode=PermissionMode.REQUEST_APPROVAL.value)
    import json
    print(json.dumps(result, indent=2, default=str))