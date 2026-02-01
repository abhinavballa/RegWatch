"""
src/agents/analysis_agent.py

This module implements the analysis agent for the RegWatch compliance monitoring system.
It uses the Toolhouse SDK to perform semantic diffs between old and new regulation text,
identifying substantive changes, determining severity, and mapping changes to specific
compliance checkers.

The agent distinguishes between:
- Substantive changes: New requirements, changed thresholds, removed exemptions.
- Clarifications: Typo fixes, rewording, formatting changes.

It also estimates customer impact and routes changes to the appropriate technical checkers
(e.g., encryption, access control, audit logging).
"""

import os
import json
from typing import Dict, List, Optional, Any, Union
from toolhouse import Toolhouse

# Initialize Toolhouse SDK
# Assumption: TOOLHOUSE_API_KEY is set in the environment
toolhouse = Toolhouse()

# Mapping of regulation sections to specific compliance checkers
# In a production system, this might be loaded from a database or configuration file.
REGULATION_TO_CHECKER_MAP = {
    "164.312(a)(1)": ["hipaa_access_control_checker"],
    "164.312(a)(2)(iv)": ["hipaa_encryption_checker"],
    "164.312(b)": ["hipaa_audit_logging_checker"],
    "164.312(c)(1)": ["hipaa_integrity_checker"],
    "164.312(d)": ["hipaa_authentication_checker"],
    "164.312(e)(1)": ["hipaa_transmission_security_checker"],
    # Generic fallbacks for broader sections
    "164.312": [
        "hipaa_access_control_checker",
        "hipaa_audit_logging_checker",
        "hipaa_encryption_checker"
    ]
}

# Heuristic estimates for customer impact based on checker type
CHECKER_IMPACT_ESTIMATES = {
    "hipaa_encryption_checker": "80%",
    "hipaa_access_control_checker": "60%",
    "hipaa_audit_logging_checker": "40%",
    "hipaa_integrity_checker": "30%",
    "hipaa_authentication_checker": "70%",
    "hipaa_transmission_security_checker": "50%"
}


def _estimate_customer_impact(affected_checkers: List[str]) -> str:
    """
    Estimates the percentage of customers likely affected based on the checkers involved.
    Returns the highest impact estimate among the affected checkers.
    """
    if not affected_checkers:
        return "0% (No technical checkers mapped)"
    
    max_impact = 0
    for checker in affected_checkers:
        impact_str = CHECKER_IMPACT_ESTIMATES.get(checker, "10%").strip('%')
        try:
            impact_val = int(impact_str)
            if impact_val > max_impact:
                max_impact = impact_val
        except ValueError:
            continue
            
    return f"{max_impact}%"


def map_to_checkers(regulation_id: str, change_summary: str) -> List[str]:
    """
    Identifies which compliance checkers are affected by the regulation change.
    
    It uses a two-step approach:
    1. Direct mapping based on the regulation_id (section number).
    2. Keyword analysis of the change_summary to catch context-specific triggers.
    
    Args:
        regulation_id: The ID or section number of the regulation (e.g., "164.312(a)(2)").
        change_summary: A text summary of the changes detected.
        
    Returns:
        List[str]: A list of unique checker names (e.g., ['hipaa_encryption_checker']).
    """
    checkers = set()

    # 1. Direct Mapping via Regulation ID
    # We try to match the specific ID, or fall back to parent sections
    for section, mapped_checkers in REGULATION_TO_CHECKER_MAP.items():
        if regulation_id.startswith(section):
            checkers.update(mapped_checkers)

    # 2. Keyword/Context Analysis
    summary_lower = change_summary.lower()
    
    if "encrypt" in summary_lower or "cipher" in summary_lower:
        checkers.add("hipaa_encryption_checker")
    
    if "log" in summary_lower or "audit" in summary_lower or "record" in summary_lower:
        checkers.add("hipaa_audit_logging_checker")
        
    if "access" in summary_lower or "permission" in summary_lower or "role" in summary_lower:
        checkers.add("hipaa_access_control_checker")

    return list(checkers)


def analyze_change(old_text: str, new_text: str, regulation_id: str) -> Dict[str, Any]:
    """
    Performs a semantic diff and impact analysis between old and new regulation text.
    
    Uses Toolhouse LLM to identify substantive changes vs clarifications, determine severity,
    and generate a summary.
    
    Args:
        old_text: The previous version of the regulation text.
        new_text: The updated version of the regulation text.
        regulation_id: The identifier for the regulation being analyzed.
        
    Returns:
        Dict containing:
            - change_type: "Substantive" or "Editorial"
            - severity: "Critical", "High", "Medium", "Low"
            - affected_checkers: List of checker modules
            - substantive_changes: List of specific change descriptions
            - summary: High-level summary of the update
            - customer_impact_estimate: String percentage estimate
    """
    
    # Edge Case: Empty text
    if not old_text and not new_text:
        return {
            "change_type": "None",
            "severity": "Low",
            "affected_checkers": [],
            "substantive_changes": [],
            "summary": "No text provided for analysis.",
            "customer_impact_estimate": "0%"
        }

    # Edge Case: Identical text
    if old_text.strip() == new_text.strip():
        return {
            "change_type": "None",
            "severity": "Low",
            "affected_checkers": [],
            "substantive_changes": [],
            "summary": "No changes detected between old and new text.",
            "customer_impact_estimate": "0%"
        }

    # Construct the prompt for the Toolhouse LLM
    # We ask for a JSON response to make parsing reliable.
    prompt = f"""
    You are a Regulatory Compliance Expert AI. Your task is to compare two versions of a regulation text (Old vs New) and perform a semantic impact analysis.
    
    Regulation ID: {regulation_id}

    OLD TEXT:
    {old_text}

    NEW TEXT:
    {new_text}

    Please analyze the differences and provide a JSON response with the following structure:
    {{
        "change_type": "Substantive" | "Editorial",
        "severity": "Critical" | "High" | "Medium" | "Low",
        "substantive_changes": ["List of specific meaningful changes with section references"],
        "summary": "A concise executive summary of what changed and why it matters."
    }}

    Rules for Analysis:
    1. **Substantive vs Editorial**: 
       - Substantive: New requirements, changed thresholds (e.g., timeout values), removed exemptions, new definitions that alter scope.
       - Editorial: Typo fixes, reformatting, rewording that does not change legal meaning.
    
    2. **Severity Determination**:
       - Critical: New mandatory technical requirements (e.g., "must encrypt").
       - High: Changed thresholds, timelines, or stricter constraints.
       - Medium: Clarifications that might affect interpretation but not immediate tooling.
       - Low: Grammar, punctuation, minor wording tweaks.

    3. **Semantic Similarity**: Group related changes together. Do not list every single word change; focus on the meaning.
    """

    try:
        # Call Toolhouse LLM
        # Note: In a real implementation, we would use the specific model completion method provided by the SDK.
        # Assuming a standard chat completion interface here.
        messages = [{"role": "user", "content": prompt}]
        response = toolhouse.chat_completion(messages=messages)
        
        # Extract content (assuming response structure similar to OpenAI/standard LLM response)
        # Adjust based on actual Toolhouse SDK response object structure
        content = response.choices[0].message.content
        
        # Parse JSON from the response
        # We attempt to clean code blocks if the LLM wraps them in ```json ... ```
        cleaned_content = content.replace("```json", "").replace("```", "").strip()
        analysis_data = json.loads(cleaned_content)
        
        # Extract fields with defaults
        change_type = analysis_data.get("change_type", "Editorial")
        severity = analysis_data.get("severity", "Low")
        substantive_changes = analysis_data.get("substantive_changes", [])
        summary = analysis_data.get("summary", "Analysis completed.")

        # Map to checkers
        affected_checkers = map_to_checkers(regulation_id, summary + " " + " ".join(substantive_changes))
        
        # Estimate impact
        impact_estimate = _estimate_customer_impact(affected_checkers)

        return {
            "change_type": change_type,
            "severity": severity,
            "affected_checkers": affected_checkers,
            "substantive_changes": substantive_changes,
            "summary": summary,
            "customer_impact_estimate": impact_estimate
        }

    except json.JSONDecodeError:
        # Fallback if LLM returns malformed JSON
        return {
            "change_type": "Unknown",
            "severity": "Medium",
            "affected_checkers": map_to_checkers(regulation_id, ""),
            "substantive_changes": ["Error parsing analysis results."],
            "summary": "The analysis agent could not parse the LLM response. Manual review recommended.",
            "customer_impact_estimate": "Unknown"
        }
    except Exception as e:
        # General error handling
        return {
            "change_type": "Error",
            "severity": "High",
            "affected_checkers": [],
            "substantive_changes": [f"System error during analysis: {str(e)}"],
            "summary": "Analysis failed due to an internal error.",
            "customer_impact_estimate": "Unknown"
        }