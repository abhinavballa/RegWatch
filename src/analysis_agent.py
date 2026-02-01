import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from enum import Enum

# Assuming Toolhouse SDK is installed. 
# Since the documentation wasn't available, we will implement a standard 
# LLM interaction pattern typical for such SDKs, wrapping the completion call.
try:
    from toolhouse import Toolhouse
except ImportError:
    # Mock class for development if SDK is missing
    class Toolhouse:
        def __init__(self, api_key: Optional[str] = None, provider: str = "openai"):
            pass

        def completion(self, messages: List[Dict[str, str]], tools: Optional[List] = None) -> Any:
            # This would be the actual API call
            pass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants & Configuration ---

TOOLHOUSE_API_KEY = os.getenv("TOOLHOUSE_API_KEY")

# Mapping of Regulation Sections to Compliance Checkers
# In a real system, this might be loaded from a database or vector store.
REGULATION_TO_CHECKER_MAP = {
    "164.312(a)(2)(iv)": ["hipaa_encryption_checker"],
    "164.312(a)(1)": ["hipaa_access_control_checker"],
    "164.312(b)": ["hipaa_audit_logging_checker"],
    "164.306": ["hipaa_encryption_checker", "hipaa_access_control_checker"],  # General security
    "GDPR-32": ["hipaa_encryption_checker"],  # Cross-mapping example
}

# Heuristic Impact Estimates (Percentage of customers affected)
CHECKER_IMPACT_ESTIMATES = {
    "hipaa_encryption_checker": "80%",
    "hipaa_access_control_checker": "60%",
    "hipaa_audit_logging_checker": "40%",
    "unknown": "10%"
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ChangeType(str, Enum):
    SUBSTANTIVE = "substantive"
    CLARIFICATION = "clarification"
    EDITORIAL = "editorial"
    NONE = "none"

# --- Helper Functions ---


def _initialize_toolhouse() -> Toolhouse:
    """Initializes the Toolhouse client."""
    if not TOOLHOUSE_API_KEY:
        logger.warning("TOOLHOUSE_API_KEY not set. Agent may fail to perform LLM operations.")
    return Toolhouse(api_key=TOOLHOUSE_API_KEY)


def _estimate_customer_impact(affected_checkers: List[str]) -> str:
    """
    Estimates customer impact based on the highest impact checker involved.
    """
    if not affected_checkers:
        return "0%"

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


def _parse_llm_response(response_content: str) -> Dict[str, Any]:
    """
    Parses the JSON response from the LLM. Handles potential markdown wrapping.
    """
    try:
        # Strip markdown code blocks if present
        clean_content = response_content.strip()
        if clean_content.startswith("```json"):
            clean_content = clean_content[7:]
        if clean_content.startswith("```"):
            clean_content = clean_content[3:]
        if clean_content.endswith("```"):
            clean_content = clean_content[:-3]

        return json.loads(clean_content.strip())
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response: {e}")
        logger.debug(f"Raw response: {response_content}")
        # Return a safe fallback structure
        return {
            "change_type": "unknown",
            "severity": "medium",
            "substantive_changes": ["Error parsing analysis result"],
            "summary": "Analysis failed due to malformed LLM response.",
            "affected_sections": []
        }

# --- Core Functions ---


def map_to_checkers(regulation_id: str, change_summary: str, affected_sections: Optional[List[str]] = None) -> List[str]:
    """
    Identifies which compliance checkers are affected by a regulatory change.

    It uses a combination of:
    1. Direct mapping via regulation ID/Section (REGULATION_TO_CHECKER_MAP).
    2. Keyword analysis of the change summary.

    Args:
        regulation_id: The ID of the regulation (e.g., "HIPAA-164.312").
        change_summary: A text summary of the changes.
        affected_sections: Specific subsections identified by the LLM (optional).

    Returns:
        List[str]: A list of unique checker names (e.g., ['hipaa_encryption_checker']).
    """
    checkers = set()

    # 1. Direct Mapping via Regulation ID
    for key, mapped_checkers in REGULATION_TO_CHECKER_MAP.items():
        if key in regulation_id:
            checkers.update(mapped_checkers)

    # 2. Direct Mapping via Identified Sections (from LLM analysis)
    if affected_sections:
        for section in affected_sections:
            for key, mapped_checkers in REGULATION_TO_CHECKER_MAP.items():
                if key in section:
                    checkers.update(mapped_checkers)

    # 3. Keyword / Semantic Fallback (Simple Heuristics)
    summary_lower = change_summary.lower()

    if any(kw in summary_lower for kw in ["encrypt", "cipher", "at rest"]):
        checkers.add("hipaa_encryption_checker")

    if any(kw in summary_lower for kw in ["access", "authentication", "password"]):
        checkers.add("hipaa_access_control_checker")

    if any(kw in summary_lower for kw in ["log", "audit", "record"]):
        checkers.add("hipaa_audit_logging_checker")

    return list(checkers)


def analyze_change(old_text: str, new_text: str, regulation_id: str) -> Dict[str, Any]:
    """
    Performs semantic diff and impact analysis on regulatory text changes using Toolhouse LLM.

    Args:
        old_text: The previous version of the regulation text.
        new_text: The new version of the regulation text.
        regulation_id: The identifier for the regulation being analyzed.

    Returns:
        Dict containing analysis results including change type, severity, and impact.
    """
    # 1. Handle Edge Cases
    if not old_text and not new_text:
        return {"error": "Both text inputs are empty"}

    if old_text.strip() == new_text.strip():
        return {
            "change_type": ChangeType.NONE.value,
            "severity": Severity.LOW.value,
            "affected_checkers": [],
            "substantive_changes": [],
            "summary": "No changes detected in text.",
            "customer_impact_estimate": "0%"
        }

    th = _initialize_toolhouse()

    # 2. Construct Prompt for Semantic Analysis
    system_prompt = (
        "You are an expert Regulatory Compliance Analyst for the RegWatch system. "
        "Your job is to compare two versions of a regulation text and determine the impact on compliance software."
    )

    user_prompt = f"""
    Please analyze the changes between the OLD and NEW regulation text for Regulation ID: {regulation_id}.

    OLD TEXT:
    {old_text}

    NEW TEXT:
    {new_text}

    Perform the following analysis:
    1. **Semantic Diff**: Identify what actually changed in meaning, ignoring simple formatting unless it changes interpretation.
    2. **Classification**:
       - "substantive": New requirements, removed exemptions, changed thresholds.
       - "clarification": Rewording for clarity without changing the core rule.
       - "editorial": Typo fixes, grammar, formatting.
    3. **Severity Assessment**:
       - "critical": New mandatory technical requirements (e.g., "must encrypt").
       - "high": Changed thresholds (e.g., "72 hours" to "24 hours") or timelines.
       - "medium": Clarifications that might affect interpretation or edge cases.
       - "low": Editorial changes.
    4. **Substantive Changes**: List specific changes that require engineering attention.
    5. **Affected Sections**: Extract specific section numbers (e.g., "164.312(a)(1)") referenced.

    Return your response in valid JSON format with the following keys:
    {{
        "change_type": "substantive" | "clarification" | "editorial",
        "severity": "critical" | "high" | "medium" | "low",
        "summary": "A concise 1-2 sentence summary of the change.",
        "substantive_changes": ["List of strings describing specific changes"],
        "affected_sections": ["List of section strings found"]
    }}
    """

    try:
        # 3. Call Toolhouse LLM
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        response = th.completion(messages=messages)

        # Extract content based on expected SDK response shape
        if hasattr(response, 'choices') and len(response.choices) > 0:
            llm_content = response.choices[0].message.content
        elif isinstance(response, dict) and 'content' in response:
            llm_content = response['content']
        else:
            llm_content = str(response)

        # 4. Parse Analysis
        analysis_data = _parse_llm_response(llm_content)

        # 5. Map to Checkers
        affected_checkers = map_to_checkers(
            regulation_id,
            analysis_data.get("summary", ""),
            analysis_data.get("affected_sections", [])
        )

        # 6. Estimate Impact
        impact_estimate = _estimate_customer_impact(affected_checkers)

        # 7. Construct Final Result
        result = {
            "change_type": analysis_data.get("change_type", "unknown"),
            "severity": analysis_data.get("severity", "medium"),
            "affected_checkers": affected_checkers,
            "substantive_changes": analysis_data.get("substantive_changes", []),
            "summary": analysis_data.get("summary", "Analysis completed."),
            "customer_impact_estimate": impact_estimate,
            "regulation_id": regulation_id
        }

        logger.info(f"Analysis complete for {regulation_id}: {result['severity']} severity detected.")
        return result

    except Exception as e:
        logger.error(f"Error during analyze_change for {regulation_id}: {str(e)}")
        return {
            "change_type": "error",
            "severity": "medium",
            "affected_checkers": [],
            "substantive_changes": [f"Automated analysis failed: {str(e)}"],
            "summary": "System error during analysis.",
            "customer_impact_estimate": "0%"
        }


if __name__ == "__main__":
    # Simple local test
    print("=== Testing Analysis Agent ===")

    old_reg_text = "Implement access control policies."
    new_reg_text = "Implement access control policies and unique user identification."

    if not TOOLHOUSE_API_KEY:
        print("Warning: TOOLHOUSE_API_KEY not set. Mocking logic would be required for real execution.")

    test_result = analyze_change(old_reg_text, new_reg_text, "HIPAA-164.312(a)(1)")
    print(json.dumps(test_result, indent=2))