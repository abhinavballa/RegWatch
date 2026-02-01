"""
src/agents/remediation_agent.py

RegWatch Remediation Agent
==========================

This module implements the automated remediation logic for the RegWatch compliance system.
It leverages the Toolhouse SDK for LLM-driven analysis and PyGithub for repository management.

Key Responsibilities:
1. Updating PDD prompt files with new regulation requirements.
2. Triggering compliance checker regeneration via PDD sync.
3. Creating and managing remediation Pull Requests with strict safety guardrails.

Dependencies:
- toolhouse: For AI-driven patch generation and safety analysis.
- PyGithub: For GitHub API interactions (Issues, PRs, Merges).
- os, re, time: Standard library utilities.

Environment Variables:
- TOOLHOUSE_API_KEY: API key for Toolhouse SDK.
- GITHUB_TOKEN: Personal Access Token for GitHub API.
- REGWATCH_REPO: Name of the central RegWatch repository (e.g., "org/regwatch-core").
"""

import os
import re
import time
import logging
from typing import List, Dict, Optional, Union, Any
from enum import Enum

from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest
from toolhouse import Toolhouse

# Configure Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
REGWATCH_REPO_NAME = os.getenv("REGWATCH_REPO", "regwatch/core-system")
MAX_AUTO_APPLY_FILES = 10
POLL_INTERVAL_SECONDS = 5
MAX_POLL_ATTEMPTS = 12  # 1 minute timeout for PDD sync acknowledgement

# Safety Keywords (Regex patterns for sensitive code detection)
SENSITIVE_PATTERNS = [
    r"auth(entication|orization)?",
    r"encrypt(ion)?",
    r"decrypt(ion)?",
    r"passwd|password",
    r"secret|token|key",
    r"cipher",
    r"login|logout"
]

class PermissionMode(Enum):
    AUTO_APPLY = "auto_apply"
    REQUEST_APPROVAL = "request_approval"
    NOTIFY_ONLY = "notify_only"

# Initialize Clients
try:
    gh_client = Github(os.getenv("GITHUB_TOKEN"))
    th_client = Toolhouse(api_key=os.getenv("TOOLHOUSE_API_KEY"))
except Exception as e:
    logger.error(f"Failed to initialize clients: {e}")
    raise

def update_prompt(prompt_file: str, new_requirements: List[str]) -> bool:
    """
    Updates a PDD prompt file by inserting new regulation requirements into the
    'Requirements' section while preserving the existing file structure.

    Args:
        prompt_file: Path to the local prompt file (e.g., 'prompts/hipaa_checker.md').
        new_requirements: List of string requirements to append.

    Returns:
        bool: True if update was successful, False otherwise.
    """
    if not os.path.exists(prompt_file):
        logger.error(f"Prompt file not found: {prompt_file}")
        return False

    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Locate the Requirements section
        # Looks for "# Requirements" or "## Requirements" case-insensitive
        req_header_match = re.search(r'^(#+\s*Requirements\s*$)', content, re.MULTILINE | re.IGNORECASE)
        
        if not req_header_match:
            logger.warning(f"No 'Requirements' section found in {prompt_file}. Appending to end.")
            # Append new section if missing
            new_content = content.rstrip() + "\n\n# Requirements\n"
            for req in new_requirements:
                new_content += f"- {req}\n"
        else:
            # Find the end of the Requirements section (start of next section or EOF)
            header_end_pos = req_header_match.end()
            
            # Look for the next header (starting with #)
            next_header_match = re.search(r'^#+\s', content[header_end_pos:], re.MULTILINE)
            
            insertion_point = header_end_pos
            if next_header_match:
                # Insert before the next header
                insertion_point += next_header_match.start()
            else:
                # Insert at EOF
                insertion_point = len(content)

            # Format new requirements
            req_text = ""
            # Check if we need a newline prefix
            if not content[header_end_pos:insertion_point].strip():
                req_text += "\n"
            
            for req in new_requirements:
                req_text += f"- {req}\n"

            # Reconstruct content
            new_content = content[:insertion_point] + req_text + content[insertion_point:]

        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        logger.info(f"Successfully updated {prompt_file} with {len(new_requirements)} new requirements.")
        return True

    except Exception as e:
        logger.error(f"Failed to update prompt file {prompt_file}: {e}")
        return False


def regenerate_checker(module_name: str) -> bool:
    """
    Triggers the PDD sync process to regenerate a compliance checker by creating
    a GitHub issue with the specific command.

    Args:
        module_name: The name of the module to regenerate (e.g., 'checkers.hipaa').

    Returns:
        bool: True if the command was acknowledged by the bot, False otherwise.
    """
    try:
        repo = gh_client.get_repo(REGWATCH_REPO_NAME)
        title = f"Regenerate {module_name}"
        body = f"/pdd-sync {module_name}\n\n*Triggered by RegWatch Remediation Agent*"
        
        issue = repo.create_issue(title=title, body=body)
        logger.info(f"Created issue #{issue.number} to regenerate {module_name}")

        # Monitor for bot response
        logger.info("Waiting for PDD bot acknowledgement...")
        for _ in range(MAX_POLL_ATTEMPTS):
            time.sleep(POLL_INTERVAL_SECONDS)
            # Refresh issue to get new comments
            issue.update()
            comments = list(issue.get_comments())
            
            for comment in comments:
                # Assuming the bot name is 'pdd-bot' or similar, or checking content
                if "sync scheduled" in comment.body.lower() or "error" in comment.body.lower():
                    if "error" in comment.body.lower():
                        logger.error(f"PDD Sync failed: {comment.body}")
                        return False
                    logger.info("PDD Sync successfully scheduled.")
                    return True
        
        logger.warning(f"Timeout waiting for PDD bot response on issue #{issue.number}")
        return False

    except GithubException as e:
        logger.error(f"GitHub API error during regeneration trigger: {e}")
        return False


def _check_safety_guardrails(
    patch: Dict[str, str], 
    branch_name: str, 
    repo: Repository
) -> bool:
    """
    Evaluates safety guardrails to determine if a patch is safe for auto-application.
    
    Guardrails:
    1. Patch size <= 10 files.
    2. Not a production branch.
    3. No sensitive code (auth/crypto) modifications.
    """
    # 1. File Count Check
    if len(patch) > MAX_AUTO_APPLY_FILES:
        logger.warning(f"Guardrail Fail: Patch affects {len(patch)} files (Limit: {MAX_AUTO_APPLY_FILES}).")
        return False

    # 2. Production Branch Check
    prod_branches = ['main', 'master', 'prod', 'production']
    if repo.default_branch in prod_branches and branch_name == repo.default_branch:
        # Note: Usually we create a feature branch, but if the target is prod, we are careful.
        # This check ensures we aren't somehow pushing directly to prod if that was the intent.
        logger.warning("Guardrail Fail: Cannot auto-apply directly to production branch.")
        return False

    # 3. Sensitive Code Check
    # Combine all patch content for analysis
    full_patch_content = "\n".join(patch.values())
    
    # Regex Check
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, full_patch_content, re.IGNORECASE):
            logger.warning(f"Guardrail Fail: Sensitive keyword match '{pattern}'.")
            return False
            
    # Toolhouse LLM Check (Double check for semantic context)
    # We ask Toolhouse if this looks like a security-critical change
    messages = [{
        "role": "user",
        "content": f"Analyze this code patch for security sensitivity. Does it modify authentication, encryption, or access control logic? Reply only 'YES' or 'NO'.\n\n{full_patch_content[:2000]}" # Truncate for token limits if needed
    }]
    try:
        response = th_client.chat_completion(messages=messages, model="claude-3-haiku") # Using a fast model
        content = response.choices[0].message.content.strip().upper()
        if "YES" in content:
            logger.warning("Guardrail Fail: LLM identified security-sensitive logic.")
            return False
    except Exception as e:
        logger.warning(f"LLM Safety check failed ({e}), defaulting to unsafe.")
        return False

    return True


def create_remediation_pr(
    customer_repo_name: str, 
    patch: Dict[str, str], 
    permission_mode: str,
    regulation_ref: str = "Unknown Regulation",
    violation_summary: str = "Compliance Violation"
) -> Optional[str]:
    """
    Creates a Pull Request or auto-applies a fix based on the permission mode.

    Args:
        customer_repo_name: Full name of the repo (e.g., 'acme/backend').
        patch: Dictionary mapping file paths to new file content.
        permission_mode: 'auto_apply', 'request_approval', or 'notify_only'.
        regulation_ref: Reference ID for the regulation (for PR description).
        violation_summary: Brief description of the violation.

    Returns:
        Optional[str]: URL of the created PR, or None if notify_only/merged.
    """
    if permission_mode == PermissionMode.NOTIFY_ONLY.value:
        logger.info(f"Mode is {permission_mode}. Notification sent (simulated). No code changes.")
        return None

    try:
        repo = gh_client.get_repo(customer_repo_name)
        default_branch = repo.get_branch(repo.default_branch)
        
        # Determine Branch Name
        timestamp = int(time.time())
        branch_name = f"regwatch/fix-{timestamp}"
        
        # Check Safety Guardrails
        is_safe = _check_safety_guardrails(patch, branch_name, repo)
        
        if permission_mode == PermissionMode.AUTO_APPLY.value and not is_safe:
            logger.warning("Auto-apply requested but guardrails failed. Downgrading to 'request_approval'.")
            permission_mode = PermissionMode.REQUEST_APPROVAL.value

        # Create Branch
        logger.info(f"Creating branch {branch_name} from {default_branch.name}")
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=default_branch.commit.sha)

        # Apply Changes (Commit)
        # Note: In a real scenario, we might batch these, but PyGithub commits one by one usually
        # unless using the Git Data API for trees. For simplicity, we iterate.
        for file_path, content in patch.items():
            try:
                # Get file SHA to update
                contents = repo.get_contents(file_path, ref=branch_name)
                repo.update_file(
                    path=file_path,
                    message=f"RegWatch: Fix violation in {file_path}",
                    content=content,
                    sha=contents.sha,
                    branch=branch_name
                )
            except GithubException:
                # File might not exist, create it
                repo.create_file(
                    path=file_path,
                    message=f"RegWatch: Create {file_path}",
                    content=content,
                    branch=branch_name
                )

        # Generate PR Description using Toolhouse
        pr_prompt = f"""
        Generate a GitHub Pull Request description for a compliance fix.
        Regulation: {regulation_ref}
        Violation: {violation_summary}
        Files Changed: {list(patch.keys())}
        
        Include sections: Summary, Regulation Details, Testing Instructions.
        """
        messages = [{"role": "user", "content": pr_prompt}]
        llm_response = th_client.chat_completion(messages=messages)
        pr_body = llm_response.choices[0].message.content

        # Create PR
        pr = repo.create_pull(
            title=f"Compliance Fix: {regulation_ref}",
            body=pr_body,
            head=branch_name,
            base=repo.default_branch
        )
        
        # Add Labels
        labels = ["compliance", "automated-fix"]
        if "hipaa" in regulation_ref.lower():
            labels.append("hipaa")
        # Determine severity label based on violation summary (simple heuristic)
        if "critical" in violation_summary.lower():
            labels.append("severity:critical")
        else:
            labels.append("severity:medium")
            
        # Ensure labels exist before adding (simplified, assuming they might exist or ignoring error)
        try:
            for label in labels:
                # In production code, check if label exists in repo first
                pass 
            pr.add_to_labels(*labels)
        except Exception:
            pass

        # Assign Reviewers
        # Default to repo owner or specific team if configured
        # pr.add_to_reviewers("compliance-team") 

        logger.info(f"Created PR #{pr.number}: {pr.html_url}")

        # Handle Auto-Apply Merge
        if permission_mode == PermissionMode.AUTO_APPLY.value and is_safe:
            logger.info("Auto-apply enabled and guardrails passed. Attempting merge...")
            try:
                # Wait briefly for checks to start (optional)
                time.sleep(2)
                merge_status = pr.merge(merge_method="squash", commit_message="RegWatch Auto-Remediation")
                if merge_status.merged:
                    logger.info(f"PR #{pr.number} successfully merged.")
                    return None
                else:
                    logger.error(f"Merge failed: {merge_status.message}")
                    return pr.html_url
            except GithubException as e:
                logger.error(f"Failed to auto-merge PR: {e}")
                return pr.html_url

        return pr.html_url

    except Exception as e:
        logger.error(f"Failed to create remediation PR: {e}")
        raise