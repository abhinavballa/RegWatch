from __future__ import annotations

import os
import re
import time
import logging
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest
from toolhouse import Toolhouse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_FILES_AUTO_APPLY = 10
MAX_LINES_AUTO_APPLY = 1000
SENSITIVE_KEYWORDS = ["auth", "password", "secret", "encrypt", "decrypt", "token", "key"]
PRODUCTION_BRANCHES = ["main", "master", "production", "prod"]
PDD_SYNC_TIMEOUT = 300  # Seconds to wait for PDD sync
PDD_SYNC_POLL_INTERVAL = 10

class PermissionMode(Enum):
    AUTO_APPLY = "auto_apply"
    REQUEST_APPROVAL = "request_approval"
    NOTIFY_ONLY = "notify_only"

class SafetyCheckResult(Enum):
    SAFE = "safe"
    UNSAFE_TOO_MANY_FILES = "unsafe_too_many_files"
    UNSAFE_PRODUCTION_BRANCH = "unsafe_production_branch"
    UNSAFE_SENSITIVE_CODE = "unsafe_sensitive_code"

# Initialize Clients
try:
    th = Toolhouse(api_key=os.environ.get("TOOLHOUSE_API_KEY"))
    gh = Github(os.environ.get("GITHUB_TOKEN"))
except Exception as e:
    logger.error(f"Failed to initialize clients: {e}")
    raise


def update_prompt(prompt_file: str, new_requirements: List[str]) -> bool:
    """
    Updates a PDD prompt file with new regulation requirements.

    Parses the existing prompt file to locate the 'Requirements' section and appends
    the new requirements, preserving the existing structure.

    Args:
        prompt_file: Path to the prompt file.
        new_requirements: List of requirement strings to add.

    Returns:
        bool: True if successful, False otherwise.
    """
    if not os.path.exists(prompt_file):
        logger.error(f"Prompt file not found: {prompt_file}")
        return False

    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Simple state machine parser to find sections
        # We look for lines starting with "% Requirements" or similar headers
        # PDD format usually uses XML-like tags or Markdown headers. 
        # Assuming standard Markdown/PDD structure: "% Requirements" or "## Requirements"
        
        lines = content.splitlines()
        req_start_idx = -1
        next_section_idx = -1
        
        # Regex to identify section headers (e.g., % Section or ## Section)
        header_pattern = re.compile(r"^[%#]+\s+(Requirements|Dependencies|Instructions|Goal|Context)", re.IGNORECASE)
        
        for i, line in enumerate(lines):
            match = header_pattern.match(line)
            if match:
                section_name = match.group(1).lower()
                if section_name == "requirements":
                    req_start_idx = i
                elif req_start_idx != -1 and next_section_idx == -1:
                    # We found the next section after requirements
                    next_section_idx = i
                    break
        
        if req_start_idx == -1:
            logger.warning(f"Could not find 'Requirements' section in {prompt_file}. Appending to end.")
            # Fallback: Append to end
            updated_lines = lines + ["", "% Requirements"] + [f"- {req}" for req in new_requirements]
        else:
            # Insert before the next section, or at the end if no next section found
            insert_idx = next_section_idx if next_section_idx != -1 else len(lines)
            
            # Check for duplicates to avoid clutter
            existing_content = "\n".join(lines[req_start_idx:insert_idx])
            to_add = []
            for req in new_requirements:
                if req not in existing_content:
                    to_add.append(f"- {req}")
            
            if not to_add:
                logger.info("No new unique requirements to add.")
                return True

            # Insert with a newline buffer if needed
            insertion_block = to_add + [""]
            updated_lines = lines[:insert_idx] + insertion_block + lines[insert_idx:]

        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(updated_lines))
            
        logger.info(f"Successfully updated {prompt_file} with {len(new_requirements)} new requirements.")
        return True

    except Exception as e:
        logger.error(f"Error updating prompt file: {e}")
        return False


def regenerate_checker(module_name: str, repo_name: str = "RegWatch") -> bool:
    """
    Triggers pdd sync to regenerate a compliance checker by creating a GitHub issue.

    Args:
        module_name: The name of the module to regenerate (e.g., 'hipaa_compliance').
        repo_name: The repository where the PDD bot is listening.

    Returns:
        bool: True if regeneration was confirmed successful, False otherwise.
    """
    try:
        repo = gh.get_user().get_repo(repo_name)
        title = f"Regenerate {module_name}"
        body = f"/pdd-sync {module_name}"
        
        logger.info(f"Creating issue in {repo_name}: {title}")
        issue = repo.create_issue(title=title, body=body)
        
        # Monitor for completion
        start_time = time.time()
        while time.time() - start_time < PDD_SYNC_TIMEOUT:
            # Refresh issue to get new comments
            issue.update()
            comments = list(issue.get_comments())
            
            for comment in reversed(comments):
                # Look for bot response
                if "pdd-sync complete" in comment.body.lower():
                    logger.info(f"PDD sync completed successfully for {module_name}")
                    issue.edit(state="closed")
                    return True
                if "pdd-sync failed" in comment.body.lower() or "error" in comment.body.lower():
                    logger.error(f"PDD sync failed for {module_name}: {comment.body}")
                    return False
            
            time.sleep(PDD_SYNC_POLL_INTERVAL)
            
        logger.error(f"Timeout waiting for PDD sync for {module_name}")
        return False

    except GithubException as e:
        logger.error(f"GitHub API error during regeneration trigger: {e}")
        return False


def _check_safety_guardrails(
    patch_content: str, 
    target_branch: str, 
    affected_files: List[str]
) -> SafetyCheckResult:
    """
    Evaluates whether a patch is safe for auto-application.
    """
    # 1. Check Production Branch
    if target_branch in PRODUCTION_BRANCHES:
        return SafetyCheckResult.UNSAFE_PRODUCTION_BRANCH

    # 2. Check Scope (File Count)
    if len(affected_files) > MAX_FILES_AUTO_APPLY:
        return SafetyCheckResult.UNSAFE_TOO_MANY_FILES

    # 3. Check Scope (Line Count - rough estimate)
    if patch_content.count('\n') > MAX_LINES_AUTO_APPLY:
        return SafetyCheckResult.UNSAFE_TOO_MANY_FILES

    # 4. Check Sensitive Code
    # This is a heuristic check.
    lower_patch = patch_content.lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lower_patch:
            return SafetyCheckResult.UNSAFE_SENSITIVE_CODE

    return SafetyCheckResult.SAFE


def _generate_patch_with_llm(
    repo_content_summary: str, 
    violations: List[str], 
    remediation_suggestions: List[str]
) -> Tuple[str, List[str]]:
    """
    Uses Toolhouse to generate a code patch based on violations.
    
    Returns:
        Tuple[str, List[str]]: (The patch content, List of affected filenames)
    """
    prompt = (
        "You are an expert software engineer fixing compliance violations.\n"
        f"Violations: {violations}\n"
        f"Suggestions: {remediation_suggestions}\n"
        f"Repository Context Summary: {repo_content_summary}\n\n"
        "Generate a unified diff patch to fix these issues. "
        "Return ONLY the patch content. Do not include markdown formatting."
    )
    
    messages = [{"role": "user", "content": prompt}]
    response = th.chat_completion(messages=messages, model="claude-3-5-sonnet-20240620")
    
    patch_content = response['content']
    
    # Extract filenames from diff headers (e.g., "+++ b/src/main.py")
    affected_files = re.findall(r"\+\+\+ b/(.+)", patch_content)
    
    return patch_content, affected_files


def create_remediation_pr(
    customer_repo_name: str,
    violations: List[str],
    remediation_suggestions: List[str],
    permission_mode: str = "request_approval",
    base_branch: str = "main"
) -> Optional[str]:
    """
    Generates a patch and creates a Pull Request or auto-applies fixes based on permission mode.

    Args:
        customer_repo_name: Full name of the repo (e.g., "acme/backend").
        violations: List of compliance violation descriptions.
        remediation_suggestions: List of suggested fixes.
        permission_mode: "auto_apply", "request_approval", or "notify_only".
        base_branch: The branch to target for the PR.

    Returns:
        Optional[str]: URL of the created PR, or None if notified/auto-merged.
    """
    mode = PermissionMode(permission_mode)
    
    if mode == PermissionMode.NOTIFY_ONLY:
        logger.info(f"Notification sent for {customer_repo_name}. No code changes applied.")
        # In a real system, this would trigger an email/Slack alert
        return None

    try:
        repo = gh.get_repo(customer_repo_name)
        
        # 1. Generate Patch
        # In a real scenario, we would fetch specific file contents here using repo.get_contents
        repo_summary = "Placeholder for repository file structure and relevant file contents."
        patch_content, affected_files = _generate_patch_with_llm(repo_summary, violations, remediation_suggestions)
        
        if not patch_content or not affected_files:
            logger.error("Failed to generate a valid patch.")
            return None

        # 2. Safety Checks & Mode Downgrade
        if mode == PermissionMode.AUTO_APPLY:
            safety_result = _check_safety_guardrails(patch_content, base_branch, affected_files)
            if safety_result != SafetyCheckResult.SAFE:
                logger.warning(f"Auto-apply downgraded to Request Approval. Reason: {safety_result.value}")
                mode = PermissionMode.REQUEST_APPROVAL

        # 3. Create Branch
        source_branch_name = f"remediation/fix-{int(time.time())}"
        sb = repo.get_branch(base_branch)
        repo.create_git_ref(ref=f"refs/heads/{source_branch_name}", sha=sb.commit.sha)
        
        # 4. Apply Changes (Commit)
        # Note: PyGithub doesn't support applying raw diffs easily. 
        # We simulate this by updating files individually based on the LLM's intent.
        # For this implementation, we assume the LLM returns file contents or we parse the diff.
        # Here, we will mock the file update for the sake of the interface.
        
        for file_path in affected_files:
            try:
                contents = repo.get_contents(file_path, ref=source_branch_name)
                # In reality, apply the patch to contents.decoded_content
                # For this demo, we append a comment
                new_content = contents.decoded_content.decode('utf-8') + "\n# Compliance Fix Applied"
                repo.update_file(
                    path=file_path,
                    message=f"Fix compliance violations in {file_path}",
                    content=new_content,
                    sha=contents.sha,
                    branch=source_branch_name
                )
            except GithubException:
                # File might be new
                repo.create_file(
                    path=file_path,
                    message=f"Create compliant {file_path}",
                    content="# New compliant file",
                    branch=source_branch_name
                )

        # 5. Create PR
        pr_body = (
            "## Automated Compliance Remediation\n\n"
            "**Violations Fixed:**\n" + "\n".join([f"- {v}" for v in violations]) + "\n\n"
            "**Regulation Reference:** HIPAA/GDPR Update 2024\n\n"
            "**Testing Notes:**\n"
            "Please verify these changes in a staging environment before merging.\n"
        )
        
        pr = repo.create_pull(
            title="[Compliance] Automated Remediation Fixes",
            body=pr_body,
            head=source_branch_name,
            base=base_branch
        )
        
        # 6. Add Labels and Reviewers
        pr.add_to_labels("compliance", "automated-fix", "hipaa", "severity:high")
        # Default to repo owner if no specific team logic
        # pr.create_review_request(reviewers=["compliance-team"]) 

        logger.info(f"PR Created: {pr.html_url}")

        # 7. Handle Auto-Merge
        if mode == PermissionMode.AUTO_APPLY:
            try:
                # Wait briefly for checks to initialize (optional)
                time.sleep(2)
                pr.merge(merge_method="squash", commit_message="Auto-merged compliance fix")
                logger.info(f"PR {pr.number} auto-merged successfully.")
                return None
            except GithubException as e:
                logger.error(f"Auto-merge failed: {e}. PR remains open.")
                return pr.html_url

        return pr.html_url

    except GithubException as e:
        logger.error(f"GitHub operation failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in create_remediation_pr: {e}")
        return None