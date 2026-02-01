# GitHub Integration Guide

## Overview

RegWatch now has **full GitHub integration** that allows users to connect their repositories for automated compliance monitoring. When issues are found, RegWatch creates PRs or Issues **on YOUR repositories**, not on the RegWatch repo.

## How It Works

### 1. **User Authentication via GitHub OAuth**

Users authenticate with GitHub using OAuth, granting RegWatch permission to:
- Read their repositories
- Create branches, commits, and pull requests
- Create issues

**Flow:**
```
User clicks "Connect with GitHub" → GitHub OAuth page → User grants permissions → Redirected to RegWatch with access token
```

### 2. **Repository Connection**

After authentication, users can:
- Browse all their GitHub repositories
- Connect specific repos for monitoring
- Filter by language (Python, JavaScript, Java, Go)
- Search repositories by name

**Endpoints:**
- `GET /api/github/repos` - List all accessible repositories
- `POST /api/github/repos/connect` - Connect a repository for monitoring

### 3. **Automated Compliance Scanning**

When a repo is connected:
- RegWatch clones it to a temporary directory
- Runs HIPAA compliance checkers (encryption, access control, audit logging)
- Calculates compliance score and fine exposure
- Stores results

**Endpoint:**
- `POST /api/github/repos/{repo_full_name}/scan` - Scan a GitHub repository

### 4. **PR/Issue Creation on User's Repos**

This is the key feature you asked about!

**When compliance issues are found:**

#### Auto-Fixable Issues → Creates Pull Request
If RegWatch can automatically fix the issue:
1. Creates a new branch on **YOUR repo** (e.g., `regwatch/fix-1738449284`)
2. Commits the fix with your GitHub token
3. Creates a PR on **YOUR repo** with:
   - Detailed description of the violation
   - Code changes made
   - Testing instructions
   - Regulation reference (e.g., HIPAA § 164.312(a)(2)(iv))

**Example PR:**
```
Repository: abhinavballa/my-healthcare-app
PR: regwatch/fix-1738449284 → main
Title: "Compliance Fix: HIPAA § 164.312(a)(2)(iv)"
Created by: YOUR GitHub account (using your token)
```

#### Complex Issues → Creates Git Issue
If the issue is too complex for automated fixing:
1. Creates an Issue on **YOUR repo**
2. Includes:
   - Detailed problem description
   - Required changes for compliance
   - Impact on current codebase
   - Step-by-step remediation guide
   - Testing requirements

**Example Issue:**
```
Repository: abhinavballa/my-healthcare-app
Issue: "HIPAA Compliance: Complex Authentication Flow Requires Custom Implementation"
Created by: YOUR GitHub account (using your token)
```

### 5. **Permission Modes**

You control how RegWatch handles fixes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Auto-Apply** | Automatically merges approved PRs | Trusted repos, minor fixes |
| **Request Approval** (Default) | Creates PR for your review | Most cases - you review before merge |
| **Notify Only** | Creates Issue, no code changes | High-risk repos, strict change control |

## Technical Implementation

### OAuth Configuration

Add to your `.env` file:
```bash
# GitHub OAuth (for user authentication)
GITHUB_CLIENT_ID=your_github_oauth_client_id_here
GITHUB_CLIENT_SECRET=your_github_oauth_client_secret_here
GITHUB_CALLBACK_URL=http://localhost:5001/auth/github/callback
```

### Create GitHub OAuth App

1. Go to: https://github.com/settings/developers
2. Click "New OAuth App"
3. Fill in:
   - **Application name:** RegWatch Compliance Monitor
   - **Homepage URL:** http://localhost:5001
   - **Authorization callback URL:** http://localhost:5001/auth/github/callback
4. Click "Register application"
5. Copy the **Client ID** and **Client Secret** to your `.env` file

### Routes

#### Authentication
- `GET /auth/github` - Initiates GitHub OAuth flow
- `GET /auth/github/callback` - Handles OAuth callback
- `POST /auth/github/disconnect` - Disconnects GitHub

#### Repositories
- `GET /repos` - Repository management page
- `GET /api/github/repos` - List user's repositories
- `POST /api/github/repos/connect` - Connect a repository
- `POST /api/github/repos/{repo_full_name}/scan` - Scan a repository

### Session Storage

User's GitHub token is stored in the Flask session:
```python
session['github_token']      # User's access token
session['github_user']       # GitHub username
session['github_user_id']    # GitHub user ID
session['connected_repos']   # List of connected repo names
```

### Remediation Agent Integration

The `create_remediation_pr()` function now accepts `user_github_token` parameter:

```python
from src.remediation_agent import create_remediation_pr

# Create PR on user's repository with their credentials
pr_url = create_remediation_pr(
    customer_repo_name="abhinavballa/my-app",  # USER'S REPO
    patch={"path/to/file.py": "fixed_content"},
    permission_mode="request_approval",
    regulation_ref="HIPAA § 164.312(a)(2)(iv)",
    violation_summary="Unencrypted database connection",
    user_github_token=session['github_token']  # USER'S TOKEN
)
```

**This ensures:**
- ✅ PRs are created on the user's repository
- ✅ PRs use the user's GitHub credentials
- ✅ PRs appear as created by the user (not RegWatch)
- ✅ User has full control over merging

## User Flow

### First-Time Setup

1. **Connect GitHub Account**
   - Visit: http://localhost:5001/repos
   - Click "Connect with GitHub"
   - Grant permissions on GitHub OAuth page
   - Redirected back to RegWatch

2. **Connect Repositories**
   - Browse your repositories
   - Click "Connect for Monitoring" on repos you want to monitor
   - Connected repos show "✓ Connected" status

3. **Configure Monitoring**
   - Set permission mode (Auto-Apply / Request Approval / Notify Only)
   - Select active regulation (HIPAA, GDPR, etc.)

### Daily Usage

1. **Automatic Monitoring** (if orchestrator is running)
   - RegWatch monitors connected repos
   - Detects code changes via webhooks (future feature)
   - Runs compliance checks automatically

2. **Manual Scanning**
   - Click "Scan Now" on any connected repo
   - View compliance score and violations
   - Review PRs/Issues created for fixes

3. **Review PRs**
   - Go to your GitHub repository
   - Review PRs created by RegWatch
   - Merge if satisfied, request changes if needed

## Security Considerations

### Token Storage
- User tokens stored in encrypted Flask sessions
- Sessions expire after inactivity
- Tokens never logged or exposed in URLs

### Permissions
- RegWatch only requests `repo` and `read:user` scopes
- Cannot access private repos unless explicitly granted
- Cannot force-push or delete branches

### Safety Guardrails
- Never auto-applies changes to authentication/encryption code
- Never auto-applies changes affecting >10 files
- Never auto-applies changes with failing tests
- Always requires approval for production branch changes

## Future Enhancements

- [ ] Webhook integration for real-time monitoring
- [ ] Slack/Email notifications for PRs/Issues
- [ ] Support for multiple GitHub accounts
- [ ] Repository health dashboard
- [ ] Automatic PR reviews using AI
- [ ] Integration with GitHub Actions for testing

## Troubleshooting

### "Not authenticated with GitHub"
- Go to `/repos` and click "Connect with GitHub"
- Ensure OAuth app is configured in `.env`

### "Failed to create PR"
- Check that you have write access to the repository
- Verify GitHub token has `repo` scope
- Check that the repository exists and is accessible

### "Permission denied"
- Ensure the repository is owned by you or your organization
- Check that you granted the `repo` permission during OAuth

## Summary

**The key point:** RegWatch now operates like a compliance assistant for YOUR repositories. It doesn't make changes to its own repo - it monitors YOUR repos and creates PRs/Issues on YOUR repos using YOUR GitHub credentials.

This is exactly what you wanted: users connect their repos, and RegWatch acts on their behalf to maintain compliance!
