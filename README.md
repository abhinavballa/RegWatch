# RegWatch - Automated Compliance Monitoring System

**Version:** 1.0 Hackathon MVP
**Status:** Development
**Tech Stack:** Python + Flask + Toolhouse.ai + ElevenLabs + PDD

## Overview

RegWatch is an automated compliance monitoring system that detects regulatory changes, analyzes impact on codebases and patient data, and auto-remediates violations using Prompt-Driven Development (PDD). The system showcases:

- **Multi-Agent Orchestration**: 4 Toolhouse-powered agents (scraper, analysis, impact, remediation)
- **PDD-First Architecture**: Regulations encoded as prompts, code regenerated automatically
- **Dual Compliance Validation**: Code analysis via AST + patient data validation via Pandas
- **Voice Integration**: Real-time narration and executive briefings via ElevenLabs
- **Self-Healing**: Automated remediation with permission controls and safety guardrails
- **Test Accumulation**: Tests never deleted, only added - permanent compliance proof

## Project Structure

```
regwatch/
├── architecture.json          # PDD architecture definition (12 modules)
├── prompts/                   # Prompt files (source of truth for regulations)
│   ├── hipaa_encryption_checker_Python.prompt
│   ├── hipaa_access_control_checker_Python.prompt
│   └── hipaa_audit_logging_checker_Python.prompt
├── src/
│   ├── checkers/              # PDD-generated compliance checkers
│   ├── agents/                # Multi-agent system (Toolhouse)
│   ├── validators/            # Patient data validator
│   ├── orchestrator.py        # Workflow coordination
│   ├── change_tracker.py      # Audit trail
│   └── voice_service.py       # ElevenLabs integration
├── web/
│   ├── app.py                 # Flask API + dashboard
│   ├── templates/             # HTML templates
│   └── static/                # CSS + JS
├── tests/                     # PDD-generated tests (accumulated)
├── test_codebases/            # Sample hospital codebases
├── test_data/                 # Sample patient CSV files
├── logs/
│   └── regulation_changes.json # Change audit trail
└── docs/
    └── hipaa_coverage_matrix.csv
```

## Prerequisites

- Python 3.10+
- PDD CLI installed (`pip install pdd-cli`)
- PDD GitHub App installed on repository
- API Keys:
  - Toolhouse.ai API key
  - ElevenLabs API key
  - GitHub Personal Access Token

## Installation

1. **Clone and setup**:
   ```bash
   git clone https://github.com/abhinavballa/RegWatch.git
   cd RegWatch
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys:
   # TOOLHOUSE_API_KEY=your_key
   # ELEVENLABS_API_KEY=your_key
   # GITHUB_TOKEN=your_token
   ```

3. **Install PDD GitHub App**:
   - Visit https://github.com/apps/prompt-driven
   - Install on your repository
   - Grant necessary permissions

## Running Locally

### 1. Generate Compliance Checkers (PDD)

```bash
# Generate all modules from architecture.json
pdd sync hipaa_encryption_checker
pdd sync hipaa_access_control_checker
pdd sync hipaa_audit_logging_checker

# Or generate all at once:
pdd sync --all
```

### 2. Run Web Dashboard

```bash
python web/app.py
```

Visit http://localhost:5000 to access the dashboard.

### 3. Run Multi-Agent Monitoring (Background)

```bash
python -m src.orchestrator
```

### 4. Run Tests

```bash
pytest tests/ -v --cov=src
```

## Architecture Overview

### 12 Modules (Priority Order)

1. **change_tracker** - Audit trail for regulation updates
2. **voice_service** - ElevenLabs narration and briefings
3. **hipaa_encryption_checker** - HIPAA § 164.312(a)(2)(iv) compliance (~47 tests)
4. **hipaa_access_control_checker** - HIPAA § 164.312(a)(1) compliance (~38 tests)
5. **hipaa_audit_logging_checker** - HIPAA § 164.312(b) compliance (~25 tests)
6. **patient_data_validator** - CSV patient record validation
7. **scraper_agent** - Monitors HHS.gov, FDA.gov, Federal Register
8. **analysis_agent** - Semantic diff + impact analysis
9. **impact_agent** - Runs checkers on customer codebases
10. **remediation_agent** - Updates prompts + creates PRs
11. **orchestrator** - Coordinates workflow + permissions
12. **web_app** - Flask API + dashboard

### Multi-Agent Workflow

```
Scraper Agent → Analysis Agent → Impact Agent → Remediation Agent
     ↓               ↓                ↓                ↓
  Monitors      Semantic Diff    Runs Checkers   Updates Prompts
  Regulations   + Severity       on Codebases    + Creates PRs
                                                       ↓
                                                 Orchestrator
                                                 (Permission Check)
                                                       ↓
                                                 Auto-Apply / PR / Notify
```

### API Endpoints

- `POST /api/scan` - Upload codebase ZIP, get violation report
- `POST /api/validate-records` - Upload patient CSV, get compliance report
- `POST /api/simulate-regulation-change` - Demo regulation update workflow
- `GET /api/change-history` - Retrieve audit trail
- `POST /api/voice-briefing` - Generate executive audio summary

## HIPAA Coverage

**Phase 1 (Hackathon MVP):**
- ✅ Encryption (§ 164.312(a)(2)(iv)) - ~47 tests
- ✅ Access Control (§ 164.312(a)(1)) - ~38 tests
- ✅ Audit Logging (§ 164.312(b)) - ~25 tests

**Phase 2+ (Roadmap):**
- 42 additional HIPAA Security Rule requirements (see docs/hipaa_coverage_matrix.csv)
- GDPR, SOX, PCI-DSS support

## Demo Scenarios

### 1. Code Compliance Scan
```bash
# Upload test codebase via dashboard or API
curl -X POST http://localhost:5000/api/scan \
  -F "codebase=@test_codebases/st_marys_hospital.zip"
```

### 2. Data Compliance Validation
```bash
# Upload patient records CSV
curl -X POST http://localhost:5000/api/validate-records \
  -F "records=@test_data/st_marys_patients.csv"
```

### 3. Simulate Regulation Change
```bash
# Trigger self-healing workflow
curl -X POST http://localhost:5000/api/simulate-regulation-change \
  -H "Content-Type: application/json" \
  -d '{
    "regulation_id": "HIPAA § 164.312(a)(2)(iv)",
    "new_text": "Encryption must use AES-512-GCM (updated from AES-256)"
  }'
```

## Permission Modes

- **Auto-Apply**: Automatically merges approved changes (for trusted customers)
- **Request Approval** (Default): Creates PR for review before merging
- **Notify Only**: Alerts but doesn't change anything

### Safety Guardrails

**Never Auto-Apply:**
- Security vulnerability patches
- Breaking changes
- Database schema modifications
- Authentication/authorization changes

**Always Require Approval:**
- Changes affecting >10 files
- Changes with failing tests
- Changes to production configs

## Test Accumulation Strategy

Tests are **never deleted**, only added:
- Old regulation tests preserved (backward compatibility)
- New regulation tests added
- Creates permanent compliance verification trail
- Example: 47 tests → 50 tests → 54 tests

## Development

### Adding New Compliance Checkers

1. Create prompt file in `prompts/`:
   ```bash
   touch prompts/gdpr_retention_checker_Python.prompt
   ```

2. Add to `architecture.json`:
   ```json
   {
     "reason": "GDPR data retention compliance",
     "description": "...",
     "dependencies": [],
     "priority": 13,
     "filename": "gdpr_retention_checker_Python.prompt",
     "filepath": "src/checkers/gdpr_retention_checker.py"
   }
   ```

3. Generate code via PDD:
   ```bash
   pdd sync gdpr_retention_checker
   ```

### Updating Regulations

1. Edit prompt file with new requirements
2. Run `pdd sync <module_name>`
3. PDD regenerates code, preserving existing tests
4. Review PR and merge

## License

MIT License - See LICENSE file

## Team

Trin + Partner

## Links

- GitHub: https://github.com/abhinavballa/RegWatch
- Devpost: [TBD]
- Demo Video: [TBD]
