# RegWatch - Automated Compliance Monitoring System

**Version:** 1.0 Hackathon MVP
**Status:** Development
**Tech Stack:** Python, Flask, Toolhouse.ai, ElevenLabs, PDD

## Overview

RegWatch is an automated compliance monitoring system that detects regulatory changes, analyzes impact on codebases and patient data, and auto-remediates violations using Prompt-Driven Development (PDD). The system uses multi-agent orchestration to continuously monitor HIPAA regulations, regenerate compliance checkers when rules change, and provide voice-powered alerts and briefings.

## Key Features

- **Dual Compliance Validation**: Code analysis (AST-based) + Data validation (CSV/database)
- **Multi-Agent Monitoring**: 4-agent pipeline (Scraper → Analysis → Impact → Remediation)
- **Self-Healing Compliance**: Automatic code regeneration via PDD when regulations change
- **Voice Integration**: Real-time narration, executive briefings, regulation alerts (ElevenLabs)
- **Test Accumulation**: Tests never deleted, only added (permanent compliance proof)
- **Change Tracking**: Complete audit trail of all regulation updates and code modifications

## Architecture

### 12 PDD Modules (Priority Order)

**Priority 1-3: HIPAA Compliance Checkers** (PDD-Generated)
- `hipaa_encryption_checker` - Database encryption validation (HIPAA § 164.312(a)(2)(iv))
- `hipaa_access_control_checker` - Authentication/RBAC validation (HIPAA § 164.312(a)(1))
- `hipaa_audit_logging_checker` - Audit logging validation (HIPAA § 164.312(b))

**Priority 4-6: Core Services**
- `change_tracker` - Audit trail management (logs/regulation_changes.json)
- `voice_service` - ElevenLabs integration (narration, briefings, alerts)
- `patient_data_validator` - Data compliance checking (CSV/pandas)

**Priority 7-10: Multi-Agent System** (Toolhouse.ai)
- `scraper_agent` - Monitors HHS.gov, FDA.gov, Federal Register
- `analysis_agent` - Semantic diff of regulation changes
- `impact_agent` - Analyzes customer codebase impact
- `remediation_agent` - Auto-generates fixes, creates PRs

**Priority 11-12: Coordination & Web Interface**
- `orchestrator` - Agent coordination & permissions
- `web_dashboard` - Flask web interface (code/data compliance tabs)

### Directory Structure

```
regwatch/
├── prompts/                          # PDD prompt files (source of truth)
│   ├── hipaa_encryption_checker_Python.prompt
│   ├── hipaa_access_control_checker_Python.prompt
│   ├── hipaa_audit_logging_checker_Python.prompt
│   ├── change_tracker_Python.prompt
│   ├── voice_service_Python.prompt
│   ├── patient_data_validator_Python.prompt
│   ├── scraper_agent_Python.prompt
│   ├── analysis_agent_Python.prompt
│   ├── impact_agent_Python.prompt
│   ├── remediation_agent_Python.prompt
│   ├── orchestrator_Python.prompt
│   └── web_dashboard_Python.prompt
│
├── src/                              # PDD-generated code
│   ├── checkers/                     # HIPAA compliance checkers
│   │   ├── hipaa_encryption_checker.py
│   │   ├── hipaa_access_control_checker.py
│   │   └── hipaa_audit_logging_checker.py
│   ├── agents/                       # Multi-agent system
│   │   ├── scraper_agent.py
│   │   ├── analysis_agent.py
│   │   ├── impact_agent.py
│   │   └── remediation_agent.py
│   ├── validators/
│   │   └── patient_data_validator.py
│   ├── orchestrator.py
│   ├── change_tracker.py
│   └── voice_service.py
│
├── web/                              # Flask web dashboard
│   ├── app.py
│   ├── templates/
│   │   ├── index.html
│   │   ├── code_compliance.html
│   │   └── data_compliance.html
│   └── static/
│       ├── style.css
│       └── dashboard.js
│
├── tests/                            # PDD-generated tests (accumulated)
│   ├── test_hipaa_encryption_checker.py
│   ├── test_hipaa_access_control_checker.py
│   └── test_hipaa_audit_logging_checker.py
│
├── test_codebases/                   # Sample codebases for testing
│   ├── st_marys_hospital/           # Bad (23/100)
│   ├── memorial_hospital/           # Good (96/100)
│   └── community_health/            # Medium (67/100)
│
├── test_data/                        # Sample patient data
│   ├── st_marys_patients.csv        # 1,247 violations
│   └── memorial_patients.csv        # 50 violations
│
├── docs/
│   └── hipaa_coverage_matrix.csv    # All 45 HIPAA requirements mapped
│
├── logs/
│   └── regulation_changes.json      # Audit trail
│
├── demo/
│   ├── master_demo.sh
│   ├── simulate_regulation_change.py
│   └── view_change_history.py
│
├── .env.example
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Prerequisites

- **Python:** 3.9 or higher
- **PDD CLI:** Installed and configured
- **GitHub Account:** For PDD GitHub App integration
- **API Keys:**
  - Toolhouse.ai API key
  - ElevenLabs API key
  - GitHub Personal Access Token

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/abhinavballa/RegWatch.git
cd RegWatch
```

### 2. Set Up Python Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env with your API keys:
# TOOLHOUSE_API_KEY=your_toolhouse_key
# ELEVENLABS_API_KEY=your_elevenlabs_key
# GITHUB_TOKEN=your_github_token
```

### 4. Install PDD GitHub App

1. Visit the [Prompt-Driven GitHub App](https://github.com/apps/prompt-driven)
2. Install on your RegWatch repository
3. Link your GitHub account to PDD Cloud

### 5. Generate Code with PDD

```bash
# Generate all modules from architecture.json
pdd sync hipaa_encryption_checker
pdd sync hipaa_access_control_checker
pdd sync hipaa_audit_logging_checker
pdd sync change_tracker
pdd sync voice_service
pdd sync patient_data_validator
pdd sync scraper_agent
pdd sync analysis_agent
pdd sync impact_agent
pdd sync remediation_agent
pdd sync orchestrator
pdd sync web_dashboard
```

Alternatively, use GitHub Issues with `pdd` and `generate` labels to trigger automated generation.

## Running Locally

### Start the Web Dashboard

```bash
cd web
python app.py
```

The dashboard will be available at `http://localhost:5000`

### Run the Multi-Agent Monitoring Cycle

```bash
python -m src.orchestrator
```

### Run Compliance Checks Manually

```bash
# Code compliance check
python -m src.checkers.hipaa_encryption_checker test_codebases/st_marys_hospital/

# Data compliance check
python -m src.validators.patient_data_validator test_data/st_marys_patients.csv
```

## Usage

### Web Dashboard

1. **Navigate to** `http://localhost:5000`
2. **Code Compliance Tab:**
   - Upload codebase ZIP file or connect GitHub repository
   - View real-time scan with voice narration
   - See violations with line numbers and remediation suggestions
   - Download PDF report or export checklist
3. **Data Compliance Tab:**
   - Upload patient records CSV
   - View validation results with patient IDs
   - Get voice briefing on compliance status
   - Export remediation checklist

### API Endpoints

```bash
# Scan codebase
curl -X POST -F "file=@codebase.zip" http://localhost:5000/api/scan

# Validate patient records
curl -X POST -F "file=@patients.csv" http://localhost:5000/api/validate-records

# Simulate regulation change (for demo)
curl -X POST -H "Content-Type: application/json" \
  -d '{"regulation_id": "HIPAA § 164.312(a)(2)(iv)", "new_text": "..."}' \
  http://localhost:5000/api/simulate-regulation-change

# Get change history
curl http://localhost:5000/api/change-history

# Generate voice briefing
curl -X POST -H "Content-Type: application/json" \
  -d '{"scan_results": {...}}' \
  http://localhost:5000/api/voice-briefing --output briefing.mp3
```

## Development

### Running Tests

```bash
pytest
pytest --cov=src tests/
```

### Code Formatting

```bash
black src/ tests/ web/
flake8 src/ tests/ web/
mypy src/
```

### PDD Workflow

1. **Modify prompt file** (e.g., `prompts/hipaa_encryption_checker_Python.prompt`)
2. **Regenerate code:** `pdd sync hipaa_encryption_checker`
3. **Review PR** created by PDD
4. **Merge** when tests pass

## Docker

### Build and Run

```bash
docker-compose up --build
```

The dashboard will be available at `http://localhost:5000`

## Demo Scenarios

### 1. Self-Healing Compliance

```bash
python demo/simulate_regulation_change.py --regulation HIPAA_encryption --change "AES-256 → AES-512"
# Watch the agents detect, analyze, regenerate code, and create PR
```

### 2. View Change History

```bash
python demo/view_change_history.py
# See complete audit trail with test accumulation (47 → 50 → 54 tests)
```

### 3. Master Demo

```bash
./demo/master_demo.sh
# Runs all demo scenarios end-to-end
```

## HIPAA Coverage

**Phase 1 (Hackathon MVP):** 3 Active Checkers
- Encryption Checker (§ 164.312(a)(2)(iv)) - ~47 tests
- Access Control Checker (§ 164.312(a)(1)) - ~38 tests
- Audit Logging Checker (§ 164.312(b)) - ~25 tests

**Phase 2+ (Roadmap):** 42 Additional Requirements
- See `docs/hipaa_coverage_matrix.csv` for full coverage plan
- Total: 45 HIPAA Security Rule requirements

## Permission Modes

1. **Auto-Apply**: System automatically merges approved changes (trusted customers)
2. **Request Approval** (Default): System creates PR for review
3. **Notify Only**: System alerts but doesn't change anything

**Safety Guardrails:**
- Never auto-apply security patches
- Require approval for breaking changes
- Require approval for database schema modifications

## Technologies

- **Python 3.9+** - Backend language
- **Flask 3.1** - Web framework
- **Toolhouse.ai** - Multi-agent orchestration
- **ElevenLabs** - Voice synthesis (Turbo v2.5)
- **Python AST** - Static code analysis
- **Tree-sitter** - Multi-language parsing
- **Pandas 2.2+** - CSV/data processing
- **PyGithub** - GitHub API integration
- **pytest** - Testing framework

## Contributing

This is a hackathon MVP. For production use, additional features needed:
- User authentication
- Database persistence (PostgreSQL)
- Production deployment (Docker/K8s)
- Additional regulations (GDPR, SOX, PCI-DSS)
- Email/Slack integrations
- Advanced analytics

## License

MIT License (see LICENSE file)

## Team

Built by Trin + Partner for [Hackathon Name]

## Support

For issues or questions:
- GitHub Issues: https://github.com/abhinavballa/RegWatch/issues
- PDD Documentation: https://pdd.dev/docs

---

**Powered by Prompt-Driven Development (PDD)**
