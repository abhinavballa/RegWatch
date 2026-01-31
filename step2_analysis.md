## Step 2: Deep Analysis

**Status:** Analysis Complete

### Feature Decomposition

| Feature | Functional Units | Candidate Module |
|---------|------------------|------------------|
| Code Compliance Checker | AST parsing, violation detection (encryption, auth, logging, SQL injection, credentials), report generation | `hipaa_encryption_checker`, `hipaa_access_control_checker`, `hipaa_audit_logging_checker` (3 separate PDD modules) |
| Data Compliance Checker | CSV parsing, patient record validation, consent checking, PHI encryption validation, access log verification | `patient_data_validator` |
| Scraper Agent | Web monitoring (HHS.gov, FDA.gov, Federal Register), regulation extraction, change detection | `scraper_agent` |
| Analysis Agent | Regulation text comparison, semantic diff, severity classification, checker mapping | `analysis_agent` |
| Impact Agent | Checker execution, customer codebase analysis, remediation effort estimation, risk prioritization | `impact_agent` |
| Remediation Agent | Prompt file updates, PDD sync orchestration, code patch generation, PR creation | `remediation_agent` |
| Change Tracking | Event logging, git diff tracking, test accumulation recording, audit trail | `change_tracker` |
| Voice Service | Real-time narration, executive briefing generation, alert broadcasting, conversational AI | `voice_service` |
| Web Dashboard | File upload, GitHub OAuth, scan results display, PDF/CSV export, regulation selector | `web_dashboard` (Flask app) |
| Orchestrator | Agent coordination, permission enforcement, workflow management, PDD sync triggering | `orchestrator` |

### Shared Concerns

- **Auth:** GitHub OAuth for repository access (out of scope for MVP per PRD §10). No user authentication system required for hackathon demo. Future: session-based auth with 15-min timeout per HIPAA requirements.
- **Error Handling:** Centralized exception handling with structured logging. Critical failures (agent errors, PDD sync failures) trigger voice alerts. Validation errors return structured JSON with violation details.
- **Logging:** Dual logging strategy: (1) Application logs for debugging/ops, (2) Audit trail in `regulation_changes.json` for compliance history. All agent actions logged with timestamps, regulation IDs, and impact metrics.
- **Validation:** Multi-layer validation: (1) Input validation (file uploads, CSV format), (2) AST-based code validation via checkers, (3) Data validation via patient record schemas, (4) Test accumulation validation (never delete tests).
- **Configuration:** JSON-based config for regulation sources, agent permissions, voice settings. Prompt files as config source of truth for compliance rules. Environment variables for API keys (Toolhouse, ElevenLabs, GitHub).

### Tech Stack (Confirmed)

**Backend:**
- Python 3.9+ (AST parsing requires modern Python)
- Flask 2.x (lightweight web framework for API + dashboard)

**Multi-Agent Orchestration:**
- Toolhouse.ai SDK (web_search, code_execution, RAG capabilities)

**Voice Integration:**
- ElevenLabs API (text-to-speech with Rachel professional voice)

**Code Analysis:**
- AST (Python stdlib for static analysis)
- Tree-sitter (inferred for JavaScript/Java parsing, not explicit in PRD)

**Data Processing:**
- Pandas 1.x+ (CSV/dataframe operations)
- JSON (stdlib for change logs)

**PDD Integration:**
- PDD CLI (prompt-driven regeneration via GitHub Issues)
- GitHub API / gh CLI (PR creation, OAuth)

**Testing:**
- pytest (inferred - standard Python testing, supports test accumulation)

**Storage:**
- File-based JSON for logs (`regulation_changes.json`)
- CSV for test data and coverage matrix

**Deployment (Demo Only):**
- Local Flask development server (production out of scope per §10)

**Justifications:**
- Python: Explicit in PRD §2, required for AST, Pandas, agent logic
- Flask: Explicit in PRD §2 for "simple dashboard"
- Toolhouse.ai: Explicit in PRD §2, §3.2 for all 4 agents
- ElevenLabs: Explicit in PRD §2, §3.5 for voice features
- Pandas: Explicit in PRD §2 for CSV processing
- AST: Explicit in PRD §3.1, §2 for code analysis
- JSON: Explicit in PRD §2, §3.3 for change logs
- PDD: Core methodology per PRD §1, §6

### Module Candidates

#### PDD-Generated Modules (3 checkers - one prompt each):
1. **hipaa_encryption_checker** - Validates database encryption, TLS, field-level PHI encryption, key management (§164.312(a)(2)(iv)). ~47 tests. (foundational)
2. **hipaa_access_control_checker** - Validates unique user IDs, RBAC, authentication, session mgmt, MFA (§164.312(a)(1)). ~38 tests. (foundational)
3. **hipaa_audit_logging_checker** - Validates ePHI access logging, retention, tamper-proofing, anomaly detection (§164.312(b)). ~25 tests. (foundational)

#### Agent Modules (4 agents - Toolhouse integration):
4. **scraper_agent** - Monitors regulatory sources, extracts regulation text, detects publications. Uses Toolhouse `web_search`. (foundational)
5. **analysis_agent** - Semantic diff of regulations, severity classification, checker mapping. Uses Toolhouse RAG + LLM. (dependent on scraper_agent)
6. **impact_agent** - Executes checkers on codebases, estimates remediation effort, prioritizes risks. Uses Toolhouse `code_execution`. (dependent on checkers, analysis_agent)
7. **remediation_agent** - Updates prompt files, triggers PDD sync, generates patches, creates PRs. Uses PDD CLI + GitHub API. (dependent on impact_agent)

#### Core System Modules:
8. **orchestrator** - Coordinates agent workflow, enforces permission modes (auto-apply/approval/notify), manages PDD sync triggers. (dependent on all agents)
9. **change_tracker** - Records regulation changes, tracks prompt diffs, accumulates test history, maintains audit trail (`logs/regulation_changes.json`). (foundational)
10. **voice_service** - ElevenLabs integration for narration, briefings, alerts, conversational AI. (foundational)
11. **patient_data_validator** - CSV/database validation for patient records, consent checking, PHI encryption verification. (foundational)

#### Web Interface:
12. **web_dashboard** - Flask app with upload UI, GitHub OAuth, scan results display, PDF/CSV export, regulation selector. (dependent on checkers, voice_service, patient_data_validator)

### Inter-Module Interfaces

**PDD Checker Interfaces:**
- `hipaa_*_checker` → `web_dashboard`: Violation report JSON with line numbers, regulation references, severity levels
- `hipaa_*_checker` → `impact_agent`: Scan results for customer codebase analysis

**Agent Flow:**
- `scraper_agent` → `analysis_agent`: Regulation text (old vs new)
- `analysis_agent` → `impact_agent`: Change metadata (severity, affected checkers)
- `impact_agent` → `remediation_agent`: Customer impact list, remediation plan
- `remediation_agent` → `orchestrator`: Prompt update requests, PDD sync triggers
- All agents → `change_tracker`: Event logs with timestamps, regulation IDs, actions

**Orchestrator Coordination:**
- `orchestrator` → `remediation_agent`: Permission mode enforcement (auto-apply/approval/notify)
- `orchestrator` → PDD CLI (via GitHub Issues): `pdd sync <module_name>` triggers
- `orchestrator` → `voice_service`: Alert notifications, briefing triggers

**Web Dashboard Integration:**
- `web_dashboard` → `hipaa_*_checker`: Codebase scan requests
- `web_dashboard` → `patient_data_validator`: CSV validation requests
- `web_dashboard` → `voice_service`: Real-time narration, briefing generation
- `web_dashboard` → `change_tracker`: Change history queries (GET /api/change-history)

**Voice Service:**
- `voice_service` ← All modules: Status updates, scan progress, alerts (unidirectional broadcast)

**Storage Interfaces:**
- `change_tracker` → `logs/regulation_changes.json`: Append-only event log
- All modules → Python logging: Structured logs for debugging

### Module Dependency Graph

Foundational (no dependencies):
- hipaa_encryption_checker (PDD-generated)
- hipaa_access_control_checker (PDD-generated)
- hipaa_audit_logging_checker (PDD-generated)
- patient_data_validator
- change_tracker
- voice_service
- scraper_agent

Dependent Layer 1:
- analysis_agent (depends on: scraper_agent)
- web_dashboard (depends on: checkers, patient_data_validator, voice_service, change_tracker)

Dependent Layer 2:
- impact_agent (depends on: checkers, analysis_agent)

Dependent Layer 3:
- remediation_agent (depends on: impact_agent)

Coordination Layer:
- orchestrator (depends on: all agents, change_tracker, voice_service)

### PDD Prompt File Mapping

Each PDD-generated module requires one prompt file:

1. `prompts/hipaa_encryption_python.prompt` → `src/checkers/hipaa_encryption_checker.py` + `tests/test_hipaa_encryption_checker.py`
2. `prompts/hipaa_access_control_python.prompt` → `src/checkers/hipaa_access_control_checker.py` + `tests/test_hipaa_access_control_checker.py`
3. `prompts/hipaa_audit_logging_python.prompt` → `src/checkers/hipaa_audit_logging_checker.py` + `tests/test_hipaa_audit_logging_checker.py`

Other modules (agents, orchestrator, web dashboard) are hand-coded, not PDD-generated.

### Key Architectural Decisions

1. **Checker Modularity:** Each HIPAA requirement = separate PDD module for independent regeneration when regulations change.
2. **Agent Separation:** 4 distinct agents (scraper, analysis, impact, remediation) enable parallel development and testing.
3. **Orchestrator Pattern:** Central coordinator enforces permission modes and manages cross-cutting concerns.
4. **Audit Trail Centralization:** Single `change_tracker` module ensures consistent event logging.
5. **Voice as Broadcast:** `voice_service` receives events from all modules but doesn't control flow (unidirectional).
6. **PDD Boundary:** Only compliance checkers are PDD-generated; agents/orchestrator are traditional code for flexibility.

---
*Proceeding to Step 3: Research*
