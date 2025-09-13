# Implementation Plan: Fix and Secure 15-Minute Authentication Session

**Branch**: `002-the-auth-feature` | **Date**: 2025-01-12 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/002-the-auth-feature/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path
   → If not found: ERROR "No feature spec at {path}"
2. Fill Technical Context (scan for NEEDS CLARIFICATION)
   → Detect Project Type from context (web=frontend+backend, mobile=app+api)
   → Set Structure Decision based on project type
3. Evaluate Constitution Check section below
   → If violations exist: Document in Complexity Tracking
   → If no justification possible: ERROR "Simplify approach first"
   → Update Progress Tracking: Initial Constitution Check
4. Execute Phase 0 → research.md
   → If NEEDS CLARIFICATION remain: ERROR "Resolve unknowns"
5. Execute Phase 1 → contracts, data-model.md, quickstart.md, agent-specific template file (e.g., `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md` for GitHub Copilot, or `GEMINI.md` for Gemini CLI).
6. Re-evaluate Constitution Check section
   → If new violations: Refactor design, return to Phase 1
   → Update Progress Tracking: Post-Design Constitution Check
7. Plan Phase 2 → Describe task generation approach (DO NOT create tasks.md)
8. STOP - Ready for /tasks command
```

**IMPORTANT**: The /plan command STOPS at step 7. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary
Fix the broken 15-minute authentication session feature in the LocalPass CLI password manager to properly maintain user sessions with rolling timeout, secure memory handling, and comprehensive audit logging. The current implementation has session management components but requires fixes to ensure proper timeout behavior, session persistence across commands, and security hardening against session hijacking.

## Technical Context
**Language/Version**: Python 3.13+  
**Primary Dependencies**: typer[all]>=0.12.0, cryptography>=41.0.0, argon2-cffi>=23.1.0  
**Storage**: SQLite with field-level encryption  
**Testing**: pytest>=7.4.0, pytest-cov, pytest-asyncio  
**Target Platform**: Cross-platform CLI (Linux/macOS/Windows)
**Project Type**: single - CLI application with library structure  
**Performance Goals**: Session validation <10ms, memory clearing <1ms  
**Constraints**: Zero persistent sessions across app restarts, secure memory handling required  
**Scale/Scope**: Single-user local password manager, ~5k LOC

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Simplicity**:
- Projects: 1 (cli with tests)
- Using framework directly? YES (Typer CLI framework directly)
- Single data model? YES (Session, MasterCredential models only)
- Avoiding patterns? YES (Direct service calls, no unnecessary abstraction)

**Architecture**:
- EVERY feature as library? YES (session_service, auth_service libraries)
- Libraries listed: 
  - session_service: Session management with timeout
  - auth_service: Authentication and session creation
  - encryption_service: Secure memory handling
- CLI per library: Each service exposed via CLI commands
- Library docs: Will be included in docstrings

**Testing (NON-NEGOTIABLE)**:
- RED-GREEN-Refactor cycle enforced? YES
- Git commits show tests before implementation? YES
- Order: Contract→Integration→E2E→Unit strictly followed? YES
- Real dependencies used? YES (SQLite, real crypto)
- Integration tests for: new libraries, contract changes, shared schemas? YES
- FORBIDDEN: Implementation before test, skipping RED phase ✓

**Observability**:
- Structured logging included? YES (audit events for auth)
- Frontend logs → backend? N/A (CLI only)
- Error context sufficient? YES

**Versioning**:
- Version number assigned? YES (1.0.0 in pyproject.toml)
- BUILD increments on every change? Will follow
- Breaking changes handled? N/A (fixing broken feature)

## Project Structure

### Documentation (this feature)
```
specs/[###-feature]/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
# Option 1: Single project (DEFAULT)
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# Option 2: Web application (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# Option 3: Mobile + API (when "iOS/Android" detected)
api/
└── [same as backend above]

ios/ or android/
└── [platform-specific structure]
```

**Structure Decision**: Option 1 (Single project - CLI application with library structure)

## Phase 0: Outline & Research
1. **Extract unknowns from Technical Context** above:
   - For each NEEDS CLARIFICATION → research task
   - For each dependency → best practices task
   - For each integration → patterns task

2. **Generate and dispatch research agents**:
   ```
   For each unknown in Technical Context:
     Task: "Research {unknown} for {feature context}"
   For each technology choice:
     Task: "Find best practices for {tech} in {domain}"
   ```

3. **Consolidate findings** in `research.md` using format:
   - Decision: [what was chosen]
   - Rationale: [why chosen]
   - Alternatives considered: [what else evaluated]

**Output**: research.md with all NEEDS CLARIFICATION resolved

## Phase 1: Design & Contracts
*Prerequisites: research.md complete*

1. **Extract entities from feature spec** → `data-model.md`:
   - Entity name, fields, relationships
   - Validation rules from requirements
   - State transitions if applicable

2. **Generate API contracts** from functional requirements:
   - For each user action → endpoint
   - Use standard REST/GraphQL patterns
   - Output OpenAPI/GraphQL schema to `/contracts/`

3. **Generate contract tests** from contracts:
   - One test file per endpoint
   - Assert request/response schemas
   - Tests must fail (no implementation yet)

4. **Extract test scenarios** from user stories:
   - Each story → integration test scenario
   - Quickstart test = story validation steps

5. **Update agent file incrementally** (O(1) operation):
   - Run `/scripts/update-agent-context.sh [claude|gemini|copilot]` for your AI assistant
   - If exists: Add only NEW tech from current plan
   - Preserve manual additions between markers
   - Update recent changes (keep last 3)
   - Keep under 150 lines for token efficiency
   - Output to repository root

**Output**: data-model.md, /contracts/*, failing tests, quickstart.md, agent-specific file

## Phase 2: Task Planning Approach
*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:
- Load `/templates/tasks-template.md` as base
- Generate tasks from Phase 1 design docs (contracts, data model, quickstart)
- Session persistence tasks (highest priority)
- Audit logging tasks (compliance requirement)
- Security hardening tasks (memory clearing)
- Each contract → contract test task [P]
- Each entity → model enhancement task [P] 
- Each user story → integration test task
- Implementation tasks to make tests pass

**Specific Task Categories**:
1. **Session Persistence** (Tasks 1-8)
   - Create session storage service
   - Implement encrypted file operations
   - Add platform-specific path handling
   - Create persistence tests

2. **Session Management** (Tasks 9-15)
   - Fix session validation logic
   - Implement rolling timeout
   - Add session extension on activity
   - Create session management tests

3. **Audit Logging** (Tasks 16-20)
   - Create audit service
   - Implement JSON Lines writer
   - Add event tracking
   - Create audit tests

4. **Security Hardening** (Tasks 21-25)
   - Implement secure memory clearing
   - Add file permission enforcement
   - Create security tests

5. **Integration** (Tasks 26-30)
   - Wire up session persistence to CLI
   - Add session decorators to commands
   - Full end-to-end testing

**Ordering Strategy**:
- TDD order: Tests before implementation 
- Priority order: Persistence → Management → Audit → Security
- Dependency order: Models before services before CLI integration
- Mark [P] for parallel execution (independent files)

**Estimated Output**: 30-35 numbered, ordered tasks in tasks.md

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation
*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)  
**Phase 4**: Implementation (execute tasks.md following constitutional principles)  
**Phase 5**: Validation (run tests, execute quickstart.md, performance validation)

## Complexity Tracking
*Fill ONLY if Constitution Check has violations that must be justified*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |


## Progress Tracking
*This checklist is updated during execution flow*

**Phase Status**:
- [x] Phase 0: Research complete (/plan command)
- [x] Phase 1: Design complete (/plan command)
- [x] Phase 2: Task planning complete (/plan command - describe approach only)
- [ ] Phase 3: Tasks generated (/tasks command)
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS
- [x] Post-Design Constitution Check: PASS
- [x] All NEEDS CLARIFICATION resolved
- [x] Complexity deviations documented (none required)

---
*Based on Constitution v2.1.1 - See `/memory/constitution.md`*