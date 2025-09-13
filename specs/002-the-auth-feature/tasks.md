# Tasks: Fix and Secure 15-Minute Authentication Session

**Input**: Design documents from `/specs/002-the-auth-feature/`
**Prerequisites**: plan.md (required), research.md, data-model.md, contracts/

## Execution Flow (main)
```
1. Load plan.md from feature directory
   → If not found: ERROR "No implementation plan found"
   → Extract: tech stack, libraries, structure
2. Load optional design documents:
   → data-model.md: Extract entities → model tasks
   → contracts/: Each file → contract test task
   → research.md: Extract decisions → setup tasks
3. Generate tasks by category:
   → Setup: project init, dependencies, linting
   → Tests: contract tests, integration tests
   → Core: models, services, CLI commands
   → Integration: DB, middleware, logging
   → Polish: unit tests, performance, docs
4. Apply task rules:
   → Different files = mark [P] for parallel
   → Same file = sequential (no [P])
   → Tests before implementation (TDD)
5. Number tasks sequentially (T001, T002...)
6. Generate dependency graph
7. Create parallel execution examples
8. Validate task completeness:
   → All contracts have tests?
   → All entities have models?
   → All endpoints implemented?
9. Return: SUCCESS (tasks ready for execution)
```

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Path Conventions
- **Single project**: `src/`, `tests/` at repository root
- Paths shown below follow single project structure per plan.md

## Phase 3.1: Setup & Configuration
- [ ] T001 Create session storage directories with proper permissions in src/services/storage/
- [ ] T002 [P] Install platformdirs dependency for cross-platform path handling
- [ ] T003 [P] Create configuration for session timeout constants in src/config/session_config.py

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3
**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

### Contract Tests for Session Operations
- [ ] T004 [P] Contract test POST /session/create in tests/contract/test_session_create.py
- [ ] T005 [P] Contract test POST /session/validate in tests/contract/test_session_validate.py
- [ ] T006 [P] Contract test POST /session/extend in tests/contract/test_session_extend.py
- [ ] T007 [P] Contract test POST /session/terminate in tests/contract/test_session_terminate.py
- [ ] T008 [P] Contract test POST /session/persist in tests/contract/test_session_persist.py
- [ ] T009 [P] Contract test GET /session/load in tests/contract/test_session_load.py

### Contract Tests for Audit Operations
- [ ] T010 [P] Contract test POST /audit/log in tests/contract/test_audit_log.py
- [ ] T011 [P] Contract test GET /audit/query in tests/contract/test_audit_query.py

### Integration Tests (Quickstart Scenarios)
- [ ] T012 [P] Integration test: Basic session creation and validation in tests/integration/test_session_basic.py
- [ ] T013 [P] Integration test: Session timeout extension in tests/integration/test_session_extension.py
- [ ] T014 [P] Integration test: Session expiration after 15 minutes in tests/integration/test_session_expiration.py
- [ ] T015 [P] Integration test: Explicit logout clears session in tests/integration/test_session_logout.py
- [ ] T016 [P] Integration test: No persistent sessions across crashes in tests/integration/test_session_crash.py
- [ ] T017 [P] Integration test: Audit log verification in tests/integration/test_audit_logging.py

### Security Tests
- [ ] T018 [P] Security test: Session file permissions (0600) in tests/security/test_file_permissions.py
- [ ] T019 [P] Security test: Session file encryption in tests/security/test_session_encryption.py
- [ ] T020 [P] Security test: Memory clearing verification in tests/security/test_memory_clearing.py

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Enhanced Models
- [ ] T021 [P] Enhance Session model with persistence support in src/models/session.py
- [ ] T022 [P] Create SessionFile model for encrypted storage in src/models/session_file.py
- [ ] T023 [P] Create AuthEvent model for audit logging in src/models/auth_event.py

### Session Storage Service
- [ ] T024 Create SessionStorageService for file operations in src/services/session_storage_service.py
- [ ] T025 Implement encrypt_session method using AES-256-GCM
- [ ] T026 Implement decrypt_session method with integrity check
- [ ] T027 Implement atomic file write with proper permissions (0600)
- [ ] T028 Add platform-specific path handling (XDG compliance)

### Enhanced Session Service
- [ ] T029 Update SessionService to use SessionStorageService in src/services/session_service.py
- [ ] T030 Implement persist_session method for saving to disk
- [ ] T031 Implement load_session method for retrieval
- [ ] T032 Fix validate_session to check persisted sessions
- [ ] T033 Implement extend_session for rolling timeout
- [ ] T034 Add session cleanup on expiration

### Audit Service
- [ ] T035 [P] Create AuditService for security logging in src/services/audit_service.py
- [ ] T036 Implement JSON Lines writer for append-only logs
- [ ] T037 Add event type validation and formatting
- [ ] T038 Implement query interface for audit retrieval
- [ ] T039 Add log rotation (90-day retention)

### Memory Security Service
- [ ] T040 [P] Create MemorySecurityService in src/services/memory_security_service.py
- [ ] T041 Implement secure_clear for bytearray zeroing
- [ ] T042 Add context manager for automatic cleanup
- [ ] T043 Implement memory locking (best effort)

## Phase 3.4: Integration

### CLI Integration
- [ ] T044 Update auth_service.py to use enhanced session management
- [ ] T045 Add session decorator for CLI commands in src/cli/decorators.py
- [ ] T046 Create login command with session persistence in src/cli/main.py
- [ ] T047 Create logout command with session cleanup
- [ ] T048 Create status command to check session
- [ ] T049 Apply session decorator to all protected commands

### Audit Integration
- [ ] T050 Wire AuditService into AuthenticationService
- [ ] T051 Add audit events for all authentication operations
- [ ] T052 Add audit events for session lifecycle

## Phase 3.5: Polish & Performance

### Unit Tests
- [ ] T053 [P] Unit tests for SessionStorageService in tests/unit/test_session_storage.py
- [ ] T054 [P] Unit tests for AuditService in tests/unit/test_audit_service.py
- [ ] T055 [P] Unit tests for MemorySecurityService in tests/unit/test_memory_security.py

### Performance Validation
- [ ] T056 Performance test: Session validation <10ms in tests/performance/test_session_speed.py
- [ ] T057 Performance test: Memory clearing <1ms in tests/performance/test_memory_speed.py

### Documentation
- [ ] T058 [P] Update CLI help text for session commands
- [ ] T059 [P] Document security considerations in docs/security.md
- [ ] T060 [P] Update README with session feature

### Final Validation
- [ ] T061 Run full quickstart.md test suite
- [ ] T062 Security audit with bandit
- [ ] T063 Type checking with mypy
- [ ] T064 Linting with ruff
- [ ] T065 Code formatting with black

## Dependencies
- Setup (T001-T003) must complete first
- All tests (T004-T020) before implementation (T021-T043)
- Models (T021-T023) before services
- SessionStorageService (T024-T028) before SessionService updates (T029-T034)
- Core services before CLI integration (T044-T052)
- Everything before polish (T053-T065)

## Parallel Execution Examples

### Launch all contract tests together (T004-T011):
```bash
Task: "Contract test POST /session/create in tests/contract/test_session_create.py"
Task: "Contract test POST /session/validate in tests/contract/test_session_validate.py"
Task: "Contract test POST /session/extend in tests/contract/test_session_extend.py"
Task: "Contract test POST /session/terminate in tests/contract/test_session_terminate.py"
Task: "Contract test POST /session/persist in tests/contract/test_session_persist.py"
Task: "Contract test GET /session/load in tests/contract/test_session_load.py"
Task: "Contract test POST /audit/log in tests/contract/test_audit_log.py"
Task: "Contract test GET /audit/query in tests/contract/test_audit_query.py"
```

### Launch all integration tests together (T012-T017):
```bash
Task: "Integration test: Basic session creation and validation in tests/integration/test_session_basic.py"
Task: "Integration test: Session timeout extension in tests/integration/test_session_extension.py"
Task: "Integration test: Session expiration after 15 minutes in tests/integration/test_session_expiration.py"
Task: "Integration test: Explicit logout clears session in tests/integration/test_session_logout.py"
Task: "Integration test: No persistent sessions across crashes in tests/integration/test_session_crash.py"
Task: "Integration test: Audit log verification in tests/integration/test_audit_logging.py"
```

### Launch model tasks together (T021-T023):
```bash
Task: "Enhance Session model with persistence support in src/models/session.py"
Task: "Create SessionFile model for encrypted storage in src/models/session_file.py"
Task: "Create AuthEvent model for audit logging in src/models/auth_event.py"
```

## Notes
- **TDD Enforcement**: Tests T004-T020 MUST fail before implementing T021-T052
- **Security Priority**: File permissions, encryption, and memory clearing are critical
- **Atomic Operations**: Session file writes must be atomic to prevent corruption
- **Platform Testing**: Test on Linux, macOS, and Windows for path compatibility
- **Audit Compliance**: Every auth operation must generate an audit event
- **Performance Targets**: Session validation <10ms is non-negotiable

## Success Criteria
✅ All 65 tasks completed
✅ All tests pass (contract, integration, security, unit, performance)
✅ Session persists for exactly 15 minutes
✅ Rolling timeout works correctly
✅ Audit log captures all events
✅ Security requirements met (encryption, permissions, memory clearing)
✅ Performance targets achieved
✅ Cross-platform compatibility verified

---
*Task list generated: 2025-01-12*
*Ready for execution with TDD approach*