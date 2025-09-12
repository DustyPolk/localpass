# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LocalPass is a feature development framework for structured software development workflows. The project uses a systematic approach to feature specification, planning, and implementation with strict branch naming conventions and documentation requirements.

## Development Workflow

### Feature Development Process

1. **Create new feature**: `./scripts/create-new-feature.sh "feature description"`
   - Creates a numbered feature branch (e.g., `001-feature-name`)
   - Sets up directory structure in `specs/`
   - Initializes specification template

2. **Setup implementation plan**: `./scripts/setup-plan.sh [--json]`
   - Must be run from a feature branch
   - Creates plan structure from template

3. **Check prerequisites**: `./scripts/check-task-prerequisites.sh [--json]`
   - Verifies feature directory and plan exist
   - Lists available design documents

4. **Update agent context**: `./scripts/update-agent-context.sh`
   - Updates agent context for the current feature

### Key Commands

- **Get feature paths**: `./scripts/get-feature-paths.sh`
  - Returns all standard paths for current feature
  - Sets environment variables: REPO_ROOT, CURRENT_BRANCH, FEATURE_DIR, etc.

All scripts support `--json` flag for JSON output format.

## Architecture

### Directory Structure

```
localpass/
├── specs/           # Feature specifications by branch
│   └── [###-feature]/
│       ├── spec.md       # Feature specification (mandatory)
│       ├── plan.md       # Implementation plan
│       ├── tasks.md      # Task breakdown
│       ├── research.md   # Research notes (optional)
│       ├── data-model.md # Data model design (optional)
│       ├── quickstart.md # Quick start guide (optional)
│       └── contracts/    # API contracts (optional)
├── memory/          # Project constitution and guidelines
├── scripts/         # Development automation scripts
└── templates/       # Document templates
```

### Branch Naming Convention

Feature branches follow strict format: `###-feature-name`
- Three-digit zero-padded number (001, 002, etc.)
- Dash separator
- Descriptive feature name in lowercase

### Core Scripts Architecture

All scripts share common functionality via `scripts/common.sh`:
- Repository and branch utilities
- Feature path resolution
- File/directory validation helpers

Scripts follow consistent patterns:
- Support both legacy (key:value) and JSON output modes
- Use `set -e` for error handling
- Validate feature branch format before operations

## Development Guidelines

1. **Feature-First Development**: Every change must be on a properly named feature branch
2. **Documentation-Driven**: Features require specification before implementation
3. **Template-Based**: Use provided templates for consistency
4. **Path Management**: Use common functions for all path operations

## Python Configuration

- Python 3.13+ required (`requires-python = ">=3.13"`)
- Project uses pyproject.toml for configuration
- Currently no dependencies specified

## Important Notes

- The constitution template (`memory/constitution.md`) outlines project principles but needs customization
- Scripts validate branch naming conventions strictly - non-feature branches will fail operations
- All feature work happens in `specs/[branch-name]/` directories
- JSON output mode available for programmatic integration
- Use UV when working with dependencies and security should be at the forefront of our development. this tool should be air tight. think about security implications before writing any code.