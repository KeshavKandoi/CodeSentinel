<p align="center">
  <img src="./R.png" alt="CodeSentinel" width="72%">
</p>

# CodeSentinel 🛡️

**A local MCP security auditor with controlled remediation and independent verification.**

`TypeScript` · `MCP over stdio`

## What is CodeSentinel?

CodeSentinel scans a selected local project for supported security findings and provides investigation, remediation, and verification tools through MCP.

## Why CodeSentinel?

Finding a potential issue and proving a fix worked are separate steps. A validated change remains `validated_pending_retest` until independent retesting checks the original finding.

## Key features

- Read-only project scans and deeper audits with explicit coverage status.
- Rule-backed findings separated from heuristic review signals and runtime proof.
- Finding-linked proposals, authorized dry runs, and controlled file changes.
- Independent retesting, fresh security sweeps, and guarded rollback.

## How it works

```text
FIND → INVESTIGATE → PROPOSE → AUTHORIZE → DRY RUN → APPLY
                                                   ↓
              VALIDATE → RETEST → SWEEP → ROLLBACK (if needed)
```

A successful apply is not a resolved finding; retesting and the sweep provide the next evidence.

## Installation

Use Git, npm, and a Node.js release supported by the installed dependencies.

```sh
git clone https://github.com/KeshavKandoi/CodeSentinel.git
cd CodeSentinel
npm ci
npm run build
```

## MCP setup

The built stdio entrypoint is `dist/index.js`. Replace the example with its absolute path on your machine.

### Claude Code

```sh
claude mcp add --transport stdio codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js
```

### Codex

```sh
codex mcp add codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js
```

`PROJECT_ROOT` can provide a server default. Tools accepting `projectRoot` use an explicit absolute path when supplied.

## Quick start

Call `scan_project` for an accessible local project:

```json
{"projectRoot":"/absolute/path/to/project"}
```

Review finding IDs, rule IDs, and coverage before investigating a result. `run_full_security_audit` provides a broader read-only audit.

## Example finding and remediation flow

For a supported rule-backed finding, call `start_security_investigation`, then `run_security_analysis`. `propose_remediation` takes an investigation finding and structured `files` entries with `path`, `originalContentHash`, `proposedContent`, and `description`.

Use its proposal ID as `remediationId` for an authorized `apply_remediation` dry run. Review the result before a separate authorized write. After validation, call `retest_finding` for the original scan finding and `security_remediation_sweep` for remaining or new findings. `rollback_remediation` is available when restoration is needed.

## Security & safety model

- Apply and rollback require explicit authorization for the exact canonical project root and a local, non-production test target.
- Path containment, symlink checks, Git cleanliness, and original/current file hashes protect controlled writes and rollback.
- Dry runs do not change source files. Scan, audit, retest, and sweep are read-only for source files; authorized runtime verification may send local requests.
- Validation alone does not mean `resolved`. Rollback rejects cross-project records and unexpected newer file changes.

## Supported coverage

Security rules `CS-NODE-001` through `CS-NODE-025` currently target detected Node.js projects. Discovery and route analysis recognize additional stacks without equivalent security-rule coverage. Static findings, review signals, runtime proof, and unsupported domains have distinct status.

## Current limitations

An empty scan does not prove a project secure. CodeSentinel cannot automatically fix every vulnerability, and unsupported or inconclusive verification remains explicit. Investigation and remediation records are held in memory and do not survive a server restart.

## Development

The test suite needs synthetic `CODESENTINEL_TEST_*` values in an ignored `.env` file; `.env.example` lists the variables. Use disposable local fixtures and allow local loopback access for integration tests.

```sh
npm test
npx tsc --noEmit
npm run build
git diff --check
```

## Roadmap

Potential areas for future work include broader rule and proof coverage and automated CI checks. These are proposals, not shipped capabilities.

## Contributing

Keep changes focused, include regression tests for behavior changes, and run the development checks. Use synthetic data and preserve project-root isolation and authorization checks.
