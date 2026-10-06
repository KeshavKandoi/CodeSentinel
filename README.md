<p align="center">
  <img src="./R.png" alt="CodeSentinel" width="72%">
</p>

# CodeSentinel

> A local MCP security auditor with controlled remediation and independent verification.

`TypeScript` · `MCP over stdio`

## What is CodeSentinel?

A local MCP server for supported security scans, finding investigation, and controlled remediation of a selected project.

## Why CodeSentinel?

Finding a potential issue and verifying its fix are separate steps. A validated change stays pending until independent retesting checks the original finding.

## Key Features

- Read-only project scans and deeper security audits with explicit coverage status.
- Rule-backed findings separated from heuristic review signals and runtime proof.
- Finding-linked remediation proposals, authorized dry runs, and controlled writes.
- Independent retesting, fresh security sweeps, and guarded rollback.

## Security Workflow

```text
FIND → INVESTIGATE → PROPOSE → AUTHORIZE → DRY RUN → APPLY
                                                    ↓
                    VALIDATE → RETEST → SWEEP → ROLLBACK*
```

`*` Rollback is available when restoration is needed.

## Installation

Use Git, npm, and a Node.js release supported by the installed dependencies.

```sh
git clone https://github.com/KeshavKandoi/CodeSentinel.git
cd CodeSentinel
npm ci
npm run build
```

## MCP Configuration

The built stdio entrypoint is `dist/index.js`. Use its absolute path:

### Claude Code

```sh
claude mcp add --transport stdio codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js
```

### Codex

```sh
codex mcp add codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js
```

## Usage

Call `scan_project` for an accessible local project:

```json
{"projectRoot":"/absolute/path/to/project"}
```

Review the findings and coverage before deciding whether to investigate or remediate a finding.

## Remediation Safety

- Apply and rollback require explicit authorization scoped to the exact canonical project root and a local, non-production test target.
- Path containment, symlink checks, Git cleanliness, and original/current file hashes protect controlled writes.
- Dry runs do not change source files. Scan, audit, retest, and sweep are read-only for source files.
- Apply validation alone does not mean `resolved`; independent retesting and a fresh sweep check the result. Rollback rejects unexpected file changes.

## Validation

```sh
npm test
npx tsc --noEmit
npm run build
git diff --check
```

Tests require synthetic `CODESENTINEL_TEST_*` values in an ignored `.env` file; `.env.example` lists the variables.

## Limitations

Security rules `CS-NODE-001` through `CS-NODE-025` currently target detected Node.js projects. Discovery of other stacks does not imply equivalent rule coverage. Static findings are not automatically runtime-proven, and unsupported or inconclusive outcomes remain explicit. An empty scan does not prove a project secure. Investigation and remediation records are held in memory and do not survive a server restart.
