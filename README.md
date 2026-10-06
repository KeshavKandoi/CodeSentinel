<p align="center">
  <img src="./R.png" alt="CodeSentinel" width="400">
</p>

# CodeSentinel

> A local MCP security auditor with controlled remediation and independent verification.

`TypeScript` · `MCP over stdio`

## What is CodeSentinel?

CodeSentinel exposes local project scanning, investigation, and controlled remediation through an MCP server. It keeps rule-backed findings, heuristic review signals, runtime proof, and coverage status distinct.

## Why CodeSentinel?

Finding an issue and proving a fix worked are separate stages. An applied change remains `validated_pending_retest` until independent retesting checks the original finding; a fresh sweep checks for remaining and new findings.

## Key Features

- Read-only discovery, rule-backed scanning, route/access analysis, and security audits.
- Finding-linked proposals, explicit authorization, dry runs, and controlled file changes.
- Independent retesting, fresh security sweeps, and guarded rollback.

## Security Workflow

```text
FIND → INVESTIGATE → PROPOSE → AUTHORIZE → DRY RUN → APPLY
                                     ↳ VALIDATE → RETEST → SWEEP
```

Rollback is available separately when restoration is needed.

## Installation

Use Git, npm, and a Node.js release supported by the installed dependencies (Node.js 22.12+ on the 22.x line, or 24.x/26.x).

```sh
git clone https://github.com/KeshavKandoi/CodeSentinel.git
cd CodeSentinel
npm ci
npm run build
```

The built stdio server is `dist/index.js` at the repository root.

## MCP Configuration

Use the absolute path to your built server:

```sh
# Claude Code
claude mcp add --transport stdio codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js

# Codex
codex mcp add codesentinel -- node /absolute/path/to/CodeSentinel/dist/index.js
```

`PROJECT_ROOT` is an optional server default. Tools that accept `projectRoot` use an explicitly supplied absolute path in preference to that default.

## Usage

Call `scan_project` with:

```json
{"projectRoot":"/absolute/path/to/project"}
```

Inspect the rule-backed findings and coverage, then use `run_full_security_audit` for a broader read-only audit. For a supported finding, use `start_security_investigation` → `run_security_analysis` → `propose_remediation`. A proposal's `files` entries are structured objects containing `path`, `originalContentHash`, `proposedContent`, and `description`.

Pass the proposal ID as `remediationId` to `apply_remediation` with explicit authorization. Run `dryRun: true` first; a separate authorized call with `dryRun: false` can apply the change. Then call `retest_finding` and `security_remediation_sweep`. Use `rollback_remediation` when restoration is needed.

## Remediation Safety

- Applying or rolling back a change requires authorization for the exact canonical project root, with `localTarget`, `allowRemediation`, and `nonProductionTestTarget` set to `true`.
- Project-root containment, symlink checks, Git cleanliness, original-content hashes, and current-file checks protect writes. A dry run does not modify source files.
- Scans, audits, retests, and sweeps do not change target source files. Runtime verification can send requests to an authorized local target; use an isolated instance.
- Validation after an apply does not mean `resolved`. Retesting must check the original issue. Rollback rejects cross-project records and unexpected newer file changes.

## Validation

```sh
cp -n .env.example .env # if .env does not already exist
npm test
npx tsc --noEmit
npm run build
git diff --check
```

Populate `CODESENTINEL_TEST_*` in the ignored `.env` with synthetic values matching the redaction tests; the empty example alone is insufficient. Tests include local MCP and HTTP integration checks and need local loopback access.

## Repository Structure

- `src/` — MCP server, scanners, audit, proof, reporting, and remediation code.
- `tests/` — unit and integration coverage, including disposable Git fixtures.
- `dist/` — generated build output.

## Limitations

Security rules `CS-NODE-001` through `CS-NODE-025` currently target detected Node.js projects. Discovery of other stacks does not imply equivalent rule coverage. Static matches are not automatically runtime-proven; unsupported and inconclusive outcomes remain explicit. An empty scan does not prove a project secure, and CodeSentinel cannot fix every vulnerability. Investigation and remediation records are held in memory and do not survive a server restart.

## License

`package.json` declares ISC. The repository does not currently include a separate license text file.
