# CodeSentinel

<div align="center">

<img src="./readme.png" alt="CodeSentinel banner" width="100%">

</div>

CodeSentinel is a local MCP security auditor with a controlled remediation workflow. It finds supported source-backed security issues, helps investigate them, and can apply a proposed file change only with explicit authorization. Validation, independent retesting, a fresh security sweep, and guarded rollback keep the result tied to evidence.

## Workflow

```text
FIND → INVESTIGATE → PROPOSE → AUTHORIZE → DRY RUN → APPLY
  → VALIDATE → RETEST → SWEEP → ROLLBACK*
```

`*` Rollback is available when needed. A validated write remains `validated_pending_retest` until the original finding is independently retested; resolving one finding does not establish that the whole project is secure.

## What it does

- **Read-only analysis:** `scan_project` and `run_full_security_audit` inspect the selected project without changing source files. Rule-backed static findings are candidates; heuristic review signals and runtime proof have separate status.
- **Controlled remediation:** `propose_remediation` records a change linked to an investigated finding. `apply_remediation` checks authorization, project scope, Git state, and file hashes before a supported write. The controlled proposal path supports one finding file at a time.
- **Verification and recovery:** `retest_finding` checks the original issue against current source. `security_remediation_sweep` runs fresh analysis for remaining and new findings. `rollback_remediation` restores original bytes only when the current file still matches the recorded post-write hash.

## Install and connect

Build the stdio MCP server with Node.js and npm:

```sh
git clone https://github.com/KeshavKandoi/CodeSentinel.git
cd CodeSentinel/security-auditor-mcp
npm install
npm run build
```

The built entrypoint is `dist/index.js`. Replace the example entrypoint with its **absolute path** on your machine.

### Claude Code

```sh
claude mcp add --transport stdio codesentinel -- node /absolute/path/to/CodeSentinel/security-auditor-mcp/dist/index.js
claude mcp list
```

### Codex

```sh
codex mcp add codesentinel -- node /absolute/path/to/CodeSentinel/security-auditor-mcp/dist/index.js
codex mcp list
```

`PROJECT_ROOT` can be configured as an optional server default. Tools that accept `projectRoot` can instead receive an absolute path in the call; that path overrides the default. The selected project must be accessible to the local server process.

## Use it

1. Start with `scan_project` and `{"projectRoot":"/absolute/path/to/project"}`. Check the findings, executed rules, and coverage limits. Use `run_full_security_audit` for the broader read-only audit.
2. For a real rule-backed finding, call `start_security_investigation`, then `run_security_analysis`. Submit a `propose_remediation` request tied to the investigation finding, with a root-relative file path, its original SHA-256, and the proposed content.
3. On an authorized disposable local test repository, call `apply_remediation` with the proposal ID as `remediationId`, the authorization below, and `dryRun: true`. Review the result before a separate call with `dryRun: false`.
4. Call `retest_finding` for the original finding, then `security_remediation_sweep`. Inspect resolved, remaining, unsupported, inconclusive, blocked, and new findings. Use `rollback_remediation` with the same authorization if restoration is needed.

## Security boundaries

Only explicitly authorized remediation can write target source. Scan, audit, investigation, dry run, retest, and sweep remain read-only for source files. Runtime verification may send bounded requests to an authorized local target, so use an isolated application instance.

For `apply_remediation` and `rollback_remediation`, authorization must name the **exact canonical project root**:

```json
{
  "projectRoot": "/absolute/path/to/project",
  "localTarget": true,
  "allowRemediation": true,
  "nonProductionTestTarget": true
}
```

The write path rejects traversal and symlink escapes, stale original hashes, pre-existing target changes, and cross-project remediation IDs. A dry run does not change file bytes. A successful apply records original and changed hashes and reports `validated_pending_retest`, not `resolved`. Rollback rejects unexpected post-write changes and repeated attempts instead of overwriting newer work.

## Coverage and limits

`scan_project` currently runs rules `CS-NODE-001` through `CS-NODE-025` for detected Node.js projects. Project discovery and route analysis recognize additional stacks, but that does not imply equivalent security-rule coverage. Static matches are not automatically runtime-proven; unsupported or inconclusive results stay explicit. An empty scan does not prove an application secure, and CodeSentinel cannot remediate every finding.

A built-MCP integration test exercises a genuine `CS-NODE-009` finding in a disposable Git fixture through proposal, authorization, dry run, controlled write, validation, independent static retest, sweep, and exact-hash rollback. This demonstrates a supported lifecycle, not universal remediation coverage.

## Development

From `security-auditor-mcp/`:

```sh
npm test
npx tsc --noEmit
npm run build
git diff --check
```
