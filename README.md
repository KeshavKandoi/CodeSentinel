# CodeSentinel

A local MCP server for source-backed security auditing and explicitly authorized, controlled remediation.

CodeSentinel helps an MCP client inspect a project, identify rule-backed security candidates, investigate evidence, and test a proposed fix. Normal discovery, scanning, auditing, investigation, retesting, and sweeps do not change target source files. A separate remediation call can write a supported fix after the operator supplies explicit authorization for a local, non-production test repository.

## How it works

```text
Discover → Scan → Investigate → Propose → Authorize → Dry run → Apply
                                                        ↓
                                       Validate → Retest → Sweep → Roll back if needed
```

- **Detection:** Deterministic static rules return source locations, evidence, severity, confidence, and coverage limits. A match is a candidate, not proof of exploitability.
- **Investigation:** Read-only discovery, route analysis, access-control analysis, and reports connect findings to evidence. Review signals are separate from rule-backed findings.
- **Remediation:** A proposal records the intended content and original SHA-256. The controlled apply path checks authorization, project scope, Git cleanliness, file identity, and content hashes before writing.
- **Verification:** Validation leaves a successful write at `validated_pending_retest`. An independent retest checks the current source; a sweep correlates the original finding, remediation, retest, fresh analysis, and new findings.
- **Recovery:** Rollback restores recorded original bytes only while the file still matches the expected post-remediation hash.

A finding classified as `resolved` does not establish that the whole project is secure. Missing coverage, unsupported proof, and blocked runtime prerequisites remain visible in the result.

## Quickstart

Prerequisites: Node.js and npm, plus a local project that CodeSentinel can read. Git is required for the guarded write workflow. Install dependencies and build from this repository:

```sh
npm install
npm run build
```

The server uses MCP over **stdio**. An MCP client normally starts it with `node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js`; `npm start` runs the same built entrypoint from this directory. Standard output is reserved for MCP messages.

`PROJECT_ROOT` is an optional server-level default. For the tools that accept `projectRoot`, pass an absolute path in the call to select that project; it overrides `PROJECT_ROOT`. If neither is available, those tools return a validation error. Some ancillary tools still require a configured `PROJECT_ROOT`; check the advertised MCP schema for per-call `projectRoot` support in a rootless session. The selected root must exist and resolve to a directory, and the root itself cannot be a symlink.

```sh
PROJECT_ROOT=/absolute/path/to/project npm start
```

Do not point the write workflow at a production or shared working tree. A disposable local Git checkout is the intended remediation target.

## Connect an MCP client

Use the absolute path to this repository's built `dist/index.js`. Build again after changing source and restart the MCP client to load the new server.

### Codex CLI and IDE

```sh
codex mcp add codesentinel -- node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js
codex mcp list
```

Set an optional default root when registering instead:

```sh
codex mcp add codesentinel --env PROJECT_ROOT=/absolute/path/to/project -- node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js
```

Codex shares MCP configuration between its CLI and IDE extension. See the [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) for configuration details.

### Claude Code

```sh
claude mcp add --transport stdio codesentinel -- node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js
claude mcp list
```

To configure an optional default root:

```sh
claude mcp add --env PROJECT_ROOT=/absolute/path/to/project --transport stdio codesentinel -- node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js
```

The `--` separates Claude Code options from the server command. Check the connection with `claude mcp get codesentinel` or `/mcp` inside Claude Code. See the [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

The client must be able to access the selected local path. This stdio configuration does not expose a hosted or remote scan service.

## Public MCP tools

These names are registered by the current server. `retest_finding` is the independent retest tool; there is no `security_remediation_retest` alias.

| Purpose | Tools |
| --- | --- |
| Project access and discovery | `list_files`, `read_file`, `search_files`, `get_project_info`, `analyze_project`, `run_command` |
| Static security analysis | `scan_project`, `discover_routes`, `analyze_access_control`, `run_deep_security_audit`, `get_security_graph` |
| Audit and investigation | `run_full_security_audit`, `start_security_audit`, `start_security_investigation`, `run_security_analysis`, `get_investigation`, `record_security_hypothesis`, `generate_security_report`, `get_security_finding` |
| Controlled remediation | `propose_remediation`, `apply_remediation`, `remediate_finding`, `retest_finding`, `security_remediation_sweep`, `verify_remediation`, `rollback_remediation` |
| Runtime proof | `list_verification_cases`, `verify_finding`, `list_security_proof_cases`, `prove_security_finding`, `request_runtime_verification` |
| Audit orchestration | `dispatch_security_action`, `plan_security_investigation`, `get_security_audit_state`, `run_audit_analysis`, `record_audit_hypothesis`, `request_audit_verification`, `complete_security_audit`, `generate_security_audit_report`, `get_security_agent_instructions` |

Each tool advertises its input schema through MCP `tools/list`. Use those schemas for optional limits, runtime targets, sessions, and detailed responses. `start_security_audit` creates an audit session; `run_full_security_audit` runs the read-only pipeline in one call.

## Read-only and write boundaries

| Operation | Reads target | Writes target source |
| --- | --- | --- |
| Discovery, scan, audit, investigation, reports | Yes | No |
| Proposal and dry run | Yes | No |
| Independent retest, verification, remediation sweep | Yes | No |
| Explicitly authorized remediation apply | Yes | Yes, to the approved finding file |
| Explicitly authorized rollback | Yes | Yes, restoring the recorded original bytes |

Runtime verification can make bounded requests to an explicitly authorized local runtime target. It does not edit source files, but an operator should use an isolated target because HTTP requests can have application side effects. Normal scan and audit do not install dependencies or start the target application.

## Use CodeSentinel on a project

These are **MCP tool arguments**, not shell commands. Replace the example path and use IDs, file content, and hashes returned or computed for your own disposable project. Never copy an example hash or finding ID into a live call.

1. Select a root and run `scan_project` with `{"projectRoot":"/absolute/path/to/project"}`. Inspect `findings`, `rulesRun`, skipped files, and limitations. Run `run_full_security_audit` with the same `projectRoot` for the wider read-only audit.
2. For a rule-backed finding, call `start_security_investigation` with `{"projectRoot":"/absolute/path/to/project","scope":["authorization"],"hypothesis":"Review the reported authorization finding."}`. Then call `run_security_analysis` with the returned `id` as `investigationId` and the same root. Use the investigation's finding ID for the proposal.
3. Call `propose_remediation` with `projectRoot`, `investigationId`, `findingId`, `description`, `rationale`, `files`, `expectedSecurityEffect`, and `requiresRuntimeVerification`. The `files` field is an array of **objects**, not path strings. Each object has a root-relative `path`, the current `originalContentHash` as a lowercase SHA-256 hex digest, full `proposedContent`, and `description`. If `requiresRuntimeVerification` is `true`, supply `runtimeVerification` as required by the tool schema. Proposal creation does not write.
4. Check the proposal and intentionally authorize a **local, non-production test target**. The apply and rollback authorization object is:

   ```json
   {
     "projectRoot": "/absolute/path/to/project",
     "localTarget": true,
     "allowRemediation": true,
     "nonProductionTestTarget": true
   }
   ```

   `authorization.projectRoot` must equal the canonical selected root exactly. `apply_remediation` requires this authorization and the returned `proposalId` passed as `remediationId`. `remediate_finding` is the separate direct single-file strategy path; it also requires explicit authorization for a write.
5. First call `apply_remediation` with `{"remediationId":"<returned proposal ID>","projectRoot":"/absolute/path/to/project","authorization":{...},"dryRun":true}`. This checks the change without changing target bytes. Then make a separate call with `dryRun: false` after reviewing the result. A successful controlled write reports `validated_pending_retest`, **not** `fixed` or `resolved`.
6. Call `retest_finding` with the original scan `findingId` and `projectRoot`. Then call `security_remediation_sweep` with `projectRoot` and `remediationIds` containing the proposal ID. Inspect `findings.resolved`, `findings.stillVulnerable`, `findings.inconclusive`, `findings.unsupported`, `findings.blocked`, `newFindings`, and overall `securityStatus`. If needed, call `rollback_remediation` with the proposal ID, the same root, and the authorization object.

The abbreviated `{...}` in step 5 means the complete authorization object shown above; it is explanatory notation, not literal JSON. The controlled proposal apply path currently accepts **exactly one finding file**, even though the proposal schema permits an array of structured file changes. Propose one file for a controlled write.

### Safe disposable test workflow

Create a temporary local Git repository with synthetic source and a supported rule-backed finding. Record its starting Git status and the target file's SHA-256. Run `scan_project` and require a real finding ID before proposing a change. Confirm an unauthorized apply is rejected and a dry run leaves the hash unchanged. Review the exact proposed content, then explicitly authorize the write, retest, sweep, and roll back while checking the restored hash. Remove the disposable repository only after collecting the results. Do not use production credentials or services.

### Lifecycle states

```text
finding → proposal → authorization → dry_run → validated_pending_retest
                                                ↓
                           independent retest → resolved | still_present | inconclusive | blocked
                                                ↓
                                  sweep → remaining/new findings + coverage
                                                ↓
                                        rollback, if needed
```

`validated_pending_retest` means the proposed source change passed validation. It does not establish resolution. Retest independently rechecks the original condition against current source and uses supported runtime proof only when supplied and applicable. The sweep performs fresh analysis and separates original, remaining, and newly introduced findings. Unsupported and inconclusive work is never promoted to resolved merely because a static match disappeared.

## Safety and scope

- Roots and file paths are checked against the canonical selected project. Path traversal, symlink escapes, and cross-project remediation IDs are rejected.
- Controlled writes require an eligible local test repository, explicit authorization, a matching original file hash, and a clean target state. Only the intended finding file may be changed by the controlled apply path.
- Apply records original and changed SHA-256 hashes. Rollback checks the stored snapshot and current post-change hash before restoring the exact original bytes; unexpected later edits and repeated rollback are rejected.
- Validation failure triggers guarded automatic rollback. Scan, audit, retest, and sweep stay read-only for target source files.
- Evidence and reports use bounded output and redaction, but operators should still avoid scanning or transmitting secrets they are not authorized to handle.

Only inspect, test, or modify projects you are authorized to access. Remediation is intended for a disposable or isolated local test target, with review before applying a change.

## Coverage and limits

The registered static security rules are `CS-NODE-001` through `CS-NODE-025` for detected Node.js projects. They cover indicators including credential exposure, injection, command execution, path traversal, SSRF, XSS, redirects, CORS, authentication and authorization, uploads, deserialization, configuration, dependency risk, CSRF, webhook signatures, mass assignment, password storage, and WebSocket security. Rule-backed matches are source-backed candidates, not universal exploit proofs.

Project discovery recognizes Node.js, Python, Go, and Rust markers. The registered route adapters cover Express, Fastify, NestJS, Next.js, FastAPI, and Django. The current `scan_project` security rules run for detected Node.js roots; recognizing another ecosystem or discovering its routes does not mean it has equivalent rule coverage. Unsupported domains are reported as unsupported rather than passed. Heuristic review signals are counted separately from rule-backed findings.

Runtime proof is limited to registered adapters and an authorized local target. Where proof-eligible findings exist but no authorized target is supplied, the audit reports blocked execution and an inconclusive security status. A completed static retest can resolve a supported original finding without establishing a universal runtime proof. Coverage gaps and unsupported or inconclusive conditions remain explicit.

The controlled proposal apply path supports one finding file at a time. CodeSentinel does not automatically generate a correct fix for every finding, install target dependencies, guarantee full framework coverage, or certify the security of an entire application.

## Verification evidence

A built-MCP integration test uses a disposable Git fixture with a genuine `CS-NODE-009` rule-backed finding. It exercises scan → investigation → structured proposal → unauthorized rejection → dry run → CodeSentinel file write → `validated_pending_retest` → independent static retest → sweep → authorized rollback. The test checks exact original SHA-256 restoration, cross-project rejection, unchanged unrelated files, and repeated-rollback rejection. This demonstrates that controlled writes work for that supported case; it does not generalize to every rule or runtime environment.

A separate real-project scan previously produced zero remediation-eligible rule-backed findings; unsupported heuristic signals were not counted as vulnerabilities. That result is not a claim that the project was secure or that a remediation was performed.

The full suite passed locally with **945 tests across 44 test files** during this README update. Re-run these commands after implementation changes to obtain a fresh result:

```sh
npm test
npx tsc --noEmit
npm run build
git diff --check
```

Some integration tests bind to local loopback addresses. A restricted execution environment that denies loopback sockets may fail those tests before their assertions run.

## Development and troubleshooting

| Symptom | Check |
| --- | --- |
| MCP tools are missing or old | Run `npm run build`, restart the MCP client, and verify its configured `dist/index.js` path. |
| `PROJECT_ROOT` error | Supply an absolute `projectRoot` to an explicit-root tool or configure `PROJECT_ROOT` for the server. |
| `EPERM` while Vitest writes `node_modules/.vite-temp` | Check local ownership and write permission of `node_modules` and its `.vite-temp` directory; run tests as a user allowed to write there. |
| Remediation rejected for a dirty target | Use a clean disposable Git checkout and inspect the rejection; do not bypass the guard. |
| Original or post-change hash mismatch | Re-scan or re-propose from the current file; rollback will not overwrite unrelated newer edits. |
| Runtime target missing or proof unsupported | Provide an authorized isolated local target when the adapter supports it; otherwise retain the blocked or unsupported classification. |

The source layout is:

```text
src/
  index.ts                MCP stdio entrypoint
  tools/                 Public tool registry and project metadata
  discovery/             Project profile detection
  security/              Static scanner and rule registry
  routes/ and access/    Route and access-control analysis
  audit/ and investigation/  Audit pipeline and investigation state
  proof/ and runtime/    Bounded runtime verification
  remediation/           Proposal, controlled apply, retest, sweep, rollback
  report/ and validation/  Reports, redaction, and input schemas
tests/                   Unit and MCP integration tests
```

Contributions should include evidence-backed tests for changed behavior and preserve the project-root and authorization boundaries. Report suspected security issues privately to the maintainer rather than publishing exploit details in a public issue.

## License

`package.json` declares the package license as ISC. This repository currently has no separate `LICENSE` file; check the package metadata before redistribution.
