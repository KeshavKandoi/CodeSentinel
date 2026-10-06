# CodeSentinel

> Find security issues. Apply controlled fixes. Verify what changed.

CodeSentinel is a local security auditor and remediation engine exposed through the Model Context Protocol (MCP). It turns source-backed findings into an evidence trail: investigate the issue, propose a specific change, require explicit authorization, validate the write, independently retest the original finding, sweep for remaining or new issues, and roll back when needed. Normal auditing never edits target source files.

![Package version 1.0.0](https://img.shields.io/badge/version-1.0.0-2563eb) ![License metadata ISC](https://img.shields.io/badge/license-ISC-334155) ![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178c6) ![MCP stdio](https://img.shields.io/badge/MCP-stdio-0f766e)

```text
FIND → INVESTIGATE → PROPOSE → AUTHORIZE → DRY RUN → APPLY
                                                   ↓
                              VALIDATE → RETEST → SWEEP
                                                    ↘ ROLLBACK, if needed
```

**A successful file change is not a resolved vulnerability.** CodeSentinel keeps a remediation at `validated_pending_retest` until independent retesting examines the original finding. A resolved finding does not imply that the entire project is secure.

## What is CodeSentinel?

CodeSentinel analyzes a selected local application, reports rule-backed security candidates with source evidence, and supports a guarded path from finding to file change. The operator or MCP client supplies the proposed content; CodeSentinel validates the proposal and controls the write.

| Stage | What CodeSentinel does |
| --- | --- |
| Detection | Runs deterministic static rules and reports findings, severity, confidence, source locations, and coverage limits. |
| Investigation | Connects findings to project, route, access-control, and source evidence. |
| Remediation | Stores a proposal tied to an actual finding and an original file hash. |
| Controlled write | Applies a supported change only after explicit authorization and integrity checks. |
| Verification | Validates the changed file, then independently retests the original issue. |
| Sweep | Runs fresh analysis and separates resolved, remaining, unsupported, inconclusive, blocked, and new findings. |
| Rollback | Restores recorded original bytes only if the current file still matches the expected post-write state. |

### Why the lifecycle matters

A static match can be useful without proving exploitability. A patch can pass syntax validation without fixing its finding. CodeSentinel records those distinctions instead of treating either event as a security conclusion. Dry runs leave target bytes unchanged; writes require explicit authorization; rollback refuses to overwrite unrelated later edits.

## Quick Start

Use a recent Node.js installation with npm. Git is needed for the guarded remediation workflow. Clone the repository, install dependencies, and build the MCP server:

```sh
git clone https://github.com/KeshavKandoi/CodeSentinel.git
cd CodeSentinel/security-auditor-mcp
npm install
npm run build
```

1. Register the built stdio server in an MCP client using the configuration below, then connect the client.
2. Confirm the client can list tools such as `scan_project` and `run_full_security_audit`.
3. Run `scan_project` with `{"projectRoot":"/absolute/path/to/project"}`. Review rule execution and coverage alongside any findings.
4. Investigate a real finding before proposing a fix. Use remediation tools only for an explicitly authorized, local, non-production test repository.

`PROJECT_ROOT` may be set as a server-level default. A tool's explicit, absolute `projectRoot` takes precedence where that tool advertises the field. If a root is required and neither source supplies one, the tool returns a validation error. Some ancillary tools require `PROJECT_ROOT`; consult each advertised MCP schema.

## MCP Integration

CodeSentinel runs locally over **MCP stdio**. Its built entrypoint is `dist/index.js`; `npm start` executes `node dist/index.js` from this package directory. The client launches the server process and exchanges MCP messages over standard input and output. Diagnostic logging uses standard error.

For MCP clients that accept an `mcpServers` JSON entry, configure a local stdio process like this, replacing the example paths:

```json
{
  "mcpServers": {
    "codesentinel": {
      "command": "node",
      "args": ["/absolute/path/to/CodeSentinel/security-auditor-mcp/dist/index.js"],
      "env": {
        "PROJECT_ROOT": "/absolute/path/to/project"
      }
    }
  }
}
```

The `env` block is optional when using tools that accept a per-call `projectRoot`. Register the same `node` command and absolute entrypoint in clients with a different MCP configuration format. Restart the client after changing the configuration or rebuilding the server, then use its tool discovery interface (`tools/list`) to confirm the registered tools and input schemas. The selected project must be accessible to the server process. CodeSentinel does not provide a hosted endpoint.

## Security Workflow

The proposal-based path is:

| Step | Tool or result | Decision point |
| --- | --- | --- |
| Find | `scan_project` | Require a genuine rule-backed finding and inspect scan coverage. |
| Investigate | `start_security_investigation`, then `run_security_analysis` | Use the returned investigation `id` as `investigationId`; select a finding from that analysis. |
| Propose | `propose_remediation` | Provide structured file changes and the current original SHA-256. No file is written. |
| Authorize | `authorization` object on `apply_remediation` | Name the exact canonical project root and explicitly allow a local, non-production write. |
| Dry run | `apply_remediation` with `dryRun: true` | Validate the candidate without changing target bytes. |
| Apply and validate | `apply_remediation` with `dryRun: false` | A successful controlled write returns `validated_pending_retest`. |
| Retest | `retest_finding` | Independently recheck the original finding against current source; use supported runtime proof where applicable. |
| Sweep | `security_remediation_sweep` | Correlate the original finding, remediation, retest, fresh analysis, and new findings. |
| Roll back, if needed | `rollback_remediation` | Restore original bytes only after project and post-write hash checks. |

`run_full_security_audit` offers the broader read-only pipeline in one call. `start_security_audit` creates a bounded audit session. Neither path automatically applies remediation.

### Controlled Remediation

A proposal's `files` field is an array of objects, not an array of path strings. Each object requires `path` (relative to the selected root), `originalContentHash` (64 lowercase SHA-256 hex characters), `proposedContent` (full replacement content), and `description`. The proposal also requires `investigationId`, `findingId`, `description`, `rationale`, `expectedSecurityEffect`, and `requiresRuntimeVerification`. When runtime verification is required, include the schema's `runtimeVerification` input.

The controlled `apply_remediation` path currently supports **exactly one finding file per proposal**, although the proposal schema accepts an array. Pass the returned `proposalId` as `remediationId`. Its authorization contract is:

```json
{
  "projectRoot": "/absolute/path/to/project",
  "localTarget": true,
  "allowRemediation": true,
  "nonProductionTestTarget": true
}
```

The authorization root must equal the canonical selected project root exactly. A write also requires an eligible local test repository, the expected original file hash, and a clean target state. Project-root containment, traversal and symlink checks, file identity checks, and cross-project isolation remain in force. CodeSentinel never infers authorization from a finding or a successful dry run.

Apply records the original and changed SHA-256 values. Validation failure triggers a guarded automatic rollback. After a successful write, `validated_pending_retest` means only that validation passed. `retest_finding` determines whether the original condition remains; the sweep then checks the wider current project for remaining and new findings. `rollback_remediation` requires authorization, rejects a different project or a repeated rollback, and refuses to replace a file changed unexpectedly after remediation. Proposal and remediation records are held in server memory, so continue the lifecycle in the same server process.

`remediate_finding` is a separate, direct single-file strategy tool. It also requires explicit authorization for a write. Scans, investigations, dry runs, retests, and sweeps remain read-only for target source files.

### Synthetic example

The following illustrates the workflow; the filename and line are placeholders, not a production finding:

```text
Rule-backed candidate: CS-NODE-009
Severity: high (illustrative)
File: src/example.ts
Line: <line reported by scan_project>

finding → investigation → one-file proposal → explicit authorization
        → dry run (no byte change) → controlled apply → validated_pending_retest
        → independent retest → sweep → optional guarded rollback
```

Use the actual IDs and hashes returned or computed for the selected disposable project. A retest result of `resolved` applies to the **original finding**. If proof or coverage is incomplete, the overall security status can still be `inconclusive`. Unsupported or inconclusive conditions are not promoted to resolved, and newly introduced findings are reported separately.

## Public MCP Tools

These names come from the current MCP registry. `retest_finding` is the independent retest tool; there is no `security_remediation_retest` alias.

| Area | Registered tools |
| --- | --- |
| Project access and discovery | `list_files`, `read_file`, `search_files`, `get_project_info`, `analyze_project`, `run_command` |
| Static analysis | `scan_project`, `discover_routes`, `analyze_access_control`, `run_deep_security_audit`, `get_security_graph` |
| Audit and investigation | `run_full_security_audit`, `start_security_audit`, `start_security_investigation`, `run_security_analysis`, `get_investigation`, `record_security_hypothesis`, `generate_security_report`, `get_security_finding` |
| Remediation | `propose_remediation`, `apply_remediation`, `remediate_finding`, `retest_finding`, `security_remediation_sweep`, `verify_remediation`, `rollback_remediation` |
| Runtime proof | `list_verification_cases`, `verify_finding`, `list_security_proof_cases`, `prove_security_finding`, `request_runtime_verification` |
| Audit orchestration | `dispatch_security_action`, `plan_security_investigation`, `get_security_audit_state`, `run_audit_analysis`, `record_audit_hypothesis`, `request_audit_verification`, `complete_security_audit`, `generate_security_audit_report`, `get_security_agent_instructions` |

Use MCP `tools/list` for the exact schema of each operation. Read-only tools can still perform bounded local runtime HTTP requests when an authorized target is supplied; source-file read-only status does not guarantee the running application has no side effects.

## Security Model

| Operation | Reads project | Writes project source |
| --- | --- | --- |
| Discovery, scan, audit, investigation, proposal | Yes | No |
| Dry run, verification, independent retest, sweep | Yes | No |
| Explicitly authorized apply | Yes | Yes, to the approved file |
| Explicitly authorized rollback | Yes | Yes, restoring the recorded original bytes |

- **Project boundary:** The selected root is canonicalized; unsafe file paths and symlink escapes are rejected. A remediation recorded for one root cannot be applied or rolled back against another.
- **Integrity boundary:** Original-content and post-write hashes detect stale proposals and unexpected changes. Rollback checks the saved snapshot and current file before restoring bytes.
- **Write boundary:** Authorization explicitly names a local, non-production test target. Dirty-target guards and file validation constrain the controlled write path.
- **Evidence boundary:** Static candidates, runtime-verified results, heuristic review signals, unsupported domains, and incomplete proof have distinct meanings. Output is bounded and redacted.

Only audit projects you are authorized to inspect. Use an isolated, disposable local repository for remediation and runtime testing. Normal scans and audits do not install target dependencies or start the target application.

## Coverage and Limitations

The current static rule registry contains `CS-NODE-001` through `CS-NODE-025` for detected Node.js projects. The rules cover indicators of secrets exposure, injection, command execution, path traversal, SSRF, XSS, redirects, CORS, authentication and authorization, uploads, deserialization, insecure configuration, dependency risk, CSRF, webhook signature handling, mass assignment, weak password storage, and WebSocket security. These are source-backed candidates, not proof that every path is exploitable.

Project discovery recognizes Node.js, Python, Go, and Rust markers. Route adapters cover Express, Fastify, NestJS, Next.js, FastAPI, and Django. Recognizing a stack or discovering routes does not imply full security-rule support: `scan_project` currently runs its security rules for detected Node.js roots. Unsupported domains are reported rather than treated as passes, and heuristic review signals are not included in rule-backed vulnerability counts.

Runtime proof exists only for registered adapters and authorized local targets. If proof-eligible findings lack an authorized runtime target, execution is blocked and security status remains inconclusive. Static retesting can establish resolution for a supported original finding without proving the whole application secure. An empty scan has the same limitation: review skipped files, failed rules, and unsupported domains before interpreting it.

The controlled proposal apply path is limited to one finding file. CodeSentinel does not generate a correct fix for every rule, install dependencies into a target project, provide universal runtime proof, or certify whole-project security.

## Verified Capabilities

A built-MCP integration test uses a disposable Git fixture with a genuine `CS-NODE-009` scanner finding. It exercises investigation, structured proposal creation, unauthorized-write rejection, a write-free dry run, CodeSentinel's controlled file write, validation, independent static retest, a security sweep, and authorized rollback with exact original SHA-256 restoration. It also checks cross-project rejection, unchanged unrelated files, and repeated-rollback protection.

That test demonstrates this lifecycle for one supported rule and fixture. It does not establish that every finding can be remediated or that a project with one resolved finding is secure. When coverage or proof is incomplete, the sweep can classify overall security as inconclusive even if the original finding is resolved.

## Development & Testing

From `security-auditor-mcp/`:

```sh
npm test
npx tsc --noEmit
npm run build
git diff --check
```

The suite covers rule detection, project-root and path isolation, route and access analysis, runtime proof, reporting, remediation guards, retesting, rollback, and MCP integration. Some integration tests bind local loopback sockets; the test environment must permit that. A local verification of this repository tree passed **945 tests in 44 test files**. Re-run the suite after implementation changes for the current result.

## Architecture

```text
MCP stdio entrypoint → tool registry → project-root validation
                                      ├─ discovery → scanner → findings
                                      ├─ routes and access → investigation → reports
                                      ├─ authorized runtime proof
                                      └─ proposal → guarded apply → validation
                                                       → retest → sweep → rollback
```

The registry exposes bounded operations and validates inputs. Discovery and analysis provide evidence for findings; remediation keeps its own proposal and snapshot state, then retests against current project content. The sweep combines retest evidence with fresh analysis to classify the original finding and newly observed findings.

## Repository Structure

```text
security-auditor-mcp/
├── src/
│   ├── index.ts           MCP stdio server
│   ├── tools/            Tool registry and project metadata
│   ├── discovery/        Project profile detection
│   ├── security/         Static scanner and rules
│   ├── routes/           Route discovery
│   ├── access/           Access-control analysis
│   ├── audit/            Audit pipeline
│   ├── investigation/    Investigation state
│   ├── proof/            Security proof engine
│   ├── runtime/          Runtime verification
│   ├── remediation/      Proposal, apply, retest, sweep, rollback
│   ├── report/           Reporting and redaction
│   └── validation/       Input schemas
└── tests/                Unit and MCP integration tests
```

## License

The package metadata declares ISC. This repository currently has no separate `LICENSE` file.
