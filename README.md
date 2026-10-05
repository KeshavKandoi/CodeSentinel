# CodeSentinel

## What it is

CodeSentinel is an agentic, deterministic security auditor that implements a phased, bounded security workflow for AI coding assistants. It provides a Model Context Protocol (MCP) server that empowers AI clients to systematically discover projects, analyze access control, surface suspected vulnerabilities (static-only), run localized proof payloads (runtime-proven), and apply authorized remediations.

CodeSentinel delegates the high-level security reasoning and contextual judgment to the external AI agent while strictly enforcing deterministic boundaries: CodeSentinel performs all target validation, evidence collection, and state transitions, ensuring that no arbitrary commands or unrestricted external HTTP requests are executed.

## Security Architecture

CodeSentinel's architecture implements an explicit separation of concerns:
- **Client (AI Agent)**: Drives the workflow, proposes hypotheses, selects findings, designs the remediation, and queries states.
- **Server (CodeSentinel)**: Executes deterministic analysis, enforces target isolation (e.g. localhost/private boundaries), validates schemas, caps evidence collection and request limits, and manages verifiable snapshots.

CodeSentinel operates in 11 explicit phases:
- Phase 1: Bounded Source Access
- Phase 2: Project Discovery and Framework Detection
- Phase 3: Static Security Analysis
- Phase 4: Route Discovery
- Phase 5: Access-Control Analysis
- Phase 6: Runtime Target Isolation & Evidence Collection
- Phase 7: Security Agent Orchestration (State Machine)
- Phase 8: Reporting and Remediation Intelligence
- Phase 9: Controlled Remediation
- Phase 10: Security Analysis Orchestration
- Phase 11: Real-world Semantic Vulnerability Proofs

## MCP Integration

CodeSentinel supports the standard MCP `stdio` transport. All protocol messages are cleanly isolated on `stdout`, while diagnostic logs are directed to `stderr` to ensure protocol integrity. CodeSentinel's tools, orchestration commands, and file operations are strictly bound to the configured `PROJECT_ROOT` environment variable.

- **transport**: `stdio`
- **local support**: `Supported` (fully isolated, sandboxed execution)
- **remote support**: `Unsupported` (requires custom deployment, see ChatGPT Integration)

## Claude Code Setup

Claude Code runs CodeSentinel locally through the standard stdio transport.

To install and use CodeSentinel in Claude Code, run the following command in your terminal. Replace `/absolute/path/to/project` with the actual path to the repository you are auditing, and `/absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js` with the correct path to the CodeSentinel dist output.

```bash
claude mcp add codesentinel node /absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js
```
Then, configure your environment before running Claude Code:
```bash
export PROJECT_ROOT=/absolute/path/to/project
claude
```

## Claude Setup

To integrate CodeSentinel into Claude Desktop, add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codesentinel": {
      "command": "node",
      "args": ["/absolute/path/to/codesentinel/security-auditor-mcp/dist/index.js"],
      "env": {
        "PROJECT_ROOT": "/absolute/path/to/project"
      }
    }
  }
}
```

## ChatGPT Integration

ChatGPT runs its MCP clients from the cloud and requires a remote transport layer (like HTTP SSE). CodeSentinel currently **does not** bundle a remote transport server because directly exposing a local development directory to the public internet violates the local security sandbox boundary.

If you must integrate CodeSentinel with ChatGPT, you must deploy a custom remote transport wrapper (e.g. an Express app implementing `@modelcontextprotocol/sdk/server/sse.js`) and host CodeSentinel in a sandboxed container (like AWS ECS or a Kubernetes Pod) that holds a clone of your repository. **Never** expose your local development machine's filesystem directly to a remote AI.

## Available MCP Tools

CodeSentinel provides a rich set of discovery, static, and orchestration tools. 37 tools are registered and every tool rejects unknown arguments. Some notable tools include:

- `analyze_project`: Detects the programming language, framework, database, and ecosystem. (STATIC-ONLY)
- `scan_project`: Runs deterministic security rules to detect static code issues. (STATIC-ONLY)

### Phase 2 Node and WebSocket detection

`scan_project` keeps the original CS-NODE-001 through CS-NODE-021 rules and adds three bounded AST-based rules:

| Rule | Detection |
| --- | --- |
| CS-NODE-022 | A parsed WebSocket message supplies an identity directly to connection registration, without a visible verification call. |
| CS-NODE-023 | A `/metrics` HTTP handler returns runtime metrics without a visible authentication guard. |
| CS-NODE-024 | A WebSocket server has no explicit `maxPayload` while its message handler parses incoming data and passes it to sensitive processing. |

For example, a message handler that parses `data`, then calls `manager.registerUser(info.id, parsed.userId)`, can yield a high-severity CS-NODE-022 finding at the registration line. Results include a rule ID, severity, category, file and line, redacted source evidence, impact in the description, and remediation. A protected metrics handler or a server with an explicit `maxPayload` does not trigger the corresponding rule.

These are static candidates. The analyzer does not prove that an upstream proxy lacks authentication or payload limits, and it cannot resolve every custom verifier or alias. It does not report missing Origin checks, generic rate limits, or `ws://` from absence alone; those require deployment context or stronger source evidence. The scanner reads bounded source files locally and does not execute or alter the target project.
- `discover_routes`: Generates an inventory of externally reachable API routes. (METADATA-ONLY)
- `analyze_access_control`: Classifies route authentication (public/authenticated/roles) and surfaces IDOR/BOLA candidates. (STATIC-ONLY)
- `run_full_security_audit`: Runs the unified read-only audit pipeline with stable finding IDs and an optional loopback proof stage. (STATIC + RUNTIME-PROVEN when a target is supplied)
- `start_security_audit`: Creates a bounded session with specific scopes. (METADATA-ONLY)
- `prove_security_finding`: Issues a verifiable payload to prove a vulnerability locally. (RUNTIME-PROVEN)
- `propose_remediation`: Submits an AI-generated fix for verification. (METADATA-ONLY)
- `apply_remediation`: Applies the authorized fix to the source. (RUNTIME-PROVEN / VERIFIED_RESOLVED)

## Recommended AI Workflow

CodeSentinel works best with a highly structured workflow:

1. **discover project** (`analyze_project`)
2. **scan project** (`scan_project`)
3. **discover routes** (`discover_routes`)
4. **analyze access control** (`analyze_access_control`)
5. **investigate finding** (Create hypothesis using audit orchestration tools)
6. **prove finding when supported** (`prove_security_finding`)
7. **generate evidence/report** (`generate_security_audit_report`)
8. **propose remediation** (`propose_remediation`)
9. **apply controlled remediation only when explicitly authorized** (`apply_remediation`)
10. **re-analyze** (Rerun analysis/proof tools)
11. **replay proof** (`verify_remediation`)
12. **report final verification state** (Mark audit completed)

## Security Boundaries

CodeSentinel explicitly enforces:
- File paths are restricted to the configured `PROJECT_ROOT`.
- Directory traversal (`../`) is blocked.
- Shell commands (`run_command`) are restricted to a pre-defined allowlist.
- Proof adapters (`prove_security_finding`, `run_full_security_audit`) execute only against loopback origins. `verify_finding` may additionally target a private-network origin only when `allowPrivateNetworkTarget` is set. Public hosts, hostnames other than `localhost`, cloud metadata addresses, and redirects that leave the configured origin are always rejected.
- Protocol Integrity: Output logging is isolated to `stderr`, leaving `stdout` purely for JSON-RPC MCP messages.
- Error schemas mask arbitrary file paths, environment variables, or token exposures.

## Runtime Proof

CodeSentinel distinguishes between theoretical vulnerabilities and **RUNTIME-PROVEN** vulnerabilities. The AI client cannot execute arbitrary requests to external targets; it can only invoke `prove_security_finding` against the local development/staging fixture. The proof mechanism ensures the vulnerability is actively exploitable using fixed semantic oracles. Receipts are bound to the target origin they were created for and cannot be reused or replayed against another origin. `prove_security_finding` returns `NOT_FOUND` for a finding ID that matches no scan or access-control finding, and an unknown ID creates no receipt and consumes no proof budget. For state-changing access-control proofs, a write is reported as a state change only when two baseline reads are identical and the post-write read differs, so volatile response fields cannot cause a false `verified`.

## Remediation and Replay

When a finding is proven and a remediation is applied, CodeSentinel snapshots the files. You can invoke `verify_remediation` to replay the original payload. If the payload is successfully blocked (or resolved securely), the status is updated to **VERIFIED_RESOLVED**. If the remediation breaks deterministic functionality or fails the replay, `rollback_remediation` restores the files to their pre-remediation hashes.

## Demo

CodeSentinel includes a comprehensive demo fixture under `tests/fixtures/security-cases`. The fixture contains realistic vulnerable routes (e.g. `vulnerable.ts` demonstrating SQLi, XSS, SSRF) and secure equivalents (`safe.ts`).

You can point CodeSentinel at this directory (`export PROJECT_ROOT=$(pwd)/tests/fixtures/security-cases`) to explore its static scanner, route analysis, and semantic runtime proof capabilities safely.

## Local Development

1. Install dependencies: `npm ci`
2. Build the project: `npm run build`
3. Run the development server (for manual tests): `npm run dev`

## Testing

CodeSentinel relies on `vitest` for the test suite.

```bash
npm run test
```
*Note: Some Phase 6 and Phase 11 networking verification tests use explicit IP (127.0.0.1) network bindings. Ensure your environment permits local loopback binding when running tests.*

## Production Deployment

For production deployments, package CodeSentinel into an isolated container alongside the target codebase. Expose it solely via local stdin/stdout piping to the invoking MCP client.

## Limitations

- `inconsistent_authorization` only compares methods that share the same file and normalized resource path.
- Weak password storage rules and cryptography misuse rules remain **STATIC-ONLY** and cannot be dynamically proven by CodeSentinel's runtime framework.
- CodeSentinel requires the target codebase to be available on the local filesystem of the executing environment.
- Complex IDOR analysis lacks full inter-procedural data-flow tracing; it relies on deterministic pattern heuristics.
- `generate_security_report` fails closed with `REPORT_INVALID` for an investigation with more than 100 findings or 250 evidence items instead of truncating.
- Receipts, remediation records, and investigations are held in memory and are lost on restart; stores are bounded.
- A `NOT_FOUND` proof lookup re-runs the static scan and route discovery to confirm the ID is unknown; the cost is bounded per call.
- Redaction is pattern-based; secret formats not covered by the shared redactor may still appear in evidence text.
- Proof attempt budgets (10 per finding, 500 per process) are held in memory and reset on restart.
- Reflected-XSS proof verifies only when the server returns the probe value unescaped.
- Body-marker and open-redirect proof adapters verify only against servers that emit their fixed marker, so real applications may produce false negatives, never false positives from a generic response.
- The permissive-CORS proof sends no Origin header and does not detect servers that reflect the request origin.
- Access-control remediation replay is refused unless the replay origin matches the origin of the original verified runtime result; only the refusal path has an end-to-end test.
- Several guarantees (static rules, route and access analysis) are covered by behavioral tests rather than formal analysis.

## Unified audit pipeline

`run_full_security_audit` runs one read-only, deterministic audit over the configured `PROJECT_ROOT`. No LLM or API key is involved.

### Stages

`discovery` → `route_discovery` → `static_scan` → `access_control` → `deep_analysis` → `candidate_classification` → `runtime_proof` → `graph_construction` → `report`

Each stage is recorded with status (`completed`, `skipped`, `failed`, `blocked`), duration, and item count. A failed optional stage records a structured issue (`stage`, `code`, safe `message`, `recoverable`, `affectedFindings`) and the audit continues. Route, scan, and access results are computed once and shared with deep analysis and graph construction.

### Audit context

An internal `AuditContext` carries the profile, route inventory, stage outputs, merged findings, receipts, remediation records, graph, issues, stage records, and execution limits between stages. It is in-memory and never persisted. The returned result is a bounded, redacted projection: no credentials, cookies, authorization headers, tokens, or raw request data.

### Finding identity and merging

Each finding gets a deterministic ID `cs-<hash>` derived from the canonical category, normalized file, route (or line for source findings), and, only when neither file nor route exists, the title. Findings from the scanner, access-control analysis, and deep analysis that share an identity are merged into one finding with all sources and stages listed. Deep-analysis findings that wrap a scanner or access finding are merged by source ID. Random IDs are used only for run identifiers (`runId`) and receipts' own identifiers.

### Finding lifecycle

`candidate → analyzed → proof_eligible → verified`, or `candidate/analyzed → unsupported | blocked | inconclusive`, or `proof_eligible → not_reproduced | inconclusive | blocked`. After remediation: `verified → remediation_applied → verified_resolved`.

`verified` can only be reached through a receipt from a registered executable adapter with a verified semantic oracle. A regex match, an existing route, an HTTP 200, a successful request, a static rule, or a differing response never verifies a finding. `verified_resolved` additionally requires a `verified_resolved` remediation record and a `not_reproduced` replay receipt.

### Proof classification

The proof adapter registry is the single source of truth, queried through `resolveProofSupport`. Each finding reports:

- `proofSupport`: `runtime` (a registered adapter handles this class), `requires-adapter` (a proof type exists but no executable adapter), or `static-only`.
- `proofStatus`: `eligible`, `unsupported`, `blocked`, or the receipt outcome (`verified`, `not_reproduced`, `inconclusive`, `blocked`).

`runtime` / `eligible` means a proof can be attempted; it is not a claim that a proof ran.

### Runtime verification

Runtime proof runs only when `target` is supplied, is bounded by `maxProofAttempts`, and goes through `proveSecurityFinding`, which applies the existing target guard (loopback or explicitly authorized origin), session, request, redirect, timeout, response-size, and destructive-method controls. Existing receipts are reused instead of repeating a verified proof.

### Security graph

The graph contains files, routes, handlers, middleware, authentication boundaries, authorization checks, ownership checks, findings, proof receipts, and remediation records, joined by evidence-backed edges. It is not an AST or taint graph. Pass `includeGraph: true` to include nodes and edges (capped); otherwise only counts are returned.

### Remediation and replay

The audit never applies remediation. Pass `investigationId` to attach remediation records (from `propose_remediation` / `apply_remediation` / `verify_remediation`) and replay receipts. Findings whose remediation was verified and replayed as `not_reproduced` appear as `verified_resolved`.

### Per-finding scoring and advisory output

Each finding carries a deterministic `riskScore` (0-100, computed from final state), a redacted, bounded `evidenceSynthesis` naming only the engines that contributed, and `correlation` metadata when more than one source contributed. `nearDuplicates` lists advisory groups of structurally similar findings; it never merges findings, changes IDs, lifecycle or proof eligibility, or adds graph edges. This audit result is the report surface for these fields; the investigation-based `generate_security_report` is a separate workflow that does not consume `AuditResult`. Each of its findings carries its own deterministic `riskScore`, a redacted, bounded `evidenceSynthesis` and a read-only `remediationState`, derived from that finding's investigation data with the same scoring and synthesis functions. Runtime verification is described only when a runtime result exists. Neither field nor any remediation record changes a finding's `status`, which comes only from runtime verification. Correlation and `nearDuplicates` are not part of that report because investigation findings are never merged across engines. Investigation views and reports share one redactor, which covers bearer, Basic, JWT, `sk_`-style keys, URL credentials, PEM keys, secret-like pairs, and `Cookie`/`Set-Cookie` header lines.

### Report

The result lists, per finding: stable ID, category, severity, confidence, status, proof support, proof status, file, line, route, evidence, remediation status, and replay status, plus summary counts (total, per severity, runtime verified, static-only, unsupported, blocked, inconclusive, resolved), stage records, issues, and limitations.

### Read-only behavior and safety

No stage writes to the project. The result reports `readOnly.sourceTreeUnchanged`, computed from file size and modification time before and after the run (bounded by `MAX_LIST_RESULTS`). Existing path guards, command allowlist, and Phase 6 runtime controls are unchanged.

### Limitations

- Deep-analysis findings are line-pattern heuristics and stay static-only unless merged into a finding a registered adapter handles.
- Each proof attempt re-derives the route inventory inside the proof engine.
- Receipts and remediation records live in memory only.
- Remediation and replay status requires the same server process and an `investigationId`.
- Runtime proof covers only the classes registered in the proof adapter registry.

## Analyze Any Local Project

You do not need to copy or clone your project into CodeSentinel. Install CodeSentinel anywhere and point it at any local directory.

**Option 1: pass `projectRoot` in the tool call (no config edits per project).**

```json
{ "name": "scan_project", "arguments": { "projectRoot": "/absolute/path/to/your/project" } }
```

Ask Claude: "Scan this project: /Users/me/my-project". `projectRoot` must be an absolute path to an existing directory and must not be a symbolic link. It is supported by these read-only tools: `get_project_info`, `scan_project`, `analyze_project`, `list_files`, `read_file`, `search_files`, `get_security_graph`, `discover_routes`, `analyze_access_control`, `run_deep_security_audit`, `list_verification_cases`, and `list_security_proof_cases`. File paths inside the project still cannot escape it.

**Option 2: set `PROJECT_ROOT` as a default.**

```json
{ "mcpServers": { "codesentinel": { "command": "node", "args": ["/path/to/security-auditor-mcp/dist/index.js"], "env": { "PROJECT_ROOT": "/absolute/path/to/your/project" } } } }
```

An explicit `projectRoot` always overrides `PROJECT_ROOT`. If neither is provided, the tool returns: `Project root is required: pass projectRoot or set PROJECT_ROOT`.

`run_command`, the investigation, remediation, proof and `run_full_security_audit` tools do not accept `projectRoot`. They keep using `PROJECT_ROOT` and return a clear error when it is unset.
