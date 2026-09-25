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

CodeSentinel provides a rich set of discovery, static, and orchestration tools. Some notable tools include:

- `analyze_project`: Detects the programming language, framework, database, and ecosystem. (STATIC-ONLY)
- `scan_project`: Runs deterministic security rules to detect static code issues. (STATIC-ONLY)
- `discover_routes`: Generates an inventory of externally reachable API routes. (METADATA-ONLY)
- `analyze_access_control`: Classifies route authentication (public/authenticated/roles) and surfaces IDOR/BOLA candidates. (STATIC-ONLY)
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
- HTTP Runtime Proofs are restricted to configured internal test servers (Loopback/Private IPs only unless specifically authorized).
- Protocol Integrity: Output logging is isolated to `stderr`, leaving `stdout` purely for JSON-RPC MCP messages.
- Error schemas mask arbitrary file paths, environment variables, or token exposures.

## Runtime Proof

CodeSentinel distinguishes between theoretical vulnerabilities and **RUNTIME-PROVEN** vulnerabilities. The AI client cannot execute arbitrary requests to external targets; it can only invoke `prove_security_finding` against the local development/staging fixture. The proof mechanism ensures the vulnerability is actively exploitable using fixed semantic oracles.

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
