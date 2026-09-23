# security-auditor-mcp

**Phase 1: MCP Foundation.** A Model Context Protocol (MCP) server that acts
as a controlled, sandboxed bridge between an AI client (ChatGPT, Codex, Claude,
or any MCP-compatible client) and a local project directory.

This phase implements five read-only inspection tools plus the security
plumbing (path sandboxing, command allowlisting, timeouts, validation,
logging) that later phases (vulnerability detection, AI remediation,
runtime attack-testing) will build on. No security-auditing logic lives
here yet -- this is purely the foundation.

## Tools provided

| Tool | Description |
|---|---|
| list_files | List files/directories under the project root (optionally recursive). |
| read_file | Read a file's contents (UTF-8, size-capped). |
| search_files | Search file contents for a text or regex pattern. |
| get_project_info | Detect project type, package manager, git branch, file counts. |
| run_command | Execute an allowlisted, read-only shell command inside the project root, with a timeout. |

All five tools:
- Validate input with strict Zod schemas (unknown keys rejected, bounded lengths/sizes).
- Are sandboxed to a single configured PROJECT_ROOT -- path traversal, absolute paths, null bytes, and symlink escapes are all rejected.
- Return structured JSON results (never raw exceptions) with a stable error-code vocabulary.
- Log execution metadata to stderr (never stdout) with automatic secret redaction.

## Architecture

    src/
      config.ts              # Loads & validates PROJECT_ROOT and limits from env
      logger.ts               # Structured stderr logger with secret redaction
      types.ts                # Shared ToolOutcome<T>/ok()/err() result envelope
      fs/
        pathGuard.ts           # Core sandboxing: resolves paths, blocks traversal/symlink escape
        fsOperations.ts        # list_files / read_file / search_files implementations
      exec/
        commandExecutor.ts      # run_command: allowlist, no-shell spawn, timeout, output capture
      validation/
        schemas.ts              # Zod input schemas for all 5 tools
      tools/
        projectInfo.ts           # get_project_info implementation
        registry.ts               # Wires validation -> operation -> MCP tool response for all 5 tools
      index.ts                    # MCP server entrypoint (stdio transport)
    tests/
      testUtils.ts                # Shared fixture-project + outside-secret-file helpers
      pathGuard.test.ts           # Security tests: traversal, absolute paths, symlink escape, null bytes
      fsOperations.test.ts        # Unit tests for list_files/read_file/search_files + security cases
      commandExecutor.test.ts     # Unit tests for run_command: allowlist, timeout, truncation, shell-injection resistance
      schemas.test.ts             # Validation edge cases: malformed/missing/oversized/wrong-type input
      registry.test.ts            # End-to-end tests through the MCP tool-handler layer

Design principles:

- Separation of concerns. MCP transport (index.ts) never touches the filesystem or spawns processes directly -- it only wires validated input to tool handlers and formats their ToolOutcome into an MCP response.
- Fail closed, never throw. Every internal operation returns { ok: true, data } or { ok: false, error } (see types.ts). Handlers never let raw exceptions escape to the MCP transport; a last-resort try/catch in index.ts exists purely as a safety net.
- Sandboxing is centralized. All filesystem access goes through pathGuard.ts's resolveWithinRoot / resolveExistingWithinRoot, which normalize ".." segments, reject absolute paths and null bytes, and re-verify containment after resolving symlinks.
- Commands never touch a shell. run_command uses spawn(..., { shell: false }), so arguments are passed directly to execve -- shell metacharacters (;, |, &&, backtick, $()) in arguments are inert, not interpreted.
- Least privilege by default. run_command's allowlist is a fixed, non-configurable set of read-only inspection tools (ls, cat, git, npm, etc.), and known mutating subcommands (git push, npm install, ...) are denylisted even for allowed binaries.

## Installation

    git clone <this-repo-url>
    cd security-auditor-mcp
    npm install
    npm run build

## Configuration

The server is configured entirely through environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| PROJECT_ROOT | Yes | -- | Absolute path to the project you want to audit. All operations are sandboxed to this directory. Must exist, must be a real directory (not a symlink). |
| COMMAND_TIMEOUT_MS | No | 10000 | Max time (ms) run_command may run before being killed. |
| MAX_OUTPUT_BYTES | No | 1000000 | Max bytes of stdout/stderr captured per command before truncation. |
| MAX_READ_FILE_BYTES | No | 2000000 | Max bytes read_file will return before truncating. |
| MAX_LIST_RESULTS | No | 2000 | Max entries list_files/search_files will return per call. |

Example:

    export PROJECT_ROOT="/Users/you/code/my-project"
    export COMMAND_TIMEOUT_MS=15000
    npm start

## Usage

### Running directly

    PROJECT_ROOT=/path/to/project npm start

The server communicates over stdio using the MCP protocol -- it is not meant
to be run interactively by a human; it is meant to be launched by an MCP
client.

### Connecting from an MCP client

Most MCP clients (Claude Desktop, Claude Code, custom ChatGPT/Codex bridges,
etc.) are configured with a JSON block describing how to launch the server.
Example (Claude Desktop-style config):

    {
      "mcpServers": {
        "security-auditor": {
          "command": "node",
          "args": ["/absolute/path/to/security-auditor-mcp/dist/index.js"],
          "env": {
            "PROJECT_ROOT": "/absolute/path/to/the/project/you/want/to/audit"
          }
        }
      }
    }

After connecting, the client will see five tools: list_files, read_file,
search_files, get_project_info, and run_command, each with a JSON Schema
description of its inputs.

### Development mode

    PROJECT_ROOT=/path/to/project npm run dev

Runs the server directly from TypeScript source via tsx, without a build step.

## Running tests

    npm test

This runs the full unit + security test suite (90 tests across 5 files)
covering: path traversal and symlink-escape attempts, invalid/malformed
input for every tool, command allowlist enforcement, timeout enforcement,
output truncation, and end-to-end tool-handler behavior.

## Error codes

All tool failures return a JSON body of the shape { "error": CODE, "message": "..." }.

| Code | Meaning |
|---|---|
| INVALID_INPUT | Input failed schema validation. |
| PATH_OUTSIDE_ROOT | Requested path resolves outside PROJECT_ROOT. |
| NOT_FOUND | File or directory does not exist. |
| NOT_A_FILE | Path exists but is not a regular file. |
| NOT_A_DIRECTORY | Path exists but is not a directory. |
| FILE_TOO_LARGE | Reserved for future use. |
| COMMAND_NOT_ALLOWED | Command or subcommand is not in the allowlist. |
| COMMAND_TIMEOUT | Command exceeded COMMAND_TIMEOUT_MS and was killed. |
| COMMAND_FAILED | Command could not be spawned or errored at the OS level. |
| INTERNAL_ERROR | Unexpected internal error; details are not leaked to the client. |

## What Phase 1 deliberately does NOT do

This is a foundation layer only. It does not: scan for vulnerabilities,
detect insecure code patterns, call any AI model for remediation, or
perform runtime attack-testing against the target project. Those are
planned for later phases and will be built on top of these five tools.


---

# Phase 2: Project Discovery and Framework Detection

Phase 2 adds a **Project Discovery module** that analyzes a project's
structure, manifests, lockfiles, and configuration files to determine what
kind of software project CodeSentinel is looking at -- language, package
manager, frameworks, database, ORM, test framework, entry points, scripts,
Docker setup, config/env files, and authentication-related dependencies --
before any security analysis is attempted. Detection is deterministic: it
inspects real files and dependency names rather than asking an LLM to
guess, and every detected item carries evidence and a confidence level.

Phase 1's five tools (list_files, read_file, search_files, get_project_info,
run_command) are unchanged. get_project_info still exists and still returns
its original lightweight summary; analyze_project is new and provides the
richer Phase 2 analysis.

## New tool: analyze_project

| Tool | Description |
|---|---|
| analyze_project | Runs full project discovery and returns a normalized ProjectProfile as structured JSON: languages, package manager, frontend/backend frameworks, database, ORM, test framework, entry points, scripts, dependencies, Docker info, config/env files, and auth indicators -- each with supporting evidence and a confidence level. Read-only; performs no vulnerability or security analysis. |

Like get_project_info, it takes no input beyond the configured PROJECT_ROOT.

## The ProjectProfile model

Every detected technology is represented as a DetectedItem:

    {
      "name": "Express",
      "confidence": "high",
      "evidence": [
        { "source": "package.json dependencies", "detail": "\"express\" (^4.19.2) listed as a dependency" },
        { "source": "content-match:src/index.ts", "detail": "Import/usage pattern for Express found" }
      ]
    }

confidence is "high", "medium", or "low" -- never a bare guess. A bare
dependency listing alone is medium confidence; confidence rises to high
only when corroborated by a matching config file and/or an actual
import/usage pattern found in a likely source file. A config file whose
name merely matches a framework's convention (e.g. a leftover
next.config.js) is never sufficient on its own to report that framework --
this was validated by an explicit negative-case test (see below).

The full ProjectProfile shape:

    {
      projectName: string | null,
      ecosystem: "node" | "python" | "unknown",
      languages: DetectedItem[],
      packageManager: DetectedItem | null,
      frameworks: { frontend: DetectedItem[], backend: DetectedItem[] },
      database: DetectedItem[],
      orm: DetectedItem[],
      testFramework: DetectedItem[],
      entryPoints: EntryPoint[],       // path + confidence + evidence
      scripts: Record<string, string>, // from package.json "scripts"
      dependencies: DependencyInfo[],  // name, version, dev flag
      docker: { hasDockerfile, hasCompose, files, evidence },
      configFiles: string[],
      envFiles: string[],              // filenames only, contents never read
      authIndicators: DetectedItem[],  // presence of auth-related deps only
      warnings: string[]               // e.g. malformed package.json
    }

## Architecture

    src/discovery/
      types.ts                # ProjectProfile, DetectedItem, Evidence, Confidence, etc.
      manifestReader.ts        # Sandboxed, non-throwing file/JSON reading (built on Phase 1's pathGuard)
      projectDiscovery.ts       # Top-level entry point: detects ecosystem, dispatches to a pipeline
      node/
        context.ts               # Parses package.json into a NodeAnalysisContext (merged dependency map)
        language.ts               # TypeScript / JavaScript detection
        packageManager.ts          # npm / yarn / pnpm detection via lockfiles
        frameworks.ts               # Backend (Express, NestJS, Fastify, Koa) and frontend (Next.js, React, Vue, Angular) detection
        dataLayer.ts                 # Database (Postgres, MySQL, MongoDB, SQLite, Redis) and ORM (Prisma, TypeORM, Sequelize, Mongoose, Drizzle) detection
        testFramework.ts              # Jest / Vitest / Mocha / Jasmine / AVA detection
        authIndicators.ts              # Presence-only detection of auth-related dependencies
        entryPoints.ts                  # Combines package.json main/start script + conventional filenames
        dockerAndConfig.ts               # Dockerfile/compose, config file, and env file presence
        nodeDiscovery.ts                  # Orchestrates all of the above into one ProjectProfile
    tests/
      fixtures/
        express-ts/           # Express + TypeScript + Prisma + Postgres + Jest + Docker + JWT/bcrypt
        nextjs-app/            # Next.js + React + Mongoose + MongoDB + next-auth + Vitest
        generic-node/            # Plain Node.js app with a decoy next.config.js (negative-case fixture)
        malformed-package/        # Deliberately invalid package.json (crash-safety fixture)
      discovery/
        projectDiscovery.test.ts  # 45 tests across all four fixtures
      registry.test.ts             # (extended) analyze_project end-to-end tests

## Design principles (Phase 2 specific)

- Evidence over assertion. Every DetectedItem explains itself; nothing is
  reported as a bare fact. This is designed so a downstream LLM consuming
  this JSON can reason about how trustworthy each detection is, rather
  than treating the whole profile as ground truth.
- Dependencies are authoritative; config files corroborate. Framework
  detection requires a real dependency entry in package.json. A
  similarly-named config file (e.g. next.config.js) can raise confidence
  from medium to high, but can never trigger detection by itself -- this
  was a deliberate fix after an initial implementation produced a false
  positive on the generic-node fixture's decoy file.
- Never throws. All file access goes through manifestReader.ts, which
  wraps every read in try/catch and treats "file missing" and "file
  unreadable" as "not detected" rather than an error. A malformed
  package.json produces a warning in the profile, not an exception --
  verified by the malformed-package fixture.
- Extensible to other ecosystems without rewriting. projectDiscovery.ts
  picks an ecosystem via cheap marker-file checks (package.json -> node;
  requirements.txt/pyproject.toml/setup.py/Pipfile -> python) and dispatches
  to an ecosystem-specific pipeline. Node's pipeline lives entirely under
  discovery/node/; adding Python support later means adding a sibling
  discovery/python/ pipeline and one new dispatch branch, with zero changes
  to existing Node detectors, the ProjectProfile type, or the MCP tool
  layer. Phase 2 already reports ecosystem: "python" with an honest
  "not yet implemented" warning when Python markers are found, rather than
  silently returning an empty/misleading profile.

## Running Phase 2 tests

    npm test

runs the complete suite (Phase 1 + Phase 2 together): 138 tests across 6
files, including the 45 discovery tests and the analyze_project end-to-end
tests in registry.test.ts.

## Known limitations / what remains for Phase 3

- Python, FastAPI, and Django are not yet implemented -- only recognized
  and reported as ecosystem: "python" with a clear warning.
- Monorepos / multi-package workspaces (e.g. Turborepo, Nx, npm workspaces)
  are not specially handled; discovery runs against a single package.json
  at the project root.
- Framework detection covers Express, NestJS, Fastify, Koa, Next.js, React,
  Vue, and Angular. Other frameworks (Remix, SvelteKit, Hapi, etc.) are not
  yet modeled.
- GraphQL API layers (Apollo, GraphQL Yoga) are not yet detected as a
  distinct backend framework category.
- No vulnerability detection, authentication vulnerability analysis,
  authorization/IDOR testing, runtime exploitation, or automatic
  remediation is implemented anywhere in Phase 2, as scoped. Phase 3 is
  expected to consume the ProjectProfile produced here as its starting
  context for that analysis.
