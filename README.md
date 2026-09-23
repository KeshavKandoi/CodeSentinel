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
