import { spawn } from 'node:child_process';
import path from 'node:path';
import { resolveExistingWithinRoot } from '../fs/pathGuard.js';
import type { AppConfig } from '../config.js';
import type { CommandResult } from '../types.js';
import { ok, err, type ToolOutcome } from '../types.js';

/**
 * Allowlist of executables run_command may invoke. This is intentionally
 * narrow read-only inspection commands only. Interpreters and package
 * managers are deliberately excluded: shell:false prevents shell parsing,
 * but it does not make `node -e`, `python3 -c`, or npm lifecycle execution
 * safe.
 *
 * Extend this list deliberately in later phases, not by request-time
 * override — the allowlist itself is not configurable via tool input.
 */
export const ALLOWED_COMMANDS = new Set([
  'ls',
  'cat',
  'pwd',
  'echo',
  'grep',
  'find',
  'wc',
  'git',
]);

// Subcommands we refuse even for otherwise-allowed binaries, because they
// mutate state or reach the network rather than just inspecting the repo.
const DENYLISTED_SUBCOMMANDS: Record<string, Set<string>> = {
  git: new Set(['push', 'clone', 'fetch', 'pull', 'reset', 'clean', 'checkout']),
};

const SAFE_GIT_SUBCOMMANDS = new Set(['status', 'log', 'diff', 'branch', 'show', 'rev-parse']);
const GIT_ESCAPE_OPTIONS = new Set(['-C', '--git-dir', '--work-tree', '--exec-path', '--upload-pack', '--config', '--output', '--ext-diff', '--textconv', '--config-env', '-c']);
const PATH_COMMANDS = new Set(['ls', 'cat', 'grep', 'find', 'wc']);
const FIND_EXEC_OPTIONS = new Set(['-exec', '-execdir', '-delete', '-ok', '-okdir', '-fprint', '-fprint0']);
const FILE_READING_OPTIONS: Record<string, Set<string>> = {
  grep: new Set(['-f', '--file']),
  find: new Set(['-files0-from']),
  wc: new Set(['--files0-from']),
};

export interface RunCommandOptions {
  command: string;
  args: string[];
}

export function validateCommand(opts: RunCommandOptions, _projectRoot?: string): ToolOutcome<true> {
  if (typeof opts.command !== 'string' || opts.command.trim() === '') {
    return err('INVALID_INPUT', 'Command must be a non-empty string');
  }
  if (!Array.isArray(opts.args) || !opts.args.every((a) => typeof a === 'string')) {
    return err('INVALID_INPUT', 'Args must be an array of strings');
  }
  if (!ALLOWED_COMMANDS.has(opts.command)) {
    return err(
      'COMMAND_NOT_ALLOWED',
      `Command "${opts.command}" is not in the allowlist: [${[...ALLOWED_COMMANDS].join(', ')}]`
    );
  }
  if (opts.args.some((arg) => arg.includes('\0'))) {
    return err('INVALID_INPUT', 'Command arguments must not contain null bytes');
  }
  const denied = DENYLISTED_SUBCOMMANDS[opts.command];
  if (denied && opts.args.some((arg) => denied.has(arg))) {
    return err(
      'COMMAND_NOT_ALLOWED',
      `Subcommand "${opts.command} ${opts.args[0]}" is not permitted in Phase 1 (read-only sandbox).`
    );
  }
  if (opts.command === 'git') {
    if (!SAFE_GIT_SUBCOMMANDS.has(opts.args[0] ?? '')) {
      return err('COMMAND_NOT_ALLOWED', 'Only read-only git subcommands are permitted.');
    }
    if (opts.args.some((arg) => isGitEscapeOption(arg) || path.isAbsolute(arg) || hasTraversalSegment(arg))) {
      return err('COMMAND_NOT_ALLOWED', 'Git path and repository override options are not permitted.');
    }
  }
  if (PATH_COMMANDS.has(opts.command) && opts.args.some((arg) => path.isAbsolute(arg) || hasTraversalSegment(arg))) {
    return err('COMMAND_NOT_ALLOWED', 'Command paths must remain inside the project root.');
  }
  if (_projectRoot && PATH_COMMANDS.has(opts.command)) {
    const pathArgs = opts.args.filter((arg) => arg !== '--' && !arg.startsWith('-'));
    for (const arg of pathArgs) {
      try {
        resolveExistingWithinRoot(_projectRoot, arg);
      } catch {
        return err('COMMAND_NOT_ALLOWED', 'Command paths must remain inside the project root.');
      }
    }
  }
  if (PATH_COMMANDS.has(opts.command)) {
    const fileOptions = FILE_READING_OPTIONS[opts.command];
    if (fileOptions) {
      for (let index = 0; index < opts.args.length; index += 1) {
        const arg = opts.args[index]!;
        const equal = arg.indexOf('=');
        const option = equal >= 0 ? arg.slice(0, equal) : arg;
        let value = equal >= 0 ? arg.slice(equal + 1) : null;
        if (!fileOptions.has(option) && !(opts.command === 'grep' && arg.startsWith('-f') && arg.length > 2)) continue;
        if (value === null) value = opts.args[index + 1] ?? '';
        else if (opts.command === 'grep' && option === '-f' && arg.length > 2) value = arg.slice(2);
        if (path.isAbsolute(value) || hasTraversalSegment(value)) {
          return err('COMMAND_NOT_ALLOWED', 'Command file-option paths must remain inside the project root.');
        }
        if (!_projectRoot) continue;
        try {
          resolveExistingWithinRoot(_projectRoot, value);
        } catch {
          return err('COMMAND_NOT_ALLOWED', 'Command file-option paths must remain inside the project root.');
        }
      }
    }
  }
  if (opts.command === 'find' && opts.args.some((arg) => FIND_EXEC_OPTIONS.has(arg))) {
    return err('COMMAND_NOT_ALLOWED', 'find execution and deletion actions are not permitted.');
  }
  return ok(true);
}

function hasTraversalSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..');
}

function isGitEscapeOption(value: string): boolean {
  return GIT_ESCAPE_OPTIONS.has(value)
    || value.startsWith('--git-dir=')
    || value.startsWith('--work-tree=')
    || value.startsWith('--exec-path=')
    || value.startsWith('--upload-pack=')
    || value.startsWith('--output=')
    || value.startsWith('--config-env=')
    || value.startsWith('-c');
}

function truncate(buf: Buffer, maxBytes: number): { text: string; truncated: boolean } {
  if (buf.length <= maxBytes) {
    return { text: buf.toString('utf-8'), truncated: false };
  }
  return { text: buf.subarray(0, maxBytes).toString('utf-8'), truncated: true };
}

export function runCommand(config: AppConfig, opts: RunCommandOptions): Promise<ToolOutcome<CommandResult>> {
  const validation = validateCommand(opts, config.projectRoot);
  if (!validation.ok) return Promise.resolve(validation as ToolOutcome<CommandResult>);

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stdoutCaptureTruncated = false;
    let stderrCaptureTruncated = false;
    let timedOut = false;

    let child;
    try {
      child = spawn(opts.command, opts.args, {
        cwd: config.projectRoot,
        // shell:false is the critical control here — args are passed
        // directly to execve, never interpreted by /bin/sh, so shell
        // metacharacters (;, |, &&, `, $(), etc.) in args are inert.
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: buildSafeEnv(),
      });
    } catch (e) {
      resolve(err('COMMAND_FAILED', `Failed to spawn command: ${(e as Error).message}`));
      return;
    }

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, config.commandTimeoutMs);

    child.stdout?.on('data', (chunk: Buffer) => {
      const remaining = config.maxOutputBytes - stdoutBytes;
      if (remaining <= 0) { stdoutCaptureTruncated = true; return; }
      if (chunk.length > remaining) stdoutCaptureTruncated = true;
      const bounded = chunk.subarray(0, remaining);
      stdoutChunks.push(bounded);
      stdoutBytes += bounded.length;
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      const remaining = config.maxOutputBytes - stderrBytes;
      if (remaining <= 0) { stderrCaptureTruncated = true; return; }
      if (chunk.length > remaining) stderrCaptureTruncated = true;
      const bounded = chunk.subarray(0, remaining);
      stderrChunks.push(bounded);
      stderrBytes += bounded.length;
    });

    child.on('error', (e: Error) => {
      clearTimeout(timer);
      resolve(err('COMMAND_FAILED', `Command execution error: ${e.message}`));
    });

    child.on('close', (exitCode: number | null, signal: NodeJS.Signals | null) => {
      clearTimeout(timer);
      const stdoutBuf = Buffer.concat(stdoutChunks);
      const stderrBuf = Buffer.concat(stderrChunks);
      const stdoutRes = truncate(stdoutBuf, config.maxOutputBytes);
      const stderrRes = truncate(stderrBuf, config.maxOutputBytes);

      const result: CommandResult = {
        command: opts.command,
        args: opts.args,
        exitCode,
        signal,
        stdout: stdoutRes.text,
        stderr: stderrRes.text,
        stdoutTruncated: stdoutCaptureTruncated || stdoutRes.truncated,
        stderrTruncated: stderrCaptureTruncated || stderrRes.truncated,
        timedOut,
        durationMs: Date.now() - startedAt,
      };

      if (timedOut) {
        resolve(err('COMMAND_TIMEOUT', `Command timed out after ${config.commandTimeoutMs}ms`));
        return;
      }

      resolve(ok(result));
    });
  });
}

/** Minimal env passed to child processes — avoids leaking the parent
 * process's full environment (which may contain API keys/secrets used by
 * this MCP server itself) into commands run against the target project. */
function buildSafeEnv(): NodeJS.ProcessEnv {
  const allowedKeys = ['HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TERM'];
  const safeEnv: NodeJS.ProcessEnv = {};
  for (const key of allowedKeys) {
    if (process.env[key] !== undefined) safeEnv[key] = process.env[key];
  }
  // Never resolve an allowlisted command through a caller-controlled PATH.
  // The MCP process environment may be attacker-influenced in an embedding
  // host, so command allowlisting must include executable resolution.
  safeEnv.PATH = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';
  return safeEnv;
}
