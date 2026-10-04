import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { openRegularFileWithinRoot, resolveExistingWithinRoot, toRelativePosix } from '../fs/pathGuard.js';
import { isSensitiveInspectionPath } from '../fs/fsOperations.js';
import type { AppConfig } from '../config.js';
import type { CommandResult } from '../types.js';
import { ok, err, type ToolOutcome } from '../types.js';

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

const DENYLISTED_SUBCOMMANDS: Record<string, Set<string>> = {
  git: new Set(['push', 'clone', 'fetch', 'pull', 'reset', 'clean', 'checkout']),
};

const TRUSTED_BIN_DIRS = ['/usr/bin', '/bin'];
const TRUSTED_PATH = TRUSTED_BIN_DIRS.join(':');
const PATH_COMMANDS = new Set(['ls', 'cat', 'grep', 'find', 'wc']);
const OUTSIDE_PATH_MESSAGE = 'Command paths must remain inside the project root.';
const SENSITIVE_PATH_MESSAGE = 'Sensitive credential and repository configuration files are not available through command execution.';
const OPTION_MESSAGE = 'Command option is not permitted.';
const MAX_GIT_CONFIG_BYTES = 1_000_000;

const names = (...values: string[]): ReadonlySet<string> => new Set(values);

interface OptionSpec {
  shortFlags: string;
  shortValue: string;
  longFlags: ReadonlySet<string>;
  longValue: ReadonlySet<string>;
}

const OPTION_SPECS: Record<string, OptionSpec> = {
  ls: {
    shortFlags: '1aAcdFghiklmnopqrRsStuUx',
    shortValue: '',
    longFlags: names('--all', '--almost-all', '--human-readable', '--recursive', '--directory', '--classify', '--size', '--reverse', '--inode', '--numeric-uid-gid', '--color=never'),
    longValue: names(),
  },
  cat: {
    shortFlags: 'AbeEnstTuv',
    shortValue: '',
    longFlags: names('--show-all', '--number-nonblank', '--show-ends', '--number', '--squeeze-blank', '--show-tabs', '--show-nonprinting'),
    longValue: names(),
  },
  wc: {
    shortFlags: 'clmwL',
    shortValue: '',
    longFlags: names('--bytes', '--chars', '--lines', '--words', '--max-line-length'),
    longValue: names(),
  },
  grep: {
    shortFlags: 'EFGHILPTUZabchilnoqrsvwxz',
    shortValue: 'emABC',
    longFlags: names(
      '--recursive', '--ignore-case', '--no-ignore-case', '--invert-match', '--word-regexp', '--line-regexp', '--count',
      '--files-with-matches', '--files-without-match', '--line-number', '--with-filename', '--no-filename', '--quiet',
      '--silent', '--fixed-strings', '--extended-regexp', '--basic-regexp', '--perl-regexp', '--only-matching',
      '--no-messages', '--text', '--null', '--null-data', '--byte-offset', '--initial-tab', '--color=never'
    ),
    longValue: names('--regexp', '--max-count', '--after-context', '--before-context', '--context', '--include', '--exclude', '--exclude-dir', '--binary-files'),
  },
};

const GREP_EXCLUDED_FILES = [
  '.env', '.env.*', '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore', '*.ppk', '.netrc', '.npmrc', '.pypirc',
  '.pgpass', '.htpasswd', '.git-credentials', '.dockercfg', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'credential', 'credentials',
];
const GREP_EXCLUDED_DIRS = ['.git', '.ssh', '.aws', '.gnupg', '.kube', 'credential', 'credentials'];

const FIND_BLOCKED = names('-exec', '-execdir', '-delete', '-ok', '-okdir', '-fprint', '-fprint0', '-fls', '-fprintf', '-files0-from');
const FIND_FLAG_PRIMARIES = names('-print', '-print0', '-prune', '-empty', '-depth', '-xdev', '-mount', '-o', '-a', '-and', '-or', '-not', '!', '(', ')', '-true', '-false');
const FIND_VALUE_PRIMARIES = names('-name', '-iname', '-path', '-ipath', '-type', '-maxdepth', '-mindepth', '-size', '-mtime', '-mmin', '-atime', '-ctime', '-perm', '-regex', '-iregex');

interface GitRule {
  flags: ReadonlySet<string>;
  patterns: RegExp[];
}

const GIT_FORMAT = /^--(?:pretty|format)=[\w%:,.\-\s()[\]]*$/;
const GIT_RULES: Record<string, GitRule> = {
  status: {
    flags: names('-s', '--short', '-b', '--branch', '--porcelain', '--porcelain=v1', '--porcelain=v2', '--long', '-z', '--untracked-files=no', '--untracked-files=normal'),
    patterns: [],
  },
  log: {
    flags: names('--oneline', '--stat', '--name-only', '--name-status', '--no-merges', '--graph', '--decorate', '--all', '--abbrev-commit', '--reverse', '--no-color', '--first-parent', '-p', '--patch', '-n'),
    patterns: [/^-\d+$/, /^-n\d+$/, /^--max-count=\d+$/, GIT_FORMAT, /^--(?:since|until|author|committer|grep)=.{1,200}$/],
  },
  diff: {
    flags: names('--stat', '--name-only', '--name-status', '--numstat', '--shortstat', '--cached', '--staged', '--no-color', '--color=never', '-p', '--patch', '--summary', '--check', '-w', '--ignore-all-space'),
    patterns: [/^-U\d+$/, /^--unified=\d+$/],
  },
  show: {
    flags: names('--stat', '--name-only', '--name-status', '--oneline', '--no-patch', '-s', '--no-color', '-p', '--patch', '--summary'),
    patterns: [GIT_FORMAT, /^-U\d+$/],
  },
  branch: {
    flags: names('-a', '-r', '-v', '-vv', '--all', '--remotes', '--verbose', '--list', '--show-current', '--no-color'),
    patterns: [],
  },
  'rev-parse': {
    flags: names('--abbrev-ref', '--short', '--verify', '--is-inside-work-tree', '--symbolic-full-name', '--show-prefix', '--quiet', '-q', '--is-bare-repository', '--is-shallow-repository'),
    patterns: [/^--short=\d+$/, /^--abbrev-ref=(?:strict|loose)$/],
  },
};

const GIT_SENSITIVE_PATHSPECS = ["**/.env","**/.env.*","**/*.pem","**/*.key","**/*.p12","**/*.pfx","**/*.jks","**/*.keystore","**/*.ppk","**/.netrc","**/.npmrc","**/.pypirc","**/.pgpass","**/.htpasswd","**/.git-credentials","**/.dockercfg","**/id_rsa","**/id_dsa","**/id_ecdsa","**/id_ed25519","**/credential","**/credential/**","**/credentials","**/credentials/**","**/.ssh/**","**/.aws/**","**/.gnupg/**","**/.kube/**"].map((glob) => `:(exclude,icase,glob)${glob}`);

export interface RunCommandOptions {
  command: string;
  args: string[];
}

function deny(message: string): ToolOutcome<string[]> {
  return err('COMMAND_NOT_ALLOWED', message);
}

function hasTraversalSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..');
}

function isOutsideLexically(value: string): boolean {
  return path.isAbsolute(value) || path.win32.isAbsolute(value) || /^[a-zA-Z]:/.test(value) || hasTraversalSegment(value);
}

function checkPaths(paths: string[], projectRoot?: string): string | null {
  for (const arg of paths) {
    if (arg === '-') continue;
    if (isOutsideLexically(arg)) return OUTSIDE_PATH_MESSAGE;
    if (isSensitiveInspectionPath(arg)) return SENSITIVE_PATH_MESSAGE;
    if (!projectRoot) continue;
    let real: string;
    try {
      real = resolveExistingWithinRoot(projectRoot, arg);
    } catch {
      return OUTSIDE_PATH_MESSAGE;
    }
    if (isSensitiveInspectionPath(toRelativePosix(projectRoot, real))) return SENSITIVE_PATH_MESSAGE;
  }
  return null;
}

interface ParsedOptions {
  positionals: string[];
  recursive: boolean;
  patternOption: boolean;
  terminatorIndex: number;
}

function parseOptions(command: string, args: string[]): ParsedOptions | null {
  const spec = OPTION_SPECS[command]!;
  const positionals: string[] = [];
  let recursive = false;
  let patternOption = false;
  let terminatorIndex = -1;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (terminatorIndex >= 0) {
      positionals.push(arg);
      continue;
    }
    if (arg === '--') {
      terminatorIndex = index;
      continue;
    }
    if (arg === '-' || !arg.startsWith('-')) {
      positionals.push(arg);
      continue;
    }
    if (arg.startsWith('--')) {
      if (spec.longFlags.has(arg)) {
        if (arg === '--recursive' && command === 'grep') recursive = true;
        continue;
      }
      const equal = arg.indexOf('=');
      const name = equal >= 0 ? arg.slice(0, equal) : arg;
      if (spec.longValue.has(name)) {
        if (equal < 0) index += 1;
        if (name === '--regexp') patternOption = true;
        continue;
      }
      return null;
    }
    for (let position = 1; position < arg.length; position += 1) {
      const flag = arg[position]!;
      if (spec.shortValue.includes(flag)) {
        if (flag === 'e') patternOption = true;
        if (position === arg.length - 1) index += 1;
        break;
      }
      if (spec.shortFlags.includes(flag) || (command === 'grep' && /\d/.test(flag))) {
        if (flag === 'r' && command === 'grep') recursive = true;
        continue;
      }
      return null;
    }
  }
  return { positionals, recursive, patternOption, terminatorIndex };
}

function caseInsensitiveGlob(value: string): string {
  return value.replace(/[a-z]/gi, (character) => `[${character.toLowerCase()}${character.toUpperCase()}]`);
}

function withGrepExclusions(args: string[], terminatorIndex: number): string[] {
  const exclusions = [
    ...GREP_EXCLUDED_FILES.map((glob) => `--exclude=${caseInsensitiveGlob(glob)}`),
    ...GREP_EXCLUDED_DIRS.map((glob) => `--exclude-dir=${caseInsensitiveGlob(glob)}`),
  ];
  if (terminatorIndex < 0) return [...args, ...exclusions];
  return [...args.slice(0, terminatorIndex), ...exclusions, ...args.slice(terminatorIndex)];
}

function parseFind(args: string[]): { paths: string[] } | { error: string } {
  const paths: string[] = [];
  const startsExpression = (token: string): boolean => token.startsWith('-') || token === '(' || token === ')' || token === '!';
  let index = 0;
  while (index < args.length && !startsExpression(args[index]!)) {
    paths.push(args[index]!);
    index += 1;
  }
  for (; index < args.length; index += 1) {
    const token = args[index]!;
    if (FIND_BLOCKED.has(token) || token.startsWith('-files0-from=')) {
      return { error: 'find execution and deletion actions are not permitted.' };
    }
    if (FIND_FLAG_PRIMARIES.has(token)) continue;
    if (FIND_VALUE_PRIMARIES.has(token)) {
      index += 1;
      continue;
    }
    return { error: 'find expression is not permitted.' };
  }
  return { paths };
}

function pathExists(target: string): boolean {
  try {
    fs.lstatSync(target);
    return true;
  } catch {
    return false;
  }
}

function gitRepositoryBlockReason(projectRoot: string): string | null {
  const gitPath = path.join(projectRoot, '.git');
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(gitPath);
  } catch {
    return null;
  }
  if (!stat.isDirectory()) return 'Git metadata must be a plain directory inside the project root.';
  if (pathExists(path.join(gitPath, 'commondir')) || pathExists(path.join(gitPath, 'objects', 'info', 'alternates'))) {
    return 'Git metadata referencing locations outside the project root is not permitted.';
  }
  const opened = openRegularFileWithinRoot(projectRoot, path.join(gitPath, 'config'));
  if (!opened.ok) {
    return opened.reason === 'not_found' ? null : 'Git configuration could not be verified.';
  }
  try {
    const size = Math.min(opened.size, MAX_GIT_CONFIG_BYTES);
    const buffer = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = fs.readSync(opened.fd, buffer, offset, size - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    if (opened.size > MAX_GIT_CONFIG_BYTES || /^\s*\[\s*(?:filter|include|includeif)\b|^\s*(?:worktree|gitdir)\s*=/im.test(buffer.subarray(0, offset).toString('utf-8'))) {
      return 'Repository git configuration defines executable or external settings.';
    }
    return null;
  } catch {
    return 'Git configuration could not be verified.';
  } finally {
    fs.closeSync(opened.fd);
  }
}

function prepareGit(args: string[], projectRoot?: string): ToolOutcome<string[]> {
  const subcommand = args[0] ?? '';
  if (!Object.prototype.hasOwnProperty.call(GIT_RULES, subcommand)) {
    return deny('Only read-only git subcommands are permitted.');
  }
  const rule = GIT_RULES[subcommand]!;
  const positionals: string[] = [];
  let listMode = false;
  let afterTerminator = false;
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!afterTerminator && arg === '--') {
      afterTerminator = true;
      continue;
    }
    if (!afterTerminator && arg.startsWith('-') && arg !== '-') {
      if (rule.flags.has(arg) || rule.patterns.some((pattern) => pattern.test(arg))) {
        if (arg === '--list') listMode = true;
        continue;
      }
      return deny('Git option is not permitted.');
    }
    positionals.push(arg);
  }
  if (subcommand === 'branch' && positionals.length > 0 && !listMode) {
    return deny('Git branch may only list branches.');
  }
  for (const arg of positionals) {
    if (path.isAbsolute(arg) || path.win32.isAbsolute(arg) || arg.split(/[\\/:]+/).includes('..')) {
      return deny('Git path and repository override options are not permitted.');
    }
    const afterColon = arg.includes(':') ? arg.slice(arg.indexOf(':') + 1) : '';
    if (isSensitiveInspectionPath(arg) || (afterColon !== '' && isSensitiveInspectionPath(afterColon))) {
      return deny(SENSITIVE_PATH_MESSAGE);
    }
  }
  if (projectRoot) {
    const reason = gitRepositoryBlockReason(projectRoot);
    if (reason) return deny(reason);
  }
  const extras = subcommand === 'diff' || subcommand === 'show' || subcommand === 'log' ? ['--no-ext-diff', '--no-textconv'] : [];
  const excludes = extras.length > 0 ? GIT_SENSITIVE_PATHSPECS : [];
  return ok([
    '--no-pager',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.pager=cat',
    '-c', 'protocol.allow=never',
    subcommand,
    ...extras,
    ...args.slice(1),
    ...excludes,
  ]);
}

function prepareCommand(opts: RunCommandOptions, projectRoot?: string): ToolOutcome<string[]> {
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
    return deny(`Subcommand "${opts.command} ${opts.args[0]}" is not permitted in Phase 1 (read-only sandbox).`);
  }
  if (opts.command === 'git') return prepareGit(opts.args, projectRoot);
  if (opts.command === 'find') {
    const parsed = parseFind(opts.args);
    if ('error' in parsed) return deny(parsed.error);
    const reason = checkPaths(parsed.paths, projectRoot);
    return reason ? deny(reason) : ok([...opts.args]);
  }
  if (PATH_COMMANDS.has(opts.command)) {
    const parsed = parseOptions(opts.command, opts.args);
    if (!parsed) return deny(OPTION_MESSAGE);
    const paths = opts.command === 'grep' && !parsed.patternOption ? parsed.positionals.slice(1) : parsed.positionals;
    const reason = checkPaths(paths, projectRoot);
    if (reason) return deny(reason);
    if (opts.command === 'grep' && parsed.recursive) {
      return ok(withGrepExclusions(opts.args, parsed.terminatorIndex));
    }
  }
  return ok([...opts.args]);
}

export function validateCommand(opts: RunCommandOptions, _projectRoot?: string): ToolOutcome<true> {
  const prepared = prepareCommand(opts, _projectRoot);
  if (!prepared.ok) return err(prepared.error.code, prepared.error.message);
  return ok(true);
}

function resolveExecutable(command: string): string | null {
  for (const dir of TRUSTED_BIN_DIRS) {
    const candidate = path.join(dir, command);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

interface Capture {
  chunks: Buffer[];
  bytes: number;
  truncated: boolean;
}

function appendBounded(capture: Capture, chunk: Buffer, limit: number): void {
  const remaining = limit - capture.bytes;
  if (remaining <= 0) {
    capture.truncated = true;
    return;
  }
  if (chunk.length > remaining) capture.truncated = true;
  const bounded = chunk.subarray(0, remaining);
  capture.chunks.push(bounded);
  capture.bytes += bounded.length;
}

export function runCommand(config: AppConfig, opts: RunCommandOptions): Promise<ToolOutcome<CommandResult>> {
  const prepared = prepareCommand(opts, config.projectRoot);
  if (!prepared.ok) return Promise.resolve(err<CommandResult>(prepared.error.code, prepared.error.message));
  const executable = resolveExecutable(opts.command);
  if (!executable) {
    return Promise.resolve(err<CommandResult>('COMMAND_FAILED', 'Command executable is not available on this host.'));
  }
  const spawnArgs = prepared.data;

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const stdout: Capture = { chunks: [], bytes: 0, truncated: false };
    const stderr: Capture = { chunks: [], bytes: 0, truncated: false };
    let timedOut = false;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const finish = (outcome: ToolOutcome<CommandResult>): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(outcome);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, spawnArgs, {
        cwd: config.projectRoot,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: buildSafeEnv(config.projectRoot),
      });
    } catch {
      finish(err('COMMAND_FAILED', 'Failed to spawn command.'));
      return;
    }

    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
      finish(err('COMMAND_TIMEOUT', `Command timed out after ${config.commandTimeoutMs}ms`));
    }, config.commandTimeoutMs);

    const onData = (capture: Capture, chunk: Buffer): void => {
      appendBounded(capture, chunk, config.maxOutputBytes);
      if (capture.truncated) child.kill('SIGKILL');
    };
    child.stdout?.on('data', (chunk: Buffer) => onData(stdout, chunk));
    child.stderr?.on('data', (chunk: Buffer) => onData(stderr, chunk));

    child.on('error', () => {
      finish(err('COMMAND_FAILED', 'Command execution error.'));
    });

    child.on('close', (exitCode: number | null, signal: NodeJS.Signals | null) => {
      finish(
        ok({
          command: opts.command,
          args: opts.args,
          exitCode,
          signal,
          stdout: Buffer.concat(stdout.chunks).toString('utf-8'),
          stderr: Buffer.concat(stderr.chunks).toString('utf-8'),
          stdoutTruncated: stdout.truncated,
          stderrTruncated: stderr.truncated,
          timedOut,
          durationMs: Date.now() - startedAt,
        })
      );
    });
  });
}

function buildSafeEnv(projectRoot: string): NodeJS.ProcessEnv {
  const safeEnv: NodeJS.ProcessEnv = {};
  for (const key of ['LANG', 'LC_ALL', 'TMPDIR', 'TERM']) {
    if (process.env[key] !== undefined) safeEnv[key] = process.env[key];
  }
  safeEnv.PATH = TRUSTED_PATH;
  safeEnv.GIT_CONFIG_NOSYSTEM = '1';
  safeEnv.GIT_CONFIG_GLOBAL = '/dev/null';
  safeEnv.GIT_CONFIG_SYSTEM = '/dev/null';
  safeEnv.GIT_ATTR_NOSYSTEM = '1';
  safeEnv.GIT_TERMINAL_PROMPT = '0';
  safeEnv.GIT_OPTIONAL_LOCKS = '0';
  safeEnv.GIT_PAGER = 'cat';
  safeEnv.PAGER = 'cat';
  safeEnv.GIT_CEILING_DIRECTORIES = path.dirname(projectRoot);
  return safeEnv;
}
