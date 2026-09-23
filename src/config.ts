import path from 'node:path';
import fs from 'node:fs';

export interface AppConfig {
  /** Absolute, resolved path to the project root. All filesystem/command
   * operations are sandboxed to this directory. */
  projectRoot: string;
  /** Max time (ms) a run_command execution may take before being killed. */
  commandTimeoutMs: number;
  /** Max bytes of stdout/stderr captured per command before truncation. */
  maxOutputBytes: number;
  /** Max file size (bytes) that read_file will return. */
  maxReadFileBytes: number;
  /** Max number of files list_files/search_files will return in one call. */
  maxListResults: number;
}

const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000; // 1MB
const DEFAULT_MAX_READ_FILE_BYTES = 2_000_000; // 2MB
const DEFAULT_MAX_LIST_RESULTS = 2_000;

function resolveProjectRoot(rawRoot: string | undefined): string {
  if (!rawRoot || rawRoot.trim() === '') {
    throw new Error(
      'PROJECT_ROOT is not set. Set the PROJECT_ROOT environment variable ' +
        'to the absolute path of the project you want to audit.'
    );
  }

  const resolved = path.resolve(rawRoot);

  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    throw new Error(`PROJECT_ROOT does not exist: ${resolved}`);
  }

  if (stat.isSymbolicLink()) {
    // Refuse a symlinked root outright: resolving it further could point
    // outside the intended sandbox in a way that's surprising to the user.
    throw new Error(
      `PROJECT_ROOT must not be a symbolic link: ${resolved}`
    );
  }

  if (!stat.isDirectory()) {
    throw new Error(`PROJECT_ROOT is not a directory: ${resolved}`);
  }

  // realpathSync collapses any remaining '..' / symlink segments in parent
  // path components so later prefix checks compare like-for-like.
  return fs.realpathSync(resolved);
}

function readIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    throw new Error(`Environment variable ${name} must be a positive integer, got: ${raw}`);
  }
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return {
    projectRoot: resolveProjectRoot(env.PROJECT_ROOT),
    commandTimeoutMs: readIntEnv('COMMAND_TIMEOUT_MS', DEFAULT_COMMAND_TIMEOUT_MS),
    maxOutputBytes: readIntEnv('MAX_OUTPUT_BYTES', DEFAULT_MAX_OUTPUT_BYTES),
    maxReadFileBytes: readIntEnv('MAX_READ_FILE_BYTES', DEFAULT_MAX_READ_FILE_BYTES),
    maxListResults: readIntEnv('MAX_LIST_RESULTS', DEFAULT_MAX_LIST_RESULTS),
  };
}
