import path from 'node:path';
import fs from 'node:fs';

export interface AppConfig {
  projectRoot: string;
  commandTimeoutMs: number;
  maxOutputBytes: number;
  maxReadFileBytes: number;
  maxListResults: number;
}

const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000;
const DEFAULT_MAX_READ_FILE_BYTES = 2_000_000;
const DEFAULT_MAX_LIST_RESULTS = 2_000;
const COMMAND_TIMEOUT_CEILING_MS = 600_000;
const MAX_OUTPUT_BYTES_CEILING = 50_000_000;
const MAX_READ_FILE_BYTES_CEILING = 100_000_000;
const MAX_LIST_RESULTS_CEILING = 100_000;

function resolveProjectRoot(rawRoot: string | undefined): string {
  if (!rawRoot || rawRoot.trim() === '') {
    throw new Error(
      'PROJECT_ROOT is not set. Set the PROJECT_ROOT environment variable to the absolute path of the project you want to audit.'
    );
  }
  if (rawRoot.includes('\0')) {
    throw new Error('PROJECT_ROOT contains an invalid character.');
  }

  const resolved = path.resolve(rawRoot);

  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    throw new Error('PROJECT_ROOT does not exist.');
  }
  if (stat.isSymbolicLink()) {
    throw new Error('PROJECT_ROOT must not be a symbolic link.');
  }
  if (!stat.isDirectory()) {
    throw new Error('PROJECT_ROOT is not a directory.');
  }
  try {
    return fs.realpathSync(resolved);
  } catch {
    throw new Error('PROJECT_ROOT could not be resolved.');
  }
}

function readIntEnv(env: NodeJS.ProcessEnv, name: string, fallback: number, ceiling: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = /^[1-9]\d*$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed > ceiling) {
    throw new Error(`Environment variable ${name} must be a positive integer no greater than ${ceiling}.`);
  }
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return {
    projectRoot: resolveProjectRoot(env.PROJECT_ROOT),
    commandTimeoutMs: readIntEnv(env, 'COMMAND_TIMEOUT_MS', DEFAULT_COMMAND_TIMEOUT_MS, COMMAND_TIMEOUT_CEILING_MS),
    maxOutputBytes: readIntEnv(env, 'MAX_OUTPUT_BYTES', DEFAULT_MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES_CEILING),
    maxReadFileBytes: readIntEnv(env, 'MAX_READ_FILE_BYTES', DEFAULT_MAX_READ_FILE_BYTES, MAX_READ_FILE_BYTES_CEILING),
    maxListResults: readIntEnv(env, 'MAX_LIST_RESULTS', DEFAULT_MAX_LIST_RESULTS, MAX_LIST_RESULTS_CEILING),
  };
}
