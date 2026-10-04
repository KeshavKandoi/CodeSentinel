import fs from 'node:fs';
import path from 'node:path';
import {
  resolveExistingWithinRoot,
  resolveWithinRoot,
  toRelativePosix,
  openRegularFileWithinRoot,
  isStableDirectory,
  PathOutsideRootError,
  InvalidPathError,
} from './pathGuard.js';
import { ok, err, type ToolOutcome, type FileEntry, type SearchMatch } from '../types.js';
import type { AppConfig } from '../config.js';

const DEFAULT_IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.venv',
  '__pycache__',
]);

const SENSITIVE_MESSAGE = 'Sensitive credential and repository configuration files are not available through inspection tools.';
const SENSITIVE_DIRECTORY_NAMES = new Set(['.ssh', '.aws', '.gnupg', '.kube', 'credential', 'credentials']);
const SENSITIVE_FILE_NAMES = new Set(['.netrc', '.npmrc', '.pypirc', '.pgpass', '.htpasswd', '.git-credentials', '.dockercfg']);
const SENSITIVE_ENV_FILE = /^\.env(?:\.|$)/;
const SENSITIVE_KEY_FILE = /\.(?:pem|key|p12|pfx|jks|keystore|ppk)$/;
const SENSITIVE_IDENTITY_FILE = /^id_(?:rsa|dsa|ecdsa|ed25519)$/;
const MAX_SEARCH_LINE_CHARS = 2000;
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d)/;

function normalizeSegment(segment: string): string {
  const base = segment.split(':')[0] ?? '';
  return base.replace(/[. ]+$/, '').toLowerCase();
}

export function isSensitiveInspectionPath(filePath: string): boolean {
  const segments = filePath
    .replaceAll('\\', '/')
    .split('/')
    .map(normalizeSegment)
    .filter((segment) => segment !== '');
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index]!;
    if (SENSITIVE_DIRECTORY_NAMES.has(segment) || SENSITIVE_FILE_NAMES.has(segment)) return true;
    if (SENSITIVE_ENV_FILE.test(segment) || SENSITIVE_KEY_FILE.test(segment) || SENSITIVE_IDENTITY_FILE.test(segment)) return true;
    if (segment === '.git' && segments[index + 1] === 'config') return true;
  }
  return false;
}

function toPathError<T>(e: unknown, attemptedPath: string): ToolOutcome<T> {
  if (e instanceof PathOutsideRootError) {
    return err('PATH_OUTSIDE_ROOT', `Access denied: "${attemptedPath}" is outside the project root.`);
  }
  if (e instanceof InvalidPathError) {
    return err('INVALID_INPUT', e.message);
  }
  return err('INTERNAL_ERROR', 'Path could not be resolved.');
}

const byName = (a: fs.Dirent, b: fs.Dirent): number => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

export interface ListFilesOptions {
  dirPath: string;
  recursive: boolean;
  maxResults: number;
}

export function listFiles(config: AppConfig, opts: ListFilesOptions): ToolOutcome<FileEntry[]> {
  let absDir: string;
  try {
    absDir = resolveExistingWithinRoot(config.projectRoot, opts.dirPath);
  } catch (e) {
    return toPathError(e, opts.dirPath);
  }
  if (isSensitiveInspectionPath(opts.dirPath) || isSensitiveInspectionPath(toRelativePosix(config.projectRoot, absDir))) {
    return err('INVALID_INPUT', SENSITIVE_MESSAGE);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(absDir);
  } catch {
    return err('NOT_FOUND', `Directory not found: ${opts.dirPath}`);
  }
  if (!stat.isDirectory()) {
    return err('NOT_A_DIRECTORY', `Not a directory: ${opts.dirPath}`);
  }
  if (!isStableDirectory(config.projectRoot, absDir)) {
    return err('PATH_OUTSIDE_ROOT', `Access denied: "${opts.dirPath}" is outside the project root.`);
  }

  const results: FileEntry[] = [];
  const cap = Math.min(opts.maxResults, config.maxListResults);

  const walk = (dirAbs: string): void => {
    if (results.length >= cap) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort(byName);

    for (const entry of entries) {
      if (results.length >= cap) return;
      if (entry.isDirectory() && DEFAULT_IGNORED_DIRS.has(entry.name)) continue;

      const entryAbs = path.join(dirAbs, entry.name);
      const relPosix = toRelativePosix(config.projectRoot, entryAbs);
      if (isSensitiveInspectionPath(relPosix)) continue;

      if (entry.isDirectory()) {
        if (!isStableDirectory(config.projectRoot, entryAbs)) continue;
        results.push({ path: relPosix, type: 'directory' });
        if (opts.recursive) walk(entryAbs);
      } else if (entry.isFile()) {
        let size: number | undefined;
        try {
          const entryStat = fs.lstatSync(entryAbs);
          if (!entryStat.isFile()) continue;
          size = entryStat.size;
        } catch {
          size = undefined;
        }
        results.push({ path: relPosix, type: 'file', sizeBytes: size });
      }
    }
  };

  walk(absDir);
  return ok(results);
}

export interface ReadFileOptions {
  filePath: string;
  maxBytes?: number;
  allowSensitive?: boolean;
}

export interface ReadFileResult {
  path: string;
  content: string;
  sizeBytes: number;
  truncated: boolean;
}

export function readFile(config: AppConfig, opts: ReadFileOptions): ToolOutcome<ReadFileResult> {
  if (!opts.allowSensitive && isSensitiveInspectionPath(opts.filePath)) {
    return err('INVALID_INPUT', SENSITIVE_MESSAGE);
  }
  let absPath: string;
  try {
    absPath = resolveExistingWithinRoot(config.projectRoot, opts.filePath);
  } catch (e) {
    return toPathError(e, opts.filePath);
  }
  if (!opts.allowSensitive && isSensitiveInspectionPath(toRelativePosix(config.projectRoot, absPath))) {
    return err('INVALID_INPUT', SENSITIVE_MESSAGE);
  }

  const limit = Math.min(opts.maxBytes ?? config.maxReadFileBytes, config.maxReadFileBytes);
  const opened = openRegularFileWithinRoot(config.projectRoot, absPath);
  if (!opened.ok) {
    if (opened.reason === 'not_found') return err('NOT_FOUND', `File not found: ${opts.filePath}`);
    if (opened.reason === 'not_file') return err('NOT_A_FILE', `Not a regular file: ${opts.filePath}`);
    if (opened.reason === 'outside') return err('PATH_OUTSIDE_ROOT', `Access denied: "${opts.filePath}" is outside the project root.`);
    return err('INTERNAL_ERROR', 'Failed to open file.');
  }
  try {
    const bytesToRead = Math.min(opened.size, limit);
    const buffer = Buffer.alloc(bytesToRead);
    let offset = 0;
    while (offset < bytesToRead) {
      const read = fs.readSync(opened.fd, buffer, offset, bytesToRead - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    return ok({
      path: opts.filePath,
      content: buffer.subarray(0, offset).toString('utf-8'),
      sizeBytes: opened.size,
      truncated: opened.size > limit,
    });
  } catch {
    return err('INTERNAL_ERROR', 'Failed to read file.');
  } finally {
    fs.closeSync(opened.fd);
  }
}

export interface SearchFilesOptions {
  query: string;
  dirPath: string;
  caseSensitive: boolean;
  maxResults: number;
  isRegex: boolean;
  allowSensitive?: boolean;
}

function readSearchableText(config: AppConfig, absPath: string): string | null {
  const opened = openRegularFileWithinRoot(config.projectRoot, absPath);
  if (!opened.ok) return null;
  try {
    if (opened.size > config.maxReadFileBytes) return null;
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < opened.size) {
      const read = fs.readSync(opened.fd, buffer, offset, opened.size - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    const content = buffer.subarray(0, offset);
    if (content.subarray(0, 512).includes(0)) return null;
    return content.toString('utf-8');
  } catch {
    return null;
  } finally {
    fs.closeSync(opened.fd);
  }
}

export function searchFiles(config: AppConfig, opts: SearchFilesOptions): ToolOutcome<SearchMatch[]> {
  if (opts.query.length === 0) {
    return err('INVALID_INPUT', 'Search query must not be empty');
  }
  if (!opts.allowSensitive && isSensitiveInspectionPath(opts.dirPath)) {
    return err('INVALID_INPUT', SENSITIVE_MESSAGE);
  }

  let absDir: string;
  try {
    absDir = resolveExistingWithinRoot(config.projectRoot, opts.dirPath);
  } catch (e) {
    return toPathError(e, opts.dirPath);
  }
  if (!opts.allowSensitive && isSensitiveInspectionPath(toRelativePosix(config.projectRoot, absDir))) {
    return err('INVALID_INPUT', SENSITIVE_MESSAGE);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(absDir);
  } catch {
    return err('NOT_FOUND', `Directory not found: ${opts.dirPath}`);
  }
  if (!stat.isDirectory()) {
    return err('NOT_A_DIRECTORY', `Not a directory: ${opts.dirPath}`);
  }
  if (!isStableDirectory(config.projectRoot, absDir)) {
    return err('PATH_OUTSIDE_ROOT', `Access denied: "${opts.dirPath}" is outside the project root.`);
  }

  if (opts.isRegex && NESTED_QUANTIFIER.test(opts.query)) {
    return err('INVALID_INPUT', 'Regex patterns with nested quantifiers are not permitted.');
  }
  let matcher: RegExp;
  try {
    const flags = opts.caseSensitive ? 'g' : 'gi';
    const pattern = opts.isRegex ? opts.query : escapeRegExp(opts.query);
    matcher = new RegExp(pattern, flags);
  } catch (e) {
    return err('INVALID_INPUT', `Invalid search pattern: ${(e as Error).message}`);
  }

  const results: SearchMatch[] = [];
  const cap = Math.min(opts.maxResults, config.maxListResults);

  const walk = (dirAbs: string): void => {
    if (results.length >= cap) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort(byName);

    for (const entry of entries) {
      if (results.length >= cap) return;
      const entryAbs = path.join(dirAbs, entry.name);
      const relPosix = toRelativePosix(config.projectRoot, entryAbs);
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
        if (!opts.allowSensitive && isSensitiveInspectionPath(relPosix)) continue;
        if (!isStableDirectory(config.projectRoot, entryAbs)) continue;
        walk(entryAbs);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!opts.allowSensitive && isSensitiveInspectionPath(relPosix)) continue;

      const text = readSearchableText(config, entryAbs);
      if (text === null) continue;

      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (results.length >= cap) return;
        const line = lines[i]!.slice(0, MAX_SEARCH_LINE_CHARS);
        matcher.lastIndex = 0;
        const m = matcher.exec(line);
        if (m) {
          results.push({
            path: relPosix,
            line: i + 1,
            column: m.index + 1,
            preview: line.slice(0, 300),
          });
        }
      }
    }
  };

  walk(absDir);
  return ok(results);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export { resolveWithinRoot };
