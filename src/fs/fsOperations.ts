import fs from 'node:fs';
import path from 'node:path';
import {
  resolveExistingWithinRoot,
  resolveWithinRoot,
  toRelativePosix,
  PathOutsideRootError,
  InvalidPathError,
} from './pathGuard.js';
import { ok, err, type ToolOutcome, type FileEntry, type SearchMatch } from '../types.js';
import type { AppConfig } from '../config.js';

// Directories we always skip while walking, regardless of caller input —
// keeps results useful and avoids pulling huge dependency trees into output.
const DEFAULT_IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.venv',
  '__pycache__',
]);

function toPathError<T>(e: unknown, attemptedPath: string): ToolOutcome<T> {
  if (e instanceof PathOutsideRootError) {
    return err('PATH_OUTSIDE_ROOT', `Access denied: "${attemptedPath}" is outside the project root.`);
  }
  if (e instanceof InvalidPathError) {
    return err('INVALID_INPUT', e.message);
  }
  throw e;
}

export interface ListFilesOptions {
  dirPath: string; // relative to project root, '.' for root
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

  let stat: fs.Stats;
  try {
    stat = fs.statSync(absDir);
  } catch {
    return err('NOT_FOUND', `Directory not found: ${opts.dirPath}`);
  }
  if (!stat.isDirectory()) {
    return err('NOT_A_DIRECTORY', `Not a directory: ${opts.dirPath}`);
  }

  const results: FileEntry[] = [];
  const cap = Math.min(opts.maxResults, config.maxListResults);

  const walk = (dirAbs: string): void => {
    if (results.length >= cap) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirAbs, { withFileTypes: true });
    } catch {
      return; // permission errors etc. — skip silently, don't fail whole listing
    }

    for (const entry of entries) {
      if (results.length >= cap) return;
      if (entry.isDirectory() && DEFAULT_IGNORED_DIRS.has(entry.name)) continue;

      const entryAbs = path.join(dirAbs, entry.name);
      const relPosix = toRelativePosix(config.projectRoot, entryAbs);

      if (entry.isDirectory()) {
        results.push({ path: relPosix, type: 'directory' });
        if (opts.recursive) walk(entryAbs);
      } else if (entry.isFile()) {
        let size: number | undefined;
        try {
          size = fs.statSync(entryAbs).size;
        } catch {
          size = undefined;
        }
        results.push({ path: relPosix, type: 'file', sizeBytes: size });
      }
      // symlinks and other special files are intentionally omitted
    }
  };

  walk(absDir);
  return ok(results);
}

export interface ReadFileOptions {
  filePath: string;
  maxBytes?: number;
}

export interface ReadFileResult {
  path: string;
  content: string;
  sizeBytes: number;
  truncated: boolean;
}

export function readFile(config: AppConfig, opts: ReadFileOptions): ToolOutcome<ReadFileResult> {
  let absPath: string;
  try {
    absPath = resolveExistingWithinRoot(config.projectRoot, opts.filePath);
  } catch (e) {
    return toPathError(e, opts.filePath);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(absPath);
  } catch {
    return err('NOT_FOUND', `File not found: ${opts.filePath}`);
  }
  if (!stat.isFile()) {
    return err('NOT_A_FILE', `Not a regular file: ${opts.filePath}`);
  }

  const limit = Math.min(opts.maxBytes ?? config.maxReadFileBytes, config.maxReadFileBytes);

  if (stat.size > limit) {
    // Read only up to the limit rather than loading the whole file then
    // truncating, to avoid memory blowup on huge files.
    const fd = fs.openSync(absPath, 'r');
    try {
      const buffer = Buffer.alloc(limit);
      fs.readSync(fd, buffer, 0, limit, 0);
      return ok({
        path: opts.filePath,
        content: buffer.toString('utf-8'),
        sizeBytes: stat.size,
        truncated: true,
      });
    } finally {
      fs.closeSync(fd);
    }
  }

  let content: string;
  try {
    content = fs.readFileSync(absPath, 'utf-8');
  } catch (e) {
    return err('INTERNAL_ERROR', `Failed to read file: ${(e as Error).message}`);
  }

  return ok({
    path: opts.filePath,
    content,
    sizeBytes: stat.size,
    truncated: false,
  });
}

export interface SearchFilesOptions {
  query: string;
  dirPath: string;
  caseSensitive: boolean;
  maxResults: number;
  isRegex: boolean;
}

export function searchFiles(config: AppConfig, opts: SearchFilesOptions): ToolOutcome<SearchMatch[]> {
  if (opts.query.length === 0) {
    return err('INVALID_INPUT', 'Search query must not be empty');
  }

  let absDir: string;
  try {
    absDir = resolveExistingWithinRoot(config.projectRoot, opts.dirPath);
  } catch (e) {
    return toPathError(e, opts.dirPath);
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

    for (const entry of entries) {
      if (results.length >= cap) return;
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
        walk(path.join(dirAbs, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;

      const entryAbs = path.join(dirAbs, entry.name);
      let stat2: fs.Stats;
      try {
        stat2 = fs.statSync(entryAbs);
      } catch {
        continue;
      }
      if (stat2.size > config.maxReadFileBytes) continue; // skip huge/binary-ish files
      if (isLikelyBinary(entryAbs)) continue;

      let text: string;
      try {
        text = fs.readFileSync(entryAbs, 'utf-8');
      } catch {
        continue;
      }

      const relPosix = toRelativePosix(config.projectRoot, entryAbs);
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (results.length >= cap) return;
        matcher.lastIndex = 0;
        const m = matcher.exec(lines[i]);
        if (m) {
          results.push({
            path: relPosix,
            line: i + 1,
            column: m.index + 1,
            preview: lines[i].slice(0, 300),
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

function isLikelyBinary(absPath: string): boolean {
  try {
    const fd = fs.openSync(absPath, 'r');
    const buffer = Buffer.alloc(512);
    const bytesRead = fs.readSync(fd, buffer, 0, 512, 0);
    fs.closeSync(fd);
    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0) return true; // null byte -> treat as binary
    }
    return false;
  } catch {
    return true;
  }
}

export { resolveWithinRoot };
