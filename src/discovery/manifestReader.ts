import fs from 'node:fs';
import { resolveExistingWithinRoot } from '../fs/pathGuard.js';

/**
 * All discovery file access goes through these helpers rather than raw
 * fs calls, so every read stays inside the Phase 1 sandbox (pathGuard) and
 * never throws — a missing or unreadable file just means "not detected",
 * never a crash.
 */

export function fileExists(root: string, relPath: string): boolean {
  try {
    const abs = resolveExistingWithinRoot(root, relPath);
    return fs.existsSync(abs) && fs.statSync(abs).isFile();
  } catch {
    return false;
  }
}

export function dirExists(root: string, relPath: string): boolean {
  try {
    const abs = resolveExistingWithinRoot(root, relPath);
    return fs.existsSync(abs) && fs.statSync(abs).isDirectory();
  } catch {
    return false;
  }
}

export function readTextFile(root: string, relPath: string): string | null {
  try {
    const abs = resolveExistingWithinRoot(root, relPath);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
    return fs.readFileSync(abs, 'utf-8');
  } catch {
    return null;
  }
}

export interface JsonReadResult<T> {
  data: T | null;
  /** Set only when the file exists but failed to parse — a genuine
   * problem worth surfacing as a ProjectProfile warning. A simply-missing
   * file is not a warning: data is null and warning is null. */
  warning: string | null;
}

export function readJsonFile<T = unknown>(root: string, relPath: string): JsonReadResult<T> {
  const text = readTextFile(root, relPath);
  if (text === null) {
    return { data: null, warning: null };
  }
  try {
    return { data: JSON.parse(text) as T, warning: null };
  } catch (e) {
    return { data: null, warning: `Failed to parse ${relPath} as JSON: ${(e as Error).message}` };
  }
}

export function listTopLevelNames(root: string, relPath: string): string[] {
  try {
    const abs = resolveExistingWithinRoot(root, relPath);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) return [];
    return fs.readdirSync(abs);
  } catch {
    return [];
  }
}
