import fs from 'node:fs';
import { openRegularFileWithinRoot, resolveExistingWithinRoot } from '../fs/pathGuard.js';

export const MAX_MANIFEST_BYTES = 2_000_000;


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
    const opened = openRegularFileWithinRoot(root, abs);
    if (!opened.ok) return null;
    try {
      if (opened.size > MAX_MANIFEST_BYTES) return null;
      const buffer = Buffer.alloc(opened.size);
      let offset = 0;
      while (offset < buffer.length) {
        const read = fs.readSync(opened.fd, buffer, offset, buffer.length - offset, offset);
        if (read === 0) return null;
        offset += read;
      }
      return buffer.toString('utf8');
    } finally {
      fs.closeSync(opened.fd);
    }
  } catch {
    return null;
  }
}

export interface JsonReadResult<T> {
  data: T | null;
  warning: string | null;
}

export function readJsonFile<T = unknown>(root: string, relPath: string): JsonReadResult<T> {
  const text = readTextFile(root, relPath);
  if (text === null) {
    try {
      const abs = resolveExistingWithinRoot(root, relPath);
      if (fs.statSync(abs).size > MAX_MANIFEST_BYTES) return { data: null, warning: `${relPath} exceeds the ${MAX_MANIFEST_BYTES}-byte discovery limit; manifest metadata was not parsed.` };
    } catch {  }
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
