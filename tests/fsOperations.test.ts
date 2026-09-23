import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { listFiles, readFile, searchFiles } from '../src/fs/fsOperations.js';
import { makeFixtureProject, makeOutsideSecretFile } from './testUtils.js';

const { config, root, cleanup } = makeFixtureProject();
afterAll(() => cleanup());

describe('listFiles', () => {
  it('lists top-level entries excluding node_modules and .git', () => {
    const result = listFiles(config, { dirPath: '.', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const names = result.data.map((e) => e.path);
    expect(names).toContain('package.json');
    expect(names).toContain('README.md');
    expect(names).toContain('src');
    expect(names).not.toContain('node_modules');
    expect(names).not.toContain('.git');
  });

  it('lists recursively when requested', () => {
    const result = listFiles(config, { dirPath: '.', recursive: true, maxResults: 100 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const names = result.data.map((e) => e.path);
    expect(names).toContain('src/index.js');
    expect(names).toContain('src/utils/helpers.js');
  });

  it('does not recurse when recursive=false', () => {
    const result = listFiles(config, { dirPath: '.', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const names = result.data.map((e) => e.path);
    expect(names).not.toContain('src/index.js');
  });

  it('respects maxResults cap', () => {
    const result = listFiles(config, { dirPath: '.', recursive: true, maxResults: 2 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.length).toBeLessThanOrEqual(2);
  });

  it('rejects path traversal attempts', () => {
    const result = listFiles(config, { dirPath: '../../etc', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('rejects absolute paths', () => {
    const result = listFiles(config, { dirPath: '/etc', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('returns NOT_FOUND for a nonexistent directory', () => {
    const result = listFiles(config, { dirPath: 'does-not-exist', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('NOT_FOUND');
  });

  it('returns NOT_A_DIRECTORY when pointed at a file', () => {
    const result = listFiles(config, { dirPath: 'README.md', recursive: false, maxResults: 100 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('NOT_A_DIRECTORY');
  });
});

describe('readFile', () => {
  it('reads a text file correctly', () => {
    const result = readFile(config, { filePath: 'README.md' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.content).toContain('Fixture project');
    expect(result.data.truncated).toBe(false);
  });

  it('reads a nested file correctly', () => {
    const result = readFile(config, { filePath: 'src/utils/helpers.js' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.content).toContain('function add');
  });

  it('truncates a file larger than maxBytes', () => {
    const result = readFile(config, { filePath: 'big.txt', maxBytes: 100 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.truncated).toBe(true);
    expect(result.data.content.length).toBe(100);
  });

  it('rejects path traversal attempts', () => {
    const result = readFile(config, { filePath: '../../../etc/passwd' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('cannot read a file outside root via a symlink', () => {
    const { secretPath, cleanup: cleanupSecret } = makeOutsideSecretFile(root);
    const linkPath = path.join(root, 'sneaky-link.txt');
    fs.symlinkSync(secretPath, linkPath);
    try {
      const result = readFile(config, { filePath: 'sneaky-link.txt' });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
    } finally {
      fs.rmSync(linkPath, { force: true });
      cleanupSecret();
    }
  });

  it('returns NOT_FOUND for a nonexistent file', () => {
    const result = readFile(config, { filePath: 'nope.txt' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('NOT_FOUND');
  });

  it('returns NOT_A_FILE when pointed at a directory', () => {
    const result = readFile(config, { filePath: 'src' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('NOT_A_FILE');
  });

  it('rejects an empty path', () => {
    const result = readFile(config, { filePath: '' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_INPUT');
  });
});

describe('searchFiles', () => {
  it('finds a plain-text match', () => {
    const result = searchFiles(config, {
      query: 'TODO',
      dirPath: '.',
      caseSensitive: false,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.some((m) => m.path === 'src/index.js')).toBe(true);
  });

  it('is case-insensitive by default', () => {
    const result = searchFiles(config, {
      query: 'todo',
      dirPath: '.',
      caseSensitive: false,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.length).toBeGreaterThan(0);
  });

  it('respects caseSensitive=true', () => {
    const result = searchFiles(config, {
      query: 'todo',
      dirPath: '.',
      caseSensitive: true,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.length).toBe(0);
  });

  it('supports regex search', () => {
    const result = searchFiles(config, {
      query: 'function\\s+add',
      dirPath: '.',
      caseSensitive: false,
      isRegex: true,
      maxResults: 50,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.some((m) => m.path === 'src/utils/helpers.js')).toBe(true);
  });

  it('rejects invalid regex patterns', () => {
    const result = searchFiles(config, {
      query: '(unclosed',
      dirPath: '.',
      caseSensitive: false,
      isRegex: true,
      maxResults: 50,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_INPUT');
  });

  it('rejects empty query', () => {
    const result = searchFiles(config, {
      query: '',
      dirPath: '.',
      caseSensitive: false,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_INPUT');
  });

  it('rejects path traversal in dirPath', () => {
    const result = searchFiles(config, {
      query: 'root',
      dirPath: '../../',
      caseSensitive: false,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('does not search inside node_modules', () => {
    const result = searchFiles(config, {
      query: 'module.exports',
      dirPath: '.',
      caseSensitive: false,
      isRegex: false,
      maxResults: 50,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.some((m) => m.path.startsWith('node_modules'))).toBe(false);
  });
});
