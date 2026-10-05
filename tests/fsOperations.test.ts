import { testCredential } from './testCredentials.js';
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

import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { isSensitiveInspectionPath } from '../src/fs/fsOperations.js';

describe('phase 1 sensitive path classification', () => {
  it.each([
    '.env', '.ENV', '.Env.Local', 'config/.env.production', '.env.', '.env::$DATA', 'app\\.env', './.env',
    '.ssh/config', 'a/.SSH/known_hosts', 'id_rsa', 'ID_ED25519', 'keys/server.PEM', 'tls/cert.key', 'store.p12',
    '.aws/credentials', 'Credentials/x', '.npmrc', '.NETRC', '.git/config', '.GIT/CONFIG', '.gnupg/pubring.kbx', '.kube/config',
  ])('treats %s as sensitive', (value) => {
    expect(isSensitiveInspectionPath(value)).toBe(true);
  });

  it.each(['src/index.js', 'README.md', 'environment.ts', 'src/env.ts', '.gitignore', '.git/HEAD', 'package.json', 'docs/keys.md', 'src/credentials.ts'])('does not treat %s as sensitive', (value) => {
    expect(isSensitiveInspectionPath(value)).toBe(false);
  });
});

describe('phase 1 filesystem hardening', () => {
  const fx = makeFixtureProject();
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-outside-'));
  fs.writeFileSync(path.join(outsideDir, 'outside.txt'), 'needle-outside\n');
  fs.writeFileSync(path.join(fx.root, '.env'), `API_KEY=${testCredential('API_KEY')}\n`);
  fs.mkdirSync(path.join(fx.root, '.ssh'));
  fs.writeFileSync(path.join(fx.root, '.ssh', 'id_rsa'), `${testCredential('DB_PASSWORD')}\n`);
  fs.mkdirSync(path.join(fx.root, 'dist'));
  fs.writeFileSync(path.join(fx.root, 'dist', 'x.js'), 'zzmatch\n');
  fs.mkdirSync(path.join(fx.root, 'build'));
  fs.writeFileSync(path.join(fx.root, 'build', 'x.js'), 'zzmatch\n');
  fs.symlinkSync(outsideDir, path.join(fx.root, 'outdir'));
  fs.symlinkSync(path.join(outsideDir, 'outside.txt'), path.join(fx.root, 'outfile.txt'));
  fs.symlinkSync(path.join(fx.root, 'README.md'), path.join(fx.root, 'inlink.md'));
  fs.symlinkSync(path.join(fx.root, '.env'), path.join(fx.root, 'envlink.txt'));
  fs.writeFileSync(path.join(fx.root, 'a.txt'), 'zzmatch\n');
  fs.writeFileSync(path.join(fx.root, 'b.txt'), 'zzmatch\n');
  fs.writeFileSync(path.join(fx.root, 'bin.dat'), Buffer.concat([Buffer.from([0]), Buffer.from('needlebin\n')]));
  fs.writeFileSync(path.join(fx.root, 'long.txt'), `${'a'.repeat(3000)}needlelong\n`);
  execFileSync('mkfifo', [path.join(fx.root, 'pipe')]);
  afterAll(() => {
    fx.cleanup();
    fs.rmSync(outsideDir, { recursive: true, force: true });
  });

  const search = (query: string, extra: Record<string, unknown> = {}, cfg = fx.config) =>
    searchFiles(cfg, { query, dirPath: '.', caseSensitive: false, isRegex: false, maxResults: 100, ...extra });

  it('readFile blocks sensitive files by case variant, nested path, and in-root symlink', () => {
    for (const filePath of ['.env', '.ENV', '.Env.Production', 'sub/.env.local', '.ssh/id_rsa', 'envlink.txt']) {
      const result = readFile(fx.config, { filePath });
      expect(result.ok, filePath).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('INVALID_INPUT');
    }
  });

  it('readFile exposes sensitive files only to trusted internal callers', () => {
    const result = readFile(fx.config, { filePath: '.env', allowSensitive: true });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.content).toContain(testCredential('API_KEY'));
  });

  it('readFile rejects sibling-prefix, mixed-separator, absolute, and null-byte paths', () => {
    const sibling = `../${path.basename(fx.root)}-other/file.txt`;
    for (const filePath of [sibling, 'src\\..\\..\\x', '/etc/passwd', 'C:\\Windows\\win.ini', 'outdir/outside.txt']) {
      const result = readFile(fx.config, { filePath });
      expect(result.ok, filePath).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
    }
    const nul = readFile(fx.config, { filePath: 'a\0b' });
    expect(nul.ok).toBe(false);
    if (!nul.ok) expect(nul.error.code).toBe('INVALID_INPUT');
  });

  it('readFile follows a symlink that stays inside the root', () => {
    const result = readFile(fx.config, { filePath: 'inlink.md' });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.content).toContain('Fixture project');
  });

  it('readFile refuses a FIFO without blocking', () => {
    const result = readFile(fx.config, { filePath: 'pipe' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('NOT_A_FILE');
  });

  it('readFile enforces the configured byte ceiling over a larger caller request', () => {
    const result = readFile({ ...fx.config, maxReadFileBytes: 10 }, { filePath: 'big.txt', maxBytes: 1000 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.content.length).toBe(10);
      expect(result.data.truncated).toBe(true);
    }
  });

  it('readFile errors never contain the host project root', () => {
    for (const filePath of ['nope.txt', '../x', '/etc/passwd', 'outdir/outside.txt']) {
      expect(JSON.stringify(readFile(fx.config, { filePath }))).not.toContain(fx.root);
    }
  });

  it('listFiles omits sensitive entries, symlinks, FIFOs, and ignored directories', () => {
    const result = listFiles(fx.config, { dirPath: '.', recursive: true, maxResults: 1000 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const names = result.data.map((entry) => entry.path);
    for (const hidden of ['.env', '.ssh', '.ssh/id_rsa', 'outdir', 'outfile.txt', 'inlink.md', 'envlink.txt', 'pipe', 'dist', 'dist/x.js', 'build', 'build/x.js', 'node_modules', '.git']) {
      expect(names, hidden).not.toContain(hidden);
    }
    expect(names).toContain('a.txt');
  });

  it('listFiles refuses sensitive and outside-symlink directories', () => {
    const sensitive = listFiles(fx.config, { dirPath: '.ssh', recursive: true, maxResults: 100 });
    expect(sensitive.ok).toBe(false);
    if (!sensitive.ok) expect(sensitive.error.code).toBe('INVALID_INPUT');
    const outside = listFiles(fx.config, { dirPath: 'outdir', recursive: true, maxResults: 100 });
    expect(outside.ok).toBe(false);
    if (!outside.ok) expect(outside.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('listFiles is deterministic, sorted, and capped by config', () => {
    const first = listFiles(fx.config, { dirPath: '.', recursive: false, maxResults: 1000 });
    const second = listFiles(fx.config, { dirPath: '.', recursive: false, maxResults: 1000 });
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    const names = first.data.map((entry) => entry.path);
    expect(names).toEqual(second.data.map((entry) => entry.path));
    expect(names).toEqual([...names].sort());
    const capped = listFiles({ ...fx.config, maxListResults: 1 }, { dirPath: '.', recursive: true, maxResults: 100 });
    expect(capped.ok).toBe(true);
    if (capped.ok) expect(capped.data.length).toBe(1);
  });

  it('searchFiles never follows symlinks to outside files or directories', () => {
    const result = search('needle-outside');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toEqual([]);
    const viaDir = searchFiles(fx.config, { query: 'x', dirPath: 'outdir', caseSensitive: false, isRegex: false, maxResults: 10 });
    expect(viaDir.ok).toBe(false);
    if (!viaDir.ok) expect(viaDir.error.code).toBe('PATH_OUTSIDE_ROOT');
  });

  it('searchFiles never returns content from sensitive files or sensitive directories', () => {
    const result = search(testCredential('DB_PASSWORD').slice(0, 12));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toEqual([]);
    const direct = searchFiles(fx.config, { query: testCredential('DB_PASSWORD').slice(0, 12), dirPath: '.ssh', caseSensitive: false, isRegex: false, maxResults: 10 });
    expect(direct.ok).toBe(false);
    if (!direct.ok) expect(direct.error.code).toBe('INVALID_INPUT');
  });

  it('searchFiles exposes sensitive files only to trusted internal callers', () => {
    const result = search(testCredential('API_KEY').slice(2, 12), { allowSensitive: true });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.some((match) => match.path === '.env')).toBe(true);
  });

  it('searchFiles skips ignored directories, binary files, oversized files, and over-long lines', () => {
    const ignored = search('zzmatch');
    expect(ignored.ok).toBe(true);
    if (ignored.ok) expect(ignored.data.map((match) => match.path)).toEqual(['a.txt', 'b.txt']);
    const binary = search('needlebin');
    expect(binary.ok && binary.data.length === 0).toBe(true);
    const longLine = search('needlelong');
    expect(longLine.ok && longLine.data.length === 0).toBe(true);
    const oversized = search('xxxxxxxx', {}, { ...fx.config, maxReadFileBytes: 1000 });
    expect(oversized.ok).toBe(true);
    if (oversized.ok) expect(oversized.data.some((match) => match.path === 'big.txt')).toBe(false);
  });

  it('searchFiles caps results and returns them in deterministic order', () => {
    const capped = search('zzmatch', { maxResults: 1 });
    expect(capped.ok).toBe(true);
    if (capped.ok) expect(capped.data.map((match) => match.path)).toEqual(['a.txt']);
  });

  it('searchFiles rejects malformed and catastrophic regexes', () => {
    for (const query of ['[', '(unclosed', '(a+)+$', '(.*)*x']) {
      const result = search(query, { isRegex: true });
      expect(result.ok, query).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('INVALID_INPUT');
    }
  });

  it('searchFiles rejects sibling-prefix, absolute, and mixed-separator directories', () => {
    for (const dirPath of [`../${path.basename(fx.root)}-other`, '/etc', 'src\\..\\..\\x', '..']) {
      const result = searchFiles(fx.config, { query: 'x', dirPath, caseSensitive: false, isRegex: false, maxResults: 10 });
      expect(result.ok, dirPath).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('PATH_OUTSIDE_ROOT');
    }
  });
});
