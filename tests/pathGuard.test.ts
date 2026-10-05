import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  resolveWithinRoot,
  resolveExistingWithinRoot,
  toRelativePosix,
  PathOutsideRootError,
  InvalidPathError,
} from '../src/fs/pathGuard.js';
import { makeFixtureProject, makeOutsideSecretFile } from './testUtils.js';

describe('pathGuard', () => {
  const { config, root, cleanup } = makeFixtureProject();
  afterAll(() => cleanup());

  it('resolves a simple relative path inside the root', () => {
    const resolved = resolveWithinRoot(root, 'src/index.js');
    expect(resolved).toBe(path.join(root, 'src', 'index.js'));
  });

  it('resolves "." to the root itself', () => {
    const resolved = resolveWithinRoot(root, '.');
    expect(resolved).toBe(path.normalize(root));
  });

  it('rejects simple ".." traversal', () => {
    expect(() => resolveWithinRoot(root, '../etc/passwd')).toThrow(PathOutsideRootError);
  });

  it('rejects nested ".." traversal that escapes then re-enters', () => {
    expect(() => resolveWithinRoot(root, 'src/../../etc/passwd')).toThrow(PathOutsideRootError);
  });

  it('rejects deeply nested ".." traversal', () => {
    expect(() => resolveWithinRoot(root, '../../../../../../etc/passwd')).toThrow(PathOutsideRootError);
  });

  it('rejects absolute paths', () => {
    expect(() => resolveWithinRoot(root, '/etc/passwd')).toThrow(PathOutsideRootError);
  });

  it('rejects absolute paths even if they happen to be inside root on disk', () => {
    expect(() => resolveWithinRoot(root, path.join(root, 'src', 'index.js'))).toThrow(PathOutsideRootError);
  });

  it('rejects an empty string', () => {
    expect(() => resolveWithinRoot(root, '')).toThrow(InvalidPathError);
  });

  it('rejects null bytes', () => {
    expect(() => resolveWithinRoot(root, 'src/index.js\0.png')).toThrow(InvalidPathError);
  });

  it('rejects non-string input', () => {
    // @ts-expect-error intentional invalid input for runtime test
    expect(() => resolveWithinRoot(root, 123)).toThrow(InvalidPathError);
  });

  it('a sibling directory that merely starts with the same prefix is not "inside" the root', () => {
    const evilSibling = root + '-evil';
    expect(() => {
      const rel = path.relative(root, evilSibling);
      resolveWithinRoot(root, rel);
    }).toThrow(PathOutsideRootError);
  });

  it('resolveExistingWithinRoot allows a real existing file', () => {
    const resolved = resolveExistingWithinRoot(root, 'README.md');
    expect(fs.existsSync(resolved)).toBe(true);
  });

  it('resolveExistingWithinRoot returns a candidate path for a non-existent file without throwing', () => {
    const resolved = resolveExistingWithinRoot(root, 'does/not/exist.txt');
    expect(resolved).toContain(root);
  });

  it('resolveExistingWithinRoot rejects a symlink that points outside the root', () => {
    const { secretPath, cleanup: cleanupSecret } = makeOutsideSecretFile(root);
    const linkPath = path.join(root, 'escape-link');
    fs.symlinkSync(secretPath, linkPath);
    try {
      expect(() => resolveExistingWithinRoot(root, 'escape-link')).toThrow(PathOutsideRootError);
    } finally {
      fs.rmSync(linkPath, { force: true });
      cleanupSecret();
    }
  });

  it('resolveExistingWithinRoot allows a symlink that points inside the root', () => {
    const linkPath = path.join(root, 'internal-link');
    fs.symlinkSync(path.join(root, 'README.md'), linkPath);
    try {
      const resolved = resolveExistingWithinRoot(root, 'internal-link');
      expect(resolved).toBe(path.join(root, 'README.md'));
    } finally {
      fs.rmSync(linkPath, { force: true });
    }
  });

  it('toRelativePosix produces forward-slash paths', () => {
    const abs = path.join(root, 'src', 'utils', 'helpers.js');
    expect(toRelativePosix(root, abs)).toBe('src/utils/helpers.js');
  });

});

import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { isInsideRoot, isStableDirectory, openRegularFileWithinRoot } from '../src/fs/pathGuard.js';
import { loadConfig } from '../src/config.js';

describe('pathGuard phase 1 hardening', () => {
  const fx = makeFixtureProject();
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-outside-'));
  fs.writeFileSync(path.join(outsideDir, 'outside.txt'), 'outside\n');
  fs.symlinkSync(outsideDir, path.join(fx.root, 'outdir'));
  fs.symlinkSync(path.join(fx.root, 'src'), path.join(fx.root, 'srclink'));
  fs.symlinkSync(path.join(fx.root, 'README.md'), path.join(fx.root, 'inlink.md'));
  fs.symlinkSync(path.join(outsideDir, 'does-not-exist'), path.join(fx.root, 'dangling'));
  execFileSync('mkfifo', [path.join(fx.root, 'pipe')]);
  afterAll(() => {
    fx.cleanup();
    fs.rmSync(outsideDir, { recursive: true, force: true });
  });

  it.each(['..\\x', 'src\\..\\..\\x', 'src/..\\..\\x', './../x', 'a/b/../../../x'])('rejects traversal with mixed separators: %s', (value) => {
    expect(() => resolveWithinRoot(fx.root, value)).toThrow(PathOutsideRootError);
  });

  it.each(['C:\\Windows\\x', 'c:/x', '\\\\server\\share\\x', '\\rooted'])('rejects windows-style absolute path: %s', (value) => {
    expect(() => resolveWithinRoot(fx.root, value)).toThrow(PathOutsideRootError);
  });

  it('allows names that merely contain two dots', () => {
    expect(resolveWithinRoot(fx.root, 'a..b')).toBe(path.join(fx.root, 'a..b'));
  });

  it('isInsideRoot uses canonical comparison and rejects sibling-prefix paths', () => {
    expect(isInsideRoot(fx.root, fx.root)).toBe(true);
    expect(isInsideRoot(fx.root, path.join(fx.root, 'src'))).toBe(true);
    expect(isInsideRoot(fx.root, `${fx.root}-other`)).toBe(false);
    expect(isInsideRoot(fx.root, path.join(`${fx.root}-other`, 'x'))).toBe(false);
    expect(isInsideRoot(fx.root, path.dirname(fx.root))).toBe(false);
  });

  it('rejects a not-yet-existing path beneath a symlinked directory that points outside', () => {
    expect(() => resolveExistingWithinRoot(fx.root, 'outdir/new/file.txt')).toThrow(PathOutsideRootError);
  });

  it('rejects a dangling symlink', () => {
    expect(() => resolveExistingWithinRoot(fx.root, 'dangling')).toThrow(PathOutsideRootError);
  });

  it('resolves a not-yet-existing path beneath a real directory', () => {
    expect(resolveExistingWithinRoot(fx.root, 'src/new/file.txt')).toBe(path.join(fx.root, 'src', 'new', 'file.txt'));
  });

  it('openRegularFileWithinRoot opens a regular file', () => {
    const opened = openRegularFileWithinRoot(fx.root, path.join(fx.root, 'README.md'));
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.size).toBeGreaterThan(0);
      fs.closeSync(opened.fd);
    }
  });

  it('openRegularFileWithinRoot reports a missing file', () => {
    const opened = openRegularFileWithinRoot(fx.root, path.join(fx.root, 'missing.txt'));
    expect(opened).toEqual({ ok: false, reason: 'not_found' });
  });

  it('openRegularFileWithinRoot refuses a final-component symlink even when it points inside', () => {
    const opened = openRegularFileWithinRoot(fx.root, path.join(fx.root, 'inlink.md'));
    expect(opened).toEqual({ ok: false, reason: 'outside' });
  });

  it('openRegularFileWithinRoot refuses a path outside the root', () => {
    const opened = openRegularFileWithinRoot(fx.root, path.join(outsideDir, 'outside.txt'));
    expect(opened).toEqual({ ok: false, reason: 'outside' });
  });

  it('openRegularFileWithinRoot refuses a path reached through a symlinked ancestor directory', () => {
    expect(openRegularFileWithinRoot(fx.root, path.join(fx.root, 'outdir', 'outside.txt'))).toEqual({ ok: false, reason: 'outside' });
    expect(openRegularFileWithinRoot(fx.root, path.join(fx.root, 'srclink', 'index.js'))).toEqual({ ok: false, reason: 'outside' });
  });

  it('openRegularFileWithinRoot refuses directories and FIFOs without blocking', () => {
    expect(openRegularFileWithinRoot(fx.root, path.join(fx.root, 'src'))).toEqual({ ok: false, reason: 'not_file' });
    expect(openRegularFileWithinRoot(fx.root, path.join(fx.root, 'pipe'))).toEqual({ ok: false, reason: 'not_file' });
  });

  it('isStableDirectory accepts only real in-root directories', () => {
    expect(isStableDirectory(fx.root, fx.root)).toBe(true);
    expect(isStableDirectory(fx.root, path.join(fx.root, 'src'))).toBe(true);
    expect(isStableDirectory(fx.root, path.join(fx.root, 'srclink'))).toBe(false);
    expect(isStableDirectory(fx.root, path.join(fx.root, 'outdir'))).toBe(false);
    expect(isStableDirectory(fx.root, path.join(fx.root, 'README.md'))).toBe(false);
    expect(isStableDirectory(fx.root, path.join(fx.root, 'missing'))).toBe(false);
  });

  it('loadConfig rejects missing, nonexistent, file, symlink, and null-byte roots without leaking host paths', () => {
    const link = path.join(outsideDir, 'rootlink');
    fs.symlinkSync(fx.root, link);
    expect(() => loadConfig({})).toThrow(/not set/);
    expect(() => loadConfig({ PROJECT_ROOT: '   ' })).toThrow(/not set/);
    expect(() => loadConfig({ PROJECT_ROOT: link })).toThrow(/symbolic link/);
    expect(() => loadConfig({ PROJECT_ROOT: path.join(fx.root, 'README.md') })).toThrow(/not a directory/);
    expect(() => loadConfig({ PROJECT_ROOT: 'a\0b' })).toThrow(/invalid character/);
    for (const candidate of [link, path.join(fx.root, 'missing'), path.join(fx.root, 'README.md')]) {
      let message = '';
      try {
        loadConfig({ PROJECT_ROOT: candidate });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message.length).toBeGreaterThan(0);
      expect(message).not.toContain(fx.root);
      expect(message).not.toContain(outsideDir);
    }
  });

  it('loadConfig canonicalizes equivalent root representations', () => {
    expect(loadConfig({ PROJECT_ROOT: `${fx.root}/src/..` }).projectRoot).toBe(fx.root);
    expect(loadConfig({ PROJECT_ROOT: `${fx.root}/` }).projectRoot).toBe(fx.root);
  });

  it.each(['12abc', '0', '-5', '1e3', '1.5', ' 5', '0x10', '99999999999999999999', '999999999999'])('loadConfig rejects malformed integer %s', (value) => {
    expect(() => loadConfig({ PROJECT_ROOT: fx.root, MAX_LIST_RESULTS: value })).toThrow(/positive integer/);
    expect(() => loadConfig({ PROJECT_ROOT: fx.root, COMMAND_TIMEOUT_MS: value })).toThrow(/positive integer/);
  });

  it('loadConfig accepts valid integers and reads only the supplied env', () => {
    const config = loadConfig({ PROJECT_ROOT: fx.root, MAX_LIST_RESULTS: '500', COMMAND_TIMEOUT_MS: '2000' });
    expect(config.maxListResults).toBe(500);
    expect(config.commandTimeoutMs).toBe(2000);
    const previous = process.env.MAX_LIST_RESULTS;
    process.env.MAX_LIST_RESULTS = 'bad';
    try {
      expect(loadConfig({ PROJECT_ROOT: fx.root }).maxListResults).toBe(2000);
    } finally {
      if (previous === undefined) delete process.env.MAX_LIST_RESULTS;
      else process.env.MAX_LIST_RESULTS = previous;
    }
  });
});
