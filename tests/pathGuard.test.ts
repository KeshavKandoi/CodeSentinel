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
    // e.g. root = /tmp/foo, candidate = /tmp/foo-evil — naive startsWith
    // (without separator) would wrongly allow this.
    const evilSibling = root + '-evil';
    expect(() => {
      // simulate by constructing a path string manually and checking guard
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
