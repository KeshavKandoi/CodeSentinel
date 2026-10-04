import path from 'node:path';
import fs from 'node:fs';

export class PathOutsideRootError extends Error {
  constructor(public readonly attemptedPath: string) {
    super(`Path resolves outside the project root: ${attemptedPath}`);
    this.name = 'PathOutsideRootError';
  }
}

export class InvalidPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPathError';
  }
}

export type ContainedOpenFailure = 'not_found' | 'not_file' | 'outside' | 'error';

export type ContainedOpen =
  | { ok: true; fd: number; size: number }
  | { ok: false; reason: ContainedOpenFailure };

export function isInsideRoot(projectRoot: string, candidate: string): boolean {
  const relative = path.relative(projectRoot, candidate);
  if (relative === '') return true;
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function hasParentSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..');
}

function isSymbolicLink(target: string): boolean {
  try {
    return fs.lstatSync(target).isSymbolicLink();
  } catch {
    return false;
  }
}

export function resolveWithinRoot(projectRoot: string, userPath: string): string {
  if (typeof userPath !== 'string' || userPath.length === 0) {
    throw new InvalidPathError('Path must be a non-empty string');
  }
  if (userPath.includes('\0')) {
    throw new InvalidPathError('Path contains a null byte');
  }
  if (
    path.isAbsolute(userPath) ||
    path.win32.isAbsolute(userPath) ||
    /^[a-zA-Z]:/.test(userPath) ||
    hasParentSegment(userPath)
  ) {
    throw new PathOutsideRootError(userPath);
  }
  const candidate = path.normalize(path.join(projectRoot, userPath));
  if (!isInsideRoot(projectRoot, candidate)) {
    throw new PathOutsideRootError(userPath);
  }
  return candidate;
}

export function resolveExistingWithinRoot(projectRoot: string, userPath: string): string {
  const candidate = resolveWithinRoot(projectRoot, userPath);
  const missing: string[] = [];
  let probe = candidate;
  for (;;) {
    try {
      const real = fs.realpathSync(probe);
      if (!isInsideRoot(projectRoot, real)) {
        throw new PathOutsideRootError(userPath);
      }
      return missing.length === 0 ? real : path.join(real, ...missing.reverse());
    } catch (e) {
      if (e instanceof PathOutsideRootError) throw e;
      const code = (e as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR') {
        throw new InvalidPathError('Path could not be resolved');
      }
      if (code === 'ENOENT' && isSymbolicLink(probe)) {
        throw new PathOutsideRootError(userPath);
      }
      if (probe === projectRoot) {
        throw new InvalidPathError('Path could not be resolved');
      }
      missing.push(path.basename(probe));
      probe = path.dirname(probe);
    }
  }
}

export function isStableDirectory(projectRoot: string, absDir: string): boolean {
  try {
    const stat = fs.lstatSync(absDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) return false;
    const real = fs.realpathSync(absDir);
    return real === absDir && isInsideRoot(projectRoot, real);
  } catch {
    return false;
  }
}

export function openRegularFileWithinRoot(projectRoot: string, absPath: string): ContainedOpen {
  if (!isInsideRoot(projectRoot, absPath)) return { ok: false, reason: 'outside' };
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(absPath, flags);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { ok: false, reason: 'not_found' };
    if (code === 'ELOOP') return { ok: false, reason: 'outside' };
    return { ok: false, reason: 'error' };
  }
  const fail = (reason: ContainedOpenFailure): ContainedOpen => {
    try {
      fs.closeSync(fd);
    } catch {
      return { ok: false, reason };
    }
    return { ok: false, reason };
  };
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile()) return fail('not_file');
    if (fs.realpathSync(absPath) !== absPath) return fail('outside');
    const linked = fs.lstatSync(absPath, { bigint: true });
    if (linked.isSymbolicLink() || linked.ino !== opened.ino || linked.dev !== opened.dev) return fail('outside');
    return { ok: true, fd, size: Number(opened.size) };
  } catch {
    return fail('error');
  }
}

export function toRelativePosix(projectRoot: string, absolutePath: string): string {
  const rel = path.relative(projectRoot, absolutePath);
  return rel.split(path.sep).join('/');
}
