import path from 'node:path';
import fs from 'node:fs';

/**
 * Resolves a user-supplied relative path against the project root and
 * guarantees the result stays inside that root.
 *
 * Defends against:
 *  - Absolute paths ("/etc/passwd")
 *  - ".." traversal ("../../etc/passwd", "a/../../b")
 *  - Null bytes
 *  - Symlinks that point outside the root (checked at existing-path time)
 *
 * Throws PathOutsideRootError if the resolved path is not inside
 * projectRoot. Callers are expected to catch this and translate it into a
 * structured tool error — never let it bubble up as a raw exception to MCP.
 */

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

function assertNoNullBytes(input: string): void {
  if (input.includes('\0')) {
    throw new InvalidPathError('Path contains a null byte');
  }
}

/**
 * Resolve `userPath` (relative, as supplied by the tool caller) against
 * `projectRoot` (absolute, already realpath'd). Returns the absolute,
 * normalized path on disk. Does NOT require the path to exist.
 */
export function resolveWithinRoot(projectRoot: string, userPath: string): string {
  if (typeof userPath !== 'string' || userPath.length === 0) {
    throw new InvalidPathError('Path must be a non-empty string');
  }
  assertNoNullBytes(userPath);

  // Reject absolute paths outright — everything must be root-relative.
  if (path.isAbsolute(userPath)) {
    throw new PathOutsideRootError(userPath);
  }

  // path.join + normalize collapses ".." segments syntactically. We then
  // verify the result is still prefixed by projectRoot.
  const candidate = path.normalize(path.join(projectRoot, userPath));

  if (!isInsideRoot(projectRoot, candidate)) {
    throw new PathOutsideRootError(userPath);
  }

  return candidate;
}

/**
 * Same as resolveWithinRoot, but additionally resolves symlinks (for paths
 * that exist) via realpath and re-checks containment. Use this before any
 * operation that reads/writes/executes an existing file or directory, so a
 * symlink inside the root cannot be used to escape it.
 */
export function resolveExistingWithinRoot(projectRoot: string, userPath: string): string {
  const candidate = resolveWithinRoot(projectRoot, userPath);

  let real: string;
  try {
    real = fs.realpathSync(candidate);
  } catch (e: unknown) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      // Doesn't exist — return the syntactically-safe candidate and let the
      // caller produce a NOT_FOUND error with proper context.
      return candidate;
    }
    throw e;
  }

  if (!isInsideRoot(projectRoot, real)) {
    throw new PathOutsideRootError(userPath);
  }

  return real;
}

function isInsideRoot(projectRoot: string, candidate: string): boolean {
  const rootWithSep = projectRoot.endsWith(path.sep) ? projectRoot : projectRoot + path.sep;
  return candidate === projectRoot || candidate.startsWith(rootWithSep);
}

/** Converts an absolute in-root path back to a POSIX-style relative path,
 * for stable, cross-platform display/output to the client. */
export function toRelativePosix(projectRoot: string, absolutePath: string): string {
  const rel = path.relative(projectRoot, absolutePath);
  return rel.split(path.sep).join('/');
}
