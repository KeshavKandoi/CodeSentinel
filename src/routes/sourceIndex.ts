import type { AppConfig } from '../config.js';
import type { ProjectProfile } from '../discovery/types.js';
import { dirExists, fileExists, listTopLevelNames } from '../discovery/manifestReader.js';
import { readFile } from '../fs/fsOperations.js';
import type { AdapterContext, SourceFile } from './types.js';

/** Directories never analyzed: dependencies, VCS, build output, virtualenvs, caches, generated code, docs. */
const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.turbo', '.cache', 'coverage', '.vercel',
  '.output', '__pycache__', '.venv', 'venv', 'virtualenv', '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache',
  'site-packages', '.idea', '.vscode', 'docs', 'doc', 'documentation', '__generated__', 'generated', 'target',
  'staticfiles', '__tests__', '__mocks__',
]);
const MAX_DEPTH = 15;
const MAX_FILES = 20_000;

function isIgnoredSourceFile(rel: string): boolean {
  const base = rel.slice(rel.lastIndexOf('/') + 1);
  return /\.d\.ts$|\.min\.js$|\.(test|spec)\.[cm]?[jt]sx?$|\.generated\.\w+$|^(test_.*|.*_test|conftest)\.py$/.test(base);
}

/**
 * Builds the context handed to framework adapters. All directory listing and
 * file reading goes through the Phase 1/2 sandboxed helpers (pathGuard-backed),
 * so adapters cannot read outside PROJECT_ROOT and never throw on I/O.
 */
export function createAdapterContext(config: AppConfig, profile: ProjectProfile, warnings: string[]): AdapterContext {
  const root = config.projectRoot;
  let allFiles: string[] | null = null;
  const cache = new Map<string, SourceFile | null>();

  const walk = (rel: string, depth: number, out: string[]): void => {
    if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;
    const names = listTopLevelNames(root, rel === '' ? '.' : rel).slice().sort();
    for (const name of names) {
      if (out.length >= MAX_FILES) return;
      const childRel = rel === '' ? name : `${rel}/${name}`;
      if (dirExists(root, childRel)) {
        if (IGNORED_DIRS.has(name) || name.endsWith('.egg-info')) continue;
        if (fileExists(root, `${childRel}/pyvenv.cfg`)) continue; // Python virtualenv
        walk(childRel, depth + 1, out);
      } else if (fileExists(root, childRel)) {
        out.push(childRel);
      }
    }
  };

  return {
    config,
    profile,
    warnings,
    listSourceFiles(extensions) {
      if (allFiles === null) {
        const out: string[] = [];
        walk('', 0, out);
        if (out.length >= MAX_FILES) {
          warnings.push(`File walk stopped after ${MAX_FILES} files; some source files were not analyzed.`);
        }
        allFiles = out.filter((f) => !isIgnoredSourceFile(f));
      }
      return allFiles.filter((f) => extensions.some((ext) => f.endsWith(ext)));
    },
    readSource(filePath) {
      if (cache.has(filePath)) return cache.get(filePath) ?? null;
      const result = readFile(config, { filePath });
      let value: SourceFile | null = null;
      if (!result.ok) {
        warnings.push(`Could not read ${filePath}: ${result.error.message}`);
      } else if (result.data.truncated) {
        warnings.push(`Skipped ${filePath}: file exceeds the configured read limit, so its routes cannot be analyzed reliably.`);
      } else {
        value = { path: filePath, content: result.data.content };
      }
      cache.set(filePath, value);
      return value;
    },
  };
}
