import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig } from '../config.js';
import { isStableDirectory, openRegularFileWithinRoot } from '../fs/pathGuard.js';
import { resolveToolRoot } from '../projectRoot.js';
import { ok, type ToolOutcome } from '../types.js';

export interface ProjectInfo {
  projectRoot: string;
  detectedTypes: string[];
  packageManager: string | null;
  hasGit: boolean;
  gitBranch: string | null;
  totalFiles: number;
  totalDirectories: number;
  topLevelEntries: string[];
}

const IGNORED_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', '.venv', '__pycache__']);
const MAX_GIT_HEAD_BYTES = 4096;

const MARKER_FILES: Record<string, string> = {
  'package.json': 'node',
  'requirements.txt': 'python',
  'pyproject.toml': 'python',
  'Cargo.toml': 'rust',
  'go.mod': 'go',
  'pom.xml': 'java-maven',
  'build.gradle': 'java-gradle',
  Gemfile: 'ruby',
  'composer.json': 'php',
};

function detectPackageManager(root: string): string | null {
  if (fs.existsSync(path.join(root, 'package-lock.json'))) return 'npm';
  if (fs.existsSync(path.join(root, 'yarn.lock'))) return 'yarn';
  if (fs.existsSync(path.join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (fs.existsSync(path.join(root, 'requirements.txt'))) return 'pip';
  if (fs.existsSync(path.join(root, 'poetry.lock'))) return 'poetry';
  if (fs.existsSync(path.join(root, 'Cargo.lock'))) return 'cargo';
  return null;
}

function detectGitBranch(root: string): string | null {
  const gitDir = path.join(root, '.git');
  if (!isStableDirectory(root, gitDir)) return null;
  const opened = openRegularFileWithinRoot(root, path.join(gitDir, 'HEAD'));
  if (!opened.ok) return null;
  try {
    if (opened.size > MAX_GIT_HEAD_BYTES) return null;
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(opened.fd, buffer, offset, buffer.length - offset, offset);
      if (count === 0) return null;
      offset += count;
    }
    const head = buffer.toString('utf8').trim();
    const match = /^ref: refs\/heads\/([^\s\\\0]+)$/.exec(head);
    if (match && !match[1].includes('..') && !match[1].includes('@{')) return match[1];
    return /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(head) ? head : null;
  } catch {
    return null;
  } finally {
    fs.closeSync(opened.fd);
  }
}

function countEntries(root: string): { files: number; dirs: number } {
  let files = 0;
  let dirs = 0;

  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        dirs++;
        walk(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        files++;
      }
    }
  };

  walk(root);
  return { files, dirs };
}

export function getProjectInfo(config: AppConfig): ToolOutcome<ProjectInfo> {
  const checkedRoot = resolveToolRoot(config, config.projectRoot);
  if (!checkedRoot.ok) return checkedRoot;
  const root = checkedRoot.data;

  const detectedTypes = Object.entries(MARKER_FILES)
    .filter(([marker]) => fs.existsSync(path.join(root, marker)))
    .map(([, type]) => type)
    .filter((v, i, arr) => arr.indexOf(v) === i);

  const hasGit = fs.existsSync(path.join(root, '.git'));
  const { files, dirs } = countEntries(root);

  let topLevelEntries: string[] = [];
  try {
    topLevelEntries = fs
      .readdirSync(root, { withFileTypes: true })
      .filter((e: fs.Dirent) => !IGNORED_DIRS.has(e.name))
      .map((e: fs.Dirent) => (e.isDirectory() ? `${e.name}/` : e.name))
      .sort();
  } catch {
    topLevelEntries = [];
  }

  return ok({
    projectRoot: root,
    detectedTypes,
    packageManager: detectPackageManager(root),
    hasGit,
    gitBranch: hasGit ? detectGitBranch(root) : null,
    totalFiles: files,
    totalDirectories: dirs,
    topLevelEntries,
  });
}
