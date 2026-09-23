import { fileExists } from '../manifestReader.js';
import type { DetectedItem } from '../types.js';

export function detectPackageManager(root: string): DetectedItem | null {
  if (fileExists(root, 'package-lock.json')) {
    return { name: 'npm', confidence: 'high', evidence: [{ source: 'file:package-lock.json', detail: 'package-lock.json is present' }] };
  }
  if (fileExists(root, 'yarn.lock')) {
    return { name: 'yarn', confidence: 'high', evidence: [{ source: 'file:yarn.lock', detail: 'yarn.lock is present' }] };
  }
  if (fileExists(root, 'pnpm-lock.yaml')) {
    return { name: 'pnpm', confidence: 'high', evidence: [{ source: 'file:pnpm-lock.yaml', detail: 'pnpm-lock.yaml is present' }] };
  }
  if (fileExists(root, 'package.json')) {
    return {
      name: 'npm',
      confidence: 'low',
      evidence: [{ source: 'file:package.json', detail: 'package.json is present but no lockfile was found; defaulting to npm' }],
    };
  }
  return null;
}
