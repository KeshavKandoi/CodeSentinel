import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveProjectRoot } from '../config.js';
import { err, ok, type ToolOutcome } from '../types.js';

export interface RemediationAuthorization {
  projectRoot: string;
  localTarget: true;
  allowRemediation: true;
  nonProductionTestTarget: true;
}

export function authorizeRemediation(projectRoot: string, authorization: RemediationAuthorization | undefined): ToolOutcome<string> {
  if (!authorization) return err('AUTHORIZATION_REQUIRED', 'Explicit remediation authorization is required before writing target files.');
  if (authorization.localTarget !== true || authorization.allowRemediation !== true || authorization.nonProductionTestTarget !== true || typeof authorization.projectRoot !== 'string') {
    return err('AUTHORIZATION_REJECTED', 'Remediation authorization must explicitly permit a local non-production test target and file changes.');
  }
  let root: string;
  try { root = resolveProjectRoot(projectRoot); } catch { return err('AUTHORIZATION_REJECTED', 'The selected project root is invalid.'); }
  if (authorization.projectRoot !== root || projectRoot !== root) return err('AUTHORIZATION_REJECTED', 'Authorization must name the exact canonical selected project root.');
  if (root === path.parse(root).root || root === os.homedir() || /(?:^|\/)(?:production|prod|live|deployment)(?:\/|$)/i.test(root)) {
    return err('AUTHORIZATION_REJECTED', 'The selected project root is not an eligible local test repository.');
  }
  try {
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('invalid root');
    const git = path.join(root, '.git');
    const manifest = path.join(root, 'package.json');
    if (!fs.existsSync(git) && !fs.existsSync(manifest)) throw new Error('unsupported repository');
  } catch { return err('AUTHORIZATION_REJECTED', 'The selected root is not a supported local repository.'); }
  return ok(root);
}
