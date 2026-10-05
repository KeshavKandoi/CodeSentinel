import path from 'node:path';
import { resolveProjectRoot, type AppConfig } from './config.js';
import { detachedRedacted } from './report/redaction.js';
import { err, ok, type ToolOutcome } from './types.js';

function shown(value: string): string {
  return String(detachedRedacted(value.slice(0, 200)));
}

export function resolveToolRoot(config: AppConfig, explicit: string | undefined): ToolOutcome<string> {
  if (explicit === undefined) {
    if (config.projectRoot) return ok(config.projectRoot);
    return err('INVALID_INPUT', 'Project root is required: pass projectRoot or set PROJECT_ROOT');
  }
  if (explicit.includes('\0')) return err('INVALID_INPUT', 'Project root contains an invalid character.');
  if (!path.isAbsolute(explicit)) return err('INVALID_INPUT', `Project root must be an absolute path: ${shown(explicit)}`);
  try {
    return ok(resolveProjectRoot(explicit));
  } catch (e) {
    const message = (e as Error).message;
    if (message.includes('does not exist')) return err('NOT_FOUND', `Project root does not exist: ${shown(explicit)}`);
    if (message.includes('not a directory')) return err('NOT_A_DIRECTORY', `Project root is not a directory: ${shown(explicit)}`);
    if (message.includes('symbolic link')) return err('INVALID_INPUT', `Project root must not be a symbolic link: ${shown(explicit)}`);
    return err('INVALID_INPUT', `Project root could not be resolved: ${shown(explicit)}`);
  }
}
