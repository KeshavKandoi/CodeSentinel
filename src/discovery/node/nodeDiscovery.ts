import type { ProjectProfile } from '../types.js';
import { emptyProjectProfile } from '../types.js';
import { readJsonFile } from '../manifestReader.js';
import { buildNodeContext, type PackageJsonShape } from './context.js';
import { detectLanguages } from './language.js';
import { detectPackageManager } from './packageManager.js';
import { detectBackendFrameworks, detectFrontendFrameworks } from './frameworks.js';
import { detectDatabases, detectOrms } from './dataLayer.js';
import { detectTestFrameworks } from './testFramework.js';
import { detectAuthIndicators } from './authIndicators.js';
import { detectEntryPoints } from './entryPoints.js';
import { detectDocker, detectConfigFiles, detectEnvFiles } from './dockerAndConfig.js';

/**
 * Runs the full Node.js/TypeScript discovery pipeline and returns a
 * populated ProjectProfile. Never throws: a malformed package.json becomes
 * a warning in the profile rather than an exception, and every detector
 * degrades to "not detected" rather than crashing when evidence is absent.
 */
export function runNodeDiscovery(root: string): ProjectProfile {
  const profile = emptyProjectProfile();
  profile.ecosystem = 'node';

  const pkgResult = readJsonFile<PackageJsonShape>(root, 'package.json');
  if (pkgResult.warning) {
    profile.warnings.push(pkgResult.warning);
  }
  const ctx = buildNodeContext(root, pkgResult.data, pkgResult.warning);

  profile.projectName = ctx.pkg?.name ?? null;
  profile.languages = detectLanguages(root, ctx);
  profile.packageManager = detectPackageManager(root);
  profile.frameworks.backend = detectBackendFrameworks(root, ctx);
  profile.frameworks.frontend = detectFrontendFrameworks(root, ctx);
  profile.database = detectDatabases(root, ctx);
  profile.orm = detectOrms(root, ctx);
  profile.testFramework = detectTestFrameworks(root, ctx);
  profile.authIndicators = detectAuthIndicators(ctx);
  profile.entryPoints = detectEntryPoints(root, ctx);
  profile.scripts = ctx.pkg?.scripts ?? {};
  profile.dependencies = Object.entries(ctx.allDeps).map(([name, info]) => ({
    name,
    version: info.version,
    dev: info.dev,
  }));
  profile.docker = detectDocker(root);
  profile.configFiles = detectConfigFiles(root);
  profile.envFiles = detectEnvFiles(root);

  if (!ctx.pkg && !pkgResult.warning) {
    profile.warnings.push('No package.json found; Node.js-specific analysis will be incomplete.');
  }

  return profile;
}
