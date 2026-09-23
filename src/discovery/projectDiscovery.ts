import type { ProjectProfile, Ecosystem } from './types.js';
import { emptyProjectProfile } from './types.js';
import { fileExists } from './manifestReader.js';
import { runNodeDiscovery } from './node/nodeDiscovery.js';

/**
 * Top-level entry point for Phase 2 discovery. Determines which ecosystem
 * a project belongs to using cheap, deterministic marker-file checks, then
 * dispatches to an ecosystem-specific discovery pipeline.
 *
 * Adding a new ecosystem (e.g. Python) means: (1) add its marker files to
 * detectEcosystem, (2) implement a sibling `runPythonDiscovery(root)` under
 * `src/discovery/python/` mirroring the shape of `runNodeDiscovery`, and
 * (3) add one dispatch branch below. No changes to existing Node detectors,
 * types, or the MCP tool layer are required.
 */

function detectEcosystem(root: string): Ecosystem {
  if (fileExists(root, 'package.json')) return 'node';
  if (
    fileExists(root, 'requirements.txt') ||
    fileExists(root, 'pyproject.toml') ||
    fileExists(root, 'setup.py') ||
    fileExists(root, 'Pipfile')
  ) {
    return 'python';
  }
  return 'unknown';
}

export function runProjectDiscovery(root: string): ProjectProfile {
  const ecosystem = detectEcosystem(root);

  if (ecosystem === 'node') {
    return runNodeDiscovery(root);
  }

  if (ecosystem === 'python') {
    // Python/FastAPI/Django support is intentionally deferred to a later
    // phase. We still report ecosystem detection honestly rather than
    // silently returning an empty/misleading profile.
    const profile = emptyProjectProfile();
    profile.ecosystem = 'python';
    profile.warnings.push(
      'Python project markers detected (requirements.txt / pyproject.toml / setup.py / Pipfile), ' +
        'but Python analysis is not yet implemented. Only ecosystem detection is available for this project.'
    );
    return profile;
  }

  const profile = emptyProjectProfile();
  profile.ecosystem = 'unknown';
  profile.warnings.push('Could not determine project ecosystem: no package.json, requirements.txt, pyproject.toml, setup.py, or Pipfile found.');
  return profile;
}
