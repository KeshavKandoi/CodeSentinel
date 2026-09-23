import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProjectDiscovery } from '../../src/discovery/projectDiscovery.js';
import type { ProjectProfile, DetectedItem } from '../../src/discovery/types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.resolve(__dirname, '..', 'fixtures');

function fixtureRoot(name: string): string {
  return fs.realpathSync(path.join(FIXTURES_ROOT, name));
}

function names(items: DetectedItem[]): string[] {
  return items.map((i) => i.name);
}

describe('runProjectDiscovery: express-ts fixture', () => {
  const profile: ProjectProfile = runProjectDiscovery(fixtureRoot('express-ts'));

  it('detects the node ecosystem', () => {
    expect(profile.ecosystem).toBe('node');
  });

  it('detects the project name from package.json', () => {
    expect(profile.projectName).toBe('express-ts-fixture');
  });

  it('detects TypeScript as a language with high confidence', () => {
    const ts = profile.languages.find((l) => l.name === 'TypeScript');
    expect(ts).toBeDefined();
    expect(ts?.confidence).toBe('high');
  });

  it('detects JavaScript as a language (package.json present)', () => {
    expect(names(profile.languages)).toContain('JavaScript');
  });

  it('detects npm as the package manager', () => {
    expect(profile.packageManager?.name).toBe('npm');
    expect(profile.packageManager?.confidence).toBe('high');
  });

  it('detects Express as a backend framework with high confidence', () => {
    const express = profile.frameworks.backend.find((f) => f.name === 'Express');
    expect(express).toBeDefined();
    expect(express?.confidence).toBe('high');
    expect(express?.evidence.length).toBeGreaterThanOrEqual(2);
  });

  it('does not detect any frontend framework', () => {
    expect(profile.frameworks.frontend.length).toBe(0);
  });

  it('detects PostgreSQL as a database', () => {
    expect(names(profile.database)).toContain('PostgreSQL');
  });

  it('detects Prisma as the ORM with high confidence (schema.prisma corroborates)', () => {
    const prisma = profile.orm.find((o) => o.name === 'Prisma');
    expect(prisma).toBeDefined();
    expect(prisma?.confidence).toBe('high');
  });

  it('detects Jest as the test framework', () => {
    expect(names(profile.testFramework)).toContain('Jest');
  });

  it('detects jsonwebtoken and bcrypt as auth indicators', () => {
    const authNames = names(profile.authIndicators);
    expect(authNames).toContain('jsonwebtoken');
    expect(authNames).toContain('bcrypt');
  });

  it('detects src/index.ts as a high-confidence entry point', () => {
    const entry = profile.entryPoints.find((e) => e.path === 'src/index.ts');
    expect(entry).toBeDefined();
  });

  it('detects Docker configuration', () => {
    expect(profile.docker.hasDockerfile).toBe(true);
    expect(profile.docker.files).toContain('Dockerfile');
  });

  it('detects .env.example as an env file', () => {
    expect(profile.envFiles).toContain('.env.example');
  });

  it('detects tsconfig.json and jest.config.js as config files', () => {
    expect(profile.configFiles).toContain('tsconfig.json');
    expect(profile.configFiles).toContain('jest.config.js');
  });

  it('reports build/start/dev/test scripts', () => {
    expect(profile.scripts.build).toBe('tsc');
    expect(profile.scripts.start).toBe('node dist/index.js');
    expect(profile.scripts.test).toBe('jest');
  });

  it('lists express as a dependency with correct dev flag', () => {
    const expressDep = profile.dependencies.find((d) => d.name === 'express');
    expect(expressDep).toBeDefined();
    expect(expressDep?.dev).toBe(false);
    const tsDep = profile.dependencies.find((d) => d.name === 'typescript');
    expect(tsDep?.dev).toBe(true);
  });

  it('has no warnings for a well-formed project', () => {
    expect(profile.warnings.length).toBe(0);
  });
});

describe('runProjectDiscovery: nextjs-app fixture', () => {
  const profile: ProjectProfile = runProjectDiscovery(fixtureRoot('nextjs-app'));

  it('detects the node ecosystem', () => {
    expect(profile.ecosystem).toBe('node');
  });

  it('detects Next.js as both a frontend framework, with high confidence', () => {
    const next = profile.frameworks.frontend.find((f) => f.name === 'Next.js');
    expect(next).toBeDefined();
    expect(next?.confidence).toBe('high');
  });

  it('detects React as a frontend framework', () => {
    expect(names(profile.frameworks.frontend)).toContain('React');
  });

  it('does not detect a backend framework (Next.js API routes are not modeled as a separate backend framework in Phase 2)', () => {
    expect(profile.frameworks.backend.length).toBe(0);
  });

  it('detects MongoDB as the database', () => {
    expect(names(profile.database)).toContain('MongoDB');
  });

  it('detects Mongoose as the ORM', () => {
    expect(names(profile.orm)).toContain('Mongoose');
  });

  it('detects next-auth as an auth indicator', () => {
    expect(names(profile.authIndicators)).toContain('next-auth');
  });

  it('detects Vitest as the test framework', () => {
    expect(names(profile.testFramework)).toContain('Vitest');
  });

  it('detects pages/_app.tsx as an entry point', () => {
    const entry = profile.entryPoints.find((e) => e.path.includes('_app.tsx'));
    expect(entry).toBeDefined();
  });

  it('detects .env.local as an env file', () => {
    expect(profile.envFiles).toContain('.env.local');
  });

  it('detects next.config.js as a config file', () => {
    expect(profile.configFiles).toContain('next.config.js');
  });

  it('reports no Docker configuration (none present)', () => {
    expect(profile.docker.hasDockerfile).toBe(false);
    expect(profile.docker.hasCompose).toBe(false);
  });
});

describe('runProjectDiscovery: generic-node fixture (negative cases)', () => {
  const profile: ProjectProfile = runProjectDiscovery(fixtureRoot('generic-node'));

  it('detects the node ecosystem', () => {
    expect(profile.ecosystem).toBe('node');
  });

  it('does NOT detect Next.js despite a next.config.js file being present, because there is no "next" dependency or import', () => {
    expect(names(profile.frameworks.frontend)).not.toContain('Next.js');
  });

  it('does not detect any backend framework', () => {
    expect(profile.frameworks.backend.length).toBe(0);
  });

  it('does not detect a database or ORM', () => {
    expect(profile.database.length).toBe(0);
    expect(profile.orm.length).toBe(0);
  });

  it('does not detect a test framework', () => {
    expect(profile.testFramework.length).toBe(0);
  });

  it('does not detect any auth indicators', () => {
    expect(profile.authIndicators.length).toBe(0);
  });

  it('detects index.js as the entry point via package.json main', () => {
    const entry = profile.entryPoints.find((e) => e.path === 'index.js');
    expect(entry).toBeDefined();
  });

  it('does not detect TypeScript (no tsconfig.json, no typescript dependency)', () => {
    expect(names(profile.languages)).not.toContain('TypeScript');
  });

  it('lists next.config.js as a config file even though no framework was detected (presence tracking is independent of framework confidence)', () => {
    expect(profile.configFiles).toContain('next.config.js');
  });
});

describe('runProjectDiscovery: malformed package.json fixture', () => {
  it('does not throw and returns a profile with a warning instead', () => {
    expect(() => runProjectDiscovery(fixtureRoot('malformed-package'))).not.toThrow();
  });

  it('records a warning about the malformed package.json', () => {
    const profile = runProjectDiscovery(fixtureRoot('malformed-package'));
    expect(profile.warnings.length).toBeGreaterThan(0);
    expect(profile.warnings.some((w) => w.includes('package.json'))).toBe(true);
  });

  it('still detects the node ecosystem and JavaScript language from file presence alone', () => {
    const profile = runProjectDiscovery(fixtureRoot('malformed-package'));
    expect(profile.ecosystem).toBe('node');
    expect(names(profile.languages)).toContain('JavaScript');
  });

  it('has a null project name since the manifest could not be parsed', () => {
    const profile = runProjectDiscovery(fixtureRoot('malformed-package'));
    expect(profile.projectName).toBeNull();
  });

  it('reports no scripts or dependencies since none could be parsed', () => {
    const profile = runProjectDiscovery(fixtureRoot('malformed-package'));
    expect(Object.keys(profile.scripts).length).toBe(0);
    expect(profile.dependencies.length).toBe(0);
  });
});

describe('runProjectDiscovery: unknown/empty ecosystem', () => {
  it('reports ecosystem "unknown" and a warning for a directory with no recognizable markers', () => {
    // The malformed-package fixture's sibling test dir has files, but for
    // a true "nothing here" case we use a scratch dir with a single
    // unrelated file.
    const emptyDir = fs.mkdtempSync(path.join(FIXTURES_ROOT, 'empty-'));
    fs.writeFileSync(path.join(emptyDir, 'README.md'), '# nothing to see here\n');
    try {
      const realRoot = fs.realpathSync(emptyDir);
      const profile = runProjectDiscovery(realRoot);
      expect(profile.ecosystem).toBe('unknown');
      expect(profile.warnings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});
