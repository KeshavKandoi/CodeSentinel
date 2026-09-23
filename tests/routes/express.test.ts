import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverRoutes } from '../../src/routes/engine.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import type { AppConfig } from '../../src/config.js';
import type { AttackSurfaceEntry, DiscoverRoutesResult } from '../../src/routes/types.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/express-routes', import.meta.url)));
const tempDirs: string[] = [];
afterAll(() => {
  for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
});

function cfg(root: string): AppConfig {
  return { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
}

function run(root: string): DiscoverRoutesResult {
  const outcome = discoverRoutes(cfg(root));
  if (!outcome.ok) throw new Error(`discoverRoutes failed: ${outcome.error.message}`);
  return outcome.data;
}

/** Temp projects are created at test time so ignored-dir fixtures (node_modules, dist, ...) never depend on .gitignore. */
function makeTempProject(files: Record<string, string>): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-routes-')));
  tempDirs.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

function lineOf(file: string, needle: string): number {
  const lines = fs.readFileSync(path.join(FIXTURE, file), 'utf-8').split('\n');
  const idx = lines.findIndex((l) => l.includes(needle));
  if (idx < 0) throw new Error(`needle not found in ${file}: ${needle}`);
  return idx + 1;
}

const data = run(FIXTURE);

function find(method: string, routePath: string): AttackSurfaceEntry {
  const e = data.entries.find((x) => x.method === method && x.path === routePath);
  if (!e) throw new Error(`route not found: ${method} ${routePath}`);
  return e;
}

describe('Express adapter: detection and counts', () => {
  it('runs only the Express adapter for an Express project', () => {
    const express = data.frameworks.find((f) => f.framework === 'express');
    expect(express?.applicable).toBe(true);
    expect(data.summary.byFramework['express']).toBe(data.summary.total);
  });

  it('finds every statically declared route in the fixture', () => {
    // app: 4, users: 4, admin: 3, api: 3, dynamic: 2
    expect(data.summary.total).toBe(16);
  });

  it('produces unique ids and evidence for every entry', () => {
    const ids = data.entries.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of data.entries) {
      expect(e.evidence.length).toBeGreaterThan(0);
      expect(e.evidence[0]?.source).toBe(`${e.file}:${e.line}`);
    }
  });
});

describe('Express adapter: methods, paths and nested prefixes', () => {
  it('detects GET, POST, PUT and DELETE', () => {
    expect(data.summary.byMethod['GET']).toBeGreaterThan(0);
    expect(data.summary.byMethod['POST']).toBeGreaterThan(0);
    expect(data.summary.byMethod['PUT']).toBe(1);
    expect(data.summary.byMethod['DELETE']).toBe(1);
  });

  it('applies mount prefixes from app.use()', () => {
    expect(find('GET', '/users').file).toBe('src/routes/users.ts');
    expect(find('GET', '/admin/stats').file).toBe('src/routes/admin.ts');
    expect(find('GET', '/api/items').file).toBe('src/routes/api.ts');
  });

  it('resolves prefixes stored in a const (API_PREFIX)', () => {
    expect(find('GET', '/api/search').pathResolved).toBe(true);
  });

  it('resolves nested routers (app -> /api -> /v2)', () => {
    const e = find('GET', '/api/v2/ping');
    expect(e.pathResolved).toBe(true);
    expect(e.evidence.filter((x) => x.source === 'mount-resolution').length).toBe(2);
  });

  it('expands router.route() chains into separate methods', () => {
    expect(find('GET', '/admin/settings').method).toBe('GET');
    expect(find('PUT', '/admin/settings').method).toBe('PUT');
  });
});

describe('Express adapter: parameters', () => {
  it('detects dynamic path parameters', () => {
    const e = find('GET', '/users/:id');
    expect(e.parameters.map((p) => p.name)).toEqual(['id']);
    expect(e.parameters[0]?.required).toBe(true);
  });

  it('detects query parameters from req.query destructuring', () => {
    expect(find('GET', '/api/search').queryParameters.map((p) => p.name)).toEqual(['page', 'q']);
  });

  it('detects body parameters from req.body destructuring', () => {
    expect(find('POST', '/login').bodyParameters.map((p) => p.name)).toEqual(['password', 'username']);
  });

  it('detects response indicators when statically visible', () => {
    expect(find('POST', '/login').responseIndicators).toContain('status:200');
    expect(find('DELETE', '/users/:id').responseIndicators).toContain('res.sendStatus');
  });
});

describe('Express adapter: middleware, auth and authorization', () => {
  it('marks routes without any guard as public', () => {
    expect(find('POST', '/login').publicOrProtected).toBe('public');
    expect(find('GET', '/users/:id').publicOrProtected).toBe('public');
    expect(find('GET', '/health').publicOrProtected).toBe('public');
  });

  it('detects route-level authentication middleware', () => {
    const e = find('POST', '/users');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.authIndicators).toContain('authenticate');
    expect(e.middleware).toContain('authenticate');
  });

  it('detects authorization middleware and reads a same-file handler by name', () => {
    const e = find('DELETE', '/users/:id');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.authorizationIndicators).toContain("requireRole('admin')");
    expect(e.handler).toBe('deleteUser');
  });

  it('inherits middleware from the mount point (app.use with guards)', () => {
    const e = find('GET', '/admin/stats');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.authorizationIndicators.length).toBeGreaterThan(0);
    expect(e.evidence.some((x) => x.source === 'mount-resolution')).toBe(true);
  });

  it('does not treat non-auth middleware (express.json) as authentication', () => {
    const e = find('GET', '/health');
    expect(e.middleware).toContain('express.json()');
    expect(e.authIndicators).toEqual([]);
  });

  it('detects file-upload indicators', () => {
    const e = find('POST', '/avatar');
    expect(e.uploadIndicators.length).toBeGreaterThan(0);
    expect(e.publicOrProtected).toBe('protected');
    expect(find('POST', '/login').uploadIndicators).toEqual([]);
  });
});

describe('Express adapter: source locations', () => {
  it('reports the real line and file of a route declaration', () => {
    const e = find('GET', '/users/:id');
    expect(e.file).toBe('src/routes/users.ts');
    expect(e.line).toBe(lineOf('src/routes/users.ts', "router.get('/:id'"));
    expect(e.sourceRange.startLine).toBe(e.line);
    expect(e.sourceRange.endLine).toBeGreaterThanOrEqual(e.line);
    expect(e.language).toBe('typescript');
  });
});

describe('Express adapter: ambiguous, unsupported and malformed input', () => {
  const dyn = data.entries.filter((e) => e.file === 'src/routes/dynamic.ts');

  it('never guesses a computed mount prefix', () => {
    expect(dyn.length).toBe(2);
    for (const e of dyn) {
      expect(e.pathResolved).toBe(false);
      expect(e.publicOrProtected).toBe('unknown');
      expect(e.confidence).toBe('low');
    }
  });

  it('reports a non-static route path as unknown', () => {
    expect(dyn.some((e) => e.path === 'unknown')).toBe(true);
  });

  it('warns about malformed files instead of crashing', () => {
    expect(data.warnings.some((w) => w.includes('broken.ts'))).toBe(true);
    expect(data.entries.some((e) => e.path.includes('broken'))).toBe(false);
  });

  it('reports duplicate route definitions', () => {
    const health = data.entries.filter((e) => e.method === 'GET' && e.path === '/health');
    expect(health.length).toBe(2);
    expect(new Set(health.map((e) => e.line)).size).toBe(2);
    expect(data.warnings.some((w) => w.includes('Duplicate route definition: GET /health'))).toBe(true);
  });
});

describe('Express adapter: false positives', () => {
  it('ignores commented-out routes, settings getters, Map.get and non-Express .get() calls', () => {
    const paths = data.entries.map((e) => e.path);
    expect(paths.some((p) => p.includes('commented-out'))).toBe(false);
    expect(paths.some((p) => p.includes('not-a-route'))).toBe(false);
    expect(paths).not.toContain('env');
    expect(data.entries.some((e) => e.file === 'src/notRoutes.ts')).toBe(false);
  });
});

describe('Express adapter: ignored directories and non-matching projects', () => {
  it('ignores node_modules, .git, dist, build, coverage, docs and caches', () => {
    const route = (p: string) =>
      `const express = require('express');\nconst app = express();\napp.get('${p}', (req, res) => res.send('x'));\n`;
    const root = makeTempProject({
      'package.json': JSON.stringify({ name: 't', dependencies: { express: '^4.19.2' } }),
      'src/app.js': route('/real'),
      'node_modules/pkg/index.js': route('/from-node-modules'),
      'dist/app.js': route('/from-dist'),
      'build/app.js': route('/from-build'),
      'coverage/report.js': route('/from-coverage'),
      'docs/example.js': route('/from-docs'),
      '.git/hooks/hook.js': route('/from-git'),
      '.next/server/app.js': route('/from-next'),
    });
    const result = run(root);
    expect(result.entries.map((e) => e.path)).toEqual(['/real']);
  });

  it('reports no routes and a warning when no supported framework is present', () => {
    const root = makeTempProject({
      'package.json': JSON.stringify({ name: 'plain', dependencies: {} }),
      'src/index.js': "console.log('hello');\n",
    });
    const result = run(root);
    expect(result.entries).toEqual([]);
    expect(result.frameworks.every((f) => f.applicable === false)).toBe(true);
    expect(result.warnings.some((w) => w.includes('No supported web framework'))).toBe(true);
  });
});

describe('discover_routes MCP tool', () => {
  const tool = toolDefinitions.find((t) => t.name === 'discover_routes');

  it('is registered and returns the structured inventory', async () => {
    if (!tool) throw new Error('discover_routes tool not registered');
    const res = await tool.handler(cfg(FIXTURE), {});
    expect(res.isError).toBe(false);
    const parsed = JSON.parse(res.content[0]!.text);
    expect(parsed.summary.total).toBe(data.summary.total);
    expect(Array.isArray(parsed.entries)).toBe(true);
    expect(Array.isArray(parsed.warnings)).toBe(true);
  });

  it('rejects unknown input keys', async () => {
    if (!tool) throw new Error('discover_routes tool not registered');
    const res = await tool.handler(cfg(FIXTURE), { extra: 1 });
    expect(res.isError).toBe(true);
    expect(JSON.parse(res.content[0]!.text).error).toBe('INVALID_INPUT');
  });
});
