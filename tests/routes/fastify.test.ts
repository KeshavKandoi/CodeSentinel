import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverRoutes } from '../../src/routes/engine.js';
import type { AppConfig } from '../../src/config.js';
import type { AttackSurfaceEntry, DiscoverRoutesResult } from '../../src/routes/types.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/fastify-routes', import.meta.url)));
const EXPRESS_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/express-routes', import.meta.url)));
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

function makeTempProject(files: Record<string, string>): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-fastify-')));
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

describe('Fastify adapter: detection and counts', () => {
  it('runs only the Fastify adapter for a Fastify project', () => {
    expect(data.frameworks.find((f) => f.framework === 'fastify')?.applicable).toBe(true);
    expect(data.frameworks.find((f) => f.framework === 'express')?.applicable).toBe(false);
    expect(data.summary.byFramework['fastify']).toBe(data.summary.total);
  });

  it('does not run the Fastify adapter on an Express project', () => {
    const express = run(EXPRESS_FIXTURE);
    expect(express.frameworks.find((f) => f.framework === 'fastify')?.applicable).toBe(false);
    expect(express.entries.every((e) => e.framework === 'express')).toBe(true);
  });

  it('finds every statically declared route in the fixture', () => {
    // server: 6, users: 4, admin: 2, v2: 2, inline /api: 1, secure: 2, dynamic: 2, orphan: 1
    expect(data.summary.total).toBe(20);
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

describe('Fastify adapter: methods, paths and nested prefixes', () => {
  it('detects GET, POST, PUT and DELETE', () => {
    for (const m of ['GET', 'POST', 'PUT', 'DELETE']) expect(data.summary.byMethod[m]).toBeGreaterThan(0);
    expect(data.summary.byMethod['PUT']).toBe(1);
    expect(data.summary.byMethod['DELETE']).toBe(1);
  });

  it('expands route() with a method array into separate entries', () => {
    expect(find('GET', '/multi').line).toBe(find('POST', '/multi').line);
  });

  it('applies register() prefixes for imported and required plugins', () => {
    expect(find('GET', '/users').file).toBe('src/plugins/users.ts');
    expect(find('GET', '/admin/stats').file).toBe('src/plugins/admin.js');
    expect(find('PUT', '/admin/settings').file).toBe('src/plugins/admin.js');
  });

  it('resolves inline plugins and prefixes stored in a const', () => {
    const e = find('GET', '/api/ping');
    expect(e.pathResolved).toBe(true);
    expect(e.file).toBe('src/server.ts');
  });

  it('resolves nested plugins (root -> /api -> /v2) via a named import', () => {
    const e = find('GET', '/api/v2/items');
    expect(e.pathResolved).toBe(true);
    expect(e.file).toBe('src/plugins/v2.ts');
    expect(e.evidence.filter((x) => x.source === 'mount-resolution').length).toBe(2);
  });
});

describe('Fastify adapter: parameters and schemas', () => {
  it('detects path parameters, including through generics', () => {
    const e = find('GET', '/users/:id');
    expect(e.parameters.map((p) => p.name)).toEqual(['id']);
    expect(e.line).toBe(lineOf('src/plugins/users.ts', 'fastify.get<{ Params'));
  });

  it('reads query parameters from the route schema', () => {
    const e = find('GET', '/api/v2/search');
    expect(e.queryParameters.map((p) => p.name).sort()).toEqual(['page', 'q']);
    expect(e.queryParameters.find((p) => p.name === 'q')?.required).toBe(true);
    expect(e.queryParameters.find((p) => p.name === 'page')?.required).toBe(false);
    expect(e.queryParameters.find((p) => p.name === 'page')?.type).toBe('integer');
  });

  it('reads body parameters from the schema and from request.body destructuring', () => {
    expect(find('POST', '/users').bodyParameters.map((p) => p.name).sort()).toEqual(['email', 'name']);
    expect(find('POST', '/login').bodyParameters.map((p) => p.name).sort()).toEqual(['password', 'username']);
  });

  it('detects response indicators when statically visible', () => {
    expect(find('POST', '/login').responseIndicators).toContain('status:200');
    expect(find('DELETE', '/users/:id').responseIndicators).toContain('status:204');
  });
});

describe('Fastify adapter: hooks, auth and authorization', () => {
  it('marks routes without any auth indicator as public, even with a non-auth hook', () => {
    expect(find('POST', '/login').publicOrProtected).toBe('public');
    const e = find('GET', '/users/:id');
    expect(e.publicOrProtected).toBe('public');
    expect(e.middleware).toContain('onRequest (inline)');
    expect(e.authIndicators).toEqual([]);
  });

  it('detects route-level preHandler authentication', () => {
    const e = find('POST', '/users');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.authIndicators).toContain('fastify.authenticate');
  });

  it('detects authorization inside a fastify.auth([...]) composition and reads a same-file handler by name', () => {
    const e = find('DELETE', '/users/:id');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.authorizationIndicators.some((a) => a.includes('verifyAdmin'))).toBe(true);
    expect(e.handler).toBe('deleteUser');
  });

  it('applies addHook() declared before the route in the same plugin', () => {
    const e = find('GET', '/admin/stats');
    expect(e.publicOrProtected).toBe('protected');
    expect(e.middleware).toContain('fastify.authenticate');
    expect(e.authorizationIndicators).toContain('requireAdmin');
    expect(e.language).toBe('javascript');
  });

  it('inherits parent hooks into nested plugins registered afterwards', () => {
    const me = find('GET', '/secure/me');
    expect(me.publicOrProtected).toBe('protected');
    expect(me.authIndicators).toContain('app.authenticate');
    const inner = find('GET', '/secure/deep/inner');
    expect(inner.publicOrProtected).toBe('protected');
    expect(inner.evidence.some((x) => x.source === 'hook')).toBe(true);
  });

  it('detects file-upload indicators', () => {
    const e = find('POST', '/avatar');
    expect(e.uploadIndicators.length).toBeGreaterThan(0);
    expect(e.publicOrProtected).toBe('protected');
    expect(find('POST', '/login').uploadIndicators).toEqual([]);
  });

  it('does not count a hook declared after a route, but records an evidence note', () => {
    const root = makeTempProject({
      'package.json': JSON.stringify({ name: 't', dependencies: { fastify: '^4.28.0' } }),
      'src/app.js': [
        "const app = require('fastify')();",
        "app.get('/before', async () => 1);",
        "app.addHook('onRequest', authenticate);",
        "app.get('/after', async () => 2);",
        'function authenticate(request, reply, done) { done(); }',
        '',
      ].join('\n'),
    });
    const result = run(root);
    const before = result.entries.find((e) => e.path === '/before');
    const after = result.entries.find((e) => e.path === '/after');
    expect(before?.publicOrProtected).toBe('public');
    expect(before?.evidence.some((x) => x.source === 'hook-ordering')).toBe(true);
    expect(after?.publicOrProtected).toBe('protected');
  });
});

describe('Fastify adapter: ambiguous, unsupported and malformed input', () => {
  const dyn = data.entries.filter((e) => e.file === 'src/plugins/dynamic.ts');

  it('never guesses a computed register() prefix', () => {
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

  it('reports plugins that no register() call mounts', () => {
    const e = data.entries.find((x) => x.file === 'src/plugins/orphan.ts');
    expect(e?.pathResolved).toBe(false);
    expect(e?.publicOrProtected).toBe('unknown');
    expect(e?.evidence.some((x) => x.detail.includes('not registered'))).toBe(true);
  });

  it('warns about malformed files instead of crashing', () => {
    expect(data.warnings.some((w) => w.includes('broken.ts'))).toBe(true);
    expect(data.entries.some((e) => e.path.includes('broken'))).toBe(false);
  });

  it('reports duplicate route definitions', () => {
    const health = data.entries.filter((e) => e.method === 'GET' && e.path === '/health');
    expect(health.length).toBe(2);
    expect(data.warnings.some((w) => w.includes('Duplicate route definition: GET /health'))).toBe(true);
  });
});

describe('Fastify adapter: false positives and ignored directories', () => {
  it('ignores commented-out routes, Map.get, non-Fastify .get() and helper functions that only look like plugins', () => {
    const paths = data.entries.map((e) => e.path);
    for (const bad of ['commented-out', 'not-a-route', 'also-not-a-route', 'trust-proxy-setting']) {
      expect(paths.some((p) => p.includes(bad))).toBe(false);
    }
    expect(data.entries.some((e) => e.file === 'src/notRoutes.ts')).toBe(false);
  });

  it('ignores node_modules, .git, dist, build, coverage, docs and caches', () => {
    const route = (p: string) => `const app = require('fastify')();\napp.get('${p}', async () => 'x');\n`;
    const root = makeTempProject({
      'package.json': JSON.stringify({ name: 't', dependencies: { fastify: '^4.28.0' } }),
      'src/app.js': route('/real'),
      'node_modules/pkg/index.js': route('/from-node-modules'),
      'dist/app.js': route('/from-dist'),
      'build/app.js': route('/from-build'),
      'coverage/report.js': route('/from-coverage'),
      'docs/example.js': route('/from-docs'),
      '.git/hooks/hook.js': route('/from-git'),
      '.next/server/app.js': route('/from-next'),
    });
    expect(run(root).entries.map((e) => e.path)).toEqual(['/real']);
  });
});
