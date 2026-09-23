import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverRoutes } from '../../src/routes/engine.js';
import type { AppConfig } from '../../src/config.js';
import type { AttackSurfaceEntry } from '../../src/routes/types.js';

const FIXTURES = fs.realpathSync(fileURLToPath(new URL('../fixtures', import.meta.url)));
const tempDirs: string[] = [];

afterAll(() => {
  for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
});

function cfg(root: string): AppConfig {
  return { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
}

function routesOf(root: string): AttackSurfaceEntry[] {
  const outcome = discoverRoutes(cfg(root));
  if (!outcome.ok) throw new Error(outcome.error.message);
  return outcome.data.entries;
}

function makeTempProject(files: Record<string, string>): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-adapters-')));
  tempDirs.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

function labels(entries: readonly AttackSurfaceEntry[]): string[] {
  return entries.map((e) => `${e.method} ${e.path}`).sort();
}

function pick(entries: readonly AttackSurfaceEntry[], method: string, routePath: string): AttackSurfaceEntry {
  const found = entries.find((e) => e.method === method && e.path === routePath);
  if (!found) throw new Error(`missing route ${method} ${routePath}`);
  return found;
}

describe('NestJS adapter', () => {
  const all = routesOf(path.join(FIXTURES, 'nestjs-routes'));
  const entries = all.filter((e) => e.file === 'src/app.controller.ts');

  it('discovers every decorated route, including methods with parameter decorators', () => {
    expect(labels(entries)).toEqual(
      ['DELETE unknown', 'GET /api/health', 'GET /api/users/:id', 'POST /api/upload', 'POST /api/users'].sort()
    );
  });

  it('reports the method name as the handler, not the first decorator', () => {
    expect(pick(entries, 'GET', '/api/health').handler).toBe('health');
    expect(pick(entries, 'GET', '/api/users/:id').handler).toBe('getUser');
    expect(pick(entries, 'POST', '/api/users').handler).toBe('createUser');
    expect(entries.find((e) => e.path === 'unknown')?.handler).toBe('remove');
  });

  it('inherits controller guards and adds method guards', () => {
    for (const e of entries) expect(e.middleware).toContain('JwtGuard');
    const create = pick(entries, 'POST', '/api/users');
    expect(create.middleware).toContain('RolesGuard');
    expect(create.authorizationIndicators).toContain('RolesGuard');
    expect(pick(entries, 'GET', '/api/health').authorizationIndicators).toEqual([]);
  });

  it('extracts path and query parameters', () => {
    const detail = pick(entries, 'GET', '/api/users/:id');
    expect(detail.parameters.map((p) => p.name)).toContain('id');
    expect(detail.queryParameters.map((p) => p.name)).toContain('expand');
  });

  it('marks an unresolvable method path as unresolved', () => {
    const dynamic = entries.find((e) => e.path === 'unknown');
    expect(dynamic?.pathResolved).toBe(false);
  });

  it('produces no routes from non-controller or broken files', () => {
    expect(all.filter((e) => e.file !== 'src/app.controller.ts')).toEqual([]);
  });

  it('handles nested parentheses in guards and parameter decorators', () => {
    const root = makeTempProject({
      'package.json': JSON.stringify({ name: 'n', dependencies: { '@nestjs/common': '^10.0.0' } }),
      'src/items.controller.ts': [
        "import { Controller, Get, Post, Param, Body, UseGuards } from '@nestjs/common';",
        '',
        "@UseGuards(AuthGuard('jwt'))",
        "@Controller('items')",
        'export class ItemsController {',
        "  @Get(':id')",
        "  findOne(@Param('id') id: string, @Body(new ValidationPipe({ whitelist: true })) dto: unknown) {",
        '    return { id };',
        '  }',
        '',
        '  @Post()',
        "  @UseGuards(AuthGuard('jwt'), RolesGuard)",
        '  create(@Body() dto: unknown) {',
        '    return dto;',
        '  }',
        '}',
        '',
      ].join('\n'),
    });
    const found = routesOf(root);
    expect(labels(found)).toEqual(['GET /items/:id', 'POST /items']);
    expect(pick(found, 'GET', '/items/:id').handler).toBe('findOne');
    expect(pick(found, 'GET', '/items/:id').middleware).toContain("AuthGuard('jwt')");
    expect(pick(found, 'POST', '/items').middleware).toEqual(expect.arrayContaining(["AuthGuard('jwt')", 'RolesGuard']));
  });
});

describe('FastAPI adapter', () => {
  const all = routesOf(path.join(FIXTURES, 'fastapi-routes'));
  const entries = all.filter((e) => e.file === 'app/main.py');

  it('discovers routes whose decorators contain nested parentheses', () => {
    expect(labels(entries)).toEqual(['GET /api/users/{id}', 'GET /health', 'POST /api/users', 'POST /api/users/upload'].sort());
  });

  it('captures decorator-level and signature-level dependencies', () => {
    const create = pick(entries, 'POST', '/api/users');
    expect(create.dependencies).toEqual(expect.arrayContaining(['require_admin', 'current_user']));
    expect(create.authorizationIndicators).toContain('require_admin');
    const upload = pick(entries, 'POST', '/api/users/upload');
    expect(upload.dependencies).toContain('current_user');
    expect(upload.uploadIndicators.length).toBeGreaterThan(0);
  });

  it('extracts brace-style path parameters and keeps them out of query parameters', () => {
    const detail = pick(entries, 'GET', '/api/users/{id}');
    expect(detail.parameters.map((p) => p.name)).toEqual(['id']);
    expect(detail.queryParameters.map((p) => p.name)).toEqual(['expand']);
  });

  it('ignores decorators that only appear inside strings', () => {
    expect(all.some((e) => e.path.includes('not-a-route'))).toBe(false);
  });

  it('inherits router-level and include-level dependencies and prefixes', () => {
    const root = makeTempProject({
      'requirements.txt': 'fastapi\n',
      'app/main.py': [
        'from fastapi import APIRouter, Depends, FastAPI',
        'from typing import Annotated',
        '',
        'def get_current_user(): return {}',
        'def require_admin(): return True',
        '',
        'app = FastAPI()',
        'router = APIRouter(prefix="/orders", dependencies=[Depends(get_current_user)])',
        'admin = APIRouter(dependencies=[Depends(require_admin)], prefix="/admin")',
        '',
        '@router.get("/{order_id}")',
        'def get_order(order_id: int):',
        '    return {}',
        '',
        '@admin.delete("/orders/{order_id}", status_code=204)',
        'def delete_order(order_id: int, user: Annotated[dict, Depends(get_current_user)]):',
        '    return None',
        '',
        'app.include_router(router)',
        'app.include_router(admin, prefix="/v1")',
        '',
      ].join('\n'),
    });
    const found = routesOf(root);
    expect(labels(found)).toEqual(['DELETE /v1/admin/orders/{order_id}', 'GET /orders/{order_id}']);
    const get = pick(found, 'GET', '/orders/{order_id}');
    expect(get.dependencies).toContain('get_current_user');
    expect(get.authIndicators).toContain('get_current_user');
    expect(get.queryParameters).toEqual([]);
    const del = pick(found, 'DELETE', '/v1/admin/orders/{order_id}');
    expect(del.dependencies).toEqual(expect.arrayContaining(['require_admin', 'get_current_user']));
    expect(del.authorizationIndicators).toContain('require_admin');
    expect(del.parameters.map((p) => p.name)).toEqual(['order_id']);
  });
});

describe('Django adapter', () => {
  const entries = routesOf(path.join(FIXTURES, 'django-routes'));

  it('does not treat a path() call inside a string literal as a route', () => {
    expect(entries.some((e) => e.path.includes('string-only'))).toBe(false);
  });

  it('discovers raw-string re_path routes and resolves include prefixes', () => {
    expect(labels(entries)).toEqual(
      expect.arrayContaining(['ALL /api/legacy/:slug', 'ALL /api/upload', 'ALL /api/users/:id', 'GET /api/admin/stats'])
    );
    expect(pick(entries, 'ALL', '/api/legacy/:slug').parameters.map((p) => p.name)).toContain('slug');
  });

  it('resolves class-based views and reads their permission classes', () => {
    const stats = pick(entries, 'GET', '/api/admin/stats');
    expect(stats.handler).toBe('views.AdminStatsView');
    expect(stats.authorizationIndicators.length).toBeGreaterThan(0);
  });

  it('does not leak indicators or methods from neighbouring definitions', () => {
    const detail = pick(entries, 'ALL', '/api/users/:id');
    expect(detail.authIndicators.length).toBeGreaterThan(0);
    expect(detail.authorizationIndicators).toEqual([]);
    expect(pick(entries, 'ALL', '/api/legacy/:slug').publicOrProtected).toBe('public');
  });

  it('follows nested include() chains', () => {
    const root = makeTempProject({
      'requirements.txt': 'django\n',
      'config/urls.py': 'from django.urls import path, include\nurlpatterns = [path("v1/", include("api.urls"))]\n',
      'api/urls.py': 'from django.urls import path, include\nurlpatterns = [path("shop/", include("api.shop.urls"))]\n',
      'api/shop/urls.py': 'from django.urls import path\nfrom . import views\nurlpatterns = [path("orders/<int:order_id>/", views.order_detail)]\n',
      'api/shop/views.py': 'def order_detail(request, order_id):\n    return None\n',
    });
    const found = routesOf(root);
    expect(labels(found)).toEqual(['ALL /v1/shop/orders/:order_id']);
    expect(found[0]?.parameters.map((p) => p.name)).toEqual(['order_id']);
  });

  it('treats an explicit AllowAny permission class as public', () => {
    const root = makeTempProject({
      'requirements.txt': 'django\n',
      'app/urls.py': 'from django.urls import path\nfrom . import views\nurlpatterns = [path("feed/", views.FeedView.as_view())]\n',
      'app/views.py': 'from rest_framework.permissions import AllowAny\n\nclass FeedView(View):\n    permission_classes = [AllowAny]\n\n    def get(self, request):\n        return None\n',
    });
    const found = routesOf(root);
    expect(labels(found)).toEqual(['GET /feed']);
    expect(found[0]?.publicOrProtected).toBe('public');
  });
});
