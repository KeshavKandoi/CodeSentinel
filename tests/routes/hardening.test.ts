import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { discoverRoutes } from '../../src/routes/engine.js';
import type { AppConfig } from '../../src/config.js';

const made: string[] = [];
afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function project(files: Record<string, string>): AppConfig {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-routes-')));
  made.push(dir);
  const all = { 'package.json': JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { express: '^4' } }), ...files };
  for (const [file, content] of Object.entries(all)) {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), content);
  }
  return { projectRoot: dir, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 5000 };
}

function routes(config: AppConfig): string[] {
  const result = discoverRoutes(config);
  if (!result.ok) throw new Error(result.error.message);
  return result.data.entries.map((entry) => `${entry.method} ${entry.path}`);
}

describe('Phase 4 route discovery hardening', () => {
  it('ignores route-like text inside string and template literals', () => {
    const config = project({
      'src/app.ts': `import express from 'express';
const app = express();
const doc = "app.get('/instring', (req, res) => res.send('x'))";
const tpl = \`app.post('/intemplate', (req, res) => res.send('x'))\`;
app.get('/real', (req, res) => res.send('ok'));
`,
    });
    expect(routes(config)).toEqual(['GET /real']);
  });

  it('does not return literal secrets from middleware text', () => {
    const config = project({
      'src/app.ts': `import express from 'express';
const app = express();
app.get('/m', basicAuth({ users: { admin: 'hunter2pw-secret' } }), (req, res) => res.send('m'));
`,
    });
    const result = discoverRoutes(config);
    expect(JSON.stringify(result)).not.toContain('hunter2pw-secret');
    expect(routes(config)).toEqual(['GET /m']);
  });

  it('does not walk symlinked directories or read symlinks that leave the root', () => {
    const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-out-')));
    made.push(outside);
    fs.writeFileSync(path.join(outside, 'evil.ts'), "import express from 'express';\nconst app = express();\napp.get('/evil', (q, s) => s.send('x'));\n");
    const config = project({ 'src/app.ts': "import express from 'express';\nconst app = express();\napp.get('/real', (q, s) => s.send('x'));\n" });
    fs.symlinkSync(path.join(config.projectRoot, 'src'), path.join(config.projectRoot, 'alias'));
    fs.symlinkSync(outside, path.join(config.projectRoot, 'out'));
    fs.symlinkSync(path.join(outside, 'evil.ts'), path.join(config.projectRoot, 'src', 'evil.ts'));
    const result = discoverRoutes(config);
    expect(routes(config)).toEqual(['GET /real']);
    expect(JSON.stringify(result)).not.toContain('/evil');
  });

  it('bounds hostile router mount graphs', () => {
    let src = "import express from 'express';\nconst app = express();\nconst r0 = express.Router();\nr0.get('/leaf', (q, s) => s.send('x'));\n";
    for (let i = 1; i <= 28; i++) src += `const r${i} = express.Router();\nr${i}.use('/a', r${i - 1});\nr${i}.use('/b', r${i - 1});\n`;
    src += "app.use('/', r28);\n";
    const started = Date.now();
    const result = discoverRoutes(project({ 'src/app.ts': src }));
    expect(result.ok).toBe(true);
    expect(Date.now() - started).toBeLessThan(10_000);
  }, 20_000);

  it('produces identical output for repeated discovery', () => {
    const config = project({ 'src/app.ts': "import express from 'express';\nconst app = express();\napp.get('/a', (q, s) => s.send('x'));\napp.get('/a', (q, s) => s.send('y'));\n" });
    expect(JSON.stringify(discoverRoutes(config))).toBe(JSON.stringify(discoverRoutes(config)));
  });
});
