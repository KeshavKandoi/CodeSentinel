import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AppConfig } from '../src/config.js';

export function makeFixtureProject(): { config: AppConfig; root: string; cleanup: () => void } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-test-')));

  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0' }, null, 2));
  fs.writeFileSync(path.join(root, 'README.md'), '# Fixture project\n\nHello world.\n');
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'index.js'), 'console.log("hello");\nconst TODO = "fix this";\n');
  fs.mkdirSync(path.join(root, 'src', 'utils'));
  fs.writeFileSync(path.join(root, 'src', 'utils', 'helpers.js'), 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n');
  fs.mkdirSync(path.join(root, 'node_modules'));
  fs.writeFileSync(path.join(root, 'node_modules', 'ignored.js'), 'module.exports = {};\n');
  fs.mkdirSync(path.join(root, '.git'));
  fs.writeFileSync(path.join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');

  fs.writeFileSync(path.join(root, 'big.txt'), 'x'.repeat(50_000));

  const config: AppConfig = {
    projectRoot: root,
    commandTimeoutMs: 5000,
    maxOutputBytes: 1_000_000,
    maxReadFileBytes: 2_000_000,
    maxListResults: 2_000,
  };

  const cleanup = () => {
    fs.rmSync(root, { recursive: true, force: true });
  };

  return { config, root, cleanup };
}

export function makeOutsideSecretFile(root: string): { secretPath: string; cleanup: () => void } {
  const parent = path.dirname(root);
  const secretPath = path.join(parent, `secret-${path.basename(root)}.txt`);
  fs.writeFileSync(secretPath, 'TOP SECRET — should never be readable via the MCP server\n');
  return {
    secretPath,
    cleanup: () => {
      try {
        fs.rmSync(secretPath, { force: true });
      } catch {
      }
    },
  };
}
