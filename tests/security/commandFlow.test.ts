import fs from 'node:fs';
import path from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { makeFixtureProject } from '../testUtils.js';

const projects: ReturnType<typeof makeFixtureProject>[] = [];
afterEach(() => { for (const project of projects.splice(0)) project.cleanup(); });

async function findings(source: string) {
  const project = makeFixtureProject();
  projects.push(project);
  fs.writeFileSync(path.join(project.root, 'src/handler.ts'), source);
  const scan = await scanProject(project.config);
  if (!scan.ok) throw new Error(scan.error.message);
  return scan.data.findings.filter(f => f.ruleId === 'CS-NODE-025');
}

it('finds a request-derived command passed to exec across statements', async () => {
  const result = await findings('import { exec } from "child_process";\napp.post("/run", (req, res) => {\n const command = req.body.command;\n exec(command);\n});');
  expect(result).toEqual([expect.objectContaining({ severity: 'high', file: 'src/handler.ts', line: 4, confidence: 'medium' })]);
  expect(result[0]?.evidence[0]?.reason).toMatch(/request|command/i);
});

it('does not report a fixed command with untrusted data passed only as an argument', async () => {
  expect(await findings('import { execFile } from "child_process";\napp.post("/run", (req, res) => { const name = req.body.name; execFile("/usr/bin/convert", [name]); });')).toEqual([]);
});

it('does not report a command selected from a fixed allowlist', async () => {
  expect(await findings('import { exec } from "child_process";\napp.post("/run", (req, res) => { const action = req.body.action; const command = action === "status" ? "git status" : "git log"; exec(command); });')).toEqual([]);
});

it('does not confuse an inner function variable with the executed command', async () => {
  expect(await findings('import { exec } from "child_process";\napp.post("/run", (req, res) => { function unused() { const command = req.body.command; return command; } const command = "git status"; exec(command); });')).toEqual([]);
});
