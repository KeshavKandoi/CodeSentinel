import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { makeFixtureProject } from '../testUtils.js';

const projects: ReturnType<typeof makeFixtureProject>[] = [];
afterEach(() => { for (const project of projects.splice(0)) project.cleanup(); });

async function scan(source: string) {
  const project = makeFixtureProject();
  projects.push(project);
  fs.writeFileSync(path.join(project.root, 'src/server.ts'), source);
  const result = await scanProject(project.config);
  if (!result.ok) throw new Error(result.error.message);
  return result.data.findings;
}

describe('semantic Node rules', () => {
  it.skipIf(!fs.existsSync('/Users/keshavkandoi/codesentinel-test-target/Web-Socket/realtime-10m/websocket-server'))('identifies the real WebSocket server evidence', async () => {
    const project = makeFixtureProject();
    projects.push(project);
    const result = await scanProject({ ...project.config, projectRoot: '/Users/keshavkandoi/codesentinel-test-target/Web-Socket/realtime-10m/websocket-server' });
    if (!result.ok) throw new Error(result.error.message);
    expect(result.data.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'CS-NODE-022', file: 'src/server.ts', line: 196 }),
      expect.objectContaining({ ruleId: 'CS-NODE-023', file: 'src/server.ts', line: 125 }),
      expect.objectContaining({ ruleId: 'CS-NODE-024', file: 'src/server.ts', line: 144 }),
    ]));
  });
  it('finds client selected WebSocket identity with source evidence', async () => {
    const findings = await scan('import { WebSocketServer } from "ws";\nconst wss = new WebSocketServer({ port: 3000 });\nwss.on("connection", socket => {\n socket.on("message", data => {\n  const parsed = JSON.parse(data.toString());\n  registry.register(parsed.userId, socket);\n });\n});');
    const finding = findings.find(f => f.ruleId === 'CS-NODE-022');
    expect(finding).toMatchObject({ severity: 'high', file: 'src/server.ts', line: 6 });
    expect(finding?.evidence[0]?.reason).toMatch(/client|message/i);
  });

  it('does not flag verified identity', async () => {
    const findings = await scan('wss.on("connection", socket => { socket.on("message", data => { const parsed = JSON.parse(data.toString()); const userId = verifyToken(parsed.token); registry.register(userId, socket); }); });');
    expect(findings.some(f => f.ruleId === 'CS-NODE-022')).toBe(false);
  });

  it('does not treat verification of an unrelated token as binding the claimed identity', async () => {
    const result = await scan('wss.on("connection", socket => { socket.on("message", data => { const parsed = JSON.parse(data.toString()); verifyToken(parsed.token); registry.register(parsed.userId, socket); }); });');
    expect(result.some(f => f.ruleId === 'CS-NODE-022')).toBe(true);
  });

  it('finds exposed operational metrics with source location', async () => {
    const findings = await scan('import http from "http";\nhttp.createServer((req, res) => {\n if (req.url === "/metrics") {\n  res.end(JSON.stringify(manager.snapshot()));\n }\n});');
    expect(findings.find(f => f.ruleId === 'CS-NODE-023')).toMatchObject({ severity: 'medium', file: 'src/server.ts', line: 3 });
  });

  it('does not flag guarded metrics or simple health', async () => {
    const findings = await scan('http.createServer((req, res) => { if (req.url === "/metrics") { if (!authenticate(req)) return res.end("denied"); res.end(JSON.stringify(manager.snapshot())); } if (req.url === "/health") res.end("ok"); });');
    expect(findings.some(f => f.ruleId === 'CS-NODE-023')).toBe(false);
  });

  it('does not treat authentication on an earlier route as protecting metrics', async () => {
    const result = await scan('http.createServer((req, res) => { if (req.url === "/admin") { authenticate(req); res.end("ok"); } if (req.url === "/metrics") { res.end(JSON.stringify(manager.snapshot())); } });');
    expect(result.some(f => f.ruleId === 'CS-NODE-023')).toBe(true);
  });

  it('finds an unbounded WebSocket payload only alongside expensive processing', async () => {
    const findings = await scan('const wss = new WebSocketServer({ server });\nwss.on("connection", socket => { socket.on("message", data => { const parsed = JSON.parse(data.toString()); database.save(parsed); }); });');
    expect(findings.find(f => f.ruleId === 'CS-NODE-024')).toMatchObject({ severity: 'medium', file: 'src/server.ts', line: 1 });
  });

  it('does not flag explicit maxPayload', async () => {
    const findings = await scan('const wss = new WebSocketServer({ server, maxPayload: 1024 * 1024 });\nwss.on("connection", socket => { socket.on("message", data => { const parsed = JSON.parse(data.toString()); database.save(parsed); }); });');
    expect(findings.some(f => f.ruleId === 'CS-NODE-024')).toBe(false);
  });

  it('does not flag a handler that rejects oversized messages before processing', async () => {
    const findings = await scan('const wss = new WebSocketServer({ server });\nwss.on("connection", socket => { socket.on("message", data => { if (data.byteLength > MAX_MESSAGE_BYTES) return socket.close(); const parsed = JSON.parse(data.toString()); database.save(parsed); }); });');
    expect(findings.some(f => f.ruleId === 'CS-NODE-024')).toBe(false);
  });
});
