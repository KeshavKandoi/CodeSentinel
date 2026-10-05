import { testCredential } from './testCredentials.js';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'child_process';
import path from 'path';

describe('MCP Server Integration', () => {
  let mcpProcess: any;
  let responses: any[] = [];
  let stderrData = '';
  let stdoutBuffer = '';

  beforeAll(async () => {
    const tsxPath = path.resolve('node_modules', '.bin', 'tsx');
    const indexPath = path.resolve('src', 'index.ts');
    mcpProcess = spawn(tsxPath, [indexPath], {
      cwd: path.resolve(__dirname, '..'),
      env: { ...process.env, PROJECT_ROOT: '.' }
    });

    mcpProcess.stdout.on('data', (data: Buffer) => {
      stdoutBuffer += data.toString();
      let newlineIdx;
      while ((newlineIdx = stdoutBuffer.indexOf('\n')) !== -1) {
        const line = stdoutBuffer.slice(0, newlineIdx);
        stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1);
        if (line.trim()) {
          try {
            responses.push(JSON.parse(line));
          } catch (e) {
            responses.push({ unparsed: line });
          }
        }
      }
    });

    mcpProcess.stderr.on('data', (data: Buffer) => {
      stderrData += data.toString();
    });

    await new Promise(resolve => setTimeout(resolve, 2000));
  });

  afterAll(() => {
    if (mcpProcess) mcpProcess.kill();
  });

  const sendRequest = async (request: any) => {
    const startCount = responses.length;
    mcpProcess.stdin.write(JSON.stringify(request) + '\n');
    let retries = 0;
    while (responses.length === startCount && retries < 50) {
      await new Promise(resolve => setTimeout(resolve, 100));
      retries++;
    }
    return responses[responses.length - 1] || {};
  };

  it('initializes MCP session', async () => {
    const initReq = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } }
    };
    const res = await sendRequest(initReq);
    expect(res.id).toBe(1);
    expect(res.result.protocolVersion).toBeDefined();
    
    await sendRequest({ jsonrpc: '2.0', method: 'notifications/initialized' });
  });

  it('lists tools', async () => {
    const res = await sendRequest({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    expect(res.id).toBe(2);
    expect(res.result.tools).toBeDefined();
    expect(res.result.tools.length).toBeGreaterThan(0);
  });

  it('invokes a harmless discovery tool', async () => {
    const res = await sendRequest({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'get_project_info', arguments: {} }
    });
    expect(res.id).toBe(3);
    expect(res.result.content[0].type).toBe('text');
    const parsed = JSON.parse(res.result.content[0].text);
    expect(parsed.hasGit).toBeDefined();
  });

  it('invokes a safe static analysis tool', async () => {
    const res = await sendRequest({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'scan_project', arguments: {} }
    });
    expect(res.id).toBe(4);
    expect(res.result.content[0].type).toBe('text');
    const parsed = JSON.parse(res.result.content[0].text);
    expect(parsed.project).toBeDefined();
  });

  it('rejects malicious MCP arguments (directory traversal)', async () => {
    const res = await sendRequest({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'list_files', arguments: { path: '../../../../../etc' } }
    });
    expect(res.id).toBe(5);
    expect(res.result.isError).toBe(true);
    const parsed = JSON.parse(res.result.content[0].text);
    expect(parsed.error).toBe('PATH_OUTSIDE_ROOT');
  });

  it('rejects arbitrary command execution', async () => {
    const res = await sendRequest({
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'run_command', arguments: { command: 'rm', args: ['-rf', '/'] } }
    });
    expect(res.id).toBe(6);
    expect(res.result.isError).toBe(true);
    const parsed = JSON.parse(res.result.content[0].text);
    expect(parsed.error).toBe('COMMAND_NOT_ALLOWED');
  });
  
  it('redacts secrets echoed in unknown-tool errors', async () => {
    const hostile = `Authorization: Basic ${testCredential('BASIC_CREDENTIAL')}`;
    const res = await sendRequest({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: hostile, arguments: {} }
    });
    expect(res.id).toBe(7);
    expect(res.result.isError).toBe(true);
    const text = JSON.stringify(res);
    expect(text).toContain('UNKNOWN_TOOL');
    expect(text).not.toContain(testCredential('BASIC_CREDENTIAL').slice(0, 12));
  });

  it('keeps hostile, oversized and malformed tool calls structured and secret-free', async () => {
    const secret = testCredential('BASIC_CREDENTIAL');
    const hostile = `Authorization: Basic ${secret}`;
    const calls: Array<[string, unknown]> = [
      [hostile, {}],
      ['verify_finding', { findingId: hostile.repeat(10), target: { allowedOrigin: 'http://127.0.0.1:1' } }],
      ['verify_finding', { findingId: 'x', target: 'bad' }],
      ['get_investigation', { investigationId: hostile.repeat(10) }],
      ['get_security_finding', { investigationId: hostile, findingId: hostile }],
      ['list_files', { path: 'x'.repeat(100_000) }],
      ['scan_project', { unknown: hostile }],
      ['read_file', null],
    ];
    let id = 100;
    for (const [name, args] of calls) {
      const res = await sendRequest({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } });
      expect(res.id).toBe(id);
      const text = JSON.stringify(res);
      expect(text).not.toContain(secret);
      expect(text).not.toMatch(/\n\s+at .*:\d+:\d+/);
      if (res.result) expect(res.result.isError).toBe(true);
      else expect(res.error).toBeDefined();
    }
  }, 60_000);

  it('does not leak logs to stdout (protocol corruption check)', () => {
    for (const res of responses) {
      expect(res.unparsed).toBeUndefined();
      if (res.jsonrpc) {
        expect(res.jsonrpc).toBe('2.0');
      }
    }
  });
});
