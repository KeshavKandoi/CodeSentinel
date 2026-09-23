import { describe, it, expect, afterAll } from 'vitest';
import { runCommand, validateCommand } from '../src/exec/commandExecutor.js';
import { makeFixtureProject } from './testUtils.js';

const { config, cleanup } = makeFixtureProject();
afterAll(() => cleanup());

describe('validateCommand', () => {
  it('accepts an allowlisted command', () => {
    const result = validateCommand({ command: 'ls', args: [] });
    expect(result.ok).toBe(true);
  });

  it('rejects a non-allowlisted command', () => {
    const result = validateCommand({ command: 'rm', args: ['-rf', '/'] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
  });

  it('rejects an arbitrary shell invocation', () => {
    const result = validateCommand({ command: 'bash', args: ['-c', 'echo hi'] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
  });

  it('rejects mutating git subcommands', () => {
    const result = validateCommand({ command: 'git', args: ['push', 'origin', 'main'] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
  });

  it('rejects npm install', () => {
    const result = validateCommand({ command: 'npm', args: ['install', 'left-pad'] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
  });

  it('allows read-only git subcommands', () => {
    const result = validateCommand({ command: 'git', args: ['status'] });
    expect(result.ok).toBe(true);
  });

  it('rejects empty command string', () => {
    const result = validateCommand({ command: '', args: [] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_INPUT');
  });

  it('rejects non-array args', () => {
    // @ts-expect-error intentional invalid input for runtime test
    const result = validateCommand({ command: 'ls', args: 'not-an-array' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_INPUT');
  });
});

describe('runCommand', () => {
  it('runs an allowlisted command and captures stdout', async () => {
    const result = await runCommand(config, { command: 'echo', args: ['hello-world'] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdout.trim()).toBe('hello-world');
    expect(result.data.exitCode).toBe(0);
    expect(result.data.timedOut).toBe(false);
  });

  it('executes inside the project root as cwd', async () => {
    const result = await runCommand(config, { command: 'pwd', args: [] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdout.trim()).toBe(config.projectRoot);
  });

  it('captures a non-zero exit code without treating it as a tool failure', async () => {
    const result = await runCommand(config, { command: 'ls', args: ['does-not-exist-xyz'] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.exitCode).not.toBe(0);
    expect(result.data.stderr.length).toBeGreaterThan(0);
  });

  it('rejects a non-allowlisted command before spawning', async () => {
    const result = await runCommand(config, { command: 'curl', args: ['http://example.com'] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
  });

  it('does not interpret shell metacharacters in args', async () => {
    // If a shell were involved, this would execute two commands. Since
    // shell:false, the whole string is passed as a single literal arg to
    // echo, so we should see the pipe/semicolon in the output verbatim.
    const result = await runCommand(config, { command: 'echo', args: ['a; echo b'] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdout.trim()).toBe('a; echo b');
  });

  it('enforces the configured timeout on a long-running command', async () => {
    const shortTimeoutConfig = { ...config, commandTimeoutMs: 200 };
    const result = await runCommand(shortTimeoutConfig, {
      command: 'node',
      args: ['-e', 'setTimeout(() => {}, 5000)'],
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('COMMAND_TIMEOUT');
  }, 10_000);

  it('truncates stdout larger than maxOutputBytes', async () => {
    const tinyOutputConfig = { ...config, maxOutputBytes: 10 };
    const result = await runCommand(tinyOutputConfig, {
      command: 'node',
      args: ['-e', 'console.log("x".repeat(1000))'],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdoutTruncated).toBe(true);
    expect(result.data.stdout.length).toBeLessThanOrEqual(10);
  });
});
