import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { runCommand, validateCommand } from '../src/exec/commandExecutor.js';
import { makeFixtureProject, makeOutsideSecretFile } from './testUtils.js';

const { config, root, cleanup } = makeFixtureProject();
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

  it.each([
    ['node', ['-e', 'process.exit(0)']],
    ['python3', ['-c', 'print(1)']],
    ['npm', ['test']],
    ['git', ['-C', '/tmp', 'status']],
    ['git', ['show', '--output=/tmp/codesentinel-audit-output']],
    ['git', ['show', '--output', '/tmp/codesentinel-audit-output']],
    ['git', ['diff', '--ext-diff']],
    ['git', ['show', '--textconv']],
    ['cat', ['/etc/passwd']],
    ['find', ['.', '-exec', 'echo', '{}', ';']],
    ['grep', ['--file=/etc/passwd', 'needle', '.']],
    ['find', ['.', '-files0-from=/etc/passwd']],
  ])('rejects unsafe command boundary %s', (command, args) => {
    const result = validateCommand({ command, args });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
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

  it('rejects a relative symlink that points outside the project root', async () => {
    const outside = makeOutsideSecretFile(root);
    const link = path.join(root, 'outside-link.txt');
    fs.symlinkSync(outside.secretPath, link);
    try {
      const result = await runCommand(config, { command: 'cat', args: ['outside-link.txt'] });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
    } finally {
      fs.rmSync(link, { force: true });
      outside.cleanup();
    }
  });

  it('truncates stdout larger than maxOutputBytes', async () => {
    const tinyOutputConfig = { ...config, maxOutputBytes: 10 };
    const result = await runCommand(tinyOutputConfig, {
      command: 'echo',
      args: ['xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdoutTruncated).toBe(true);
    expect(result.data.stdout.length).toBeLessThanOrEqual(10);
  });
});

import os from 'node:os';
import { execFileSync } from 'node:child_process';

describe('phase 1 command hardening', () => {
  const fx = makeFixtureProject();
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-outside-'));
  fs.writeFileSync(path.join(outsideDir, 'outside.txt'), 'outside\n');
  fs.writeFileSync(path.join(fx.root, '.env'), 'needlesecret\n');
  fs.mkdirSync(path.join(fx.root, '.ssh'));
  fs.writeFileSync(path.join(fx.root, '.ssh', 'id_rsa'), 'needlesecret\n');
  fs.writeFileSync(path.join(fx.root, 'src', '.ENV'), 'needlesecret\n');
  fs.writeFileSync(path.join(fx.root, 'src', 'ok.txt'), 'needlesecret\n');
  fs.symlinkSync(path.join(fx.root, '.env'), path.join(fx.root, 'envlink.txt'));
  fs.symlinkSync(path.join(outsideDir, 'outside.txt'), path.join(fx.root, 'outlink.txt'));
  afterAll(() => {
    fx.cleanup();
    fs.rmSync(outsideDir, { recursive: true, force: true });
  });

  const rejects = (command: string, args: string[]) => {
    const result = validateCommand({ command, args }, fx.root);
    expect(result.ok, `${command} ${args.join(' ')}`).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
      expect(result.error.message).not.toContain(fx.root);
    }
  };
  const accepts = (command: string, args: string[]) => {
    const result = validateCommand({ command, args }, fx.root);
    expect(result.ok, `${command} ${args.join(' ')}`).toBe(true);
  };

  it.each([
    ['/bin/ls', []], ['./ls', []], ['LS', []], ['ls ', []], ['sh', ['-c', 'id']], ['env', []], ['xargs', []], ['awk', []],
    ['sed', ['-i', 'x']], ['tar', []], ['curl', []], ['wget', []], ['python3', []], ['node', []], ['npm', []], ['perl', []],
    ['ssh', []], ['rm', []], ['mv', []], ['cp', []], ['tee', []], ['dd', []], ['touch', []], ['chmod', []], ['__proto__', []], ['constructor', []],
  ])('rejects non-allowlisted command form %s', (command, args) => {
    rejects(command, args as string[]);
  });

  it('rejects null bytes and malformed argument shapes as invalid input', () => {
    for (const args of [['a\0b'], [1], 'x', undefined, null]) {
      const result = validateCommand({ command: 'ls', args: args as unknown as string[] }, fx.root);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('INVALID_INPUT');
    }
  });

  it.each([
    [['-c', 'core.pager=sh', 'status']], [['--exec-path', 'status']], [['status', '--git-dir=/tmp']], [['status', '-C', '/tmp']],
    [['status', '--upload-pack=x']], [['log', '--output=/tmp/x']], [['log', '--out=/tmp/x']], [['diff', '--ext-diff']], [['diff', '--ext']],
    [['show', '--textconv']], [['branch', 'newbranch']], [['branch', '-D', 'main']], [['branch', '--delete', 'x']], [['branch', '-m', 'a', 'b']],
    [['show', 'HEAD:.env']], [['show', 'HEAD:../x']], [['log', '/etc/passwd']], [['diff', '--', '../x']], [['config', '--list']],
    [['remote', '-v']], [['stash']], [['worktree', 'list']], [['archive', 'HEAD']], [['grep', 'x']], [['push']], [['__proto__']],
    [['constructor']], [['toString']], [[]],
  ])('rejects git invocation %j', (args) => {
    rejects('git', args as string[]);
  });

  it.each([
    [['status']], [['status', '--porcelain']], [['log', '--oneline', '-n', '5']], [['log', '--max-count=5']], [['diff', '--stat']],
    [['branch', '--list']], [['branch', '-a']], [['rev-parse', '--abbrev-ref', 'HEAD']], [['show', '--stat', 'HEAD']],
  ])('accepts read-only git invocation %j', (args) => {
    accepts('git', args as string[]);
  });

  it('rejects git when repository metadata can run or load external configuration', () => {
    const cases: Array<{ name: string; setup: (root: string) => void }> = [
      { name: 'filter', setup: (root) => fs.writeFileSync(path.join(root, '.git', 'config'), '[filter "x"]\n\tclean = sh\n') },
      { name: 'include', setup: (root) => fs.writeFileSync(path.join(root, '.git', 'config'), '[include]\n\tpath = /tmp/x\n') },
      { name: 'includeIf', setup: (root) => fs.writeFileSync(path.join(root, '.git', 'config'), '[includeIf "gitdir:/"]\n\tpath = /tmp/x\n') },
      { name: 'alternates', setup: (root) => { fs.mkdirSync(path.join(root, '.git', 'objects', 'info'), { recursive: true }); fs.writeFileSync(path.join(root, '.git', 'objects', 'info', 'alternates'), '/tmp/x\n'); } },
      { name: 'commondir', setup: (root) => fs.writeFileSync(path.join(root, '.git', 'commondir'), '../other\n') },
      { name: 'gitfile', setup: (root) => { fs.rmSync(path.join(root, '.git'), { recursive: true, force: true }); fs.writeFileSync(path.join(root, '.git'), 'gitdir: /elsewhere\n'); } },
    ];
    for (const item of cases) {
      const project = makeFixtureProject();
      try {
        item.setup(project.root);
        const result = validateCommand({ command: 'git', args: ['status'] }, project.root);
        expect(result.ok, item.name).toBe(false);
        if (!result.ok) expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
      } finally {
        project.cleanup();
      }
    }
  });

  it.each([
    [['.env']], [['.ENV']], [['src/../.env']], [['/etc/passwd']], [['../x']], [['..\\x']], [['envlink.txt']], [['outlink.txt']],
    [['.ssh/id_rsa']], [['-', '.env']], [['--', '.env']], [['--', '/etc/passwd']], [['--help']], [['-z', 'README.md']],
  ])('rejects cat arguments %j', (args) => {
    rejects('cat', args as string[]);
  });

  it.each([[['-n', 'README.md']], [['--number', 'README.md']], [['src/index.js']]])('accepts cat arguments %j', (args) => {
    accepts('cat', args as string[]);
  });

  it.each([
    [['--color=always']], [['--format=x']], [['--hide=*']], [['/etc']], [['..']], [['.ssh']], [['.env']], [['-I', 'x']],
  ])('rejects ls arguments %j', (args) => {
    rejects('ls', args as string[]);
  });

  it.each([[['-la', 'src']], [['-R', '.']], [['--color=never', '.']]])('accepts ls arguments %j', (args) => {
    accepts('ls', args as string[]);
  });

  it.each([
    [['-f', 'x', 'y', '.']], [['--file=x', 'n', '.']], [['--exclude-from=x', 'n', '.']], [['--rec', 'n', '.']], [['-rf', 'x', 'n', '.']],
    [['n', '/etc/passwd']], [['n', '.env']], [['-r', 'n', '.ssh']], [['-e', 'n', '../x']], [['--regexp=n', '/etc']], [['-r', 'n', 'envlink.txt']],
  ])('rejects grep arguments %j', (args) => {
    rejects('grep', args as string[]);
  });

  it.each([[['-rn', 'TODO', 'src']], [['--recursive', 'TODO', 'src']], [['-e', 'TODO', 'src']], [['-r', 'TODO', '.']]])('accepts grep arguments %j', (args) => {
    accepts('grep', args as string[]);
  });

  it.each([
    [['--files0-from=x']], [['--files0-from', 'x']], [['--total', 'x']], [['/etc/passwd']], [['.env']],
  ])('rejects wc arguments %j', (args) => {
    rejects('wc', args as string[]);
  });

  it('accepts wc on an in-root file', () => {
    accepts('wc', ['-l', 'README.md']);
  });

  it.each([
    [['.', '-exec', 'echo', '{}', ';']], [['.', '-execdir', 'x', ';']], [['.', '-ok', 'x', ';']], [['.', '-okdir', 'x', ';']], [['.', '-delete']],
    [['.', '-fprint', 'x']], [['.', '-fprint0', 'x']], [['.', '-fls', 'x']], [['.', '-fprintf', 'x', '%p']], [['.', '-newer', '/etc/passwd']],
    [['.', '-files0-from=x']], [['/', '-name', 'x']], [['..']], [['.ssh']], [['-L', '.']], [['outlink.txt']],
  ])('rejects find arguments %j', (args) => {
    rejects('find', args as string[]);
  });

  it.each([[['.', '-name', '*.js', '-type', 'f']], [['src', '-maxdepth', '1']]])('accepts find arguments %j', (args) => {
    accepts('find', args as string[]);
  });

  it('does not expand shell metacharacters or substitutions', async () => {
    const args = ['$(id)', '`id`', '$HOME', 'a|b', 'x&&y', '>out.txt', '*'];
    const result = await runCommand(fx.config, { command: 'echo', args });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.stdout.trim()).toBe(args.join(' '));
    expect(fs.existsSync(path.join(fx.root, 'out.txt'))).toBe(false);
  });

  it('resolves executables from pinned system directories, not a caller-controlled PATH', async () => {
    const fakeDir = path.join(outsideDir, 'fakebin');
    fs.mkdirSync(fakeDir);
    fs.writeFileSync(path.join(fakeDir, 'ls'), '#!/bin/sh\necho FAKE\n');
    fs.chmodSync(path.join(fakeDir, 'ls'), 0o755);
    const original = process.env.PATH;
    process.env.PATH = `${fakeDir}:${original ?? ''}`;
    try {
      const result = await runCommand(fx.config, { command: 'ls', args: ['.'] });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.data.stdout).toContain('README.md');
        expect(result.data.stdout).not.toContain('FAKE');
      }
    } finally {
      if (original === undefined) delete process.env.PATH;
      else process.env.PATH = original;
    }
  });

  it('refuses sensitive and outside paths at execution time without leaking the host root', async () => {
    for (const [command, args] of [['cat', ['.env']], ['cat', ['envlink.txt']], ['cat', ['outlink.txt']], ['ls', ['.ssh']]] as Array<[string, string[]]>) {
      const result = await runCommand(fx.config, { command, args });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
      expect(JSON.stringify(result)).not.toContain(fx.root);
    }
  });

  it('excludes sensitive files and directories from recursive grep regardless of case', async () => {
    const result = await runCommand(fx.config, { command: 'grep', args: ['-rn', 'needlesecret', '.'] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.stdout).toContain('ok.txt');
    expect(result.data.stdout).not.toContain('.env');
    expect(result.data.stdout).not.toContain('.ENV');
    expect(result.data.stdout).not.toContain('id_rsa');
  });

  it('enforces the timeout and resolves promptly', async () => {
    const fifo = path.join(fx.root, 'blocker');
    execFileSync('mkfifo', [fifo]);
    try {
      const startedAt = Date.now();
      const result = await runCommand({ ...fx.config, commandTimeoutMs: 300 }, { command: 'cat', args: ['blocker'] });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('COMMAND_TIMEOUT');
      expect(Date.now() - startedAt).toBeLessThan(3000);
    } finally {
      fs.rmSync(fifo, { force: true });
    }
  });

  it('bounds oversized stderr and stdout independently', async () => {
    const small = { ...fx.config, maxOutputBytes: 10 };
    const err = await runCommand(small, { command: 'ls', args: [`does-not-exist-${'x'.repeat(100)}`] });
    expect(err.ok).toBe(true);
    if (err.ok) {
      expect(err.data.stderrTruncated).toBe(true);
      expect(Buffer.byteLength(err.data.stderr)).toBeLessThanOrEqual(10);
    }
    const out = await runCommand(small, { command: 'echo', args: ['y'.repeat(200)] });
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.data.stdoutTruncated).toBe(true);
      expect(Buffer.byteLength(out.data.stdout)).toBeLessThanOrEqual(10);
    }
  });
});

describe('phase 1 git history and repository configuration hardening', () => {
  const git = (root: string, args: string[]) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', ...args], { cwd: root, stdio: 'pipe' });

  const makeRepo = () => {
    const project = makeFixtureProject();
    fs.rmSync(path.join(project.root, '.git'), { recursive: true, force: true });
    git(project.root, ['init', '-q']);
    fs.writeFileSync(path.join(project.root, 'ok1.txt'), 'visible-one\n');
    git(project.root, ['add', '-A']);
    git(project.root, ['commit', '-q', '-m', 'first']);
    fs.writeFileSync(path.join(project.root, '.env'), 'HISTORYSECRET=abc\n');
    fs.writeFileSync(path.join(project.root, 'upper.ENV'), 'visible-upper\n');
    fs.mkdirSync(path.join(project.root, 'sub'));
    fs.writeFileSync(path.join(project.root, 'sub', '.ENV'), 'HISTORYSECRET=def\n');
    fs.writeFileSync(path.join(project.root, 'server.pem'), 'HISTORYSECRET=ghi\n');
    fs.writeFileSync(path.join(project.root, 'ok2.txt'), 'visible-two\n');
    git(project.root, ['add', '-A']);
    git(project.root, ['commit', '-q', '-m', 'second']);
    return project;
  };

  it.each([
    [['log', '-p', '--all']],
    [['show', 'HEAD']],
    [['diff', 'HEAD~1', 'HEAD']],
    [['log', '--stat']],
    [['show', '--stat', 'HEAD']],
    [['diff', '--name-only', 'HEAD~1', 'HEAD']],
  ])('never prints sensitive files committed to history for git %j', async (args) => {
    const project = makeRepo();
    try {
      const result = await runCommand(project.config, { command: 'git', args: args as string[] });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const output = result.data.stdout;
      expect(output).not.toContain('HISTORYSECRET');
      expect(output).not.toContain('server.pem');
      expect(output).not.toMatch(/\.env\b/i);
      if (args[0] !== 'log' || args.includes('-p')) expect(output).toMatch(/ok2\.txt|first|second/);
    } finally {
      project.cleanup();
    }
  });

  it('still shows non-sensitive history content', async () => {
    const project = makeRepo();
    try {
      const result = await runCommand(project.config, { command: 'git', args: ['show', 'HEAD'] });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.data.stdout).toContain('visible-two');
        expect(result.data.stdout).toContain('visible-upper');
      }
    } finally {
      project.cleanup();
    }
  });

  it.each([
    ['worktree', '[core]\n\tworktree = /tmp/elsewhere\n'],
    ['gitdir', '[core]\n\tgitdir = /tmp/elsewhere\n'],
    ['indented worktree', '[core]\n    Worktree=/tmp/elsewhere\n'],
  ])('rejects git when .git/config sets %s', (_name, content) => {
    const project = makeRepo();
    try {
      fs.writeFileSync(path.join(project.root, '.git', 'config'), content);
      const result = validateCommand({ command: 'git', args: ['status'] }, project.root);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('COMMAND_NOT_ALLOWED');
        expect(result.error.message).not.toContain(project.root);
      }
    } finally {
      project.cleanup();
    }
  });
});
