import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AppConfig } from '../src/config.js';
import { getProjectInfo } from '../src/tools/projectInfo.js';
import { toolDefinitions } from '../src/tools/registry.js';

const made: string[] = [];
const config = (projectRoot: string): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 });
function fixture(): { base: string; root: string; gitDir: string } {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-project-info-')));
  made.push(base);
  const root = path.join(base, 'project');
  const gitDir = path.join(root, '.git');
  fs.mkdirSync(gitDir, { recursive: true });
  return { base, root, gitDir };
}
function tool() {
  const found = toolDefinitions.find((item) => item.name === 'get_project_info');
  if (!found) throw new Error('get_project_info is not registered');
  return found;
}
afterEach(() => { for (const base of made.splice(0)) fs.rmSync(base, { recursive: true, force: true }); });

describe('get_project_info Git metadata boundary', () => {
  it('preserves normal branch and detached HEAD detection', () => {
    const { root, gitDir } = fixture();
    fs.writeFileSync(path.join(gitDir, 'HEAD'), 'ref: refs/heads/main\n');
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { hasGit: true, gitBranch: 'main' } });
    const sha = 'a'.repeat(40);
    fs.writeFileSync(path.join(gitDir, 'HEAD'), `${sha}\n`);
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { hasGit: true, gitBranch: sha } });
  });

  it('does not expose a marker through an outside HEAD symlink', async () => {
    const { base, root, gitDir } = fixture();
    const marker = 'OUTSIDE_ROOT_PRIVATE_MARKER_7e3a';
    const outside = path.join(base, 'outside-marker');
    fs.writeFileSync(outside, marker);
    fs.symlinkSync(outside, path.join(gitDir, 'HEAD'));
    const direct = getProjectInfo(config(root));
    expect(direct).toMatchObject({ ok: true, data: { hasGit: true, gitBranch: null } });
    expect(JSON.stringify(direct)).not.toContain(marker);
    const response = await tool().handler(config(''), { projectRoot: root });
    expect(response.isError).toBe(false);
    expect(JSON.stringify(response)).not.toContain(marker);
    expect(JSON.parse(response.content[0]!.text).gitBranch).toBeNull();
  });

  it('ignores internal HEAD symlinks and a symlinked .git directory', () => {
    const { base, root, gitDir } = fixture();
    fs.writeFileSync(path.join(root, 'internal-head'), 'ref: refs/heads/internal\n');
    fs.symlinkSync(path.join(root, 'internal-head'), path.join(gitDir, 'HEAD'));
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { gitBranch: null } });
    fs.rmSync(gitDir, { recursive: true });
    const outsideGit = path.join(base, 'outside-git');
    fs.mkdirSync(outsideGit);
    fs.writeFileSync(path.join(outsideGit, 'HEAD'), 'ref: refs/heads/outside\n');
    fs.symlinkSync(outsideGit, gitDir);
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { gitBranch: null } });
  });

  it('handles missing Git, malformed HEAD, and oversized HEAD safely', () => {
    const { root, gitDir } = fixture();
    fs.rmSync(gitDir, { recursive: true });
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { hasGit: false, gitBranch: null } });
    fs.mkdirSync(gitDir);
    fs.writeFileSync(path.join(gitDir, 'HEAD'), 'malformed private-looking text\n');
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { hasGit: true, gitBranch: null } });
    fs.writeFileSync(path.join(gitDir, 'HEAD'), 'x'.repeat(5000));
    expect(getProjectInfo(config(root))).toMatchObject({ ok: true, data: { hasGit: true, gitBranch: null } });
  });

  it('uses an explicit root over PROJECT_ROOT and falls back to PROJECT_ROOT', async () => {
    const first = fixture();
    const second = fixture();
    fs.writeFileSync(path.join(first.gitDir, 'HEAD'), 'ref: refs/heads/first\n');
    fs.writeFileSync(path.join(second.gitDir, 'HEAD'), 'ref: refs/heads/second\n');
    const fallback = await tool().handler(config(first.root), {});
    const override = await tool().handler(config(first.root), { projectRoot: second.root });
    expect(JSON.parse(fallback.content[0]!.text).gitBranch).toBe('first');
    expect(JSON.parse(override.content[0]!.text).gitBranch).toBe('second');
  });

  it('rejects invalid and symlinked roots at the project-info entry point', () => {
    const { base, root } = fixture();
    const link = path.join(base, 'root-link');
    const file = path.join(base, 'file-root');
    fs.writeFileSync(file, 'file');
    fs.symlinkSync(root, link);
    for (const invalid of [link, path.join(base, 'missing'), file, 'relative-root', `${root}\0extra`]) {
      const result = getProjectInfo(config(invalid));
      expect(result.ok).toBe(false);
    }
  });
});
