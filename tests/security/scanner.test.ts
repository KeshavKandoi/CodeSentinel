import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { getSecurityRules } from '../../src/security/ruleRegistry.js';
import type { AppConfig } from '../../src/config.js';
import type { SecurityFinding } from '../../src/security/types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureRoot = path.resolve(__dirname, '..', 'fixtures', 'security-cases');
const pythonFixtureRoot = path.resolve(__dirname, '..', 'fixtures', 'fastapi-routes');
const config: AppConfig = {
  projectRoot: fixtureRoot,
  commandTimeoutMs: 5000,
  maxOutputBytes: 1_000_000,
  maxReadFileBytes: 2_000_000,
  maxListResults: 5_000,
};

async function runScan(): Promise<SecurityFinding[]> {
  const result = await scanProject(config);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.error.message);
  return result.data.findings;
}

describe('Phase 3 security rule registry', () => {
  it('registers unique, metadata-complete rules for the initial rule set', () => {
    const rules = getSecurityRules();
    expect(rules).toHaveLength(21);
    expect(new Set(rules.map((rule) => rule.id)).size).toBe(rules.length);
    for (const rule of rules) {
      expect(rule.id).toMatch(/^CS-NODE-\d{3}$/);
      expect(rule.title.length).toBeGreaterThan(5);
      expect(rule.description.length).toBeGreaterThan(20);
      expect(rule.evidenceRequirements.length).toBeGreaterThan(10);
      expect(rule.remediation.length).toBeGreaterThan(10);
      expect(rule.falsePositiveGuidance.length).toBeGreaterThan(10);
      expect(rule.languages).toContain('node');
    }
  });
});

describe('Phase 3 static security scanner', () => {
  it('does not run Node rules against explicitly unsupported Python projects', async () => {
    const result = await scanProject({ ...config, projectRoot: pythonFixtureRoot });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.project.ecosystem).toBe('python');
    expect(result.data.rulesRun).toEqual([]);
    expect(result.data.findings).toEqual([]);
    expect(result.data.warnings.join(' ')).toMatch(/Python analysis is not yet implemented/i);
  });
  it('returns normalized suspected findings with evidence and summary counts', async () => {
    const result = await scanProject(config);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.project.ecosystem).toBe('node');
    expect(result.data.rulesRun).toHaveLength(21);
    expect(result.data.summary.total).toBe(result.data.findings.length);
    for (const finding of result.data.findings) {
      expect(finding.id).toContain(finding.ruleId);
      expect(finding.status).toBe('suspected');
      expect(finding.verificationStatus).toBe('not_verified');
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(finding.evidence[0].reason.length).toBeGreaterThan(10);
    }
  });

  it('redacts literal credentials from scanner evidence returned through the MCP surface', async () => {
    const findings = await runScan();
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain('sk_live_abcdef1234567890');
    expect(serialized).not.toContain('real-prod-password-12345');
    expect(serialized).toContain('[REDACTED]');
  });

  it('detects one or more positive examples for every initial rule', async () => {
    const findings = await runScan();
    const ids = new Set(findings.map((finding) => finding.ruleId));
    expect(ids).toEqual(new Set(getSecurityRules().map((rule) => rule.id)));
  });

  it('reports source locations for source-backed findings and package evidence for dependency findings', async () => {
    const findings = await runScan();
    const sourceFinding = findings.find((finding) => finding.ruleId === 'CS-NODE-003');
    expect(sourceFinding?.file).toBe('src/vulnerable.ts');
    expect(sourceFinding?.line).toBeGreaterThan(0);
    expect(sourceFinding?.evidence[0].context).toContain('exec');

    const dependencyFinding = findings.find((finding) => finding.ruleId === 'CS-NODE-014');
    expect(dependencyFinding?.file).toBe('package.json');
    expect(dependencyFinding?.evidence[0].matchedText).toContain('node-serialize');
  });

  it('does not trigger on safe examples, comments, documentation, generated folders, or unrelated strings', async () => {
    const findings = await runScan();
    expect(findings.some((finding) => finding.file === 'src/safe.ts')).toBe(false);
    expect(findings.some((finding) => finding.file === 'src/noise.ts')).toBe(false);
    expect(findings.some((finding) => finding.file?.startsWith('docs/'))).toBe(false);
    expect(findings.some((finding) => finding.file?.startsWith('node_modules/'))).toBe(false);
    expect(findings.some((finding) => finding.file?.startsWith('dist/'))).toBe(false);
    expect(findings.some((finding) => finding.evidence[0].matchedText?.includes('changeme'))).toBe(false);
  });

  it('handles malformed and oversized files without crashing or reporting noise', async () => {
    const largeFile = path.join(fixtureRoot, 'src', 'large-generated.js');
    fs.writeFileSync(largeFile, `const apiKey = 'sk_live_large_file_should_be_skipped_12345';\n${'x'.repeat(2_100_000)}`);
    try {
      const findings = await runScan();
      expect(findings.some((finding) => finding.file === 'src/malformed.ts')).toBe(false);
      expect(findings.some((finding) => finding.file === 'src/large-generated.js')).toBe(false);
    } finally {
      fs.rmSync(largeFile, { force: true });
    }
  });

  it('deduplicates findings by rule, location, and evidence', async () => {
    const findings = await runScan();
    const keys = findings.map((finding) => `${finding.ruleId}:${finding.file}:${finding.line}:${finding.evidence[0].matchedText}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
