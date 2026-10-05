import { testCredential } from '../testCredentials.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { getSecurityRules } from '../../src/security/ruleRegistry.js';
import type { AppConfig } from '../../src/config.js';
import type { SecurityFinding } from '../../src/security/types.js';
import { addBoundedWarning, redactSecurityText } from '../../src/security/utils.js';
import { safeText } from '../../src/audit/identity.js';

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
    expect(rules.filter((rule) => Number(rule.id.slice(-3)) <= 21)).toHaveLength(21);
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
  it('explains an unknown root containing nested Node applications without scanning them', async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-workspace-')));
    try {
      fs.mkdirSync(path.join(root, 'service'));
      fs.writeFileSync(path.join(root, 'service', 'package.json'), '{"name":"service"}');
      const result = await scanProject({ ...config, projectRoot: root });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.project.ecosystem).toBe('unknown');
      expect(result.data.project.nestedProjects).toEqual(['service']);
      expect(result.data.message).toMatch(/Nested Node project/i);
      expect(result.data.rulesRun).toEqual([]);
      expect(result.data.fileAnalysis.analyzed).toBe(0);
      expect(result.data.warnings.join(' ')).toMatch(/service.*projectRoot/i);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
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
    expect(result.data.rulesRun.filter((id) => Number(id.slice(-3)) <= 21)).toHaveLength(21);
    expect(result.data.summary.total).toBe(result.data.findings.length);
    for (const finding of result.data.findings) {
      expect(finding.id).toContain(finding.ruleId);
      expect(finding.status).toBe('suspected');
      expect(finding.verificationStatus).toBe('not_verified');
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(finding.evidence[0].reason.length).toBeGreaterThan(10);
      expect(finding.impact.length).toBeGreaterThan(10);
    }
  });

  it('redacts literal credentials from scanner evidence returned through the MCP surface', async () => {
    const findings = await runScan();
    const serialized = JSON.stringify(findings);
    expect(serialized.includes(testCredential('STRIPE_KEY').slice(8, 20))).toBe(false);
    expect(serialized).not.toContain('real-prod-password-12345');
    expect(serialized).toContain('[REDACTED]');
  });

  it('detects one or more positive examples for every initial rule', async () => {
    const findings = await runScan();
    const ids = new Set(findings.map((finding) => finding.ruleId));
    expect(ids).toEqual(new Set(getSecurityRules().filter((rule) => Number(rule.id.slice(-3)) <= 21).map((rule) => rule.id)));
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
    fs.writeFileSync(largeFile, `const apiKey = '${testCredential('API_KEY')}_file_should_be_skipped';\n${'x'.repeat(2_100_000)}`);
    try {
      const findings = await runScan();
      expect(findings.some((finding) => finding.file === 'src/malformed.ts')).toBe(false);
      expect(findings.some((finding) => finding.file === 'src/large-generated.js')).toBe(false);
      const boundedScan = await scanProject(config);
      expect(boundedScan.ok && boundedScan.data.warnings.some(warning => warning.includes('src/large-generated.js') && warning.includes('read limit'))).toBe(true);
      expect(boundedScan.ok && boundedScan.data.fileAnalysis.skippedFiles.some(item => item.file === 'src/large-generated.js' && item.reason.includes('read limit'))).toBe(true);
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

describe('Phase 3 evidence redaction and bounds', () => {
  it.each([
    ['cookie literal', `res.cookie('session', '${testCredential('COOKIE_TOKEN')}', { secure: false })`, testCredential('COOKIE_TOKEN').slice(0, 12)],
    ['Basic header', `res.setHeader('Authorization', 'Basic ${testCredential('BASIC_CREDENTIAL')}')`, testCredential('BASIC_CREDENTIAL').slice(0, 12)],
    ['JWT', `const t = "${testCredential('JWT')}";`, testCredential('JWT').split('.')[1]!.slice(0, 12)],
    ['database URL', `postgres://admin:${testCredential('DB_PASSWORD')}@db.local/app`, testCredential('DB_PASSWORD').slice(0, 12)],
    ['private key', `-----BEGIN RSA PRIVATE KEY-----\n${testCredential('PEM_BODY')}\n-----END RSA PRIVATE KEY-----`, testCredential('PEM_BODY').slice(0, 12)],
  ])('redacts secret-bearing text: %s', (_label, input, secret) => {
    const redacted = redactSecurityText(input);
    expect(redacted.includes(secret)).toBe(false);
    expect(redacted).toContain('[REDACTED]');
  });

  it('does not return literal cookie values in scanner output', async () => {
    expect(JSON.stringify(await runScan())).not.toContain('fixture-secret');
  });

  it('keeps non-sensitive configuration text readable', () => {
    expect(redactSecurityText("res.setHeader('Access-Control-Allow-Origin', '*')")).toContain("'*'");
  });

  it('applies the same redaction to audit evidence text', () => {
    expect(safeText("res.cookie('session', 'audit-literal-abc', {})")).not.toContain('audit-literal-abc');
  });

  it('bounds the number and length of scanner warnings', () => {
    const warnings: string[] = [];
    for (let i = 0; i < 200; i++) addBoundedWarning(warnings, 'x'.repeat(1000));
    expect(warnings.length).toBeLessThanOrEqual(51);
    expect(warnings.every((warning) => warning.length <= 400)).toBe(true);
  });
});

describe('Phase 5 quoted-key and header redaction', () => {
  it.each([
    ['password', JSON.stringify({ password: testCredential('DB_PASSWORD') }), testCredential('DB_PASSWORD').slice(0, 12)],
    ['API key', `'apiKey': '${testCredential('API_KEY')}'`, testCredential('API_KEY').slice(2, 14)],
    ['Cookie', `Cookie: session=${testCredential('COOKIE_TOKEN')}`, testCredential('COOKIE_TOKEN').slice(0, 12)],
  ])('redacts %s', (_label, input, secret) => {
    expect(redactSecurityText(input).includes(secret)).toBe(false);
  });
  it('keeps object-style cookie configuration readable', () => {
    expect(redactSecurityText('cookie: { secure: false }')).toContain('secure: false');
  });

});
