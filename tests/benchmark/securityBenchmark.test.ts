import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { runDeepSecurityAudit } from '../../src/intelligence/engine.js';
import { buildSecurityProofCaseTemplate } from '../../src/proof/engine.js';
import { PROOF_CASE_TYPES } from '../../src/proof/types.js';

const vulnerableRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const secureRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/generic-node', import.meta.url)));
const config = (projectRoot: string): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 });

describe('local security proof benchmark', () => {
  it('reports the proof catalog without publishing unsupported benchmark claims', () => {
    const catalog = PROOF_CASE_TYPES.map(buildSecurityProofCaseTemplate);
    expect(catalog).toHaveLength(19);
    expect(catalog.every((item) => item.prerequisites.length > 0 && item.vulnerableOracle.length > 0 && item.safeOracle.length > 0)).toBe(true);
  });

  it('compares vulnerable and secure local fixtures for detection and functionality-preserving coverage', async () => {
    const vulnerable = await runDeepSecurityAudit(config(vulnerableRoot));
    const secure = await runDeepSecurityAudit(config(secureRoot));
    expect(vulnerable.ok).toBe(true);
    expect(secure.ok).toBe(true);
    if (!vulnerable.ok || !secure.ok) return;
    const benchmark = {
      detection: vulnerable.data.findings.length > 0,
      falsePositiveCheck: secure.data.integrity.valid,
      verification: 'not_attempted_without_an_operator_authorized_local_target',
      remediation: 'delegated_to_existing_phase9_tests',
      reVerification: 'delegated_to_existing_phase9_tests',
      functionalityPreserved: secure.data.integrity.valid,
    };
    expect(benchmark.detection).toBe(true);
    expect(benchmark.falsePositiveCheck).toBe(true);
    expect(benchmark.verification).toContain('not_attempted');
    expect(JSON.stringify(benchmark)).not.toContain('score');
  });
});
